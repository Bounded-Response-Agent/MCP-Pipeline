"""Real defensive controls for the isolated Podman shipboard lab."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from lab.stack import SLOTS, pod
from lab.firewall import IptablesFirewall, NftablesFirewall
from profiles import profile_path
from response_logic import ResponseError, Scenario

PROBE_BY_PORT = {8004: "F004", 8005: "F005", 8006: "F006"}


def request(service, path, *, data=None, token=None, method=None, slot="default"):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if isinstance(data, dict):
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode()
    elif data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = data.encode()
    url = f"http://127.0.0.1:{SLOTS[slot][2][service]}{path}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, headers, method=method), timeout=5) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise ResponseError(f"{service} returned HTTP {exc.code}.") from exc
    except (OSError, ValueError) as exc:
        raise ResponseError(f"{service} is unavailable or returned invalid data.") from exc


def in_container(container, *arguments, slot="default"):
    try:
        subnet = SLOTS[slot][1]
        arguments = [str(arg).replace("10.245.77", subnet) for arg in arguments]
        return pod("exec", f"bra-{container}", *arguments, timeout=12, slot=slot).strip()
    except RuntimeError as exc:
        raise ResponseError(str(exc)) from exc


class LabScenario(Scenario):
    def __init__(self, configuration):
        super().__init__(profile_path(configuration.get("profile", "shipboard")))
        self.lab = configuration
        self.slot = configuration.get("slot", "default")
        self.subnet = SLOTS[self.slot][1]
        binding = self.profile["lab"]
        self.flow_ports = binding["flow_ports"]
        self.account = binding["account"]
        self.primary = self.functions[self.monitor]["primary_asset"]
        self.backup = self.functions[self.monitor]["backup_asset"]
        self.limit = int(self.functions[self.monitor]["max_tolerable_gap_s"])
        driver = {"nftables": NftablesFirewall, "iptables": IptablesFirewall}[binding["firewall"]]
        self.firewall = driver(lambda *args: self.container("primary", *args))
        self.policy["global_rules"]["max_actions_per_case_without_review"] = 8
        self.hold = Path(configuration["state_dir"]) / "lab-hold.txt"

    def request(self, *args, **kwargs):
        return request(*args, **kwargs, slot=self.slot)

    def container(self, container, *args):
        return in_container(container, *args, slot=self.slot)

    def lab_alerts(self):
        try:
            rows = self.container("primary", "tail", "-n", "300", "/tmp/eve.json")
        except ResponseError:
            raise ResponseError("Suricata EVE is unavailable. Check the lab sensor.") from None
        alerts = []
        for line in rows.splitlines():
            event = json.loads(line)
            if event.get("event_type") != "alert" or event.get("src_ip") != f"{self.subnet}.10":
                continue
            alerts.append({"source": "Suricata", "timestamp": event["timestamp"], "flow_id": event["flow_id"],
                           "destination_port": event["dest_port"], "signature": event["alert"]["signature"],
                           "signature_id": event["alert"]["signature_id"]})
        return alerts[-30:]

    def get_investigation_findings(self, case_id=None):
        return {**super().get_investigation_findings(case_id), "lab_alerts": self.lab_alerts()}

    def token(self, *, admin=False, refresh=None):
        if admin:
            fields = {"grant_type": "client_credentials", "client_id": "bra-admin",
                      "client_secret": self.lab["client_secret"]}
        elif refresh:
            fields = {"grant_type": "refresh_token", "client_id": "bra-login", "refresh_token": refresh}
        else:
            fields = {"grant_type": "password", "client_id": "bra-login", "username": self.account,
                      "password": self.lab["user_password"]}
        return self.request("keycloak", "/realms/bra/protocol/openid-connect/token", data=urllib.parse.urlencode(fields))

    def identity(self):
        token = self.token(admin=True)["access_token"]
        query = urllib.parse.urlencode({"username": self.account, "exact": "true"})
        users = self.request("keycloak", f"/admin/realms/bra/users?{query}", token=token)
        if len(users) != 1 or users[0]["username"] != self.account:
            raise ResponseError("The dedicated Keycloak lab account could not be resolved.")
        return token, users[0]

    def set_identity(self, enabled):
        token, user = self.identity()
        path = f"/admin/realms/bra/users/{user['id']}"
        if user["enabled"] != enabled:
            self.request("keycloak", path, token=token, method="PUT", data={"enabled": enabled})
        if not enabled:
            self.request("keycloak", path + "/logout", token=token, method="POST")

    def login_allowed(self, refresh=None):
        try:
            self.token(refresh=refresh)
            return True
        except ResponseError as exc:
            if str(exc) == "keycloak returned HTTP 400.":
                return False
            raise

    def probe(self, target):
        probe = PROBE_BY_PORT[self.flow_ports[target]] if target in self.flow_ports else target
        result = self.container("primary", "python3", "/lab/workload.py", "probe", probe)
        if result not in ("0", "1"):
            raise ResponseError("The lab network probe returned invalid data.")
        return int(result)

    def observe_threats(self):
        legitimate = bool(self.probe("legitimate"))
        outcomes = {target: {"hostile_attempts": 1, "allowed": self.probe(target),
                             "legitimate_scope_available": legitimate, "source": "lab connection probe"}
                    for target in self.threat_targets("related_flows")}
        outcomes[self.account] = {"hostile_attempts": 1, "allowed": int(self.login_allowed()), "source": "Keycloak"}
        return outcomes

    def poll_samples(self, poller, metric):
        query = urllib.parse.urlencode({"query": f'{metric}{{poller="{poller}"}}[20s]'})
        rows = self.request("prometheus", f"/api/v1/query?{query}")["data"]["result"]
        return [(float(stamp), float(value)) for stamp, value in rows[0]["values"]] if rows else []

    def observe_cooling(self, switch_gap=0):
        source = self.runtime["function_location"][self.monitor]
        poller = "backup" if source == self.backup else "primary"
        samples = self.poll_samples(poller, "bra_cooling_last_poll_seconds")
        active = self.poll_samples(poller, "bra_cooling_active")
        polls = sorted({value for _, value in samples if value > 0})
        now = time.time()
        age = round(now - polls[-1], 2) if polls else None
        gaps = [round(b - a, 2) for a, b in zip(polls, polls[1:])]
        max_gap = max([max(0, age or 0), *gaps]) if polls else None
        healthy = bool(active and active[-1][1] == 1 and age is not None
                       and -2 <= age <= min(6, self.limit) and max_gap <= self.limit)
        return {"source": source, "backend": "Prometheus", "window_s": 20, "poll_timestamps": polls,
                "max_gap_s": max_gap, "latest_poll_age_s": age,
                "aborted_for_missing_telemetry": not healthy, "limit_s": self.limit, "healthy": healthy}

    def policy_decision(self, simulation, *, phase, operator_role):
        if self.hold.exists():
            raise ResponseError("The lab is on hold. Reconcile the actuator state before resuming.")
        health = self.observe_cooling()
        target = simulation["target"]
        if target in self.flow_ports:
            alerts = self.lab_alerts()
            live_evidence = any(
                alert["destination_port"] == self.flow_ports[target]
                and 0 <= time.time() - datetime.fromisoformat(alert["timestamp"]).timestamp() <= 1800
                for alert in alerts
            )
        else:
            live_evidence = True
        action = simulation["action"]
        scope = {"block_network_flow": list(self.flow_ports), "restrict_network_flow": list(self.flow_ports),
                 "disable_account": [self.account], "failover_to_backup": [self.monitor],
                 "isolate_endpoint": [self.primary] if self.profile["isolation_supported"] else []}
        body = {"case_id": self.findings["case_id"], "profile": self.profile["id"],
                "scope": scope, "expected_backup": self.backup, "action": action, "target": target,
                "simulation_allowed": simulation["verdict"] == "allowed" and live_evidence,
                "phase": phase, "operator_role": operator_role,
                "required_role": simulation["approval_level_if_allowed"],
                "cooling_source": health["source"], "cooling_healthy": health["healthy"]}
        result = self.request("opa", "/v1/data/bra/response/decision", data={"input": body}).get("result", {})
        return {"allowed": result.get("allow") is True, "revision": result.get("revision"),
                "live_evidence": live_evidence, "input": body}

    def firewall_apply(self, action, target, execution_id):
        if action == "isolate_endpoint":
            if not self.profile["isolation_supported"] or target != self.primary:
                raise ResponseError("This live environment cannot isolate that endpoint.")
            self.firewall.apply(execution_id, [], isolate=True)
            return
        if target not in self.flow_ports:
            raise ResponseError("No live firewall binding exists for this flow.")
        ports = [self.flow_ports[target]]
        if action == "block_network_flow" and target in self.profile["legitimate_scope_penalty"]:
            ports.append(8007)
        self.firewall.apply(execution_id, ports)

    def wait_for_poller(self, poller, *, after=None, timeout=12):
        after = time.time() if after is None else after
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            samples = self.poll_samples(poller, "bra_cooling_last_poll_seconds")
            if samples and samples[-1][1] >= after:
                return True
            time.sleep(0.8)
        return False

    def commit_live_action(self):
        self.hold.unlink(missing_ok=True)

    def begin_live_mutation(self, execution_id, action, target):
        if self.hold.exists():
            raise ResponseError("The lab is on hold. Reconcile the actuator state before resuming.")
        self.hold.parent.mkdir(parents=True, exist_ok=True)
        with self.hold.open("x", encoding="utf-8") as file:
            file.write(f"{execution_id} {action} {target}: mutation in progress\n")
            file.flush()
            os.fsync(file.fileno())

    def execute_action(self, action, target, execution_id):
        before = self.observe_cooling()
        refresh = None
        self.begin_live_mutation(execution_id, action, target)
        try:
            if action == "disable_account":
                refresh = self.token()["refresh_token"]
                self.set_identity(False)
            elif action == "failover_to_backup":
                self.container("backup", "touch", "/tmp/poll-active")
                if self.wait_for_poller("backup"):
                    self.container("primary", "rm", "-f", "/tmp/poll-active")
            else:
                self.firewall_apply(action, target, execution_id)
            self._verification_baseline = before
            self._refresh = refresh
            if action != "failover_to_backup":
                poller = "backup" if before["source"] == self.backup else "primary"
                self._post_action_poll = self.wait_for_poller(poller, timeout=8)
            else:
                self._post_action_poll = True
            return super().execute_action(action, target, execution_id)
        except Exception as exc:
            # Preserve the operator hold if a side effect might have happened before readback.
            self.hold.write_text(f"{execution_id} {action} {target}: {exc}\n", encoding="utf-8")
            raise ResponseError(f"{execution_id} has an uncertain lab outcome. Review the lab hold before retrying.") from exc
        finally:
            self._verification_baseline = None
            self._refresh = None
            self._post_action_poll = None

    def verify_execution(self, execution_id, switch_gap=0):
        result = super().verify_execution(execution_id, switch_gap)
        record = self.executions[execution_id]
        if getattr(self, "_post_action_poll", None) is False:
            result["cooling"]["healthy"] = False
            result["cooling"]["reason"] = "No fresh poll was observed after applying the control."
        action = record["action"]
        if action == "disable_account":
            result["configuration_applied"] &= self.identity()[1]["enabled"] is False
            refresh = getattr(self, "_refresh", None)
            if refresh:
                result["existing_session_refresh_denied"] = not self.login_allowed(refresh)
                result["targeted_activity_stopped"] &= result["existing_session_refresh_denied"]
        elif action == "failover_to_backup":
            # Measure the transition from real poll timestamps from both sources.
            baseline = getattr(self, "_verification_baseline", None)
            if baseline and baseline["poll_timestamps"] and result["cooling"]["poll_timestamps"]:
                last_primary = baseline["poll_timestamps"][-1]
                next_backup = next((stamp for stamp in result["cooling"]["poll_timestamps"] if stamp >= last_primary), None)
                if next_backup is not None:
                    gap = round(next_backup - last_primary, 2)
                    result["cooling"]["transition_gap_s"] = gap
                    result["cooling"]["max_gap_s"] = max(gap, result["cooling"]["max_gap_s"])
                    result["cooling"]["healthy"] &= gap <= self.limit
        else:
            result["firewall_rule_handles"] = self.firewall.rules(execution_id)
            result["configuration_applied"] &= bool(result["firewall_rule_handles"])
            if action == "isolate_endpoint":
                result["targeted_activity_stopped"] &= not self.probe("cooling") and not self.probe("legitimate")
        result["verified"] &= (result["configuration_applied"] and result["targeted_activity_stopped"]
                               and result["cooling"]["healthy"])
        result["environment"] = "live lab"
        return result

    def rollback_action(self, execution_id):
        record = self.executions.get(execution_id)
        if not record or record["status"] == "rolled_back":
            return super().rollback_action(execution_id)
        action = record["action"]
        for change in record["patch"]:
            if self.runtime[change["field"]][change["key"]] != change["after"]:
                raise ResponseError("Rollback conflicts with a later change.")
        if action == "failover_to_backup" and self.runtime["device_isolated"][self.primary]:
            raise ResponseError("The primary is isolated. Keep backup monitoring active.")
        if getattr(self, "_verification_baseline", None) is None:
            self.begin_live_mutation(execution_id, "rollback", record["target"])
        if action == "failover_to_backup":
            self.container("primary", "touch", "/tmp/poll-active")
            if not self.wait_for_poller("primary"):
                raise ResponseError("Primary polling is unverified. Keep backup monitoring active.")
            self.container("backup", "rm", "-f", "/tmp/poll-active")
        elif action == "disable_account":
            self.set_identity(True)
            if not self.identity()[1]["enabled"] or not self.login_allowed():
                raise ResponseError("Keycloak rollback could not be verified.")
        else:
            self.firewall.rollback(execution_id)
            if self.firewall.rules(execution_id):
                raise ResponseError("Firewall rollback could not be verified.")
        return super().rollback_action(execution_id)


def load_lab():
    config = os.environ.get("BRA_LAB_CONFIG")
    return LabScenario(json.loads(Path(config).read_text(encoding="utf-8"))) if config else None
