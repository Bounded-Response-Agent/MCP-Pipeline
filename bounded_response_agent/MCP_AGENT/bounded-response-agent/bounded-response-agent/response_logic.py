"""Read-only analysis layer for the Bounded Response Agent.

Everything here is pure Python with no MCP imports, so it can be unit tested without the
MCP package. server.py exposes these methods as MCP tools. Nothing in this module changes
state: simulations are dry runs over the scenario files in data/v2.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_DATA = Path(__file__).parent / "data" / "v2"
FLOW_ACTIONS = ("block_network_flow", "restrict_network_flow")
SEVERITY_ORDER = {"none": 0, "low": 1, "unacceptable": 2}


class ResponseError(Exception):
    """Invalid request. The server turns this into a ToolError the model can read."""


def _read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _true(value: str) -> bool:
    return str(value).strip().lower() == "true"


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "passed": bool(passed), "detail": detail}


class Scenario:
    def __init__(self, data_dir: Path | str = DEFAULT_DATA):
        d = Path(data_dir)
        self.devices = {r["hostname"]: r for r in _read_csv(d / "devices.csv")}
        self.accounts = {r["account"]: r for r in _read_csv(d / "accounts.csv")}
        self.flows = {r["flow_id"]: r for r in _read_csv(d / "flows.csv")}
        self.functions = {r["function_id"]: r for r in _read_csv(d / "functions.csv")}
        self.dependencies = _read_csv(d / "dependencies.csv")
        self.health = _read_csv(d / "health.csv")
        self.events = _read_csv(d / "events.csv")
        self.findings = json.loads((d / "findings.json").read_text(encoding="utf-8"))
        self.policy = json.loads((d / "policy.json").read_text(encoding="utf-8"))
        self.runtime = {
            "flow_status": {flow_id: row["status"] for flow_id, row in self.flows.items()},
            "account_enabled": {account: True for account in self.accounts},
            "device_isolated": {hostname: False for hostname in self.devices},
            "function_location": {
                function_id: row["primary_asset"] for function_id, row in self.functions.items()
            },
        }
        self.executions: dict[str, dict[str, Any]] = {}
        self._next_execution_id = 1

    # ------------------------------------------------------------------ read tools
    def lookup_device(self, hostname: str) -> dict[str, str]:
        key = (hostname or "").strip()
        if key not in self.devices:
            raise ResponseError(f"No device named '{hostname}'. Known devices: {', '.join(sorted(self.devices))}.")
        return dict(self.devices[key])

    def lookup_account(self, account: str) -> dict[str, str]:
        key = (account or "").strip()
        if key not in self.accounts:
            raise ResponseError(f"No account named '{account}'. Known accounts: {', '.join(sorted(self.accounts))}.")
        return dict(self.accounts[key])

    def get_network_flows(self, host: str | None = None) -> list[dict[str, str]]:
        if host is None:
            return [dict(f) for f in self.flows.values()]
        self.lookup_device(host)
        h = host.strip()
        return [dict(f) for f in self.flows.values() if h in (f["src_host"], f["dst_host"])]

    def get_system_health(self, system: str | None = None) -> list[dict[str, str]]:
        if system is None:
            return [dict(r) for r in self.health]
        s = system.strip()
        rows = [dict(r) for r in self.health if r["system"] == s]
        if not rows:
            raise ResponseError(f"No health telemetry for '{system}'.")
        return rows

    def get_events(
        self,
        host: str | None = None,
        source: str | None = None,
        severity: str | None = None,
        action: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, str]]:
        """Event timeline from EDR, firewall and identity sources, oldest first."""
        if not 1 <= limit <= 200:
            raise ResponseError("limit must be between 1 and 200.")
        for name, value in (("source", source), ("severity", severity), ("action", action)):
            if value is not None:
                allowed = sorted({e[name] for e in self.events})
                if value not in allowed:
                    raise ResponseError(f"{name} must be one of: {', '.join(allowed)}.")
        if host is not None:
            host = host.strip()
            if host not in self.devices:
                try:
                    host = str(ipaddress.ip_address(host))
                except ValueError:
                    raise ResponseError(f"'{host}' is neither a known device nor a valid IP address.") from None
        cutoff = None
        if since is not None:
            try:
                cutoff = datetime.fromisoformat(since.strip().replace("Z", "+00:00"))
            except ValueError:
                raise ResponseError("since must be an ISO timestamp like 2026-10-12T21:00:00Z.") from None
        out = []
        for e in self.events:
            if host is not None and host not in (e["src"], e["dst"]):
                continue
            if source is not None and e["source"] != source:
                continue
            if severity is not None and e["severity"] != severity:
                continue
            if action is not None and e["action"] != action:
                continue
            if cutoff is not None and datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) < cutoff:
                continue
            out.append(dict(e))
        return sorted(out, key=lambda e: e["timestamp"])[:limit]

    def get_mission_dependencies(self, function_id: str | None = None) -> list[dict[str, Any]]:
        if function_id is not None and function_id.strip() not in self.functions:
            raise ResponseError(f"No function '{function_id}'. Known functions: {', '.join(self.functions)}.")
        ids = [function_id.strip()] if function_id else list(self.functions)
        return [
            {
                "function": dict(self.functions[fid]),
                "dependencies": [dict(d) for d in self.dependencies if d["function_id"] == fid],
            }
            for fid in ids
        ]

    def get_investigation_findings(self, case_id: str | None = None) -> dict[str, Any]:
        self._check_case(case_id)
        return self.findings

    def get_response_policy(self, action: str | None = None) -> dict[str, Any]:
        base = {
            "policy_version": self.policy["policy_version"],
            "roles": self.policy["roles"],
            "global_rules": self.policy["global_rules"],
        }
        if action is None:
            return {**base, "principles": self.policy["principles"], "actions": self.policy["actions"]}
        return {**base, "action": action, "rules": self._rules(action)}

    # ------------------------------------------------------------------ helpers
    def _check_case(self, case_id: str | None) -> None:
        if case_id and case_id.strip() != self.findings["case_id"]:
            raise ResponseError(f"Unknown case '{case_id}'. The open case is {self.findings['case_id']}.")

    def _rules(self, action: str) -> dict[str, Any]:
        actions = self.policy["actions"]
        if action not in actions:
            raise ResponseError(f"Unknown action '{action}'. Valid actions: {', '.join(actions)}.")
        return actions[action]

    def _resolve_target(self, action: str, target: str | None) -> tuple[str | None, str | None]:
        rules = self._rules(action)
        ttype = rules.get("target_type")
        if ttype is None:
            return None, (target or "").strip() or None
        table = {
            "flow": self.flows,
            "account": self.accounts,
            "function": self.functions,
            "device": self.devices,
        }[ttype]
        t = (target or "").strip()
        if t not in table:
            raise ResponseError(
                f"{action} needs a {ttype} target; '{target}' is not one. Valid {ttype}s: {', '.join(table)}."
            )
        return ttype, t

    def _parse_assumed(self, assume_done: list[str] | None) -> set[tuple[str, str]]:
        done: set[tuple[str, str]] = set()
        for item in assume_done or []:
            if ":" not in item:
                raise ResponseError(
                    f"assume_done entry '{item}' must look like 'failover_to_backup:cooling_monitoring'."
                )
            a, t = (s.strip() for s in item.split(":", 1))
            if not self._rules(a).get("state_changing"):
                raise ResponseError(f"assume_done entry '{item}': '{a}' does not change state.")
            self._resolve_target(a, t)
            done.add((a, t))
        return done

    def _effects(self, action: str, target: str | None) -> set[tuple[str, str]]:
        """Resources that stop being available if the action is carried out."""
        if action in FLOW_ACTIONS:
            return {("flow", target)}
        if action == "disable_account":
            return {("account", target)}
        if action == "isolate_endpoint":
            lost = {("device", target)}
            lost |= {("flow", fid) for fid, f in self.flows.items() if target in (f["src_host"], f["dst_host"])}
            lost |= {
                ("account", name)
                for name, row in self.accounts.items()
                if row["bound_hosts"] and set(row["bound_hosts"].split(";")) == {target}
            }
            return lost
        return set()

    def _function_impact(self, fid: str, lost: set[tuple[str, str]], done: set[tuple[str, str]]) -> dict[str, Any]:
        fn = self.functions[fid]
        deps = [d for d in self.dependencies if d["function_id"] == fid]
        key = lambda d: (d["requires_type"], d["requires_id"])  # noqa: E731
        primary_lost = [key(d) for d in deps if d["role"] in ("primary", "shared") and key(d) in lost]
        backup_lost = [key(d) for d in deps if d["role"] in ("backup", "shared") and key(d) in lost]
        failed_over = ("failover_to_backup", fid) in done
        safety = _true(fn["safety_critical"])
        max_gap = int(fn["max_tolerable_gap_s"])
        has_backup = bool(fn["backup_asset"]) and _true(fn["backup_ready"])
        out: dict[str, Any] = {
            "function_id": fid,
            "name": fn["name"],
            "safety_critical": safety,
            "max_tolerable_gap_s": max_gap,
            "failed_over": failed_over,
            "severity": "none",
            "status": "unaffected",
            "predicted_gap_s": 0,
            "exceeds_max_gap": False,
            "detail": "",
            "mitigation": None,
        }
        impaired = (primary_lost and not failed_over) or (failed_over and backup_lost)
        if impaired:
            lost_names = [f"{t}:{i}" for t, i in (backup_lost if failed_over else primary_lost)]
            out.update(
                status="impaired",
                predicted_gap_s=None,
                exceeds_max_gap=True,
                severity="unacceptable" if safety else "low",
            )
            out["detail"] = (
                f"Loses {', '.join(lost_names)}. Telemetry or service stays down until "
                + ("the backup is restored." if failed_over else "failover completes or the primary is restored.")
                + f" That exceeds the {max_gap} s limit."
            )
            if not failed_over and has_backup and not backup_lost:
                out["mitigation"] = f"failover_to_backup:{fid}"
        elif backup_lost and not failed_over:
            out.update(status="failover_capability_lost", severity="low")
            out["detail"] = (
                "Primary keeps working but the standby path is lost, so failover would no longer be possible."
            )
        elif failed_over:
            out.update(status="running_on_backup")
            out["detail"] = "Backup carries the function; primary losses do not interrupt it."
        return out

    def _safety_functions_depending_on_device(self, device: str) -> list[str]:
        out = []
        for fid, fn in self.functions.items():
            if not _true(fn["safety_critical"]):
                continue
            if any(
                d["function_id"] == fid
                and d["role"] == "primary"
                and d["requires_type"] == "device"
                and d["requires_id"] == device
                for d in self.dependencies
            ):
                out.append(fid)
        return out

    def _backup_health(self, fid: str) -> tuple[bool, str]:
        backup = self.functions[fid]["backup_asset"]
        rows = [r for r in self.health if r["system"] == backup]
        if not rows:
            return False, f"No health telemetry for {backup or 'a backup'}."
        bad = [f"{r['metric']}={r['value']}" for r in rows if r["status"] != "ok"]
        return (not bad), (
            f"{backup} metrics all ok ({len(rows)} checked)." if not bad else f"{backup} unhealthy: {', '.join(bad)}."
        )

    def _role_level(self, role: str | None) -> int:
        return self.policy["roles"][role]["level"] if role else 0

    def _runtime_done(self) -> set[tuple[str, str]]:
        done = {
            ("block_network_flow", flow_id)
            for flow_id, status in self.runtime["flow_status"].items()
            if status == "blocked"
        }
        done |= {
            ("restrict_network_flow", flow_id)
            for flow_id, status in self.runtime["flow_status"].items()
            if status == "restricted"
        }
        done |= {
            ("disable_account", account)
            for account, enabled in self.runtime["account_enabled"].items()
            if not enabled
        }
        done |= {
            ("isolate_endpoint", hostname)
            for hostname, isolated in self.runtime["device_isolated"].items()
            if isolated
        }
        done |= {
            ("failover_to_backup", function_id)
            for function_id, location in self.runtime["function_location"].items()
            if location == self.functions[function_id]["backup_asset"]
        }
        return done

    # ------------------------------------------------------------------ analysis tools
    def analyze_mission_impact(
        self, action: str, target: str | None = None, assume_done: list[str] | None = None
    ) -> dict[str, Any]:
        done = self._parse_assumed(assume_done)
        ttype, tgt = self._resolve_target(action, target)
        if (action, tgt) in done and self._rules(action).get("state_changing"):
            raise ResponseError(f"'{action}:{tgt}' is already in assume_done; analyze a different step.")
        lost: set[tuple[str, str]] = set()
        for a, t in done:
            lost |= self._effects(a, t)
        lost |= self._effects(action, tgt)

        functions = [self._function_impact(fid, lost, done) for fid in self.functions]
        functions = [f for f in functions if f["severity"] != "none" or f["status"] == "running_on_backup"]

        if action == "failover_to_backup":
            fn = self.functions[tgt]
            window = int(fn["failover_time_s"])
            limit = int(fn["max_tolerable_gap_s"])
            functions = [f for f in functions if f["function_id"] != tgt]
            functions.append(
                {
                    "function_id": tgt,
                    "name": fn["name"],
                    "safety_critical": _true(fn["safety_critical"]),
                    "max_tolerable_gap_s": limit,
                    "failed_over": True,
                    "severity": "unacceptable" if window > limit else "low",
                    "status": "switching",
                    "predicted_gap_s": window,
                    "exceeds_max_gap": window > limit,
                    "detail": f"Switch to {fn['backup_asset']} takes about {window} s against a {limit} s limit.",
                    "mitigation": None,
                }
            )

        severity = max((f["severity"] for f in functions), key=SEVERITY_ORDER.get, default="none")
        safety_affected = [f["function_id"] for f in functions if f["safety_critical"] and f["severity"] != "none"]
        own = self._effects(action, tgt)
        resources = sorted(f"{t}:{i}" for t, i in own)
        if severity == "none":
            summary = "No mission function is interrupted."
        else:
            summary = " ".join(f"{f['function_id']}: {f['detail']}" for f in functions if f["severity"] != "none")
        return {
            "action": action,
            "target": tgt,
            "assumed_done": sorted(f"{a}:{t}" for a, t in done),
            "severity": severity,
            "safe_to_proceed": severity != "unacceptable",
            "safety_critical_functions_affected": safety_affected,
            "functions": functions,
            "resources_lost": resources,
            "summary": summary,
        }

    def _addressed_findings(self, action: str, tgt: str | None) -> list[dict[str, Any]]:
        out = []
        for fd in self.findings["findings"]:
            if action in FLOW_ACTIONS:
                hit = tgt in fd.get("related_flows", [])
            elif action == "disable_account":
                hit = tgt in fd.get("affected_accounts", [])
            elif action == "isolate_endpoint":
                hit = tgt in fd.get("affected_assets", []) or any(
                    self.flows[fl]["src_host"] == tgt for fl in fd.get("related_flows", []) if fl in self.flows
                )
            else:
                hit = False
            if hit:
                out.append(fd)
        return out

    def simulate_response(
        self, action: str, target: str | None = None, assume_done: list[str] | None = None
    ) -> dict[str, Any]:
        """Dry run: policy check, preconditions, evidence and mission impact. Changes nothing."""
        rules = self._rules(action)
        done = self._parse_assumed(assume_done) | self._runtime_done()
        ttype, tgt = self._resolve_target(action, target)
        impact = self.analyze_mission_impact(
            action, tgt, [f"{a}:{t}" for a, t in sorted(done)]
        )
        g = self.policy["global_rules"]
        forbidden: list[str] = []
        pre: list[dict[str, Any]] = []
        role = rules.get("approval_required")
        changes: list[str] = []

        if action in FLOW_ACTIONS:
            f = self.flows[tgt]
            already = any(a in FLOW_ACTIONS and t == tgt for a, t in done)
            if _true(f["mission_critical"]):
                forbidden.append(
                    f"Flow {tgt} is mission critical ({f['purpose']}); policy forbids blocking or restricting it."
                )
            pre.append(
                _check(
                    "flow_is_active",
                    self.runtime["flow_status"][tgt] == "active" and not already,
                    f"status is '{'changed earlier' if already else self.runtime['flow_status'][tgt]}'.",
                )
            )
            pre.append(
                _check("no_function_pushed_past_its_limit", impact["severity"] != "unacceptable", impact["summary"])
            )
            dest = f["dst_host"] or f["dst_ip"]
            verb = "blocked" if action == "block_network_flow" else "restricted"
            changes.append(f"Flow {tgt} ({f['src_host']} -> {dest}:{f['dst_port']} {f['protocol']}) active -> {verb}.")
        elif action == "disable_account":
            a = self.accounts[tgt]
            privileged = "admin" in a["privilege"]
            if a["revocable_by_agent"] != "true":
                forbidden.append(f"Account {tgt} is not revocable by the agent; escalate to a human.")
            if privileged:
                forbidden.append(f"Account {tgt} is privileged ({a['privilege']}); policy forbids disabling it.")
            fid = a["used_by_function"]
            if a["type"] == "service" and fid in self.functions:
                fn = self.functions[fid]
                if _true(fn["safety_critical"]) and not (fn["backup_asset"] and _true(fn["backup_ready"])):
                    forbidden.append(f"{tgt} is the primary identity of safety-critical {fid} and no backup is ready.")
            pre.append(_check("account_not_privileged", not privileged, f"privilege is '{a['privilege']}'."))
            pre.append(
                _check(
                    "account_enabled",
                    self.runtime["account_enabled"][tgt] and ("disable_account", tgt) not in done,
                    "account is currently enabled." if self.runtime["account_enabled"][tgt] else "account is disabled.",
                )
            )
            changes.append(f"Account {tgt} enabled -> disabled; new logins denied.")
        elif action == "isolate_endpoint":
            d = self.devices[tgt]
            if _true(d["protected"]):
                forbidden.append(f"{tgt} is a protected {d['role']}; the agent may not act on it. Escalate.")
            pre.append(_check("device_not_protected", not _true(d["protected"]), f"protected={d['protected']}."))
            dependents = self._safety_functions_depending_on_device(tgt)
            for fid in dependents:
                ok = ("failover_to_backup", fid) in done
                pre.append(
                    _check(
                        f"failover_completed:{fid}",
                        ok,
                        "failover assumed complete." if ok else f"{fid} still runs on {tgt}; fail over first.",
                    )
                )
            pre.append(_check("predicted_gap_within_limit", impact["severity"] != "unacceptable", impact["summary"]))
            if dependents and rules.get("approval_required_if_safety_dependency"):
                role = rules["approval_required_if_safety_dependency"]
            changes.append(
                f"Device {tgt} network-isolated. Flows lost: "
                f"{', '.join(i for t, i in sorted(self._effects(action, tgt)) if t == 'flow') or 'none'}."
            )
        elif action == "failover_to_backup":
            fn = self.functions[tgt]
            health_ok, health_detail = (
                self._backup_health(tgt) if fn["backup_asset"] else (False, "No backup asset defined.")
            )
            pre.append(
                _check(
                    "function_has_backup", bool(fn["backup_asset"]), f"backup asset: {fn['backup_asset'] or 'none'}."
                )
            )
            pre.append(_check("backup_marked_ready", _true(fn["backup_ready"]), f"backup_ready={fn['backup_ready']}."))
            pre.append(_check("backup_health_ok", health_ok, health_detail))
            pre.append(
                _check(
                    "not_already_failed_over",
                    False if ("failover_to_backup", tgt) in done else True,
                    "function is on its primary.",
                )
            )
            changes.append(
                f"Function {tgt}: polling moves from {fn['primary_asset']} to {fn['backup_asset']}; "
                f"expected switch window {fn['failover_time_s']} s."
            )
        else:
            changes.append("No change. Keep watching the affected assets.")

        addressed = self._addressed_findings(action, tgt)
        threat = [f for f in addressed if f.get("kind") == "threat"]
        threshold = g["min_finding_confidence_to_act"]
        if action in FLOW_ACTIONS + ("disable_account", "isolate_endpoint"):
            meets = any(f["confidence"] >= threshold for f in threat)
            containment = "targeted" if threat else "none"
        elif action == "failover_to_backup":
            meets, containment = True, "enabler"
        else:
            meets, containment = True, "none"

        if impact["safety_critical_functions_affected"] and rules.get("state_changing"):
            needed = g["safety_critical_impact_requires"]
            if self._role_level(needed) > self._role_level(role):
                role = needed

        failed_pre = [p for p in pre if not p["passed"]]
        reasons: list[str] = []
        if forbidden:
            verdict, reasons = "forbidden", forbidden
        elif rules.get("state_changing") and not meets:
            verdict = "insufficient_evidence"
            reasons = [f"No finding at or above confidence {threshold} supports acting on {tgt}."]
        elif impact["severity"] == "unacceptable":
            verdict, reasons = "unacceptable_impact", [impact["summary"]]
            mitigations = [f["mitigation"] for f in impact["functions"] if f.get("mitigation")]
            if mitigations:
                reasons.append(f"Possible mitigation first: {', '.join(mitigations)}.")
        elif failed_pre:
            verdict = "preconditions_not_met"
            reasons = [f"{p['check']}: {p['detail']}" for p in failed_pre]
        else:
            verdict = "allowed"
            reasons = ["Policy, evidence, preconditions and mission impact all pass."]

        decision = "BLOCKED" if verdict != "allowed" else (
            "PENDING_APPROVAL" if rules.get("state_changing") else "APPROVED"
        )
        return {
            "dry_run": True,
            "action": action,
            "target": tgt,
            "assumed_done": impact["assumed_done"],
            "verdict": verdict,
            "decision": decision,
            "reasons": reasons,
            "approval_required": role if (rules.get("state_changing") and verdict == "allowed") else None,
            "approval_level_if_allowed": role if rules.get("state_changing") else None,
            "disruption_rank": rules["disruption_rank"],
            "preconditions": pre,
            "evidence": {
                "containment": containment,
                "meets_confidence_threshold": meets,
                "threshold": threshold,
                "findings": [
                    {"id": f["id"], "claim": f["claim"], "confidence": f["confidence"], "kind": f.get("kind")}
                    for f in addressed
                ],
            },
            "mission_impact": impact,
            "predicted_state_changes": changes,
            "rollback": rules.get("rollback"),
            "max_duration_minutes": rules.get("max_duration_minutes"),
        }

    def evaluate_response_request(
        self, action: str, target: str | None = None, assume_done: list[str] | None = None
    ) -> dict[str, Any]:
        """Classify a proposed response as approved, rejected, or requiring human review."""
        simulation = self.simulate_response(action, target, assume_done)
        if simulation["verdict"] != "allowed":
            gate_status = "REJECTED"
            explanation = (
                "The request was rejected because it failed the defensive policy gate. "
                + " ".join(simulation["reasons"])
            )
        elif simulation["approval_required"] is not None:
            gate_status = "HUMAN_REVIEW"
            explanation = (
                f"The request passed automated checks but requires approval from "
                f"{simulation['approval_required']} before execution."
            )
        else:
            gate_status = "APPROVED"
            explanation = "The request is read-only or non-state-changing and passed automated checks."
        return {
            "gate_status": gate_status,
            "explanation": explanation,
            "action": simulation["action"],
            "target": simulation["target"],
            "reasoning": simulation["reasons"],
            "simulation": simulation,
            "next_step": {
                "REJECTED": "Do not execute. Escalate or choose a safer action.",
                "HUMAN_REVIEW": "Create an operator approval request; do not execute yet.",
                "APPROVED": "Proceed with the read-only or non-state-changing result.",
            }[gate_status],
        }

    def evaluate_investigation_response(
        self, case_id: str | None = None, assume_done: list[str] | None = None
    ) -> dict[str, Any]:
        """Evaluate response options derived from the current investigation findings."""
        self._check_case(case_id)
        options = self.list_response_options(case_id, assume_done)["options"]
        decisions = []
        for option in options:
            gate = self.evaluate_response_request(option["action"], option["target"], assume_done)
            decisions.append(
                {
                    "action": gate["action"],
                    "target": gate["target"],
                    "gate_status": gate["gate_status"],
                    "explanation": gate["explanation"],
                    "reasoning": gate["reasoning"],
                    "required_role": gate["simulation"]["approval_required"],
                    "disruption_rank": gate["simulation"]["disruption_rank"],
                    "predicted_state_changes": gate["simulation"]["predicted_state_changes"],
                    "next_step": gate["next_step"],
                }
            )
        return {
            "case_id": self.findings["case_id"],
            "source": "investigation_findings",
            "finding_summary": self.findings["summary"],
            "decisions": decisions,
        }

    def execute_action(self, action: str, target: str | None, assume_done: list[str] | None = None) -> dict[str, Any]:
        """Apply an already-authorized action to simulated state and verify it."""
        simulation = self.simulate_response(action, target, assume_done)
        if simulation["verdict"] != "allowed":
            raise ResponseError(f"Execution blocked: {simulation['verdict']}: {' '.join(simulation['reasons'])}")
        snapshot = {
            "flow_status": dict(self.runtime["flow_status"]),
            "account_enabled": dict(self.runtime["account_enabled"]),
            "device_isolated": dict(self.runtime["device_isolated"]),
            "function_location": dict(self.runtime["function_location"]),
        }
        target = simulation["target"]
        if action == "block_network_flow":
            self.runtime["flow_status"][target] = "blocked"
        elif action == "restrict_network_flow":
            self.runtime["flow_status"][target] = "restricted"
        elif action == "disable_account":
            self.runtime["account_enabled"][target] = False
        elif action == "isolate_endpoint":
            self.runtime["device_isolated"][target] = True
        elif action == "failover_to_backup":
            self.runtime["function_location"][target] = self.functions[target]["backup_asset"]
            for flow_id, flow in self.flows.items():
                if flow["function_id"] == target and flow["src_host"] == self.functions[target]["backup_asset"]:
                    self.runtime["flow_status"][flow_id] = "active"
        execution_id = f"EXE-{self._next_execution_id:04d}"
        self._next_execution_id += 1
        self.executions[execution_id] = {
            "execution_id": execution_id,
            "action": action,
            "target": target,
            "snapshot": snapshot,
            "status": "executed",
            "verified": False,
        }
        verification = self.verify_execution(execution_id)
        self.executions[execution_id]["verified"] = verification["verified"]
        if not verification["verified"]:
            self.rollback_action(execution_id)
            raise ResponseError(f"Execution verification failed for {execution_id}; state was rolled back.")
        return {
            "execution_id": execution_id,
            "status": "executed",
            "decision": "APPROVED",
            "verification": verification,
            "predicted_state_changes": simulation["predicted_state_changes"],
        }

    def verify_execution(self, execution_id: str) -> dict[str, Any]:
        record = self.executions.get(execution_id)
        if record is None:
            raise ResponseError(f"No execution named '{execution_id}'.")
        action, target = record["action"], record["target"]
        if action == "block_network_flow":
            verified = self.runtime["flow_status"][target] == "blocked"
            observed = self.runtime["flow_status"][target]
        elif action == "restrict_network_flow":
            verified = self.runtime["flow_status"][target] == "restricted"
            observed = self.runtime["flow_status"][target]
        elif action == "disable_account":
            verified = not self.runtime["account_enabled"][target]
            observed = "disabled" if verified else "enabled"
        elif action == "isolate_endpoint":
            verified = self.runtime["device_isolated"][target]
            observed = "isolated" if verified else "reachable"
        elif action == "failover_to_backup":
            verified = self.runtime["function_location"][target] == self.functions[target]["backup_asset"]
            observed = self.runtime["function_location"][target]
        else:
            raise ResponseError(f"'{action}' cannot be verified.")
        return {"execution_id": execution_id, "verified": verified, "observed_state": observed}

    def rollback_action(self, execution_id: str) -> dict[str, Any]:
        record = self.executions.get(execution_id)
        if record is None:
            raise ResponseError(f"No execution named '{execution_id}'.")
        if record["status"] == "rolled_back":
            return {"execution_id": execution_id, "status": "rolled_back", "decision": "APPROVED"}
        for key, value in record["snapshot"].items():
            self.runtime[key] = dict(value)
        record["status"] = "rolled_back"
        return {"execution_id": execution_id, "status": "rolled_back", "decision": "APPROVED"}

    def list_response_options(self, case_id: str | None = None, assume_done: list[str] | None = None) -> dict[str, Any]:
        self._check_case(case_id)
        threat = [f for f in self.findings["findings"] if f.get("kind") == "threat"]
        cands: list[tuple[str, str | None]] = [("continue_monitoring", None)]
        assets: list[str] = []
        for fd in threat:
            for fl in fd.get("related_flows", []):
                cands += [("block_network_flow", fl), ("restrict_network_flow", fl)]
            for acct in fd.get("affected_accounts", []):
                cands.append(("disable_account", acct))
            for host in fd.get("affected_assets", []):
                cands.append(("isolate_endpoint", host))
                assets.append(host)
        for fid, fn in self.functions.items():
            if fn["backup_asset"] and fn["primary_asset"] in assets:
                cands.append(("failover_to_backup", fid))
        done = self._parse_assumed(assume_done)
        seen: set[tuple[str, str | None]] = set(done)  # steps already assumed are not options
        options = []
        for a, t in cands:
            if (a, t) in seen:
                continue
            seen.add((a, t))
            sim = self.simulate_response(a, t, assume_done)
            options.append(
                {
                    "action": a,
                    "target": t,
                    "disruption_rank": sim["disruption_rank"],
                    "verdict": sim["verdict"],
                    "approval_required": sim["approval_required"],
                    "mission_severity": sim["mission_impact"]["severity"],
                    "addresses_findings": [f["id"] for f in sim["evidence"]["findings"] if f["kind"] == "threat"],
                    "reason": sim["reasons"][0] if sim["reasons"] else "",
                }
            )
        options.sort(key=lambda o: (o["disruption_rank"], o["target"] or ""))
        covered = {fid for o in options if o["verdict"] == "allowed" for fid in o["addresses_findings"]}
        uncovered = [f["id"] for f in threat if f["id"] not in covered]
        blocked_cover = {
            fid: [
                f"{o['action']}:{o['target']} ({o['verdict']})"
                for o in options
                if fid in o["addresses_findings"] and o["verdict"] != "allowed"
            ]
            for fid in uncovered
        }
        return {
            "case_id": self.findings["case_id"],
            "assumed_done": sorted(f"{a}:{t}" for a, t in self._parse_assumed(assume_done)),
            "options": options,
            "threat_findings_covered_by_allowed_options": sorted(covered),
            "threat_findings_not_covered": uncovered,
            "only_blocked_options_would_cover": blocked_cover,
        }
