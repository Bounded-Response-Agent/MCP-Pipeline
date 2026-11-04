"""Run and capture an end-to-end live lab exercise through the web console and MCP."""

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from lab_backend import LabScenario
from operator_console import provision

ROOT = Path(__file__).resolve().parent
STEPS = [("block_network_flow", "F004"), ("restrict_network_flow", "F005"),
         ("restrict_network_flow", "F006"), ("disable_account", "eng.mokoa")]


def run(config, port):
    lab = LabScenario(json.loads(config.read_text(encoding="utf-8")))
    if Path(lab.lab["state_dir"], "approvals").exists():
        raise RuntimeError("Run the integration demo against a fresh lab and configuration.")
    base = f"http://127.0.0.1:{port}"
    events = []
    with tempfile.TemporaryDirectory() as temp:
        credentials = Path(temp) / "operators.json"
        passwords = {identity: secrets.token_urlsafe(24) for identity in ("soc-watch", "ot-watch")}
        provision(credentials, passwords)
        env = {**os.environ, "BRA_LAB_CONFIG": str(config.resolve()), "BRA_WEB_CASE": "", "BRA_OPERATOR_FILE": str(credentials)}
        process = subprocess.Popen([sys.executable, str(ROOT / "web_console.py"), "--port", str(port)], env=env)
        try:
            token = None
            scope = None

            def call(path, data=None, *, error=False):
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["X-Operator-Token"] = token
                    headers["X-Case-Scope"] = scope
                body = json.dumps(data).encode() if data is not None else None
                try:
                    with urllib.request.urlopen(urllib.request.Request(base + path, body, headers), timeout=100) as r:
                        result = json.load(r)
                    assert not error, (path, result)
                except urllib.error.HTTPError as exc:
                    result = json.load(exc)
                    assert error, (path, result)
                if token:
                    arguments = {k: v for k, v in (data or {}).items() if k != "passphrase"}
                    saved = {key: value for key, value in result.items() if key not in ("token", "scope")}
                    events.append({"endpoint": path, "arguments": arguments, "result": saved})
                return result

            deadline = time.monotonic() + 30
            while True:
                try:
                    initial_auth = call("/api/dashboard")
                    token, scope = initial_auth["token"], initial_auth["scope"] or ""
                    break
                except urllib.error.URLError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.5)
            enterprise = lab.profile["id"] == "enterprise"
            steps = [("block_network_flow", "WEB004"), ("disable_account", "checkout-support")] if enterprise else STEPS
            for target in lab.flow_ports:
                assert lab.probe(target)
            deadline = time.monotonic() + 15
            while not set(lab.flow_ports.values()).issubset({item["destination_port"] for item in lab.lab_alerts()}):
                if time.monotonic() > deadline:
                    raise RuntimeError("Suricata did not report the required live probe alerts.")
                time.sleep(1)
            scan = call("/api/scan-intake", {})
            assert scan["new_groups"] == len(lab.flow_ports)
            assert call("/api/scan-intake", {})["alerts_added"] == 0
            inbox = call("/api/dashboard")
            assert inbox["active_case"] is None
            assert inbox["intake"][0]["status"] == "Needs review"
            call("/api/select-case", {"case": "live"})
            initial = call("/api/dashboard")
            scope = initial["scope"]
            assert initial["intake"][0]["status"] == "Opened"
            assert initial["approvals"]["result"] == []
            assert initial["environment"]["mode"] == "live lab"
            assert initial["findings"]["lab_alerts"]
            assert initial["outcomes"]["cooling"]["healthy"]
            assert [(s["action"], s["target"]) for s in initial["plans"]["recommended_plan"]["steps"]] == steps

            def propose(action, target, *, error=False):
                return call("/api/request", {"action": action, "target": target, "rationale": "Reviewed lab containment and mission dependencies."}, error=error)

            def decision(operation, identity, **fields):
                return call("/api/" + operation, {"identity": identity, "passphrase": passwords[identity], **fields})

            def apply(action, target, identity="soc-watch", expected="verified"):
                approved = propose(action, target)
                assert approved["status"] == "pending", approved
                aid = approved["approval_id"]
                decision("approve", identity, approval_id=aid)
                result = call("/api/execute", {"approval_id": aid})
                assert result["status"] == expected, result
                print("PASS", action, target, expected, flush=True)
                return result

            if enterprise:
                assert "Unknown action" in propose("isolate_endpoint", lab.primary, error=True)["error"]
            else:
                assert propose("isolate_endpoint", "ws-eng01")["status"] == "refused"
            assert propose("block_network_flow", "WEB001" if enterprise else "F001")["status"] == "refused"
            pending = propose(*steps[0])
            call("/api/execute", {"approval_id": pending["approval_id"]}, error=True)
            call("/api/approve", {"approval_id": pending["approval_id"], "identity": "soc-watch",
                                  "passphrase": "intentionally wrong"}, error=True)
            results = [apply(*step) for step in steps]
            assert results[-1]["verification"]["existing_session_refresh_denied"]
            activity = call("/api/activity")["actions"]
            flow = next(item for item in activity if item.get("execution_id") == results[0]["execution_id"])
            path = steps[0][1]
            assert [step["label"] for step in flow["stages"]][-3:] == ["Executing", "Applied", "Verified"]
            assert flow["before"]["probes"][path]["allowed"] > 0
            assert flow["after"]["probes"][path]["allowed"] == 0
            assert flow["after"]["cooling"]["healthy"]
            assert flow["operator"].startswith("soc-watch:")
            contained = call("/api/dashboard")["outcomes"]
            assert all(item["allowed"] == 0 for item in contained["probes"].values())
            assert contained["cooling"]["healthy"]

            if enterprise:
                assert contained["cooling"]["limit_s"] == 30
                execution = results[0]["execution_id"]
                assert results[0]["verification"]["firewall_rule_handles"]
                decision("authorize-rollback", "soc-watch", execution_id=execution, note="Review scoped recovery.")
                restored = call("/api/rollback", {"execution_id": execution})
                assert restored["probes"]["WEB004"]["allowed"] == 1
                assert restored["probes"]["checkout-support"]["allowed"] == 0
                assert restored["cooling"]["healthy"]
                lab.container("primary", "touch", "/tmp/poll-silent")
                try:
                    deadline = time.monotonic() + 15
                    while lab.observe_cooling()["healthy"] and time.monotonic() < deadline:
                        time.sleep(1)
                    assert not lab.observe_cooling()["healthy"]
                    assert "OPA denied" in propose("failover_to_backup", lab.monitor, error=True)["error"]
                finally:
                    lab.container("primary", "rm", "-f", "/tmp/poll-silent")
                assert lab.wait_for_poller("primary")
                apply(*steps[0])
                final = call("/api/dashboard")
                assert final["outcomes"]["cooling"]["healthy"] and final["audit_integrity"]["ok"]
                assert all(item["allowed"] == 0 for item in final["outcomes"]["probes"].values())
                return {"environment": "enterprise live Podman lab", "status": "passed", "events": events}

            # Exercise a separate escalation branch after an authorized scoped reversal.
            flow_execution = results[2]["execution_id"]
            decision("authorize-rollback", "soc-watch", execution_id=flow_execution,
                     note="Exercise reversal. A subsequent lab fault will leave one path active.")
            reversed_flow = call("/api/rollback", {"execution_id": flow_execution})
            assert reversed_flow["probes"]["F006"]["allowed"] == 1
            assert all(reversed_flow["probes"][target]["allowed"] == 0 for target in ("F004", "F005", "eng.mokoa"))
            # Install a real earlier exception to simulate an independently managed rule.
            lab.container("primary", "nft", "insert", "rule", "inet", "bra", "output",
                "ip", "daddr", "10.245.77.20", "tcp", "dport", "8006", "accept", "comment", "exercise-conflict")
            events.append({"fixture": "added lab firewall precedence conflict for F006"})
            conflict = apply("restrict_network_flow", "F006", expected="rolled_back")
            assert conflict["verification"]["configuration_applied"]
            assert not conflict["verification"]["targeted_activity_stopped"]
            escalation = call("/api/dashboard")["plans"]["recommended_plan"]
            assert escalation["name"] == "failover_then_isolate", escalation
            # Open a lab-only failure condition before requesting a real failover.
            lab.container("backup", "touch", "/tmp/poll-silent")
            try:
                failed = apply("failover_to_backup", "cooling_monitoring", "ot-watch", "rolled_back")
                assert failed["recovery"]["cooling"]["healthy"]
                recovery = next(item for item in call("/api/activity")["actions"]
                                if item.get("execution_id") == failed["execution_id"])
                assert [step["label"] for step in recovery["stages"]][-2:] == ["Verification failed", "Rolled back"]
                assert recovery["before"]["probes"]["F004"]["allowed"] == 0
                assert recovery["recovery"]["probes"]["F004"]["allowed"] == 0
                assert failed["recovery"]["probes"]["F006"]["allowed"] == 1
                assert all(failed["recovery"]["probes"][target]["allowed"] == 0 for target in ("F004", "F005", "eng.mokoa"))
                assert propose("isolate_endpoint", "ws-eng01")["status"] == "refused"
            finally:
                lab.container("backup", "rm", "-f", "/tmp/poll-silent")
            moved = apply("failover_to_backup", "cooling_monitoring", "ot-watch")
            assert moved["verification"]["cooling"]["transition_gap_s"] <= 120
            isolated = apply("isolate_endpoint", "ws-eng01", "ot-watch")
            assert isolated["verification"]["cooling"]["source"] == "backup-mon01"
            assert isolated["verification"]["firewall_rule_handles"]
            final = call("/api/dashboard")
            assert all(item["allowed"] == 0 for item in final["outcomes"]["probes"].values())
            assert final["outcomes"]["cooling"]["healthy"]
            assert final["audit_integrity"]["ok"]
            assert any(event["event"] == "lab_policy_decision" and event["revision"] == "shipboard-lab-v2"
                       for event in final["audit"]["result"])
            return {"environment": "live Podman lab", "status": "passed", "events": events}
        finally:
            process.terminate()
            process.wait(timeout=15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("lab-state/config.json"))
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--output", type=Path, default=Path("live-trace.json"))
    args = parser.parse_args()
    trace = run(args.config, args.port)
    args.output.write_text(json.dumps(trace, indent=2) + "\n", encoding="utf-8")
