import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

project = Path(__file__).resolve().parent
key = "scripted-test-secret-never-logged"
action = {"action": "block_network_flow", "target": "F004", "rationale": "Stop evidenced test C2 flow."}


class Gateway(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.headers["Authorization"] == f"Bearer {key}"
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert data["model"] == "gpt-oss-120b"
        names = {tool["function"]["name"] for tool in data["tools"]}
        results = [entry for entry in data["messages"] if entry["role"] == "tool"]
        enterprise = any(entry["role"] == "user" and "WEB004" in entry["content"] for entry in data["messages"])
        proposal = {**action, "target": "WEB004"} if enterprise else action
        tool = None
        latest_prompt = [entry["content"] for entry in data["messages"] if entry["role"] == "user"][-1]
        is_followup = latest_prompt == "Can you explain your earlier recommendation?"
        if is_followup:
            assert "Request F004 containment." in [entry["content"] for entry in data["messages"] if entry["role"] == "user"]
            assert any(entry["role"] == "assistant" and entry["content"] == "Scripted completion verified."
                       for entry in data["messages"])
            if not results:
                tool, args = "execute_approved_action", {"approval_id": "APR-0001"}
            else:
                assert "during this run" in json.loads(results[-1]["content"])["result"]
        elif "execute_approved_action" not in names:
            assert "request_operator_approval" not in names
            if not results:
                tool, args = "execute_approved_action", {"approval_id": "APR-0001"}
            else:
                assert json.loads(results[-1]["content"])["is_error"]
        elif not results:
            assert "rollback_action" not in names
            tool, args = "execute_approved_action", {"approval_id": "APR-9999"}
        elif len(results) == 1:
            assert json.loads(results[-1]["content"])["is_error"]
            tool, args = "request_operator_approval", proposal
        elif len(results) == 2:
            approval = json.loads(json.loads(results[-1]["content"])["result"])
            tool, args = "wait_for_approval", {"approval_id": approval["approval_id"]}
        elif len(results) == 3:
            approval = json.loads(json.loads(results[-1]["content"])["result"])
            assert approval["status"] == "approved"
            tool, args = "execute_approved_action", {"approval_id": approval["approval_id"]}
        else:
            outcome = json.loads(json.loads(results[-1]["content"])["result"])
            assert outcome["verification"]["verified"]
            assert outcome["verification"]["cooling"]["healthy"]
        message = {"role": "assistant", "content": "Scripted completion verified." if not tool else None}
        if tool:
            message["tool_calls"] = [{"id": str(len(results)), "type": "function",
                                      "function": {"name": tool, "arguments": json.dumps(args)}}]
        body = json.dumps({"choices": [{"message": message}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass



def main():
    with tempfile.TemporaryDirectory() as temp, ThreadingHTTPServer(("127.0.0.1", 0), Gateway) as gateway:
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "BRA_LAB_CONFIG": "", "BRA_WEB_CASE": "", "BRA_STATE_DIR": str(Path(temp) / "state"),
               "BRA_OPERATOR_FILE": str(Path(temp) / "operators.json")}
        launch = ("import browser_agent, uvicorn, web_console; "
                  f"browser_agent.GATEWAY_URL='http://127.0.0.1:{gateway.server_port}/v1'; "
                  f"uvicorn.run(web_console.app, port={port}, log_level='error')")
        app = subprocess.Popen([sys.executable, "-c", launch], cwd=project, env=env)
        base = f"http://127.0.0.1:{port}"
        token = None
        scope = ""
        def call(path, data=None, *, forbidden=False, auth=True):
            headers = {"Content-Type": "application/json"}
            if token and auth:
                headers["X-Operator-Token"] = token
                headers["X-Case-Scope"] = scope
            request = urllib.request.Request(base + path, json.dumps(data).encode() if data is not None else None, headers)
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    body = json.load(response)
                assert not forbidden
                assert key not in json.dumps(body)
                return body
            except urllib.error.HTTPError as exc:
                assert forbidden, exc.read()
                return json.load(exc)

        def wait(predicate):
            deadline = time.monotonic() + 18
            while time.monotonic() < deadline:
                info = call("/api/ai")
                if predicate(info):
                    return info
                time.sleep(0.2)
            raise AssertionError(info)

        try:
            for _ in range(30):
                try:
                    token = call("/api/dashboard")["token"]
                    break
                except urllib.error.URLError:
                    time.sleep(0.3)
            assert token
            idle = call("/api/dashboard")
            assert idle["active_case"] is None
            call("/api/ai-run", {"goal": "no case", "mode": "recommend"}, forbidden=True)
            shipboard = next(case for case in idle["cases"] if case["profile"] == "shipboard")
            commerce = next(case for case in idle["cases"] if case["profile"] == "enterprise")
            call("/api/select-case", {"case": shipboard["key"]})
            scope = call("/api/dashboard")["scope"]
            call("/api/ai-configure", {"model": "gpt-oss-120b", "key": key}, forbidden=True, auth=False)
            call("/api/ai-configure", {"model": "gpt-oss-120b", "key": key})
            call("/api/provision-operators", {"soc": "test password one", "ot": "test password two"})
            call("/api/ai-run", {"goal": "Read findings.", "mode": "recommend"})
            read = wait(lambda info: info["run"]["status"] != "running")
            assert read["run"]["status"] == "completed", read
            assert call("/api/approvals")["result"] == []
            print("PASS browser key setup, CSRF and read-only boundary")
            call("/api/ai-run", {"goal": "Request F004 containment.", "mode": "containment"})
            pending = wait(lambda info: any(e["kind"] == "approval" for e in info["run"]["events"]))
            approval = next(e["approval"] for e in pending["run"]["events"] if e["kind"] == "approval")
            aid = approval["approval_id"]
            call("/api/select-case", {"case": commerce["key"]}, forbidden=True)
            assert call("/api/approvals")["result"][0]["status"] == "pending"
            call("/api/execute", {"approval_id": aid}, forbidden=True)
            call("/api/approve", {"approval_id": aid, "identity": "soc-watch", "passphrase": "wrong"}, forbidden=True)
            call("/api/approve", {"approval_id": aid, "identity": "soc-watch", "passphrase": "test password one"})
            final = wait(lambda info: info["run"]["status"] != "running")
            assert final["run"]["status"] == "completed", final
            assert call("/api/approvals")["result"][0]["execution_status"] == "verified"
            action_card = call("/api/activity")["actions"][0]
            assert [step["label"] for step in action_card["stages"]][-3:] == ["Executing", "Applied", "Verified"]
            assert action_card["before"]["probes"]["F004"]["allowed"] == 3
            assert action_card["after"]["probes"]["F004"]["allowed"] == 0
            assert action_card["after"]["cooling"]["healthy"]
            print("PASS shipboard browser approval, MCP execution, and verified timeline")
            call("/api/select-case", {"case": commerce["key"]})
            data = call("/api/dashboard")
            assert data["active_case"]["health_label"] == "Checkout availability"
            assert data["outcomes"]["cooling"]["limit_s"] == 30
            assert data["outcomes"]["cooling"]["healthy"]
            assert data["approvals"]["result"] == []
            assert call("/api/ai")["history"] == []
            call("/api/request", action, forbidden=True)  # old case scope
            scope = data["scope"]
            call("/api/execute", {"approval_id": aid}, forbidden=True)  # old ID with current scope
            request = {"action": "block_network_flow", "target": "WEB004", "rationale": "Contain suspicious egress."}
            pending = call("/api/request", request)
            call("/api/select-case", {"case": shipboard["key"]}, forbidden=True)
            call("/api/deny", {"approval_id": pending["approval_id"], "identity": "soc-watch", "passphrase": "test password one"})
            call("/api/ai-run", {"goal": "Request WEB004 containment.", "mode": "containment"})
            pending = wait(lambda info: any(e["kind"] == "approval" for e in info["run"]["events"]))
            approval = next(e["approval"] for e in pending["run"]["events"] if e["kind"] == "approval")
            assert approval["target"] == "WEB004"
            call("/api/approve", {"approval_id": approval["approval_id"], "identity": "soc-watch",
                                  "passphrase": "test password one"})
            final = wait(lambda info: info["run"]["status"] != "running")
            assert final["run"]["status"] == "completed", final
            after = call("/api/dashboard")["outcomes"]
            assert after["probes"]["WEB004"]["allowed"] == 0 and after["cooling"]["healthy"]
            print("PASS enterprise browser AI, approval, execution, and checkout verification")
            case = {"case_id": "CUSTOM-001", "title": "Custom egress report", "summary": "Unexpected traffic.",
                    "produced_by": "Test SOC", "findings": [{"id": "E1", "kind": "threat",
                    "claim": "Unusual outbound session", "confidence": 0.95, "evidence": ["Observed egress"],
                    "related_flows": ["F004"]}]}
            call("/api/import-case", {"profile": "enterprise", "incident": case}, forbidden=True)
            case["findings"][0]["related_flows"] = ["WEB004"]
            imported = call("/api/import-case", {"profile": "enterprise", "incident": case})
            assert call("/api/dashboard")["intake"][0]["status"] == "Needs review"
            call("/api/select-case", {"case": imported["case"]})
            data = call("/api/dashboard")
            assert data["active_case"]["case_id"] == "CUSTOM-001"
            assert data["intake"][0]["status"] == "Opened"
            assert data["outcomes"]["probes"].keys() == {"WEB004"}
            assert data["approvals"]["result"] == []
            print("PASS environment selection, validated import, pending switch refusal and isolated approvals")
            app.terminate()
            app.wait(timeout=10)
            app = subprocess.Popen([sys.executable, "-c", launch], cwd=project, env=env)
            token, scope = None, ""
            for _ in range(30):
                try:
                    token = call("/api/dashboard")["token"]
                    break
                except urllib.error.URLError:
                    time.sleep(0.3)
            assert token
            call("/api/select-case", {"case": shipboard["key"]})
            scope = call("/api/dashboard")["scope"]
            restored = call("/api/ai")
            assert not restored["configured"] and len(restored["history"]) == 2
            assert restored["history"][1]["goal"] == "Request F004 containment."
            call("/api/ai-configure", {"model": "gpt-oss-120b", "key": key})
            call("/api/ai-run", {"goal": "Can you explain your earlier recommendation?", "mode": "containment"})
            followup = wait(lambda info: info["run"]["status"] != "running")
            assert followup["run"]["status"] == "completed", followup
            assert len(followup["history"]) == 3
            exported = call("/api/conversation?scope=" + scope)
            assert len(exported["turns"]) == 3 and exported["turns"][1]["events"]
            assert "test password one" not in json.dumps(exported)
            assert not any("WEB004" in turn["goal"] for turn in exported["turns"])
            print("PASS persistent thread after restart, follow-up context, case isolation, and fresh approval scope")
        finally:
            app.terminate()
            app.wait(timeout=10)
            gateway.shutdown()


if __name__ == "__main__":
    main()
