"""Local REST test environment for safe external execution demonstrations."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class TestEnvironmentState:
    def __init__(self) -> None:
        self.flows = {"F004": "active"}
        self.executions: dict[str, dict[str, Any]] = {}
        self.next_id = 1

    def execute(self, approval_id: str, action: str, target: str) -> dict[str, Any]:
        if action != "block_network_flow" or target not in self.flows:
            raise ValueError("Only block_network_flow for a known test flow is enabled.")
        if self.flows[target] != "active":
            raise ValueError("The test flow is not active.")
        execution_id = f"EXT-{self.next_id:04d}"
        self.next_id += 1
        self.executions[execution_id] = {
            "execution_id": execution_id,
            "approval_id": approval_id,
            "action": action,
            "target": target,
            "previous_state": self.flows[target],
            "state": "blocked",
            "verified": True,
        }
        self.flows[target] = "blocked"
        return self.executions[execution_id]

    def rollback(self, execution_id: str) -> dict[str, Any]:
        execution = self.executions[execution_id]
        restored_state = execution["previous_state"]
        self.flows[execution["target"]] = restored_state
        execution["state"] = restored_state
        execution["status"] = "rolled_back"
        execution["verified"] = True
        return execution


def create_server(state: TestEnvironmentState | None = None) -> ThreadingHTTPServer:
    environment = state or TestEnvironmentState()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, result: dict[str, Any]) -> None:
            body = json.dumps(result).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("request body must be an object")
            return value

        def do_POST(self) -> None:
            try:
                body = self._body()
                if self.path == "/actions":
                    self._send(200, environment.execute(body["approval_id"], body["action"], body["target"]))
                elif self.path.startswith("/executions/") and self.path.endswith("/rollback"):
                    execution_id = self.path.split("/")[2]
                    self._send(200, environment.rollback(execution_id))
                else:
                    self._send(404, {"error": "not found"})
            except (KeyError, ValueError):
                self._send(400, {"error": "invalid test action"})

        def do_GET(self) -> None:
            if self.path.startswith("/executions/"):
                execution_id = self.path.split("/")[2]
                if execution_id in environment.executions:
                    self._send(200, environment.executions[execution_id])
                else:
                    self._send(404, {"error": "unknown execution"})
            else:
                self._send(404, {"error": "not found"})

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


if __name__ == "__main__":
    server = create_server()
    print(f"http://{server.server_address[0]}:{server.server_address[1]}", flush=True)
    server.serve_forever()
