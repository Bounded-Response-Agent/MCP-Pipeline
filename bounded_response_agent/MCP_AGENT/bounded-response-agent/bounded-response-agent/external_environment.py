"""Explicitly opt-in REST adapter for the local containment test environment."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class ExternalEnvironmentError(Exception):
    """The external test environment rejected or could not complete an operation."""


class ExternalTestEnvironment:
    """Call a REST environment only when it is explicitly marked as a test target."""

    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or os.environ.get("BRA_EXTERNAL_BASE_URL") or "").rstrip("/")
        self.token = token or os.environ.get("BRA_EXTERNAL_TOKEN")
        if os.environ.get("BRA_EXECUTION_MODE") != "external-test":
            raise ExternalEnvironmentError("External execution requires BRA_EXECUTION_MODE=external-test.")
        if os.environ.get("BRA_ENVIRONMENT") != "test":
            raise ExternalEnvironmentError("External execution requires BRA_ENVIRONMENT=test.")
        if not self.base_url:
            raise ExternalEnvironmentError("BRA_EXTERNAL_BASE_URL is required for external execution.")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Bounded-Response-Mode": "test",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ExternalEnvironmentError(f"External test environment request failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ExternalEnvironmentError("External test environment returned a non-object response.")
        return result

    def execute(self, approval_id: str, action: str, target: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/actions",
            {"approval_id": approval_id, "action": action, "target": target},
        )

    def verify(self, execution_id: str) -> dict[str, Any]:
        return self._request("GET", f"/executions/{execution_id}")

    def rollback(self, execution_id: str) -> dict[str, Any]:
        return self._request("POST", f"/executions/{execution_id}/rollback", {})
