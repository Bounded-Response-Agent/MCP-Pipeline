"""Tests for approvals and the audit log. Run: python -m unittest -v test_approvals"""

import ast
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from approvals import ApprovalService
from response_logic import ResponseError, Scenario
from test_environment import TestEnvironmentState, create_server

FAILOVER = ["failover_to_backup:cooling_monitoring"]
SERVER = Path(__file__).parent / "server.py"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 12, 22, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


class ApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenario = Scenario()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.environment = patch.dict(
            os.environ,
            {
                "BRA_EXECUTION_MODE": "",
                "BRA_ENVIRONMENT": "",
                "BRA_EXTERNAL_BASE_URL": "",
                "BRA_EXTERNAL_TOKEN": "",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.clock = Clock()
        self.svc = ApprovalService(self.scenario, self.tmp.name, self.clock)

    def request_block(self, flow="F004"):
        return self.svc.request("block_network_flow", flow, "Stop traffic to the suspected C2 host")

    # ---- requests
    def test_allowed_action_creates_pending_request(self):
        r = self.request_block()
        self.assertEqual(r["status"], "pending")
        self.assertEqual(r["approval_id"], "APR-0001")
        self.assertEqual(r["required_role"], "soc_operator")
        self.assertEqual((r["action"], r["target"]), ("block_network_flow", "F004"))
        self.assertEqual(r["case_id"], "CASE-2026-1012-001")
        self.assertEqual(r["seconds_left"], 900)
        self.assertFalse(r["valid_for_execution"])
        self.assertEqual(r["plan"]["mission_severity"], "none")
        self.assertEqual(len(r["plan_hash"]), 64)

    def test_supervisor_needed_for_isolation_after_failover(self):
        r = self.svc.request("isolate_endpoint", "ws-eng01", "Contain the host", FAILOVER)
        self.assertEqual(r["required_role"], "ot_supervisor")

    def test_refused_requests_create_no_approval_but_are_audited(self):
        for action, target, verdict in (
            ("isolate_endpoint", "ws-eng01", "unacceptable_impact"),
            ("block_network_flow", "F001", "forbidden"),
            ("disable_account", "adm.kealoha", "forbidden"),
            ("isolate_endpoint", "ws-eng02", "insufficient_evidence"),
        ):
            r = self.svc.request(action, target, "Try it")
            self.assertEqual((r["status"], r["verdict"]), ("refused", verdict), (action, target))
        self.assertEqual(self.svc.list_approvals(), [])
        refusals = self.svc.audit.read(event="approval_request_refused")
        self.assertEqual([e["verdict"] for e in refusals][0], "unacceptable_impact")
        self.assertEqual(len(refusals), 4)

    def test_bad_requests_raise(self):
        for call in (
            lambda: self.svc.request("continue_monitoring", None, "Just watching"),
            lambda: self.svc.request("block_network_flow", "F004", ""),
            lambda: self.svc.request("block_network_flow", "F004", "x" * 501),
            lambda: self.svc.request("launch_missiles", "x", "Because"),
            lambda: self.svc.request("block_network_flow", "F999", "Because"),
        ):
            with self.assertRaises(ResponseError):
                call()

    def test_duplicate_request_returns_the_same_approval(self):
        first = self.request_block()
        second = self.request_block()
        self.assertEqual(first["approval_id"], second["approval_id"])
        self.assertEqual(len(self.svc.list_approvals()), 1)
        self.assertEqual(first["plan_hash"], second["plan_hash"])

    def test_case_cap_forces_human_review(self):
        for action, flow in (
            ("block_network_flow", "F004"),
            ("block_network_flow", "F005"),
            ("block_network_flow", "F006"),
            ("restrict_network_flow", "F004"),
            ("restrict_network_flow", "F005"),
        ):
            self.assertEqual(self.svc.request(action, flow, "Contain")["status"], "pending")
        sixth = self.svc.request("restrict_network_flow", "F006", "Contain")
        self.assertEqual(sixth["verdict"], "review_needed")

    # ---- decisions
    def test_approve_and_deny(self):
        a = self.request_block("F004")
        b = self.request_block("F005")
        done = self.svc.decide(a["approval_id"], "approve", "soc_operator", "R. Nakamura", "Looks right")
        self.assertEqual(done["status"], "approved")
        self.assertTrue(done["valid_for_execution"])
        self.assertEqual(done["decided_by"], {"name": "R. Nakamura", "role": "soc_operator"})
        denied = self.svc.decide(b["approval_id"], "deny", "soc_operator", "R. Nakamura", "Not yet")
        self.assertEqual(denied["status"], "denied")
        self.assertFalse(denied["valid_for_execution"])

    def test_approved_action_executes_verifies_and_rolls_back(self):
        request = self.request_block()
        self.svc.decide(request["approval_id"], "approve", "soc_operator", "R. Nakamura")

        executed = self.svc.execute_approved(request["approval_id"])

        self.assertEqual(executed["status"], "executed")
        self.assertTrue(executed["verification"]["verified"])
        self.assertEqual(self.scenario.runtime["flow_status"]["F004"], "blocked")
        verified = self.svc.verify_execution(executed["execution_id"])
        self.assertTrue(verified["verified"])

        rolled_back = self.svc.rollback_execution(executed["execution_id"])
        self.assertEqual(rolled_back["status"], "rolled_back")
        self.assertEqual(self.scenario.runtime["flow_status"]["F004"], "active")

    def test_unapproved_action_is_blocked_before_execution(self):
        request = self.request_block()

        with self.assertRaises(ResponseError):
            self.svc.execute_approved(request["approval_id"])

        self.assertEqual(self.scenario.runtime["flow_status"]["F004"], "active")
        self.assertEqual(self.svc.audit.read(event="execution_blocked")[0]["approval_id"], request["approval_id"])

    def test_approved_action_can_execute_verify_and_rollback_in_external_test_environment(self):
        state = TestEnvironmentState()
        http_server = create_server(state)
        thread = threading.Thread(target=http_server.serve_forever)
        thread.start()
        self.addCleanup(http_server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(http_server.shutdown)
        host, port = http_server.server_address
        with patch.dict(
            os.environ,
            {
                "BRA_EXECUTION_MODE": "external-test",
                "BRA_ENVIRONMENT": "test",
                "BRA_EXTERNAL_BASE_URL": f"http://{host}:{port}",
            },
        ):
            request = self.request_block()
            self.svc.decide(request["approval_id"], "approve", "soc_operator", "Test Operator")
            executed = self.svc.execute_approved(request["approval_id"])
            self.assertTrue(executed["external"])
            self.assertTrue(executed["verification"]["verified"])
            self.assertEqual(state.flows["F004"], "blocked")
            rolled_back = self.svc.rollback_execution(executed["execution_id"])
            self.assertEqual(rolled_back["state"], "active")
            self.assertEqual(state.flows["F004"], "active")

    def test_role_level_is_enforced_and_logged(self):
        r = self.svc.request("isolate_endpoint", "ws-eng01", "Contain", FAILOVER)
        with self.assertRaises(ResponseError):
            self.svc.decide(r["approval_id"], "approve", "soc_operator", "R. Nakamura")
        self.assertEqual(self.svc.status(r["approval_id"])["status"], "pending")
        self.assertEqual(len(self.svc.audit.read(event="approval_decision_rejected")), 1)
        self.assertEqual(self.svc.decide(r["approval_id"], "approve", "ship_cio", "Captain")["status"], "approved")

    def test_lower_role_may_still_deny(self):
        r = self.svc.request("isolate_endpoint", "ws-eng01", "Contain", FAILOVER)
        self.assertEqual(self.svc.decide(r["approval_id"], "deny", "soc_operator", "R. Nakamura")["status"], "denied")

    def test_a_decision_cannot_be_changed(self):
        r = self.request_block()
        self.svc.decide(r["approval_id"], "approve", "soc_operator", "R. Nakamura")
        with self.assertRaises(ResponseError):
            self.svc.decide(r["approval_id"], "deny", "soc_operator", "R. Nakamura")
        self.assertEqual(self.svc.status(r["approval_id"])["status"], "approved")

    def test_bad_decisions_raise(self):
        r = self.request_block()
        for args in (
            (r["approval_id"], "maybe", "soc_operator", "R. Nakamura"),
            (r["approval_id"], "approve", "janitor", "R. Nakamura"),
            (r["approval_id"], "approve", "soc_operator", "  "),
            ("APR-9999", "approve", "soc_operator", "R. Nakamura"),
            ("../../etc/passwd", "approve", "soc_operator", "R. Nakamura"),
        ):
            with self.assertRaises(ResponseError, msg=str(args)):
                self.svc.decide(*args)

    # ---- time
    def test_pending_request_expires_and_cannot_be_approved(self):
        r = self.request_block()
        self.clock.advance(901)
        self.assertEqual(self.svc.status(r["approval_id"])["status"], "expired")
        self.svc.status(r["approval_id"])
        self.assertEqual(len(self.svc.audit.read(event="approval_expired")), 1)
        with self.assertRaises(ResponseError):
            self.svc.decide(r["approval_id"], "approve", "soc_operator", "R. Nakamura")

    def test_approval_window_starts_at_the_decision(self):
        r = self.request_block()
        self.clock.advance(800)
        self.svc.decide(r["approval_id"], "approve", "soc_operator", "R. Nakamura")
        self.clock.advance(800)
        self.assertTrue(self.svc.status(r["approval_id"])["valid_for_execution"])
        self.clock.advance(200)
        late = self.svc.status(r["approval_id"])
        self.assertEqual(late["status"], "expired")
        self.assertFalse(late["valid_for_execution"])

    def test_a_new_request_is_allowed_after_expiry(self):
        first = self.request_block()
        self.clock.advance(901)
        second = self.request_block()
        self.assertNotEqual(first["approval_id"], second["approval_id"])
        self.assertEqual(second["status"], "pending")

    # ---- audit log
    def test_audit_chain_records_everything_and_verifies(self):
        r = self.request_block()
        self.svc.request("block_network_flow", "F001", "Try it")
        self.svc.decide(r["approval_id"], "approve", "soc_operator", "R. Nakamura")
        events = [e["event"] for e in self.svc.audit.read()]
        self.assertEqual(events, ["approval_requested", "approval_request_refused", "approval_approved"])
        verdict = self.svc.audit.verify()
        self.assertEqual((verdict["ok"], verdict["entries"]), (True, 3))
        self.assertEqual(self.svc.audit.read()[0]["actor"], "agent")
        self.assertEqual(self.svc.audit.read()[2]["actor"], "operator:R. Nakamura:soc_operator")

    def test_empty_audit_log_verifies(self):
        self.assertEqual(self.svc.audit.verify()["entries"], 0)

    def test_tampering_is_detected(self):
        for _ in range(3):
            self.request_block()
            self.clock.advance(901)
        path = Path(self.tmp.name) / "audit.jsonl"
        original = path.read_text(encoding="utf-8")
        lines = original.splitlines()
        self.assertTrue(self.svc.audit.verify()["ok"])

        edited = json.loads(lines[1])
        edited["target"] = "F005"
        for label, mutated in (
            ("edited", [lines[0], json.dumps(edited, sort_keys=True), *lines[2:]]),
            ("removed", [lines[0], *lines[2:]]),
            ("reordered", [lines[1], lines[0], *lines[2:]]),
            ("garbage", [*lines, "not json"]),
        ):
            path.write_text("\n".join(mutated) + "\n", encoding="utf-8")
            self.assertFalse(self.svc.audit.verify()["ok"], label)
        path.write_text(original, encoding="utf-8")
        self.assertTrue(self.svc.audit.verify()["ok"])

    def test_entry_spliced_in_from_another_log_is_detected(self):
        self.request_block("F004")
        self.request_block("F005")
        other_dir = tempfile.TemporaryDirectory()
        self.addCleanup(other_dir.cleanup)
        other = ApprovalService(self.scenario, other_dir.name, self.clock)
        other.request("block_network_flow", "F006", "A different history")
        other.request("restrict_network_flow", "F006", "A different history")
        mine = Path(self.tmp.name) / "audit.jsonl"
        lines = mine.read_text(encoding="utf-8").splitlines()
        foreign = (Path(other_dir.name) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertTrue(self.svc.audit.verify()["ok"])
        mine.write_text("\n".join([lines[0], foreign[1]]) + "\n", encoding="utf-8")
        result = self.svc.audit.verify()
        self.assertFalse(result["ok"])
        self.assertIn("does not follow", result["problem"])

    # ---- separation of duties
    def test_server_exposes_no_tool_that_decides(self):
        tree = ast.parse(SERVER.read_text(encoding="utf-8"))
        tools = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any("tool" in ast.dump(d) for d in node.decorator_list)
        ]
        self.assertIn("request_operator_approval", tools)
        for name in tools:
            self.assertFalse(any(word in name for word in ("decide", "deny", "grant")), name)
            self.assertNotIn(name, ("approve", "approve_request", "approve_action"))
        self.assertNotIn(".decide(", SERVER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
