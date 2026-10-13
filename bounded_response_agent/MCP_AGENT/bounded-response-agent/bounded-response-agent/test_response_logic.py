"""Tests for the step 2 analysis layer. Run: python -m unittest -v test_response_logic

The ground-truth file is read only by these tests. The agent never sees it.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from response_logic import ResponseError, Scenario

DATA = Path(__file__).parent / "data" / "v2"
FAILOVER = ["failover_to_backup:cooling_monitoring"]


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Scenario()
        cls.truth = json.loads((DATA / "scenario_ground_truth.json").read_text(encoding="utf-8"))

    def verdict(self, action, target=None, done=None):
        return self.s.simulate_response(action, target, done)

    # ---- the expected recommendation is allowed, with the expected approvals
    def test_expected_recommendation_actions_are_allowed(self):
        for item in self.truth["expected_recommendation"]["actions"]:
            r = self.verdict(item["action"], item["target"])
            self.assertEqual(r["verdict"], "allowed", f"{item}: {r['reasons']}")
            self.assertEqual(r["approval_required"], item["approval"], item)
            self.assertEqual(r["mission_impact"]["safety_critical_functions_affected"], [])

    # ---- the scenario trade-off
    def test_isolating_ws_eng01_first_is_unacceptable(self):
        r = self.verdict("isolate_endpoint", "ws-eng01")
        self.assertEqual(r["verdict"], "unacceptable_impact")
        cooling = next(f for f in r["mission_impact"]["functions"] if f["function_id"] == "cooling_monitoring")
        self.assertTrue(cooling["exceeds_max_gap"])
        self.assertIsNone(cooling["predicted_gap_s"])
        self.assertEqual(cooling["mitigation"], "failover_to_backup:cooling_monitoring")
        self.assertIsNone(r["approval_required"])

    def test_isolation_after_failover_is_allowed_with_supervisor(self):
        r = self.verdict("isolate_endpoint", "ws-eng01", FAILOVER)
        self.assertEqual(r["verdict"], "allowed", r["reasons"])
        self.assertEqual(r["approval_required"], "ot_supervisor")
        self.assertEqual(r["mission_impact"]["safety_critical_functions_affected"], [])

    def test_failover_itself_is_within_the_gap_limit(self):
        r = self.verdict("failover_to_backup", "cooling_monitoring")
        self.assertEqual(r["verdict"], "allowed", r["reasons"])
        self.assertEqual(r["approval_required"], "ot_supervisor")
        self.assertEqual(r["mission_impact"]["functions"][0]["predicted_gap_s"], 45)

    def test_failover_not_possible_without_backup(self):
        r = self.verdict("failover_to_backup", "engineering_config")
        self.assertEqual(r["verdict"], "preconditions_not_met")

    def test_disabling_polling_account_breaks_monitoring_unless_failed_over(self):
        impact = self.s.analyze_mission_impact("disable_account", "svc-cool-poll")
        self.assertEqual(impact["severity"], "unacceptable")
        after = self.s.analyze_mission_impact("disable_account", "svc-cool-poll", FAILOVER)
        self.assertEqual(after["severity"], "none")

    # ---- must never happen
    def test_critical_flows_cannot_be_blocked_or_restricted(self):
        for fid in ("F001", "F002", "F008"):
            for action in ("block_network_flow", "restrict_network_flow"):
                self.assertEqual(self.verdict(action, fid)["verdict"], "forbidden", (action, fid))

    def test_protected_devices_are_forbidden(self):
        for host in ("fw01", "core-sw1", "dc01", "plc-cool01", "hmi-cool01"):
            r = self.verdict("isolate_endpoint", host)
            self.assertEqual(r["verdict"], "forbidden", host)
            self.assertIsNone(r["approval_required"])

    def test_privileged_account_is_forbidden(self):
        self.assertEqual(self.verdict("disable_account", "adm.kealoha")["verdict"], "forbidden")

    def test_no_evidence_means_no_action(self):
        self.assertEqual(self.verdict("isolate_endpoint", "ws-eng02")["verdict"], "insufficient_evidence")
        self.assertEqual(self.verdict("block_network_flow", "F003")["verdict"], "insufficient_evidence")

    def test_ground_truth_forbidden_outcomes_never_allowed(self):
        self.assertNotEqual(self.verdict("isolate_endpoint", "ws-eng01")["verdict"], "allowed")
        self.assertNotEqual(self.verdict("disable_account", "adm.kealoha")["verdict"], "allowed")

    # ---- option listing
    def test_option_list_is_ranked_and_reports_uncovered_threat(self):
        out = self.s.list_response_options()
        ranks = [o["disruption_rank"] for o in out["options"]]
        self.assertEqual(ranks, sorted(ranks))
        allowed = {(o["action"], o["target"]) for o in out["options"] if o["verdict"] == "allowed"}
        for item in self.truth["expected_recommendation"]["actions"]:
            self.assertIn((item["action"], item["target"]), allowed)
        self.assertNotIn(("isolate_endpoint", "ws-eng01"), allowed)
        self.assertEqual(out["threat_findings_not_covered"], ["FND-1"])
        self.assertIn("FND-1", out["only_blocked_options_would_cover"])

    def test_option_list_after_failover_covers_everything(self):
        out = self.s.list_response_options(assume_done=FAILOVER)
        self.assertEqual(out["threat_findings_not_covered"], [])

    # ---- read tools and errors
    def test_unknown_inputs_raise_readable_errors(self):
        for call in (
            lambda: self.s.lookup_device("db99"),
            lambda: self.s.lookup_account("nobody"),
            lambda: self.s.get_system_health("nothing"),
            lambda: self.s.get_response_policy("launch_missiles"),
            lambda: self.s.simulate_response("block_network_flow", "F999"),
            lambda: self.s.simulate_response("block_network_flow", None),
            lambda: self.s.get_investigation_findings("CASE-X"),
            lambda: self.s.simulate_response("isolate_endpoint", "ws-eng01", ["nonsense"]),
            lambda: self.s.simulate_response("isolate_endpoint", "ws-eng01", ["continue_monitoring:x"]),
        ):
            with self.assertRaises(ResponseError):
                call()

    def test_events_filters(self):
        beacons = self.s.get_events(host="198.51.100.77")
        self.assertEqual(len(beacons), 4)
        self.assertEqual([e["timestamp"] for e in beacons], sorted(e["timestamp"] for e in beacons))
        high = self.s.get_events(host="ws-eng01", severity="high")
        self.assertTrue(high and all(e["severity"] == "high" for e in high))
        self.assertEqual(len(self.s.get_events(source="idp")), 2)
        self.assertEqual(len(self.s.get_events(action="deny")), 3)
        late = self.s.get_events(since="2026-10-12T21:30:00Z")
        self.assertTrue(late and all(e["timestamp"] >= "2026-10-12T21:30:00Z" for e in late))
        self.assertEqual(len(self.s.get_events(limit=3)), 3)

    def test_events_bad_inputs(self):
        for kwargs in ({"host": "db99"}, {"source": "radar"}, {"severity": "huge"}, {"action": "explode"},
                       {"since": "yesterday"}, {"limit": 0}, {"limit": 500}):
            with self.assertRaises(ResponseError, msg=str(kwargs)):
                self.s.get_events(**kwargs)

    def test_simulation_is_a_dry_run(self):
        before = {p.name: p.read_bytes() for p in DATA.iterdir() if p.is_file()}
        self.s.simulate_response("isolate_endpoint", "ws-eng01")
        self.s.list_response_options()
        after = {p.name: p.read_bytes() for p in DATA.iterdir() if p.is_file()}
        self.assertEqual(before, after)

    def test_data_files_are_consistent(self):
        result = subprocess.run([sys.executable, "-I", str(DATA / "validate_data.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
