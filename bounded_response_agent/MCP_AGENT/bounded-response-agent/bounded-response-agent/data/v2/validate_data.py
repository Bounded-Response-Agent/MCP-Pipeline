"""Check that the v2 scenario files agree with each other. Run: python validate_data.py"""
import csv, json, sys
from pathlib import Path

D = Path(__file__).parent


def rows(name):
    with open(D / name, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


devices = {r["hostname"]: r for r in rows("devices.csv")}
accounts = {r["account"]: r for r in rows("accounts.csv")}
flows = {r["flow_id"]: r for r in rows("flows.csv")}
functions = {r["function_id"]: r for r in rows("functions.csv")}
errors = []


def check(ok, msg):
    if not ok:
        errors.append(msg)


for a in accounts.values():
    for h in filter(None, a["bound_hosts"].split(";")):
        check(h in devices, f"account {a['account']}: unknown host {h}")
    check(not a["used_by_function"] or a["used_by_function"] in functions, f"account {a['account']}: unknown function")
for d in devices.values():
    check(not d["primary_account"] or d["primary_account"] in accounts, f"device {d['hostname']}: unknown account")
for f in flows.values():
    check(f["src_host"] in devices, f"flow {f['flow_id']}: unknown src")
    check(not f["dst_host"] or f["dst_host"] in devices, f"flow {f['flow_id']}: unknown dst")
    if f["dst_host"]:
        check(devices[f["dst_host"]]["ip"] == f["dst_ip"], f"flow {f['flow_id']}: dst_ip mismatch")
    check(not f["function_id"] or f["function_id"] in functions, f"flow {f['flow_id']}: unknown function")
for fn in functions.values():
    check(fn["primary_asset"] in devices, f"function {fn['function_id']}: unknown primary")
    check(not fn["backup_asset"] or fn["backup_asset"] in devices, f"function {fn['function_id']}: unknown backup")
kinds = {"device": devices, "flow": flows, "account": accounts}
for r in rows("dependencies.csv"):
    check(r["function_id"] in functions, f"dependency: unknown function {r['function_id']}")
    check(r["requires_id"] in kinds[r["requires_type"]], f"dependency: unknown {r['requires_type']} {r['requires_id']}")
for r in rows("health.csv"):
    check(r["system"] in devices, f"health: unknown system {r['system']}")
for r in rows("events.csv"):
    for k in ("src", "dst"):
        check(not r[k] or r[k] in devices or r[k].count(".") == 3, f"event: unknown {k} {r[k]}")
findings = json.loads((D / "findings.json").read_text(encoding="utf-8"))
for fd in findings["findings"]:
    check(fd.get("kind") in ("threat", "assessment"), f"{fd['id']}: kind must be threat or assessment")
    for h in fd.get("affected_assets", []):
        check(h in devices, f"{fd['id']}: unknown asset {h}")
    for a in fd.get("affected_accounts", []):
        check(a in accounts, f"{fd['id']}: unknown account {a}")
    for fl in fd.get("related_flows", []):
        check(fl in flows, f"{fd['id']}: unknown flow {fl}")
policy = json.loads((D / "policy.json").read_text(encoding="utf-8"))
for name, act in policy["actions"].items():
    lvl = act.get("approval_required")
    check(lvl is None or lvl in policy["roles"], f"policy {name}: unknown role {lvl}")
truth = json.loads((D / "scenario_ground_truth.json").read_text(encoding="utf-8"))
for a in truth["expected_recommendation"]["actions"]:
    check(a["action"] in policy["actions"], f"truth: unknown action {a['action']}")
    pool = {"block_network_flow": flows, "restrict_network_flow": flows, "disable_account": accounts}.get(a["action"], {})
    check(a["target"] in pool, f"truth: unknown target {a['target']}")

if errors:
    print("FAILED"); [print(" -", e) for e in errors]; sys.exit(1)
print(f"OK: {len(devices)} devices, {len(accounts)} accounts, {len(flows)} flows, {len(functions)} functions")
