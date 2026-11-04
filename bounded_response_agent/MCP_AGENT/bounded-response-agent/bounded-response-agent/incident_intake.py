"""Review queue for supported lab alerts and validated SOC handoffs."""

import json
import os
from datetime import datetime, timezone

from approvals import _file_lock


def read_intake(workspace):
    path = workspace.service.dir / "intake.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"groups": {}, "reviewed": False}


def save_intake(workspace, record):
    directory = workspace.service.dir
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "intake.tmp"
    temporary.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(temporary, directory / "intake.json")


def review(workspace):
    with _file_lock(workspace.service.dir / "intake.lock"):
        record = read_intake(workspace)
        if not record["reviewed"]:
            record["reviewed"] = True
            save_intake(workspace, record)


def ingest_suricata(workspace, alerts):
    scenario = workspace.scenario
    targets = {port: target for target, port in scenario.flow_ports.items()}
    with _file_lock(workspace.service.dir / "intake.lock"):
        record = read_intake(workspace)
        new_groups = 0
        added = 0
        for alert in alerts:
            target = targets.get(alert.get("destination_port"))
            if not target or alert.get("source") != "Suricata":
                continue
            key = f"{alert['signature_id']}:{alert['destination_port']}"
            if key not in record["groups"]:
                new_groups += 1
                flow = scenario.flows[target]
                record["groups"][key] = {"source": "Suricata", "target": target,
                                         "asset": flow["src_host"], "destination": flow["dst_host"] or flow["dst_ip"],
                                         "signature": alert["signature"], "alerts": {}}
            group = record["groups"][key]
            identity = f"{alert['flow_id']}:{alert['timestamp']}"
            if identity not in group["alerts"]:
                group["alerts"][identity] = alert["timestamp"]
                added += 1
        if new_groups:
            record["reviewed"] = False
        if added:
            for group in record["groups"].values():
                group["alerts"] = dict(sorted(group["alerts"].items(), key=lambda pair: pair[1])[-100:])
            save_intake(workspace, record)
        return {"alerts_added": added, "new_groups": new_groups}


def queue_entries(catalog):
    entries = []
    for workspace in catalog.items.values():
        record = read_intake(workspace)
        if not record["groups"] and not workspace.case_file:
            continue
        summary = workspace.summary()
        case = workspace.scenario.findings
        if workspace.case_file:
            assets = sorted({asset for finding in case["findings"] for asset in finding.get("affected_assets", [])})
            time = datetime.fromtimestamp(workspace.case_file.stat().st_mtime, timezone.utc).isoformat()
            evidence = [{"source": case["produced_by"], "asset": ", ".join(assets) or "See findings",
                         "signature": case["summary"], "latest": time}]
        else:
            evidence = [{**{key: value for key, value in group.items() if key != "alerts"},
                         "count": len(group["alerts"]), "latest": max(group["alerts"].values())}
                        for group in record["groups"].values()]
        entries.append({**summary, "status": "Opened" if record["reviewed"] else "Needs review",
                        "evidence": evidence})
    return sorted(entries, key=lambda item: (item["status"] != "Needs review", item["title"]))
