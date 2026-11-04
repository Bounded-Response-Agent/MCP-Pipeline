"""Build an operator timeline from the verified audit record, independent of model prose."""


def response_activity(events):
    actions = {}
    stage_names = {
        "approval_requested": "Awaiting approval",
        "approval_approved": "Approved",
        "approval_denied": "Denied",
        "approval_expired": "Expired",
        "execution_blocked": "Execution blocked",
        "action_started": "Executing",
        "action_applied": "Applied",
        "action_apply_unconfirmed": "Application unconfirmed",
        "action_outcome_unconfirmed": "Outcome unconfirmed",
        "rollback_authorized": "Rollback approved",
        "rollback_blocked": "Rollback blocked",
        "action_rolled_back": "Rolled back",
        "approval_request_refused": "Refused",
    }
    for entry in events:
        name = entry["event"]
        if name == "lab_policy_decision" and entry.get("phase") == "proposal" and not entry.get("allowed"):
            # The normal simulator denial has its own refusal entry.
            if not entry.get("input", {}).get("simulation_allowed") and entry.get("live_evidence"):
                continue
            payload = entry["input"]
            entry = {**entry, "action": payload["action"], "target": payload["target"],
                     "reason": "Live policy refused the proposal. Review evidence and service telemetry."}
            name = "approval_request_refused"
        if name not in stage_names and name not in ("action_verification", "automatic_recovery"):
            continue
        execution_id = entry.get("execution_id")
        approval_id = entry.get("approval_id") or (f"APR-{execution_id[4:]}" if execution_id else None)
        key = approval_id or f"refusal-{entry['seq']}"
        action = actions.setdefault(key, {"id": key, "stages": []})
        for field in ("action", "target", "execution_id", "required_role"):
            if entry.get(field):
                action[field] = entry[field]
        if name in ("approval_approved", "approval_denied"):
            action["operator"] = entry["actor"].removeprefix("operator:")
        label = stage_names.get(name)
        if name == "approval_requested":
            action["stages"].append({"label": "Proposed", "time": entry["ts"], "actor": entry["actor"]})
        elif name == "action_verification":
            observed = entry["observations"]
            action["before"] = entry.get("before")
            action["after"] = observed
            label = "Verified" if observed.get("verified") else "Verification failed"
        elif name == "automatic_recovery":
            action["recovery"] = entry["outcome"]
            label = "Rolled back" if entry["outcome"]["status"] == "rolled_back" else "Recovery needs review"
        elif name == "action_rolled_back":
            action["recovery"] = {key: entry[key] for key in ("status", "restored", "probes", "cooling") if key in entry}
        if name == "approval_request_refused":
            action["stages"].append({"label": "Proposed", "time": entry["ts"], "actor": entry["actor"]})
        action["stages"].append({"label": label, "time": entry["ts"], "actor": entry["actor"],
                                 "detail": entry.get("problem") or entry.get("reason") or
                                 " ".join(entry.get("reasons") or []) or entry.get("verdict")})
        action["sequence"] = entry["seq"]
    return sorted((item for item in actions.values() if item.get("action")),
                  key=lambda item: item["sequence"], reverse=True)[:12]
