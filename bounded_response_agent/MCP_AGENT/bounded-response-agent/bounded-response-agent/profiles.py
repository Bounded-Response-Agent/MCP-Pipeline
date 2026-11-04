"""Trusted environment profiles and validation for SOC incident imports."""

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROFILES = {"shipboard": ROOT / "data/v2", "enterprise": ROOT / "data/enterprise"}


def profile_path(key):
    if key not in PROFILES:
        raise ValueError("Unknown environment profile.")
    return PROFILES[key]


def scenario_from_environment():
    from response_logic import Scenario
    profile = os.environ.get("BRA_PROFILE", "shipboard")
    case_file = os.environ.get("BRA_CASE_FILE")
    return Scenario(profile_path(profile), case_file=case_file)


def validate_case(body, scenario):
    if not isinstance(body, dict):
        raise ValueError("The SOC handoff must be a JSON object.")
    for key, size in {"case_id": 80, "title": 140, "summary": 1200, "produced_by": 100}.items():
        if not isinstance(body.get(key), str) or not 1 <= len(body[key].strip()) <= size:
            raise ValueError(f"Provide {key} with up to {size} characters.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", body["case_id"]):
        raise ValueError("Use letters, numbers, dots, underscores, or hyphens in the case ID.")
    findings = body.get("findings")
    if not isinstance(findings, list) or not 1 <= len(findings) <= 12:
        raise ValueError("Provide between 1 and 12 findings.")
    seen = set()
    clean = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be an object.")
        identifier, claim = finding.get("id"), finding.get("claim")
        confidence, evidence = finding.get("confidence"), finding.get("evidence")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 80 or identifier in seen:
            raise ValueError("Each finding needs a unique ID.")
        if not isinstance(claim, str) or not 1 <= len(claim.strip()) <= 600:
            raise ValueError("Each finding needs a claim of up to 600 characters.")
        if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
            raise ValueError("Finding confidence must be between 0 and 1.")
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 10 or not all(
            isinstance(item, str) and 1 <= len(item.strip()) <= 600 for item in evidence
        ):
            raise ValueError("Each finding needs 1–10 evidence strings.")
        if finding.get("kind") not in ("threat", "assessment"):
            raise ValueError("Finding kind must be threat or assessment.")
        row = {key: finding[key] for key in ("id", "claim", "confidence", "evidence", "kind")}
        seen.add(identifier)
        for key, allowed in (("affected_assets", scenario.devices), ("affected_accounts", scenario.accounts),
                             ("related_flows", scenario.flows)):
            values = finding.get(key, [])
            if not isinstance(values, list) or not all(isinstance(value, str) and value in allowed for value in values):
                raise ValueError(f"{key} must reference known assets in the selected environment.")
            row[key] = list(dict.fromkeys(values))
        if finding["kind"] == "threat" and not any(row[key] for key in ("affected_assets", "affected_accounts", "related_flows")):
            raise ValueError("Each threat must identify at least one affected asset, account, or flow.")
        clean.append(row)
    if len({v for row in clean for v in row["related_flows"] + row["affected_accounts"]}) > 6:
        raise ValueError("Split this handoff into cases with up to six flow and account targets.")
    return {**{key: body[key] for key in ("case_id", "title", "summary", "produced_by")}, "findings": clean}
