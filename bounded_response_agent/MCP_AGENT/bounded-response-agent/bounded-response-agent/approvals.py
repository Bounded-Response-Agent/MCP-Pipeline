"""Approval and audit services for the Bounded Response Agent.

The agent can ask for approval, but only a human operator can grant it, and only through
a channel the model has no tool for (operator_console.py, or the prompt in client.py).
Every request, refusal, decision and expiry is written to a hash-chained audit log.

State lives in a directory (default ./state, override with BRA_STATE_DIR):
  approvals/APR-0001.json   one file per approval, so separate processes never clash
  audit.jsonl               append-only log; each entry carries the hash of the one before
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from response_logic import ResponseError, Scenario

DEFAULT_STATE_DIR = Path(os.environ.get("BRA_STATE_DIR") or Path(__file__).parent / "state")
GENESIS_HASH = "0" * 64
APPROVAL_ID = re.compile(r"^APR-\d{4}$")
OPEN_STATUSES = ("pending", "approved")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@contextmanager
def _file_lock(path: Path, timeout: float = 5.0) -> Iterator[None]:
    """Cross-process lock using an exclusively created file. Stale locks expire after 10 s."""
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > 10:
                    path.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise ResponseError("The state store is busy. Try again.") from None
            time.sleep(0.05)
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


class AuditLog:
    """Append-only JSON Lines log. Each entry stores the hash of the previous entry."""

    def __init__(self, path: Path, clock: Callable[[], datetime] = utc_now):
        self.path = path
        self.clock = clock

    def _entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def append(self, event: str, actor: str, **fields: Any) -> dict[str, Any]:
        with _file_lock(self.path.with_name("audit.lock")):
            entries = self._entries()
            last = entries[-1] if entries else None
            entry: dict[str, Any] = {
                "seq": (last["seq"] + 1) if last else 1,
                "ts": _iso(self.clock()),
                "event": event,
                "actor": actor,
                **fields,
                "prev_hash": last["hash"] if last else GENESIS_HASH,
            }
            entry["hash"] = _sha(_canonical(entry))
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def read(self, limit: int = 50, event: str | None = None) -> list[dict[str, Any]]:
        entries = self._entries()
        if event is not None:
            entries = [e for e in entries if e["event"] == event]
        return entries[-limit:]

    def verify(self) -> dict[str, Any]:
        """Recompute the whole chain. Any edited, removed or reordered entry is reported."""
        previous = GENESIS_HASH
        count = 0
        if not self.path.exists():
            return {"ok": True, "entries": 0, "head_hash": previous}
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return {"ok": False, "entries": count, "problem": f"line {line_no} is not valid JSON"}
            count += 1
            body = {k: v for k, v in entry.items() if k != "hash"}
            problem = None
            if entry.get("seq") != count:
                problem = f"entry {count} has sequence number {entry.get('seq')}"
            elif entry.get("prev_hash") != previous:
                problem = f"entry {count} does not follow the previous entry"
            elif entry.get("hash") != _sha(_canonical(body)):
                problem = f"entry {count} was altered"
            if problem:
                return {"ok": False, "entries": count, "first_bad_seq": count, "problem": problem}
            previous = entry["hash"]
        return {"ok": True, "entries": count, "head_hash": previous}


class ApprovalService:
    def __init__(
        self,
        scenario: Scenario,
        state_dir: Path | str | None = None,
        clock: Callable[[], datetime] = utc_now,
    ):
        self.scenario = scenario
        self.clock = clock
        self.dir = Path(state_dir) if state_dir else DEFAULT_STATE_DIR
        self.approvals_dir = self.dir / "approvals"
        self.audit = AuditLog(self.dir / "audit.jsonl", clock)

    # ------------------------------------------------------------------ storage
    def _path(self, approval_id: str) -> Path:
        return self.approvals_dir / f"{approval_id}.json"

    def _save(self, record: dict[str, Any]) -> None:
        self.approvals_dir.mkdir(parents=True, exist_ok=True)
        path = self._path(record["approval_id"])
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def _stored(self) -> list[dict[str, Any]]:
        if not self.approvals_dir.exists():
            return []
        paths = sorted(self.approvals_dir.glob("APR-*.json"))
        return [json.loads(p.read_text(encoding="utf-8")) for p in paths]

    def _next_id(self) -> str:
        numbers = [int(r["approval_id"][4:]) for r in self._stored()]
        return f"APR-{(max(numbers) + 1) if numbers else 1:04d}"

    def _refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        """Mark a lapsed pending or approved record as expired and log it once."""
        now = self.clock()
        if record["status"] in OPEN_STATUSES and now > _parse(record["expires_at"]):
            previous = record["status"]
            record["status"] = "expired"
            self._save(record)
            self.audit.append(
                "approval_expired",
                "system",
                approval_id=record["approval_id"],
                case_id=record["case_id"],
                action=record["action"],
                target=record["target"],
                was=previous,
            )
        return record

    def _load(self, approval_id: str) -> dict[str, Any]:
        key = (approval_id or "").strip()
        if not APPROVAL_ID.match(key):
            raise ResponseError(f"'{approval_id}' is not an approval id. Ids look like APR-0001.")
        path = self._path(key)
        if not path.exists():
            raise ResponseError(f"No approval named '{key}'.")
        return self._refresh(json.loads(path.read_text(encoding="utf-8")))

    def _view(self, record: dict[str, Any]) -> dict[str, Any]:
        left = int((_parse(record["expires_at"]) - self.clock()).total_seconds())
        view = dict(record)
        view["seconds_left"] = max(left, 0) if record["status"] in OPEN_STATUSES else 0
        view["valid_for_execution"] = record["status"] == "approved"
        return view

    def _level(self, role: str) -> int:
        roles = self.scenario.policy["roles"]
        if role not in roles:
            raise ResponseError(f"Unknown role '{role}'. Valid roles: {', '.join(roles)}.")
        return roles[role]["level"]

    # ------------------------------------------------------------------ plan fingerprint
    def plan_digest(self, simulation: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """What the approver is shown, and a hash of it. Step 4 recomputes it before executing."""
        digest = {
            "verdict": simulation["verdict"],
            "mission_severity": simulation["mission_impact"]["severity"],
            "predicted_state_changes": simulation["predicted_state_changes"],
            "addresses_findings": [f["id"] for f in simulation["evidence"]["findings"]],
            "assumed_done": simulation["assumed_done"],
            "rollback": simulation["rollback"],
        }
        return digest, _sha(_canonical(digest))

    # ------------------------------------------------------------------ agent side
    def request(
        self, action: str, target: str | None, rationale: str, assume_done: list[str] | None = None
    ) -> dict[str, Any]:
        """Ask for human approval of one action. Refused unless the dry run says 'allowed'."""
        reason = (rationale or "").strip()
        if not reason or len(reason) > 500:
            raise ResponseError("rationale is required and must be 500 characters or fewer.")
        rules = self.scenario.get_response_policy(action)["rules"]
        if not rules.get("state_changing"):
            raise ResponseError(f"{action} does not change anything and needs no approval.")
        sim = self.scenario.simulate_response(action, target, assume_done)
        case_id = self.scenario.findings["case_id"]
        common = {"case_id": case_id, "action": action, "target": sim["target"]}

        if sim["verdict"] != "allowed":
            self.audit.append("approval_request_refused", "agent", verdict=sim["verdict"], rationale=reason, **common)
            return {
                "status": "refused",
                "verdict": sim["verdict"],
                "reasons": sim["reasons"],
                "next_step": "No approval was created. Pick a different action or escalate to a human.",
            }

        stored = [r for r in self._stored() if r["case_id"] == case_id]
        for rec in (self._refresh(r) for r in stored):
            same = (rec["action"], rec["target"], rec["assume_done"]) == (action, sim["target"], sim["assumed_done"])
            if same and rec["status"] in OPEN_STATUSES:
                self.audit.append("approval_request_duplicate", "agent", approval_id=rec["approval_id"], **common)
                return {**self._view(rec), "note": "An open approval for this exact action already exists."}

        cap = self.scenario.policy["global_rules"]["max_actions_per_case_without_review"]
        if len(stored) >= cap:
            self.audit.append("approval_request_refused", "agent", verdict="review_needed", rationale=reason, **common)
            return {
                "status": "refused",
                "verdict": "review_needed",
                "reasons": [f"This case already has {len(stored)} approval requests; a human must review before more."],
                "next_step": "Escalate to a human reviewer.",
            }

        digest, digest_hash = self.plan_digest(sim)
        now = self.clock()
        expiry = self.scenario.policy["global_rules"]["approval_expiry_seconds"]
        record = {
            "approval_id": self._next_id(),
            "status": "pending",
            **common,
            "assume_done": sim["assumed_done"],
            "rationale": reason,
            "required_role": sim["approval_level_if_allowed"],
            "requested_by": "agent",
            "requested_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=expiry)),
            "plan": digest,
            "plan_hash": digest_hash,
            "decided_by": None,
            "decided_at": None,
            "decision_note": None,
        }
        self._save(record)
        self.audit.append(
            "approval_requested",
            "agent",
            approval_id=record["approval_id"],
            required_role=record["required_role"],
            plan_hash=digest_hash,
            rationale=reason,
            **common,
        )
        return {
            **self._view(record),
            "next_step": "A human operator must decide. Use wait_for_approval or get_approval_status. "
            "You cannot approve this yourself.",
        }

    def status(self, approval_id: str) -> dict[str, Any]:
        return self._view(self._load(approval_id))

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        valid = ("pending", "approved", "denied", "expired")
        if status is not None and status not in valid:
            raise ResponseError(f"status must be one of: {', '.join(valid)}.")
        views = [self._view(self._refresh(r)) for r in self._stored()]
        return [v for v in views if status is None or v["status"] == status]

    # ------------------------------------------------------------------ human side
    def decide(self, approval_id: str, decision: str, role: str, name: str, note: str | None = None) -> dict[str, Any]:
        """Record a human decision. Not exposed as a model tool."""
        if decision not in ("approve", "deny"):
            raise ResponseError("decision must be 'approve' or 'deny'.")
        level = self._level(role)
        who = (name or "").strip()
        if not who:
            raise ResponseError("The operator's name is required.")
        record = self._load(approval_id)
        actor = f"operator:{who}:{role}"
        info = {
            "approval_id": record["approval_id"],
            "case_id": record["case_id"],
            "action": record["action"],
            "target": record["target"],
        }
        if record["status"] != "pending":
            self.audit.append("approval_decision_rejected", actor, problem=f"already {record['status']}", **info)
            raise ResponseError(f"{record['approval_id']} is already {record['status']}; it cannot be decided again.")
        if decision == "approve" and level < self._level(record["required_role"]):
            self.audit.append("approval_decision_rejected", actor, problem=f"needs {record['required_role']}", **info)
            raise ResponseError(f"{record['approval_id']} needs {record['required_role']}; {role} is not enough.")
        now = self.clock()
        record["status"] = "approved" if decision == "approve" else "denied"
        record["decided_by"] = {"name": who, "role": role}
        record["decided_at"] = _iso(now)
        if decision == "approve":  # a fresh validity window starts when the human approves
            expiry = self.scenario.policy["global_rules"]["approval_expiry_seconds"]
            record["expires_at"] = _iso(now + timedelta(seconds=expiry))
        record["decision_note"] = (note or "").strip() or None
        self._save(record)
        self.audit.append(f"approval_{record['status']}", actor, note=record["decision_note"], **info)
        return self._view(record)
