"""Approval and audit services for the Bounded Response Agent.

The agent can ask for approval, but only a human operator can grant it, and only through
the authenticated local operator console.
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
APPROVAL_ID = re.compile(r"^APR-\d{4,}$")
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
    """Lock a stable file. The OS releases the lock if the process exits."""
    if os.name == "nt":
        import msvcrt

        def lock(file):
            msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)

        def unlock(file):
            msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        def lock(file):
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def unlock(file):
            fcntl.flock(file, fcntl.LOCK_UN)

    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    with path.open("a+b") as file:
        file.seek(0)
        while True:
            try:
                lock(file)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise ResponseError("The state store is busy. Try again.") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            unlock(file)


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
        self.scenario.fault = os.environ.get("BRA_SIM_FAULT") or None

    def load_environment(self) -> None:
        path = self.dir / "environment.json"
        if path.exists():
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.scenario.runtime = saved["runtime"]
            self.scenario.executions = saved["executions"]

    def _save_environment(self) -> None:
        path = self.dir / "environment.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(_canonical({"runtime": self.scenario.runtime,
                                         "executions": self.scenario.executions}), encoding="utf-8")
        os.replace(temporary, path)

    @contextmanager
    def _transaction(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.dir / "response.lock"):
            self.load_environment()
            yield

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
        if record["status"] in OPEN_STATUSES and not record.get("execution_id") and now > _parse(record["expires_at"]):
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
        view["valid_for_execution"] = record["status"] == "approved" and not record.get("execution_id")
        view["decision"] = {
            "pending": "PENDING_APPROVAL",
            "approved": "APPROVED",
            "denied": "BLOCKED",
            "expired": "BLOCKED",
        }[record["status"]]
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
            "mission_impact": simulation["mission_impact"],
            "required_role": simulation["approval_level_if_allowed"],
            "evidence": simulation["evidence"],
            "policy": self.scenario.policy,
            "target": simulation["target"],
            "action": simulation["action"],
            "case_id": self.scenario.findings["case_id"],
            "environment": self.scenario.profile["id"],
            "environment_scope": _sha(str(self.dir.resolve())),
            "automatic_recovery": "Scoped rollback on failed verification, subject to mission safety.",
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
        """Request approval using observed preconditions."""
        with self._transaction():
            if assume_done:
                self.audit.append("approval_request_refused", "agent", action=action, target=target,
                                  verdict="hypothetical_preconditions")
                return {"status": "refused", "decision": "BLOCKED", "verdict": "hypothetical_preconditions",
                        "reasons": ["Hypothetical preconditions are only available in planning tools."]}
            return self._request(action, target, rationale)

    def _request(self, action: str, target: str | None, rationale: str) -> dict[str, Any]:
        reason = (rationale or "").strip()
        if not reason or len(reason) > 500:
            raise ResponseError("rationale is required and must be 500 characters or fewer.")
        rules = self.scenario.get_response_policy(action)["rules"]
        if not rules.get("state_changing"):
            raise ResponseError(f"{action} does not change anything and needs no approval.")
        sim = self.scenario.simulate_response(action, target)
        self._check_lab_policy(sim, phase="proposal")
        case_id = self.scenario.findings["case_id"]
        common = {"case_id": case_id, "action": action, "target": sim["target"]}

        if sim["verdict"] != "allowed":
            self.audit.append("approval_request_refused", "agent", verdict=sim["verdict"], rationale=reason,
                              reasons=sim["reasons"], **common)
            return {
                "status": "refused",
                "verdict": sim["verdict"],
                "decision": "BLOCKED",
                "reasons": sim["reasons"],
                "next_step": "No approval was created. Pick a different action or escalate to a human.",
            }

        digest, digest_hash = self.plan_digest(sim)
        stored = [r for r in self._stored() if r["case_id"] == case_id]
        for rec in (self._refresh(r) for r in stored):
            same = (rec["action"], rec["target"], rec["assume_done"]) == (action, sim["target"], sim["assumed_done"])
            if (same and rec["status"] in OPEN_STATUSES and not rec.get("execution_id")
                    and rec["plan_hash"] == digest_hash):
                self.audit.append("approval_request_duplicate", "agent", approval_id=rec["approval_id"], **common)
                return {**self._view(rec), "note": "An open approval for this exact action already exists."}

        cap = self.scenario.policy["global_rules"]["max_actions_per_case_without_review"]
        if len(stored) >= cap:
            self.audit.append("approval_request_refused", "agent", verdict="review_needed", rationale=reason, **common)
            return {
                "status": "refused",
                "verdict": "review_needed",
                "decision": "BLOCKED",
                "reasons": [f"This case already has {len(stored)} approval requests; a human must review before more."],
                "next_step": "Escalate to a human reviewer.",
            }

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
        with self._transaction():
            return self._view(self._load(approval_id))

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        valid = ("pending", "approved", "denied", "expired")
        if status is not None and status not in valid:
            raise ResponseError(f"status must be one of: {', '.join(valid)}.")
        with self._transaction():
            views = [self._view(self._refresh(r)) for r in self._stored()]
        return [v for v in views if status is None or v["status"] == status]

    def _check_lab_policy(self, simulation, *, phase, operator_role=None):
        evaluate = getattr(self.scenario, "policy_decision", None)
        if evaluate is None:
            return
        decision = evaluate(simulation, phase=phase, operator_role=operator_role)
        self.audit.append("lab_policy_decision", "opa", phase=phase, **decision)
        if simulation["verdict"] == "allowed" and not decision["allowed"]:
            raise ResponseError("OPA denied the action. Check live evidence and protected-service telemetry.")

    def execute_approved(self, approval_id: str) -> dict[str, Any]:
        """Apply an approval once, recording the result atomically with simulator state."""
        with self._transaction():
            record = self._load(approval_id)
            execution_id = f"EXE-{record['approval_id'][4:]}"
            previous = self.scenario.executions.get(execution_id)
            if previous:
                if not record.get("execution_id"):
                    self._record_execution(record, previous["result"])
                return {**previous["result"], "approval_id": approval_id,
                        "current_status": previous["status"], "replayed": True}
            info = {"approval_id": approval_id, "case_id": record["case_id"],
                    "action": record["action"], "target": record["target"]}
            if record["status"] != "approved":
                self.audit.append("execution_blocked", "agent", problem=f"approval is {record['status']}", **info)
                raise ResponseError(f"{approval_id} is {record['status']}; execution is blocked.")
            simulation = self.scenario.simulate_response(record["action"], record["target"])
            _, digest_hash = self.plan_digest(simulation)
            if simulation["verdict"] != "allowed" or digest_hash != record["plan_hash"]:
                self.audit.append("execution_blocked", "agent", problem="observed plan changed", **info)
                raise ResponseError("The approved plan no longer matches observed preconditions, policy or impact.")
            try:
                self._check_lab_policy(simulation, phase="execution", operator_role=record["decided_by"]["role"])
                before = {"cooling": self.scenario.observe_cooling(), "probes": self.scenario.observe_threats()}
                if not before["cooling"]["healthy"]:
                    raise ResponseError("Protected-service telemetry is unhealthy or unavailable before execution.")
            except ResponseError as exc:
                self.audit.append("execution_blocked", "system", problem=str(exc), **info)
                raise
            self.audit.append("action_started", "system", execution_id=execution_id, **info)
            try:
                result = self.scenario.execute_action(record["action"], record["target"], execution_id)
            except ResponseError as exc:
                self.audit.append("action_outcome_unconfirmed", "system", reason=str(exc), **info)
                raise
            result["before"] = before
            self.scenario.executions[execution_id]["result"] = result
            self._save_environment()
            self._record_execution(record, result)
            commit = getattr(self.scenario, "commit_live_action", None)
            if commit is not None and result.get("recovery", {}).get("status") != "escalation_required":
                commit()
            return {**result, "approval_id": approval_id}

    def _record_execution(self, record: dict[str, Any], result: dict[str, Any]) -> None:
        info = {"approval_id": record["approval_id"], "case_id": record["case_id"],
                "action": record["action"], "target": record["target"], "execution_id": result["execution_id"]}
        actor = "lab" if getattr(self.scenario, "lab", None) else "simulator"
        verification = result["verification"]
        apply_event = "action_applied" if verification.get("configuration_applied") else "action_apply_unconfirmed"
        self.audit.append(apply_event, actor, **info)
        self.audit.append("action_verification", actor, observations=verification,
                          before=result.get("before"), **info)
        if "recovery" in result:
            self.audit.append("automatic_recovery", actor, outcome=result["recovery"], **info)
        record["execution_id"] = result["execution_id"]
        record["execution_status"] = result["status"]
        self._save(record)

    def verify_execution(self, execution_id: str) -> dict[str, Any]:
        with self._transaction():
            result = self.scenario.verify_execution(execution_id)
            self.audit.append("action_verified", "agent", **result)
            return result

    def authorize_rollback(self, execution_id: str, role: str, name: str, note: str) -> None:
        """Human channel. Authorize one scoped reversal after reviewing the threat reopening risk."""
        with self._transaction():
            record = self.scenario.executions.get(execution_id)
            if not record or record["status"] != "executed":
                raise ResponseError("A live execution is required.")
            approval = self._load(f"APR-{execution_id[4:]}")
            if self._level(role) < self._level(approval["required_role"]) or not note.strip():
                raise ResponseError("Rollback requires the original approval level and a reason.")
            if record["action"] == "failover_to_backup":
                primary = self.scenario.functions[record["target"]]["primary_asset"]
                if self.scenario.runtime["device_isolated"][primary]:
                    raise ResponseError("Rollback would return the protected service to an isolated primary.")
            record["rollback_authorization"] = {
                "actor": f"operator:{name}:{role}", "note": note,
                "expires_at": _iso(self.clock() + timedelta(seconds=900)),
                "state_hash": _sha(_canonical(self.scenario.runtime)),
            }
            self._save_environment()
            self.audit.append("rollback_authorized", f"operator:{name}:{role}", execution_id=execution_id, note=note)

    def rollback_execution(self, execution_id: str) -> dict[str, Any]:
        with self._transaction():
            record = self.scenario.executions.get(execution_id)
            if record and record["status"] == "rolled_back":
                return record["recovery"]
            auth = record.get("rollback_authorization") if record else None
            if (not auth or self.clock() > _parse(auth["expires_at"])
                    or auth["state_hash"] != _sha(_canonical(self.scenario.runtime))):
                self.audit.append("rollback_blocked", "agent", execution_id=execution_id)
                raise ResponseError("Rollback requires current operator authorization for this execution.")
            try:
                result = self.scenario.rollback_action(execution_id)
            except ResponseError as exc:
                self.audit.append("rollback_blocked", "agent", execution_id=execution_id, problem=str(exc))
                raise
            self._save_environment()
            self.audit.append("action_rolled_back", auth["actor"], **result)
            approval = self._load(f"APR-{execution_id[4:]}")
            approval["execution_status"] = result["status"]
            self._save(approval)
            commit = getattr(self.scenario, "commit_live_action", None)
            if commit is not None:
                commit()
            return result

    def decide(self, approval_id: str, decision: str, role: str, name: str, note: str | None = None) -> dict[str, Any]:
        """Record a decision from the trusted operator channel."""
        with self._transaction():
            return self._decide(approval_id, decision, role, name, note)

    def _decide(self, approval_id: str, decision: str, role: str, name: str, note: str | None) -> dict[str, Any]:
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
        if decision == "approve":
            simulation = self.scenario.simulate_response(record["action"], record["target"])
            _, digest_hash = self.plan_digest(simulation)
            self._check_lab_policy(simulation, phase="approval", operator_role=role)
            if simulation["verdict"] != "allowed" or digest_hash != record["plan_hash"]:
                self.audit.append("approval_decision_rejected", actor, problem="reviewed plan is stale", **info)
                raise ResponseError("The reviewed plan changed. A fresh request is required.")
        now = self.clock()
        record["status"] = "approved" if decision == "approve" else "denied"
        record["decided_by"] = {"name": who, "role": role}
        record["decided_at"] = _iso(now)
        if decision == "approve":  # a fresh validity window starts when the human approves
            expiry = self.scenario.policy["global_rules"]["approval_expiry_seconds"]
            record["expires_at"] = _iso(now + timedelta(seconds=expiry))
        record["decision_note"] = (note or "").strip() or None
        self._save(record)
        self.audit.append(f"approval_{record['status']}", actor, note=record["decision_note"], plan_hash=record["plan_hash"], **info)
        return self._view(record)
