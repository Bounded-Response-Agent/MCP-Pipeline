"""Durable, case-local Claude conversations."""

import json
import sqlite3
from contextlib import closing

from approvals import _file_lock
from response_logic import ResponseError


class Conversation:
    def __init__(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "conversation.sqlite3"
        self.lock_path = directory / "conversation.lock"
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS turns (
                       sequence INTEGER PRIMARY KEY,
                       id TEXT NOT NULL UNIQUE,
                       payload TEXT NOT NULL
                       )""")

    def lock(self):
        return _file_lock(self.lock_path, timeout=0)

    def save(self, run):
        payload = json.dumps(run, ensure_ascii=False)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""INSERT INTO turns (id, payload) VALUES (?, ?)
                       ON CONFLICT(id) DO UPDATE SET payload = excluded.payload""",
                       (run["id"], payload))

    def latest(self):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT payload FROM turns ORDER BY sequence DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def recover(self):
        try:
            with self.lock():
                run = self.latest()
                if run and run["status"] == "running":
                    run["status"] = "interrupted"
                    run["error"] = "The console stopped during this turn. Review any outstanding approval before continuing."
                    self.save(run)
        except ResponseError:
            # A different local console still owns the active turn.
            return

    def history(self, limit=None, *, include_events=False):
        if include_events:
            query = "SELECT payload FROM turns ORDER BY sequence ASC"
            args = ()
        else:
            query = """SELECT json_remove(payload, '$.events') FROM turns
                       ORDER BY sequence DESC LIMIT ?"""
            args = (limit if limit is not None else 100,)
        with closing(sqlite3.connect(self.path)) as db:
            rows = [json.loads(row[0]) for row in db.execute(query, args)]
        return rows if include_events else rows[::-1]

    def context(self):
        messages = []
        remaining = 24000
        for turn in reversed(self.history(16)):
            if turn["status"] != "completed" or not turn.get("answer"):
                continue
            user, answer = turn["goal"], turn["answer"][:8000]
            if len(user) + len(answer) > remaining:
                break
            messages[0:0] = [{"role": "user", "content": user}, {"role": "assistant", "content": answer}]
            remaining -= len(user) + len(answer)
            if len(messages) >= 16:
                break
        return messages
