"""Session-only course gateway credentials and an MCP-backed case conversation."""

import asyncio
import re
import secrets
from datetime import datetime, timezone
from dataclasses import dataclass

from client import DEFAULT_BASE_URL, DEFAULT_MODEL, create_completion, run_session
from conversation import Conversation
from response_logic import ResponseError

GATEWAY_URL = DEFAULT_BASE_URL


@dataclass(repr=False, frozen=True)
class GatewaySettings:
    model: str
    key: str


class BrowserAgent:
    def __init__(self, session, state_dir):
        self.session = session
        self.conversation = Conversation(state_dir)
        self.conversation.recover()
        self.guard = None
        self.settings = None
        self.task = None
        self.run = self.conversation.latest()

    def snapshot(self):
        return {"configured": self.settings is not None,
                "model": self.settings.model if self.settings else None,
                "run": self.run if self.task and not self.task.done() else self.conversation.latest(),
                "history": self.conversation.history()}

    def configure(self, model, key):
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,96}", model):
            raise ResponseError(f"Enter a course gateway model ID, such as {DEFAULT_MODEL}.")
        if not isinstance(key, str) or not re.fullmatch(r"[^\s\x00-\x1f\x7f]{1,512}", key.strip()):
            raise ResponseError("Enter a course gateway API key.")
        self.settings = GatewaySettings(model, key.strip())

    def start(self, goal, mode, case):
        if self.task is not None and not self.task.done():
            raise ResponseError("Wait for the current AI run to finish.")
        if not self.settings:
            raise ResponseError("Configure your course gateway API key first.")
        if not isinstance(goal, str) or not 1 <= len(goal.strip()) <= 4000:
            raise ResponseError("Enter a prompt of 1–4000 characters.")
        if mode not in ("recommend", "containment"):
            raise ResponseError("Choose a supported AI run mode.")
        if self.settings.key in goal:
            raise ResponseError("Enter the API key in Settings and remove it from the message.")
        self.conversation.recover()
        guard = self.conversation.lock()
        guard.__enter__()
        try:
            context = self.conversation.context()
            self.run = {"id": secrets.token_hex(8), "status": "running", "model": self.settings.model,
                        "goal": goal.strip(), "mode": mode, "case": case, "events": [],
                        "started_at": datetime.now(timezone.utc).isoformat()}
            self.conversation.save(self.run)
            self.guard = guard
            self.task = asyncio.create_task(self._run(self.settings, context))
        except BaseException:
            guard.__exit__(None, None, None)
            self.guard = None
            raise

    async def _run(self, settings, context):
        run = self.run

        async def complete(messages, tools):
            return await create_completion(messages, tools, settings.model,
                                           base_url=GATEWAY_URL, api_key=settings.key)

        def notify(event):
            run["events"].append(event)
            if event["kind"] == "approval":
                self.conversation.save(run)

        try:
            result = await run_session(self.session, run["goal"], run["mode"] == "containment",
                                       complete, notify=notify, scoped_approvals=True, max_turns=20,
                                       history=context)
            run["status"] = result["status"]
            run["answer"] = result["final_answer"]
        except RuntimeError as exc:
            run["status"] = "failed"
            run["error"] = str(exc).replace(settings.key, "[redacted]")
        except Exception:
            run["status"] = "failed"
            run["error"] = "The model or MCP server returned an unexpected response. Try a new run."
        except asyncio.CancelledError:
            run["status"] = "interrupted"
            raise
        finally:
            try:
                self.conversation.save(run)
            finally:
                self.release()

    def release(self):
        if self.guard:
            self.guard.__exit__(None, None, None)
            self.guard = None

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        self.release()
