"""A dedicated MCP connection and approval store for each loaded case."""

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from approvals import ApprovalService
from browser_agent import BrowserAgent
from lab_backend import load_lab
from profiles import PROFILES, profile_path, validate_case
from response_logic import ResponseError, Scenario

ROOT = Path(__file__).resolve().parent


class CaseWorkspace:
    def __init__(self, key, scenario, state_dir, *, case_file=None, live=False):
        self.key = key
        self.scenario = scenario
        self.service = ApprovalService(scenario, state_dir)
        self.case_file = case_file
        self.live = live
        self.task = None

    def summary(self):
        profile = self.scenario.profile
        case = self.scenario.findings
        return {"key": self.key, "profile": profile["id"], "environment": profile["name"],
                "mode": "live lab" if self.live else "simulator",
                "case_id": case["case_id"], "title": case["title"],
                "health_label": profile["health_label"], "source_label": profile["source_label"]}

    async def connect(self):
        if self.task and not self.task.done():
            return
        self.stop = asyncio.Event()
        ready = asyncio.get_running_loop().create_future()
        self.task = asyncio.create_task(self._serve(ready))
        await ready

    async def _serve(self, ready):
        env = {"BRA_PROFILE": self.scenario.profile["id"], "BRA_CASE_FILE": str(self.case_file or ""),
               "BRA_LAB_CONFIG": os.environ["BRA_LAB_CONFIG"] if self.live else "",
               "BRA_STATE_DIR": str(self.service.dir.resolve()),
               "BRA_SIM_FAULT": "" if self.live else os.environ.get("BRA_SIM_FAULT", "")}
        params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "server.py")], env=env)
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.session = session
                    self.agent = BrowserAgent(session, self.service.dir)
                    ready.set_result(None)
                    try:
                        await self.stop.wait()
                    finally:
                        await self.agent.close()
        except Exception:
            if not ready.done():
                ready.set_exception(ResponseError("The MCP server could not open this incident."))

    async def close(self):
        if self.task and not self.task.done():
            self.stop.set()
            await self.task


class CaseCatalog:
    def __init__(self):
        self.root = Path(os.environ.get("BRA_STATE_DIR", ROOT / "state")).resolve()
        self.items = {}
        self.active = None
        self.scope = None
        self.lock = asyncio.Lock()
        for profile, data in PROFILES.items():
            self.add_simulated(profile, Scenario(data))
        lab = load_lab()
        if lab:
            self.items["live"] = CaseWorkspace("live", lab, lab.lab["state_dir"], live=True)
        for profile in PROFILES:
            for path in sorted((self.root / "imports" / profile).glob("*.json")):
                try:
                    validate_case(json.loads(path.read_text(encoding="utf-8")), Scenario(profile_path(profile)))
                    self.add_simulated(profile, Scenario(profile_path(profile), case_file=path), path)
                except (OSError, ValueError, ResponseError):
                    continue

    def add_simulated(self, profile, scenario, case_file=None):
        key = f"{profile}:{scenario.findings['case_id']}"
        directory = self.root / "cases" / profile / f"case-{scenario.findings['case_id']}-state"
        if any(existing.casefold() == key.casefold() for existing in self.items):
            raise ResponseError("This case ID already exists in the selected environment.")
        self.items[key] = CaseWorkspace(key, scenario, directory, case_file=case_file)
        return key

    def import_case(self, profile, body):
        directory = profile_path(profile)
        clean = validate_case(body, Scenario(directory))
        key = f"{profile}:{clean['case_id']}"
        if any(existing.casefold() == key.casefold() for existing in self.items):
            raise ResponseError("This case ID already exists in the selected environment.")
        path = self.root / "imports" / profile / f"case-{clean['case_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as file:
            json.dump(clean, file, indent=2)
        return self.add_simulated(profile, Scenario(directory, case_file=path), path)
