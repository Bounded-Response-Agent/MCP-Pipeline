"""Protocol-level check: discover and call every tool over stdio (no LLM).

All current tools are read-only, so this check changes nothing and needs no reset.
Run from the project folder: python verify_tools.py
"""
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FAILOVER = ["failover_to_backup:cooling_monitoring"]
CALLS = [
    ("get_investigation_findings", {}),
    ("get_events", {"host": "ws-eng01", "severity": "high"}),
    ("get_events", {"source": "radar"}),
    ("get_response_policy", {"action": "isolate_endpoint"}),
    ("lookup_device", {"hostname": "ws-eng01"}),
    ("lookup_account", {"account": "eng.mokoa"}),
    ("get_network_flows", {"host": "ws-eng01"}),
    ("get_system_health", {"system": "backup-mon01"}),
    ("get_mission_dependencies", {"function_id": "cooling_monitoring"}),
    ("analyze_mission_impact", {"action": "isolate_endpoint", "target": "ws-eng01"}),
    ("simulate_response", {"action": "block_network_flow", "target": "F004"}),
    ("simulate_response", {"action": "isolate_endpoint", "target": "ws-eng01"}),
    ("simulate_response", {"action": "isolate_endpoint", "target": "ws-eng01", "assume_done": FAILOVER}),
    ("simulate_response", {"action": "isolate_endpoint", "target": "fw01"}),
    ("simulate_response", {"action": "block_network_flow", "target": "F001"}),
    ("list_response_options", {}),
    ("lookup_device", {"hostname": "db99"}),
    ("simulate_response", {"action": "launch_missiles", "target": "x"}),
]


async def main():
    params = StdioServerParameters(command=sys.executable, args=[str(Path(__file__).with_name("server.py"))])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("DISCOVERED:", [t.name for t in tools.tools])
            for name, args in CALLS:
                res = await s.call_tool(name, args)
                text = " ".join(c.text for c in res.content if hasattr(c, "text"))
                print(f"\n{name}({json.dumps(args)}) is_error={res.is_error}\n  {text[:300]}")


asyncio.run(main())
