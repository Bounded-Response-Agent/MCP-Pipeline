"""Protocol-level check: discover and call every tool over stdio (no LLM)."""
import asyncio, sys, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CALLS = [
    ("lookup_device", {"hostname": "ws-bob"}),
    ("get_events_for_ip", {"ip": "10.0.30.22", "action": "deny"}),
    ("summarize_denied_by_source", {"min_count": 2}),
    ("quarantine_host", {"hostname": "ws-bob", "reason": "repeated deny hits to db01"}),
    ("quarantine_host", {"hostname": "ws-bob", "reason": "repeat call, should be idempotent"}),
    ("quarantine_host", {"hostname": "core-sw1", "reason": "test out-of-scope refusal"}),
    ("lookup_device", {"hostname": "printer07"}),
    ("get_events_for_ip", {"ip": "999.1.1.1"}),
]

async def main():
    params = StdioServerParameters(command=sys.executable, args=["server.py"])
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
