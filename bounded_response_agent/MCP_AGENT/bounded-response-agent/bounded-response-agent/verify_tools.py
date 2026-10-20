"""Protocol-level check: discover and call every tool over stdio (no LLM).

Approval requests are written to a throwaway state folder, so this check never touches your
real approvals or audit log and needs no reset.
Run from the project folder: python verify_tools.py
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FAILOVER = ["failover_to_backup:cooling_monitoring"]
CALLS = [
    ("resolve_indicator_dns", {"hostname": "localhost"}),
    ("inspect_indicator_tls", {"hostname": "example.com"}),
    ("check_urlhaus_host", {"host": "198.51.100.77"}),
    ("lookup_nvd_cve", {"cve_id": "CVE-2024-3094"}),
    ("search_security_advisories", {"ecosystem": "pip", "severity": "high", "limit": 1}),
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
    ("request_operator_approval", {"action": "block_network_flow", "target": "F004", "rationale": "Stop exfiltration"}),
    ("request_operator_approval", {"action": "isolate_endpoint", "target": "ws-eng01", "rationale": "Contain host"}),
    ("get_approval_status", {"approval_id": "APR-0001"}),
    ("wait_for_approval", {"approval_id": "APR-0001", "timeout_seconds": 1}),
    ("list_approvals", {}),
    ("get_audit_log", {"limit": 10}),
    ("verify_audit_log", {}),
    ("get_approval_status", {"approval_id": "nope"}),
    ("request_operator_approval", {"action": "continue_monitoring", "rationale": "Just watching"}),
    ("lookup_device", {"hostname": "db99"}),
    ("simulate_response", {"action": "launch_missiles", "target": "x"}),
]


async def main():
    with tempfile.TemporaryDirectory() as state_dir:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).with_name("server.py"))],
            env={"BRA_STATE_DIR": state_dir},
        )
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
