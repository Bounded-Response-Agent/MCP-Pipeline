"""Assert the defensive workflow through MCP using scripted demo operators."""

import argparse
import asyncio
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from operator_console import provision

ROOT = Path(__file__).resolve().parent
TARGETED = [("block_network_flow", "F004"), ("restrict_network_flow", "F005"),
            ("restrict_network_flow", "F006"), ("disable_account", "eng.mokoa")]
FAILOVER = ("failover_to_backup", "cooling_monitoring")
ISOLATE = ("isolate_endpoint", "ws-eng01")


async def run_case(name, fault):
    trace = {"case": name, "fault": fault, "events": []}
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        identities = root / "operators.json"
        passwords = {identity: secrets.token_urlsafe(24) for identity in ("soc-watch", "ot-watch")}
        provision(identities, passwords)
        server_env = {"BRA_LAB_CONFIG": "", "BRA_STATE_DIR": str(root / "state"), "BRA_SIM_FAULT": fault or ""}
        operator_env = {**os.environ, **server_env, "BRA_OPERATOR_FILE": str(identities)}
        parameters = StdioServerParameters(command=sys.executable, args=[str(ROOT / "server.py")], env=server_env)
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                assert not tools.intersection({"decide", "approve", "deny", "authorize_rollback"})
                trace["tools"] = sorted(tools)

                async def call(tool, *, error=False, **arguments):
                    response = await session.call_tool(tool, arguments)
                    body = "\n".join(block.text for block in response.content if hasattr(block, "text"))
                    result = body if response.is_error else response.structured_content
                    if result is None:
                        result = json.loads(body)
                    trace["events"].append({"channel": "mcp", "tool": tool, "arguments": arguments,
                                            "error": response.is_error, "result": result})
                    assert bool(response.is_error) == error, (tool, arguments, result)
                    return result

                def operator(command, reference, identity, *, error=False, note=None, wrong_password=False):
                    arguments = [command, reference, "--operator", identity]
                    if note:
                        arguments += ["--note", note]
                    decision = subprocess.run(
                        [sys.executable, str(ROOT / "operator_console.py"), *arguments], env=operator_env,
                        input=("wrong password" if wrong_password else passwords[identity]) + "\n",
                        text=True, capture_output=True, check=False, timeout=15,
                    )
                    assert bool(decision.returncode) == error, (decision.stdout, decision.stderr)
                    result = decision.stderr.strip().splitlines()[-1] if error else json.loads(decision.stdout)
                    trace["events"].append({"channel": "scripted_demo_operator", "command": command,
                                            "reference": reference, "identity": identity, "result": result})

                async def request(step, **kwargs):
                    action, target = step
                    return await call("request_operator_approval", action=action, target=target,
                                      rationale="Scoped defensive action after policy and mission review.", **kwargs)

                async def apply(step, identity="soc-watch", expected="verified"):
                    pending = await request(step)
                    assert pending["status"] == "pending", pending
                    aid = pending["approval_id"]
                    operator("approve", aid, identity)
                    assert (await call("wait_for_approval", approval_id=aid, timeout_seconds=1))["status"] == "approved"
                    result = await call("execute_approved_action", approval_id=aid)
                    assert result["status"] == expected, result
                    return aid, result

                async def assert_contained():
                    end = await call("observe_response_outcomes")
                    assert all(p["allowed"] == 0 for p in end["probes"].values())
                    assert end["cooling"]["healthy"] and end["cooling"]["max_gap_s"] <= 120

                await call("get_investigation_findings")
                if name == "targeted_containment":
                    comparison = await call("compare_response_plans")
                    assert [(s["action"], s["target"]) for s in comparison["recommended_plan"]["steps"]] == TARGETED
                    assert (await request(ISOLATE))["verdict"] == "unacceptable_impact"
                    assert (await request(ISOLATE, assume_done=["failover_to_backup:cooling_monitoring"]))[
                        "verdict"] == "hypothetical_preconditions"
                    assert (await request(("block_network_flow", "F001")))["verdict"] == "forbidden"
                    assert (await request(("disable_account", "adm.kealoha")))["verdict"] == "forbidden"
                    executions = [await apply(step) for step in TARGETED]
                    await assert_contained()
                    assert (await call("compare_response_plans"))["recommended_plan"]["name"] == "continue_monitoring"
                    aid, first = executions[0]
                    execution = first["execution_id"]
                    retry = await call("execute_approved_action", approval_id=aid)
                    assert retry["replayed"] and retry["execution_id"] == execution
                    assert (await call("verify_system_state", execution_id=execution))["verified"]
                    await call("rollback_action", execution_id=execution, error=True)
                    operator("authorize-rollback", execution, "soc-watch",
                             note="Demo reversal after accepting that F004 will reopen in the simulator.")
                    assert (await call("rollback_action", execution_id=execution))["status"] == "rolled_back"
                    after = await call("observe_response_outcomes")
                    assert after["probes"]["F004"]["allowed"] > 0
                    assert all(after["probes"][t]["allowed"] == 0 for t in ("F005", "F006", "eng.mokoa"))
                    assert after["cooling"]["healthy"]
                elif name == "authorized_escalation":
                    for step in TARGETED:
                        await apply(step, expected="rolled_back" if step[1] == "F006" else "verified")
                    before = await call("observe_response_outcomes")
                    assert before["probes"]["F006"]["allowed"] > 0 and before["cooling"]["healthy"]
                    next_plan = (await call("compare_response_plans"))["recommended_plan"]
                    assert next_plan["name"] == "failover_then_isolate", next_plan
                    _, moved = await apply(FAILOVER, "ot-watch")
                    cooling = moved["verification"]["cooling"]
                    assert cooling["source"] == "backup-mon01" and cooling["max_gap_s"] <= 120
                    await apply(ISOLATE, "ot-watch")
                    await assert_contained()
                    operator("authorize-rollback", moved["execution_id"], "ot-watch", error=True,
                             note="Unsafe attempt to return monitoring to the isolated primary.")
                elif name == "mission_verification_failure":
                    await apply(TARGETED[0])
                    _, failed = await apply(FAILOVER, "ot-watch", "rolled_back")
                    assert failed["verification"]["configuration_applied"]
                    assert not failed["verification"]["cooling"]["healthy"]
                    assert failed["recovery"]["cooling"]["source"] == "ws-eng01"
                    assert failed["recovery"]["cooling"]["gap_through_recovery_s"] <= 120
                    assert failed["recovery"]["probes"]["F004"]["allowed"] == 0
                    assert (await request(ISOLATE))["status"] == "refused"
                else:
                    aid = (await request(FAILOVER))["approval_id"]
                    await call("execute_approved_action", approval_id=aid, error=True)
                    operator("approve", aid, "ot-watch", error=True, wrong_password=True)
                    operator("approve", aid, "soc-watch", error=True)
                    operator("approve", aid, "ot-watch")
                    # Expiry fixture avoids a real-time 15-minute delay.
                    path = root / "state" / "approvals" / f"{aid}.json"
                    approval = json.loads(path.read_text(encoding="utf-8"))
                    approval["expires_at"] = "2000-01-01T00:00:00Z"
                    path.write_text(json.dumps(approval), encoding="utf-8")
                    trace["events"].append({"channel": "test_fixture", "action": "force_approval_expiry"})
                    await call("execute_approved_action", approval_id=aid, error=True)
                    assert (await call("get_approval_status", approval_id=aid))["status"] == "expired"
                    assert (await call("observe_response_outcomes"))["cooling"]["source"] == "ws-eng01"
                assert (await call("verify_audit_log"))["ok"]
                await call("get_audit_log", limit=200)
    trace["status"] = "passed"
    return trace


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("demo-traces.json"))
    args = parser.parse_args()
    cases = {"targeted_containment": None, "authorized_escalation": "ineffective_F006",
             "mission_verification_failure": "backup_silent", "authority_refusals": None}
    traces = []
    for name, fault in cases.items():
        traces.append(await run_case(name, fault))
        print(f"PASS {name}")
    args.output.write_text(json.dumps(traces, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
