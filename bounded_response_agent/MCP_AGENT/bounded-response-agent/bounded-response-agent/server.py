"""Bounded Response Agent MCP server (step 2: read and analysis tools).

All tools here are read-only. They explain the situation, check policy, and predict mission
impact so the agent can recommend the least disruptive effective response. The analysis logic
lives in response_logic.py so it can be tested without the MCP package. Tools that change
state (approval, execution, verification, rollback) come in later steps.

The previous quarantine demo is kept in legacy/.
"""
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from response_logic import ResponseError, Scenario

mcp = MCPServer("bounded-response-agent")
scenario = Scenario()


def _run(fn, *args, **kwargs):
    """Call scenario logic and surface ResponseError messages to the model."""
    try:
        return fn(*args, **kwargs)
    except ResponseError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
def get_investigation_findings(case_id: str | None = None) -> dict[str, Any]:
    """Return the SOC Investigation Agent's findings: claims, confidence, evidence, and the
    assets, accounts and flows each finding concerns. Read-only.

    Args:
        case_id: Optional case id, e.g. 'CASE-2026-1012-001'.
    """
    return _run(scenario.get_investigation_findings, case_id)


@mcp.tool()
def get_response_policy(action: str | None = None) -> dict[str, Any]:
    """Return the response policy: for each action its disruption rank, required approval
    role, forbidden conditions, preconditions and rollback. Pass an action for just that one.
    Read-only.

    Args:
        action: Optional. One of continue_monitoring, block_network_flow,
            restrict_network_flow, disable_account, failover_to_backup, isolate_endpoint.
    """
    return _run(scenario.get_response_policy, action)


@mcp.tool()
def lookup_device(hostname: str) -> dict[str, str]:
    """Look up a device: IP, role, zone, criticality and whether it is protected
    (protected devices must never be acted on by the agent). Read-only.

    Args:
        hostname: Exact hostname, e.g. 'ws-eng01'.
    """
    return _run(scenario.lookup_device, hostname)


@mcp.tool()
def lookup_account(account: str) -> dict[str, str]:
    """Look up an account: type, privilege, bound hosts, the function it serves and whether
    the agent may revoke it. Read-only.

    Args:
        account: Exact account name, e.g. 'eng.mokoa'.
    """
    return _run(scenario.lookup_account, account)


@mcp.tool()
def get_network_flows(host: str | None = None) -> list[dict[str, str]]:
    """List network flows (id, source, destination, port, purpose, status, whether mission
    critical). Pass a host to see only flows that start or end there. Read-only.

    Args:
        host: Optional hostname filter.
    """
    return _run(scenario.get_network_flows, host)


@mcp.tool()
def get_system_health(system: str | None = None) -> list[dict[str, str]]:
    """Return health telemetry (metric, value, normal range, status). Pass a system to see
    only that one. Read-only.

    Args:
        system: Optional hostname, e.g. 'backup-mon01'.
    """
    return _run(scenario.get_system_health, system)


@mcp.tool()
def get_events(
    host: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> list[dict[str, str]]:
    """Return the event timeline behind the findings (EDR, firewall and identity events),
    oldest first, with optional filters. Read-only.

    Args:
        host: Hostname or IP that is the source or destination of the event.
        source: 'edr', 'firewall' or 'idp'.
        severity: 'info', 'medium' or 'high'.
        action: 'allow', 'deny' or 'alert'.
        since: ISO timestamp, only events at or after it, e.g. '2026-10-12T21:00:00Z'.
        limit: Maximum events to return (1-200).
    """
    return _run(scenario.get_events, host, source, severity, action, since, limit)


@mcp.tool()
def get_mission_dependencies(function_id: str | None = None) -> list[dict[str, Any]]:
    """Return mission functions and what each depends on (devices, flows, accounts, primary
    or backup), plus safety flag, maximum tolerable telemetry gap and backup readiness.
    Read-only.

    Args:
        function_id: Optional, e.g. 'cooling_monitoring'.
    """
    return _run(scenario.get_mission_dependencies, function_id)


@mcp.tool()
def analyze_mission_impact(
    action: str, target: str | None = None, assume_done: list[str] | None = None
) -> dict[str, Any]:
    """Predict which mission functions an action would interrupt and for how long, compared
    with each function's maximum tolerable gap. Read-only; nothing is executed.

    Args:
        action: A response action name from get_response_policy.
        target: Flow id, account, device or function id the action applies to.
        assume_done: Optional earlier steps to assume complete, such as
            ['failover_to_backup:cooling_monitoring'], to evaluate a sequence.
    """
    return _run(scenario.analyze_mission_impact, action, target, assume_done)


@mcp.tool()
def simulate_response(
    action: str, target: str | None = None, assume_done: list[str] | None = None
) -> dict[str, Any]:
    """Dry run of one response action: policy check, preconditions, supporting evidence,
    mission impact, required approval level and a verdict (allowed, forbidden,
    insufficient_evidence, unacceptable_impact, preconditions_not_met). Read-only; nothing
    is executed and no approval is requested.

    Args:
        action: A response action name from get_response_policy.
        target: Flow id, account, device or function id the action applies to.
        assume_done: Optional earlier steps to assume complete, such as
            ['failover_to_backup:cooling_monitoring'], to evaluate a sequence.
    """
    return _run(scenario.simulate_response, action, target, assume_done)


@mcp.tool()
def list_response_options(
    case_id: str | None = None, assume_done: list[str] | None = None
) -> dict[str, Any]:
    """Simulate every candidate response for the open case, ranked from least to most
    disruptive, and report which threat findings only a blocked option could address.
    Read-only.

    Args:
        case_id: Optional case id.
        assume_done: Optional earlier steps to assume complete.
    """
    return _run(scenario.list_response_options, case_id, assume_done)


if __name__ == "__main__":
    mcp.run(transport="stdio")
