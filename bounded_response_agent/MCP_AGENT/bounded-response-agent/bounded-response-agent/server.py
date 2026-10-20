"""Bounded Response Agent MCP server (steps 2 and 3: analysis, approval and audit).

The analysis tools are read-only: they explain the situation, check policy, and predict
mission impact so the agent can recommend the least disruptive effective response. The
approval tools let the agent ask a human for permission and read the answer. There is
deliberately no tool that approves or denies; only a human can, through operator_console.py
or the prompt in client.py. Execution, verification and rollback come in later steps.

Logic lives in response_logic.py and approvals.py so it can be tested without the MCP package.
The previous quarantine demo is kept in legacy/.
"""

import asyncio
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from approvals import ApprovalService
from integrations import (
    IntegrationError,
    inspect_tls_certificate,
    lookup_cve,
    query_urlhaus_host,
    resolve_dns,
    search_github_advisories,
)
from response_logic import ResponseError, Scenario

mcp = MCPServer("bounded-response-agent")
scenario = Scenario()
approvals = ApprovalService(scenario)


def _run(fn, *args, **kwargs):
    """Call scenario logic and surface ResponseError messages to the model."""
    try:
        return fn(*args, **kwargs)
    except ResponseError as exc:
        raise ToolError(str(exc)) from exc


def _integration(fn, *args, **kwargs):
    """Run a live read-only integration and expose failures as MCP tool errors."""
    try:
        return fn(*args, **kwargs)
    except IntegrationError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
def resolve_indicator_dns(hostname: str) -> dict[str, Any]:
    """Resolve a hostname with the local configured DNS resolver.

    Use this to pivot from a finding or URL to current network ownership clues. It is
    read-only and returns the observation timestamp and source.
    """
    return _integration(resolve_dns, hostname)


@mcp.tool()
def inspect_indicator_tls(hostname: str, port: int = 443) -> dict[str, Any]:
    """Inspect a live TLS endpoint's certificate, issuer, SANs and negotiated cipher.

    Use this to corroborate whether an external indicator presents an expected identity.
    No request payload is sent beyond the TLS handshake.
    """
    return _integration(inspect_tls_certificate, hostname, port)


@mcp.tool()
def check_urlhaus_host(host: str) -> dict[str, Any]:
    """Query the public URLhaus malware database for URLs associated with a host or IP."""
    return _integration(query_urlhaus_host, host)


@mcp.tool()
def lookup_nvd_cve(cve_id: str) -> dict[str, Any]:
    """Look up a CVE in NIST's public National Vulnerability Database."""
    return _integration(lookup_cve, cve_id)


@mcp.tool()
def search_security_advisories(
    ecosystem: str,
    severity: str | None = None,
    keyword: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Search GitHub's public Advisory Database for vulnerable packages.

    This is useful when a finding names a software component or the agent needs to
    prioritize remediation evidence without changing any repository or package state.
    """
    return _integration(search_github_advisories, ecosystem, severity=severity, keyword=keyword, limit=limit)


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
def simulate_response(action: str, target: str | None = None, assume_done: list[str] | None = None) -> dict[str, Any]:
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
def list_response_options(case_id: str | None = None, assume_done: list[str] | None = None) -> dict[str, Any]:
    """Simulate every candidate response for the open case, ranked from least to most
    disruptive, and report which threat findings only a blocked option could address.
    Read-only.

    Args:
        case_id: Optional case id.
        assume_done: Optional earlier steps to assume complete.
    """
    return _run(scenario.list_response_options, case_id, assume_done)


@mcp.tool()
def request_operator_approval(
    action: str, rationale: str, target: str | None = None, assume_done: list[str] | None = None
) -> dict[str, Any]:
    """Ask a human operator to approve one response action. The action is dry-run first and the
    request is refused unless the verdict is 'allowed'. This only creates a pending request:
    nothing is executed, and you cannot approve it yourself. Every request is audited.

    Args:
        action: A response action name from get_response_policy (not continue_monitoring).
        rationale: Why this action, in one or two sentences (required).
        target: Flow id, account, device or function id the action applies to.
        assume_done: Optional earlier steps assumed complete, e.g.
            ['failover_to_backup:cooling_monitoring'].
    """
    return _run(approvals.request, action, target, rationale, assume_done)


@mcp.tool()
def get_approval_status(approval_id: str) -> dict[str, Any]:
    """Return an approval's status (pending, approved, denied, expired), who decided, the role
    required, and seconds left before it lapses. Read-only.

    Args:
        approval_id: e.g. 'APR-0001'.
    """
    return _run(approvals.status, approval_id)


@mcp.tool()
async def wait_for_approval(approval_id: str, timeout_seconds: int = 120) -> dict[str, Any]:
    """Wait until a human decides the approval or the timeout passes, then return its status.
    A status of 'pending' after the timeout means no human has answered yet. Read-only.

    Args:
        approval_id: e.g. 'APR-0001'.
        timeout_seconds: How long to wait, 1-300.
    """
    if not 1 <= timeout_seconds <= 300:
        raise ToolError("timeout_seconds must be between 1 and 300.")
    deadline = time.monotonic() + timeout_seconds
    while True:
        status = _run(approvals.status, approval_id)
        if status["status"] != "pending":
            return status
        if time.monotonic() >= deadline:
            return {**status, "note": f"Still pending after {timeout_seconds} s. No human has answered yet."}
        await asyncio.sleep(1)


@mcp.tool()
def list_approvals(status: str | None = None) -> list[dict[str, Any]]:
    """List approvals, optionally only those pending, approved, denied or expired. Read-only.

    Args:
        status: Optional filter.
    """
    return _run(approvals.list_approvals, status)


@mcp.tool()
def get_audit_log(limit: int = 50, event: str | None = None) -> list[dict[str, Any]]:
    """Return the most recent audit entries (requests, refusals, decisions, expiries). Read-only.

    Args:
        limit: Maximum entries, 1-200.
        event: Optional event name, e.g. 'approval_request_refused'.
    """
    if not 1 <= limit <= 200:
        raise ToolError("limit must be between 1 and 200.")
    return approvals.audit.read(limit, event)


@mcp.tool()
def verify_audit_log() -> dict[str, Any]:
    """Check the audit log's hash chain. Reports the first entry that was altered, removed or
    reordered. Read-only."""
    return approvals.audit.verify()


if __name__ == "__main__":
    mcp.run(transport="stdio")
