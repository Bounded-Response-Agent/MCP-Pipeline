"""Bounded Response Agent MCP server.

Investigation tools (lookup_device, get_events_for_ip, summarize_denied_by_source)
are unrestricted read access, like a SOC analyst's monitoring dashboard.

The one RESPONSE tool, quarantine_host, is bounded: it will only act on a
device whose `in_scope` flag is true in the inventory. Devices outside that
boundary (core infrastructure, firewalls) are visible for investigation but
the agent refuses to take action on them and says so, modeling an
access-control boundary between "read" and "act" authority.
"""
import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

DATA = Path(__file__).parent / "data"
DEVICES_CSV = DATA / "devices.csv"
EVENTS_CSV = DATA / "events.csv"
ACTIONS_CSV = DATA / "actions_log.csv"

mcp = MCPServer("bounded-response-agent")


def _rows(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ToolError(f"'{ip}' is not a valid IP address.")


@mcp.tool()
def lookup_device(hostname: str) -> dict:
    """Look up a device by hostname: IP, role, VLAN, and whether it is inside
    the agent's authorized response scope (in_scope).

    Args:
        hostname: Exact hostname, e.g. 'ws-bob'.
    """
    for d in _rows(DEVICES_CSV):
        if d["hostname"] == hostname.strip():
            return d
    raise ToolError(f"No device named '{hostname}'. Use list_devices-style lookup with a valid hostname.")


@mcp.tool()
def get_events_for_ip(ip: str, action: str | None = None, limit: int = 20) -> list[dict]:
    """Return firewall log events where the IP is the source or destination.
    Read-only; not restricted by response scope.

    Args:
        ip: IPv4/IPv6 address to search for.
        action: Optional filter, 'allow' or 'deny'.
        limit: Max events to return (1-100).
    """
    ip = _valid_ip(ip)
    if action is not None and action not in ("allow", "deny"):
        raise ToolError("action must be 'allow' or 'deny'.")
    if not 1 <= limit <= 100:
        raise ToolError("limit must be between 1 and 100.")
    ev = [e for e in _rows(EVENTS_CSV) if ip in (e["src_ip"], e["dst_ip"])]
    if action:
        ev = [e for e in ev if e["action"] == action]
    return ev[:limit]


@mcp.tool()
def summarize_denied_by_source(min_count: int = 1) -> list[dict]:
    """Count denied connections per source IP, highest first. Read-only.

    Args:
        min_count: Only include sources with at least this many denies (>=1).
    """
    if min_count < 1:
        raise ToolError("min_count must be >= 1.")
    counts: dict[str, int] = {}
    for e in _rows(EVENTS_CSV):
        if e["action"] == "deny":
            counts[e["src_ip"]] = counts.get(e["src_ip"], 0) + 1
    out = [{"src_ip": k, "denied": v} for k, v in counts.items() if v >= min_count]
    return sorted(out, key=lambda r: -r["denied"])


@mcp.tool()
def quarantine_host(hostname: str, reason: str) -> dict:
    """Quarantine a device (the agent's one RESPONSE action). Bounded: only
    permitted for devices marked in_scope=true in the inventory. Devices
    outside the authorized scope (e.g. core switches, firewalls) are refused
    and must be escalated to a senior analyst instead.

    Args:
        hostname: Exact hostname to quarantine.
        reason: Short justification, e.g. 'repeated deny hits from ws-bob'.
    """
    if not reason or not reason.strip():
        raise ToolError("reason is required and cannot be empty.")

    devices = _rows(DEVICES_CSV)
    device = next((d for d in devices if d["hostname"] == hostname.strip()), None)
    if device is None:
        raise ToolError(f"No device named '{hostname}'. Cannot quarantine an unknown host.")

    if device["in_scope"].strip().lower() != "true":
        raise ToolError(
            f"'{hostname}' ({device['role']}, VLAN {device['vlan']}) is outside this agent's "
            "authorized response scope. Refusing to act. Escalate to a senior analyst for "
            "manual containment."
        )

    already = [r for r in _rows(ACTIONS_CSV) if r["hostname"] == hostname.strip()]
    if already:
        return {
            "status": "already_quarantined",
            "hostname": hostname,
            "quarantined_at": already[-1]["quarantined_at"],
            "reason": already[-1]["reason"],
        }

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(ACTIONS_CSV, "a", newline="") as f:
        csv.writer(f).writerow([hostname.strip(), ts, reason.strip()])

    return {"status": "quarantined", "hostname": hostname, "quarantined_at": ts, "reason": reason}


if __name__ == "__main__":
    mcp.run(transport="stdio")
