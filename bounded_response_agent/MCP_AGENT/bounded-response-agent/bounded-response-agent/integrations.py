"""Read-only integrations with public security and network services.

The integrations deliberately do not change remote state. They return normalized data
that the response agent can use as corroborating evidence, while preserving the source
and timestamp of every result.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


class IntegrationError(Exception):
    """A public integration could not return a usable result."""


USER_AGENT = "bounded-response-agent/1.0"
TIMEOUT_SECONDS = 10


def _observed_at() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _request_json(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any] | list[Any]:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise IntegrationError(f"Integration returned HTTP {exc.code}: {url}") from exc
    except urllib.error.URLError as exc:
        raise IntegrationError(f"Integration is unavailable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise IntegrationError(f"Integration timed out after {TIMEOUT_SECONDS} seconds: {url}") from exc
    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise IntegrationError(f"Integration returned invalid JSON: {url}") from exc
    if not isinstance(result, (dict, list)):
        raise IntegrationError(f"Integration returned an unexpected response: {url}")
    return result


def resolve_dns(hostname: str) -> dict[str, Any]:
    """Resolve a hostname using the host's configured DNS resolver."""
    host = hostname.strip()
    if not host or len(host) > 253:
        raise IntegrationError("hostname must be 1-253 characters.")
    try:
        addresses = sorted({result[4][0] for result in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise IntegrationError(f"DNS resolution failed for '{hostname}': {exc}") from exc
    return {"hostname": host, "addresses": addresses, "observed_at": _observed_at(), "source": "system DNS"}


def inspect_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Inspect the peer certificate presented by a TLS endpoint."""
    host = hostname.strip()
    if not host or len(host) > 253:
        raise IntegrationError("hostname must be 1-253 characters.")
    if not 1 <= port <= 65535:
        raise IntegrationError("port must be between 1 and 65535.")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
    except (OSError, ssl.SSLError) as exc:
        raise IntegrationError(f"TLS inspection failed for {host}:{port}: {exc}") from exc
    if not certificate:
        raise IntegrationError(f"{host}:{port} did not present a certificate.")
    subject = dict(item[0] for item in certificate.get("subject", ()))
    issuer = dict(item[0] for item in certificate.get("issuer", ()))
    return {
        "hostname": host,
        "port": port,
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "subject_alternative_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "tls_version": tls_socket.version(),
        "cipher": cipher[0] if cipher else None,
        "observed_at": _observed_at(),
        "source": "peer TLS certificate",
    }


def query_urlhaus_host(host: str) -> dict[str, Any]:
    """Query abuse.ch URLhaus for malicious URLs associated with a host or IP."""
    indicator = host.strip()
    if not indicator or len(indicator) > 253:
        raise IntegrationError("host must be 1-253 characters.")
    payload = urllib.parse.urlencode({"host": indicator}).encode("ascii")
    result = _request_json("https://urlhaus-api.abuse.ch/v1/host/", method="POST", data=payload)
    if not isinstance(result, dict):
        raise IntegrationError("URLhaus returned an unexpected response.")
    urls = result.get("urls", [])
    return {
        "host": indicator,
        "query_status": result.get("query_status"),
        "url_count": len(urls) if isinstance(urls, list) else 0,
        "urls": urls[:10] if isinstance(urls, list) else [],
        "blacklists": result.get("blacklists", []),
        "observed_at": _observed_at(),
        "source": "URLhaus (abuse.ch)",
    }


def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Retrieve a CVE record from the public NIST National Vulnerability Database."""
    normalized = cve_id.strip().upper()
    if not normalized.startswith("CVE-") or len(normalized) > 30:
        raise IntegrationError("cve_id must look like CVE-2024-12345.")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(normalized)}"
    result = _request_json(url)
    if not isinstance(result, dict) or not result.get("vulnerabilities"):
        return {
            "cve_id": normalized,
            "found": False,
            "observed_at": _observed_at(),
            "source": "NIST NVD",
        }
    item = result["vulnerabilities"][0].get("cve", {})
    metrics = item.get("metrics", {})
    cvss = next(iter(metrics.values()), [{}])[0] if metrics else {}
    return {
        "cve_id": normalized,
        "found": True,
        "description": (item.get("descriptions") or [{}])[0].get("value"),
        "published": item.get("published"),
        "last_modified": item.get("lastModified"),
        "cvss_base_score": cvss.get("cvssData", {}).get("baseScore"),
        "severity": cvss.get("cvssData", {}).get("baseSeverity"),
        "references": [ref.get("url") for ref in item.get("references", [])[:10]],
        "observed_at": _observed_at(),
        "source": "NIST NVD",
    }


def search_github_advisories(
    ecosystem: str,
    *,
    severity: str | None = None,
    keyword: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Search GitHub's public Advisory Database for vulnerable packages."""
    allowed_ecosystems = {"rubygems", "npm", "pip", "maven", "nuget", "composer", "go"}
    normalized_ecosystem = ecosystem.strip().lower()
    if normalized_ecosystem not in allowed_ecosystems:
        raise IntegrationError(f"ecosystem must be one of: {', '.join(sorted(allowed_ecosystems))}.")
    if severity is not None and severity.lower() not in {"low", "moderate", "high", "critical"}:
        raise IntegrationError("severity must be low, moderate, high or critical.")
    if not 1 <= limit <= 20:
        raise IntegrationError("limit must be between 1 and 20.")
    query = urllib.parse.urlencode(
        {
            "ecosystem": normalized_ecosystem,
            **({"severity": severity.lower()} if severity else {}),
            **({"keyword": keyword.strip()} if keyword and keyword.strip() else {}),
            "per_page": limit,
        }
    )
    result = _request_json(f"https://api.github.com/advisories?{query}")
    if not isinstance(result, list):
        raise IntegrationError("GitHub returned an unexpected advisory response.")
    advisories = [
        {
            "ghsa_id": advisory.get("ghsa_id"),
            "cve_id": advisory.get("cve_id"),
            "summary": advisory.get("summary"),
            "severity": advisory.get("severity"),
            "published_at": advisory.get("published_at"),
            "updated_at": advisory.get("updated_at"),
            "html_url": advisory.get("html_url"),
        }
        for advisory in result[:limit]
    ]
    return {
        "ecosystem": normalized_ecosystem,
        "keyword": keyword,
        "advisories": advisories,
        "observed_at": _observed_at(),
        "source": "GitHub Advisory Database",
    }
