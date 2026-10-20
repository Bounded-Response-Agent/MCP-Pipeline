"""Behaviour tests for the five live integrations.

The public integration functions are exercised with deterministic upstream responses so
these tests prove normalization and failure semantics without depending on the internet.
"""

import urllib.error
from unittest.mock import Mock

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import integrations
from integrations import IntegrationError
from server import _integration

def test_urlhaus_response_is_normalized_to_bounded_indicator_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """The URLhaus adapter returns only the bounded evidence fields used by the agent."""
    monkeypatch.setattr(
        integrations,
        "_request_json",
        lambda *args, **kwargs: {
            "query_status": "ok",
            "urls": [{"url": f"https://bad.example/{index}"} for index in range(20)],
            "blacklists": [{"name": "ExampleBL", "detected": True}],
        },
    )

    result = integrations.query_urlhaus_host("198.51.100.77")

    assert result["query_status"] == "ok"
    assert result["url_count"] == 20
    assert len(result["urls"]) == 10
    assert result["blacklists"] == [{"name": "ExampleBL", "detected": True}]
    assert result["source"] == "URLhaus (abuse.ch)"
    assert result["observed_at"].endswith("Z")


def test_nvd_lookup_returns_found_false_for_a_valid_unknown_cve(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CVE-shaped identifier with no NVD record is an explicit not-found result."""
    monkeypatch.setattr(integrations, "_request_json", lambda *args, **kwargs: {"vulnerabilities": []})

    result = integrations.lookup_cve("cve-2099-99999")

    assert result["cve_id"] == "CVE-2099-99999"
    assert result["found"] is False
    assert result["source"] == "NIST NVD"
    assert result["observed_at"].endswith("Z")


def test_github_advisories_are_normalized_and_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    """GitHub advisory results preserve triage fields and respect the requested result cap."""
    monkeypatch.setattr(
        integrations,
        "_request_json",
        lambda *args, **kwargs: [
            {
                "ghsa_id": "GHSA-0000-0000-0000",
                "cve_id": "CVE-2024-0001",
                "summary": "Example issue",
                "severity": "high",
                "published_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-02T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-0000-0000-0000",
            },
            {"ghsa_id": "GHSA-ignored"},
        ],
    )

    result = integrations.search_github_advisories("PIP", severity="HIGH", keyword="example", limit=1)

    assert result["ecosystem"] == "pip"
    assert result["keyword"] == "example"
    assert result["advisories"] == [
        {
            "ghsa_id": "GHSA-0000-0000-0000",
            "cve_id": "CVE-2024-0001",
            "summary": "Example issue",
            "severity": "high",
            "published_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z",
            "html_url": "https://github.com/advisories/GHSA-0000-0000-0000",
        }
    ]


def test_upstream_http_failures_become_integration_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """An upstream HTTP failure is explicit and cannot become a false safe verdict."""
    monkeypatch.setattr(
        integrations.urllib.request,
        "urlopen",
        Mock(side_effect=urllib.error.URLError("certificate verify failed")),
    )

    with pytest.raises(IntegrationError) as error:
        integrations.lookup_cve("CVE-2024-0001")
    assert str(error.value).startswith("Integration is unavailable")


def test_mcp_integration_errors_are_translated_to_tool_errors() -> None:
    """The MCP boundary exposes integration outages as tool errors for the model."""

    def unavailable() -> None:
        raise IntegrationError("provider unavailable")

    with pytest.raises(ToolError) as error:
        _integration(unavailable)
    assert str(error.value) == "provider unavailable"


def test_advisory_limit_boundary_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The maximum supported advisory page remains bounded at the public API boundary."""
    monkeypatch.setattr(integrations, "_request_json", lambda *args, **kwargs: [])

    result = integrations.search_github_advisories("npm", limit=20)

    assert result["advisories"] == []
