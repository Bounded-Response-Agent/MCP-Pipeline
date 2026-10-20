"""Tests for live integration normalization and input safety.

Network calls are mocked here; the protocol verifier exercises the real services.
"""

import json
import socket
import unittest
from unittest.mock import Mock, patch

from integrations import (
    IntegrationError,
    inspect_tls_certificate,
    lookup_cve,
    resolve_dns,
    search_github_advisories,
)


class IntegrationTests(unittest.TestCase):
    def test_resolve_dns_normalizes_duplicate_addresses(self):
        with patch(
            "integrations.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
            ],
        ):
            result = resolve_dns("indicator.example")
        self.assertEqual(result["addresses"], ["192.0.2.10", "2001:db8::10"])
        self.assertEqual(result["source"], "system DNS")

    def test_lookup_cve_returns_normalized_nvd_fields(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"value": "Example vulnerability"}],
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}],
                    }
                }
            ]
        }
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(payload).encode()
        with patch("integrations.urllib.request.urlopen", return_value=response):
            result = lookup_cve("cve-2024-0001")
        self.assertTrue(result["found"])
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["cvss_base_score"], 9.8)

    def test_advisory_search_rejects_unknown_ecosystem(self):
        with self.assertRaises(IntegrationError):
            search_github_advisories("unknown")

    def test_tls_inspection_rejects_invalid_port_before_connecting(self):
        with patch("integrations.socket.create_connection") as create_connection:
            with self.assertRaises(IntegrationError):
                inspect_tls_certificate("example.com", 70000)
        create_connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
