"""
tests.test_http_client
=======================

Tests core/http_client.py against the local lab server (lab/local_cors_lab.py)
so no external network access is required to run the test suite.
"""

import threading
import unittest

from core.http_client import (
    HttpClient,
    InvalidURLError,
    UnsupportedSchemeError,
    ConnectionFailedError,
    DNSError,
)
from lab.local_cors_lab import run as run_lab


class TestUrlValidation(unittest.TestCase):

    def test_valid_https_url_passes(self):
        HttpClient.validate_url("https://example.web-security-academy.net")  # should not raise

    def test_missing_scheme_raises(self):
        with self.assertRaises(InvalidURLError):
            HttpClient.validate_url("example.com")

    def test_missing_host_raises(self):
        with self.assertRaises(InvalidURLError):
            HttpClient.validate_url("https://")

    def test_unsupported_scheme_raises(self):
        with self.assertRaises(UnsupportedSchemeError):
            HttpClient.validate_url("ftp://example.com")

    def test_empty_string_raises(self):
        with self.assertRaises(InvalidURLError):
            HttpClient.validate_url("")

    def test_non_string_raises(self):
        with self.assertRaises(InvalidURLError):
            HttpClient.validate_url(None)  # type: ignore[arg-type]


class TestHttpClientAgainstLocalLab(unittest.TestCase):
    """Uses a real (local) HTTP server so response parsing is exercised end to end."""

    @classmethod
    def setUpClass(cls):
        cls.server = run_lab(host="127.0.0.1", port=0)  # port=0 -> OS picks a free port
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.client = HttpClient(timeout=5)

    def test_get_plain_endpoint(self):
        resp = self.client.get(f"{self.base_url}/plain")
        self.assertEqual(resp.status, 200)
        self.assertIsNone(resp.get_header("Access-Control-Allow-Origin"))

    def test_get_with_origin_header_reflected(self):
        resp = self.client.get(f"{self.base_url}/reflect", headers={"Origin": "https://evil.example"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.get_header("Access-Control-Allow-Origin"), "https://evil.example")

    def test_header_lookup_is_case_insensitive(self):
        resp = self.client.get(f"{self.base_url}/reflect", headers={"Origin": "https://evil.example"})
        self.assertEqual(
            resp.get_header("access-control-allow-origin"),
            resp.get_header("Access-Control-Allow-Origin"),
        )

    def test_options_preflight_request(self):
        resp = self.client.options(
            f"{self.base_url}/preflight",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Test-Header",
            },
        )
        self.assertEqual(resp.status, 204)
        self.assertIn("PUT", resp.get_header("Access-Control-Allow-Methods"))

    def test_404_response_still_returns_headers(self):
        resp = self.client.get(f"{self.base_url}/does-not-exist")
        self.assertEqual(resp.status, 404)

    def test_connection_refused_raises_connection_failed(self):
        # Nothing should be listening on this port.
        bad_client = HttpClient(timeout=2)
        with self.assertRaises(ConnectionFailedError):
            bad_client.get("http://127.0.0.1:1")

    def test_dns_failure_raises_dns_error(self):
        bad_client = HttpClient(timeout=2)
        with self.assertRaises(DNSError):
            bad_client.get("https://this-domain-should-not-exist.invalid/")


if __name__ == "__main__":
    unittest.main()
