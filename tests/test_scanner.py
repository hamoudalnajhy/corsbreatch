"""
tests.test_scanner
===================

End-to-end tests of core/scanner.py (HTTP client + analyzer working
together) against the local lab, plus tests for the CLI's configuration
validation and error handling in corsbreach.py. No external network access
is required.
"""

import json
import os
import tempfile
import threading
import unittest

import corsbreach
from core.http_client import HttpClient
from core.models import Severity
from core.scanner import Scanner
from lab.local_cors_lab import run as run_lab


class TestScannerAgainstLocalLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = run_lab(host="127.0.0.1", port=0)
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
        self.scanner = Scanner(HttpClient(timeout=5))

    def test_secure_endpoint_has_no_findings(self):
        result = self.scanner.scan(f"{self.base_url}/secure")
        self.assertEqual(result.target_status, "reachable")
        self.assertEqual(result.findings, [])

    def test_plain_endpoint_has_no_findings(self):
        result = self.scanner.scan(f"{self.base_url}/plain")
        self.assertEqual(result.findings, [])

    def test_wildcard_endpoint_reports_f002_only(self):
        result = self.scanner.scan(f"{self.base_url}/wildcard")
        ids = {f.id for f in result.findings}
        self.assertEqual(ids, {"F002"})

    def test_reflect_endpoint_reports_reflection_and_confirmation(self):
        result = self.scanner.scan(f"{self.base_url}/reflect")
        ids = {f.id for f in result.findings}
        self.assertIn("F001", ids)
        self.assertIn("F008", ids)

    def test_reflect_credentials_endpoint_reports_high_severity(self):
        result = self.scanner.scan(f"{self.base_url}/reflect-credentials")
        ids = {f.id for f in result.findings}
        self.assertIn("F003", ids)
        severities = {f.severity for f in result.findings if f.id == "F003"}
        self.assertEqual(severities, {Severity.HIGH})

    def test_null_origin_endpoint_reports_f004(self):
        result = self.scanner.scan(f"{self.base_url}/null-origin")
        ids = {f.id for f in result.findings}
        self.assertIn("F004", ids)

    def test_preflight_endpoint_reports_methods_and_headers(self):
        result = self.scanner.scan(f"{self.base_url}/preflight")
        ids = {f.id for f in result.findings}
        self.assertIn("F006", ids)  # PUT/DELETE allowed
        self.assertIn("F007", ids)  # Authorization allowed

    def test_unreachable_target_sets_unreachable_status(self):
        result = self.scanner.scan("http://127.0.0.1:1/")
        self.assertEqual(result.target_status, "unreachable")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    def test_result_serializes_to_json(self):
        result = self.scanner.scan(f"{self.base_url}/reflect-credentials")
        # Must not raise - this is exactly what output/reporter.py relies on.
        json.dumps(result.to_dict())


class TestConfigValidation(unittest.TestCase):

    def test_missing_config_path_returns_defaults(self):
        config = corsbreach.load_config(None)
        self.assertEqual(config, corsbreach.DEFAULT_CONFIG)

    def test_nonexistent_config_file_raises(self):
        with self.assertRaises(corsbreach.ConfigError):
            corsbreach.load_config("/tmp/definitely-does-not-exist-corsbreach.json")

    def test_malformed_json_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{ not valid json")
            path = fh.name
        try:
            with self.assertRaises(corsbreach.ConfigError):
                corsbreach.load_config(path)
        finally:
            os.unlink(path)

    def test_invalid_values_fall_back_to_defaults_instead_of_crashing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({
                "timeout": "not-a-number",
                "test_origins": "not-a-list",
                "follow_redirects": "yes",
                "log_level": "NOT_A_LEVEL",
                "batch_delay_seconds": -5,
            }, fh)
            path = fh.name
        try:
            config = corsbreach.load_config(path)
            self.assertEqual(config["timeout"], corsbreach.DEFAULT_CONFIG["timeout"])
            self.assertEqual(config["test_origins"], corsbreach.DEFAULT_CONFIG["test_origins"])
            self.assertEqual(config["follow_redirects"], corsbreach.DEFAULT_CONFIG["follow_redirects"])
            self.assertEqual(config["log_level"], corsbreach.DEFAULT_CONFIG["log_level"])
            self.assertEqual(config["batch_delay_seconds"], corsbreach.DEFAULT_CONFIG["batch_delay_seconds"])
        finally:
            os.unlink(path)

    def test_valid_partial_config_merges_over_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"timeout": 30}, fh)
            path = fh.name
        try:
            config = corsbreach.load_config(path)
            self.assertEqual(config["timeout"], 30)
            self.assertEqual(config["user_agent"], corsbreach.DEFAULT_CONFIG["user_agent"])
        finally:
            os.unlink(path)


class TestBatchFileParsing(unittest.TestCase):

    def test_reads_targets_and_skips_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\n\nhttps://a.example\n   \nhttps://b.example\n")
            path = fh.name
        try:
            targets = corsbreach._read_targets(path)
            self.assertEqual(targets, ["https://a.example", "https://b.example"])
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(corsbreach.ConfigError):
            corsbreach._read_targets("/tmp/definitely-missing-targets.txt")


if __name__ == "__main__":
    unittest.main()
