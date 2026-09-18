"""
tests.test_analyzer
====================

Pure unit tests for core/analyzer.py. No network access - every case is
built from hand-crafted "observations" dictionaries, the same shape that
core/scanner.py produces from real HTTP responses.
"""

import unittest

from core import analyzer
from core.models import Severity


class TestHeaderParsing(unittest.TestCase):

    def test_parse_list_header_splits_and_trims(self):
        self.assertEqual(
            analyzer.parse_list_header("GET, POST,  PUT ,DELETE"),
            ["GET", "POST", "PUT", "DELETE"],
        )

    def test_parse_list_header_handles_empty(self):
        self.assertEqual(analyzer.parse_list_header(None), [])
        self.assertEqual(analyzer.parse_list_header(""), [])
        self.assertEqual(analyzer.parse_list_header("   "), [])


class TestDetectionHelpers(unittest.TestCase):

    def test_is_wildcard(self):
        self.assertTrue(analyzer.is_wildcard("*"))
        self.assertTrue(analyzer.is_wildcard(" * "))
        self.assertFalse(analyzer.is_wildcard("https://example.com"))
        self.assertFalse(analyzer.is_wildcard(None))

    def test_is_reflected(self):
        self.assertTrue(analyzer.is_reflected("https://evil.example", "https://evil.example"))
        self.assertFalse(analyzer.is_reflected("https://trusted.example", "https://evil.example"))
        self.assertFalse(analyzer.is_reflected("*", "https://evil.example"))
        self.assertFalse(analyzer.is_reflected(None, "https://evil.example"))

    def test_credentials_enabled_is_case_insensitive(self):
        self.assertTrue(analyzer.credentials_enabled("true"))
        self.assertTrue(analyzer.credentials_enabled("True"))
        self.assertTrue(analyzer.credentials_enabled(" TRUE "))
        self.assertFalse(analyzer.credentials_enabled("false"))
        self.assertFalse(analyzer.credentials_enabled(None))

    def test_is_null_origin_allowed(self):
        self.assertTrue(analyzer.is_null_origin_allowed("null"))
        self.assertTrue(analyzer.is_null_origin_allowed("NULL"))
        self.assertFalse(analyzer.is_null_origin_allowed("https://example.com"))
        self.assertFalse(analyzer.is_null_origin_allowed(None))


class TestAnalyzeSecureConfigurations(unittest.TestCase):
    """A well-configured server should produce NO findings."""

    def test_explicit_allowlist_no_findings(self):
        observations = {
            "origin1_value": "https://evil.example",
            "origin2_value": "https://attacker.example",
            "reflected": {"acao": None, "acac": None},
            "second_origin": {"acao": None, "acac": None},
            "null_origin": {"acao": None, "acac": None},
            "preflight": {"acao": None, "acac": None, "acam": "GET", "acah": "Content-Type"},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(findings, [])

    def test_no_cors_headers_at_all_no_findings(self):
        findings = analyzer.analyze({})
        self.assertEqual(findings, [])


class TestWildcard(unittest.TestCase):

    def test_wildcard_alone_is_info(self):
        observations = {
            "origin1_value": "https://evil.example",
            "reflected": {"acao": "*", "acac": None},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "F002")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_wildcard_with_credentials_flag_adds_f005(self):
        observations = {
            "origin1_value": "https://evil.example",
            "reflected": {"acao": "*", "acac": "true"},
        }
        findings = analyzer.analyze(observations)
        ids = {f.id for f in findings}
        self.assertIn("F002", ids)
        self.assertIn("F005", ids)
        f005 = next(f for f in findings if f.id == "F005")
        self.assertEqual(f005.severity, Severity.MEDIUM)


class TestReflection(unittest.TestCase):

    def test_reflected_origin_alone_is_medium(self):
        observations = {
            "origin1_value": "https://evil.example",
            "origin2_value": "https://attacker.example",
            "reflected": {"acao": "https://evil.example", "acac": None},
            "second_origin": {"acao": None, "acac": None},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "F001")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_reflected_origin_with_credentials_is_high(self):
        observations = {
            "origin1_value": "https://evil.example",
            "origin2_value": "https://attacker.example",
            "reflected": {"acao": "https://evil.example", "acac": "true"},
            "second_origin": {"acao": None, "acac": None},
        }
        findings = analyzer.analyze(observations)
        ids = {f.id for f in findings}
        self.assertIn("F001", ids)
        self.assertIn("F003", ids)
        f003 = next(f for f in findings if f.id == "F003")
        self.assertEqual(f003.severity, Severity.HIGH)

    def test_confirmed_arbitrary_reflection_escalates_f001_to_high(self):
        observations = {
            "origin1_value": "https://evil.example",
            "origin2_value": "https://attacker.example",
            "reflected": {"acao": "https://evil.example", "acac": None},
            "second_origin": {"acao": "https://attacker.example", "acac": None},
        }
        findings = analyzer.analyze(observations)
        ids = {f.id for f in findings}
        self.assertIn("F001", ids)
        self.assertIn("F008", ids)
        f001 = next(f for f in findings if f.id == "F001")
        self.assertEqual(f001.severity, Severity.HIGH)

    def test_single_matching_origin_is_not_confused_with_reflection(self):
        """A fixed, trusted-origin allowlist must not trigger F001/F008."""
        observations = {
            "origin1_value": "https://evil.example",
            "origin2_value": "https://attacker.example",
            "reflected": {"acao": "https://trusted.example", "acac": None},
            "second_origin": {"acao": "https://trusted.example", "acac": None},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(findings, [])


class TestNullOrigin(unittest.TestCase):

    def test_null_origin_without_credentials_is_low(self):
        observations = {"null_origin": {"acao": "null", "acac": None}}
        findings = analyzer.analyze(observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "F004")
        self.assertEqual(findings[0].severity, Severity.LOW)

    def test_null_origin_with_credentials_is_medium(self):
        observations = {"null_origin": {"acao": "null", "acac": "true"}}
        findings = analyzer.analyze(observations)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_null_origin_not_reflected_is_no_finding(self):
        observations = {"null_origin": {"acao": None, "acac": None}}
        findings = analyzer.analyze(observations)
        self.assertEqual(findings, [])


class TestPreflightMethodsAndHeaders(unittest.TestCase):

    def test_sensitive_methods_flagged(self):
        observations = {
            "preflight": {"acam": "GET, POST, PUT, DELETE", "acah": "Content-Type"},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "F006")
        self.assertIn("PUT", findings[0].evidence)
        self.assertIn("DELETE", findings[0].evidence)

    def test_only_safe_methods_no_finding(self):
        observations = {"preflight": {"acam": "GET, HEAD, OPTIONS", "acah": "Content-Type"}}
        findings = analyzer.analyze(observations)
        self.assertEqual(findings, [])

    def test_sensitive_headers_flagged(self):
        observations = {
            "preflight": {"acam": "GET", "acah": "Content-Type, Authorization"},
        }
        findings = analyzer.analyze(observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "F007")
        self.assertIn("Authorization", findings[0].evidence)


if __name__ == "__main__":
    unittest.main()
