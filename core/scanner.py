"""
core.scanner
============

Orchestrates the CORS tests against a single target and produces a
ScanResult. This module only sends safe, read-only requests (GET and
OPTIONS) - it never performs a state-changing request against the target.

REQUEST BUDGET
---------------
The project brief describes nine conceptual tests. Several of them analyze
different aspects of the *same* HTTP response rather than requiring a new
request (for example, reflection and wildcard detection both just look at
the Access-Control-Allow-Origin header returned for the same Origin value).
CORSBreach makes exactly five real requests per target:

    1. GET  (no Origin)                         -> baseline
    2. GET  Origin: <origin1>                    -> reflection + wildcard + credentials
    3. GET  Origin: null                         -> null origin behavior
    4. GET  Origin: <origin2>                     -> second-origin comparison
    5. OPTIONS with Origin/ACRM/ACRH             -> preflight + methods + headers

This keeps the tool polite to the target (relevant for shared lab
infrastructure) while still covering every test described in the brief.
"""

import logging
from typing import Optional

from core import analyzer
from core.http_client import HttpClient, HttpClientError
from core.models import ScanResult

logger = logging.getLogger("corsbreach.scanner")

SCANNER_VERSION = "1.0.0"

DEFAULT_ORIGIN_1 = "https://evil.example"
DEFAULT_ORIGIN_2 = "https://attacker.example"
NULL_ORIGIN = "null"

# A distinctive header/method used only to observe preflight behavior -
# never sent as an actual state-changing request.
PREFLIGHT_REQUEST_METHOD = "PUT"
PREFLIGHT_REQUEST_HEADERS = "X-Test-Header, Authorization"


class Scanner:
    """Runs the full CORSBreach test sequence against one target URL."""

    def __init__(self, client: HttpClient, test_origins: Optional[list] = None):
        self.client = client
        origins = [o for o in (test_origins or []) if o and o.lower() != "null"]
        self.origin1 = origins[0] if len(origins) >= 1 else DEFAULT_ORIGIN_1
        self.origin2 = origins[1] if len(origins) >= 2 else DEFAULT_ORIGIN_2

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scanner_version=SCANNER_VERSION)

        # --- TEST 1: baseline (no Origin header) ---------------------------
        try:
            baseline = self.client.get(target)
        except HttpClientError as exc:
            result.target_status = "unreachable"
            result.error = str(exc)
            result.add_test("baseline", "error", str(exc))
            logger.warning("Baseline request failed for %s: %s", target, exc)
            return result

        result.target_status = "reachable"
        result.http_status = baseline.status
        result.add_test("baseline", "ok", f"HTTP {baseline.status}")
        result.observations["baseline"] = {
            "status": baseline.status,
            "acao": baseline.get_header("Access-Control-Allow-Origin"),
            "acac": baseline.get_header("Access-Control-Allow-Credentials"),
        }

        # --- TEST 2 & 3 & 4: reflection / wildcard / credentials (origin1) --
        result.observations["origin1_value"] = self.origin1
        try:
            resp1 = self.client.get(target, headers={"Origin": self.origin1})
            result.add_test("reflected_origin", "ok", f"HTTP {resp1.status}")
            result.add_test("wildcard_origin", "ok", "derived from same response")
            result.add_test("credentials_analysis", "ok", "derived from same response")
            result.observations["reflected"] = {
                "status": resp1.status,
                "acao": resp1.get_header("Access-Control-Allow-Origin"),
                "acac": resp1.get_header("Access-Control-Allow-Credentials"),
            }
        except HttpClientError as exc:
            result.add_test("reflected_origin", "error", str(exc))
            logger.warning("Origin1 request failed for %s: %s", target, exc)

        # --- TEST 5: null origin --------------------------------------------
        try:
            resp_null = self.client.get(target, headers={"Origin": NULL_ORIGIN})
            result.add_test("null_origin", "ok", f"HTTP {resp_null.status}")
            result.observations["null_origin"] = {
                "status": resp_null.status,
                "acao": resp_null.get_header("Access-Control-Allow-Origin"),
                "acac": resp_null.get_header("Access-Control-Allow-Credentials"),
            }
        except HttpClientError as exc:
            result.add_test("null_origin", "error", str(exc))
            logger.warning("Null-origin request failed for %s: %s", target, exc)

        # --- TEST 6: second untrusted origin ---------------------------------
        result.observations["origin2_value"] = self.origin2
        try:
            resp2 = self.client.get(target, headers={"Origin": self.origin2})
            result.add_test("second_origin_comparison", "ok", f"HTTP {resp2.status}")
            result.observations["second_origin"] = {
                "status": resp2.status,
                "acao": resp2.get_header("Access-Control-Allow-Origin"),
                "acac": resp2.get_header("Access-Control-Allow-Credentials"),
            }
        except HttpClientError as exc:
            result.add_test("second_origin_comparison", "error", str(exc))
            logger.warning("Origin2 request failed for %s: %s", target, exc)

        # --- TEST 7 & 8 & 9: preflight / methods / headers -------------------
        try:
            preflight_resp = self.client.options(target, headers={
                "Origin": self.origin1,
                "Access-Control-Request-Method": PREFLIGHT_REQUEST_METHOD,
                "Access-Control-Request-Headers": PREFLIGHT_REQUEST_HEADERS,
            })
            result.add_test("preflight", "ok", f"HTTP {preflight_resp.status}")
            result.add_test("methods_analysis", "ok", "derived from preflight response")
            result.add_test("headers_analysis", "ok", "derived from preflight response")
            result.observations["preflight"] = {
                "status": preflight_resp.status,
                "acao": preflight_resp.get_header("Access-Control-Allow-Origin"),
                "acac": preflight_resp.get_header("Access-Control-Allow-Credentials"),
                "acam": preflight_resp.get_header("Access-Control-Allow-Methods"),
                "acah": preflight_resp.get_header("Access-Control-Allow-Headers"),
            }
        except HttpClientError as exc:
            result.add_test("preflight", "error", str(exc))
            logger.warning("Preflight request failed for %s: %s", target, exc)

        # --- Analysis ---------------------------------------------------------
        findings = analyzer.analyze(result.observations)
        for finding in findings:
            result.add_finding(finding)

        return result
