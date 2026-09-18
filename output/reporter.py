"""
output.reporter
================

Renders a ScanResult as a plain-text terminal report or a JSON file.
No color libraries, no third-party templating - just str.format and json,
both from the standard library.
"""

import json
from typing import TextIO

from core.models import ScanResult

BAR = "=" * 50

# Symbols used in the plain-text test summary line. Kept ASCII-only so the
# report renders identically on Windows and Linux terminals.
STATUS_OK = "[+]"
STATUS_FLAG = "[!]"
STATUS_ERROR = "[x]"

TEST_DISPLAY_NAMES = {
    "baseline": "Baseline Request",
    "reflected_origin": "Reflected Origin",
    "wildcard_origin": "Wildcard",
    "credentials_analysis": "Credentials",
    "null_origin": "Null Origin",
    "second_origin_comparison": "Second Origin",
    "preflight": "Preflight",
    "methods_analysis": "Allowed Methods",
    "headers_analysis": "Allowed Headers",
}

# Test names whose corresponding finding IDs (if any) mark them "flagged"
# rather than plain "ok" in the summary section.
TEST_TO_FINDING_IDS = {
    "reflected_origin": {"F001"},
    "wildcard_origin": {"F002"},
    "credentials_analysis": {"F003", "F005"},
    "null_origin": {"F004"},
    "second_origin_comparison": {"F008"},
    "methods_analysis": {"F006"},
    "headers_analysis": {"F007"},
}


def _test_line(test_name: str, status: str, finding_ids_present: set) -> str:
    display = TEST_DISPLAY_NAMES.get(test_name, test_name)
    if status == "error":
        symbol = STATUS_ERROR
    elif TEST_TO_FINDING_IDS.get(test_name, set()) & finding_ids_present:
        symbol = STATUS_FLAG
    else:
        symbol = STATUS_OK
    return f"{symbol} {display}"


def render_terminal_report(result: ScanResult) -> str:
    """Build the full plain-text report as a single string."""
    lines = []
    lines.append(BAR)
    lines.append("CORSBreach v" + result.scanner_version)
    lines.append("CORS Misconfiguration Scanner")
    lines.append(BAR)
    lines.append("")
    lines.append("Target:")
    lines.append(result.target)
    lines.append("")
    lines.append("Target Status:")
    lines.append("Reachable" if result.target_status == "reachable" else "Unreachable")
    lines.append("")

    if result.error:
        lines.append("Error:")
        lines.append(result.error)
        lines.append("")
        lines.append(BAR)
        return "\n".join(lines)

    lines.append("HTTP Status:")
    lines.append(str(result.http_status))
    lines.append("")
    lines.append("-" * 50)
    lines.append("CORS TESTS")
    lines.append("-" * 50)
    lines.append("")

    finding_ids_present = {f.id for f in result.findings}
    for test in result.tests_performed:
        lines.append(_test_line(test.name, test.status, finding_ids_present))

    lines.append("")
    lines.append("-" * 50)
    lines.append("FINDINGS")
    lines.append("-" * 50)
    lines.append("")

    if not result.findings:
        lines.append("No findings - no evidence of CORS misconfiguration was observed.")
    else:
        for finding in result.findings:
            lines.append(f"[{finding.id}] {finding.title}")
            lines.append(f"Severity: {finding.severity}")
            lines.append("")
            lines.append("Evidence:")
            lines.append(finding.evidence)
            lines.append("")
            lines.append("Description:")
            lines.append(finding.description)
            lines.append("")
            lines.append("Recommendation:")
            lines.append(finding.recommendation)
            lines.append("")
            lines.append("-" * 50)

    summary = result.summary()
    lines.append("")
    lines.append("Summary:")
    lines.append(f"Tests Performed: {summary['tests_performed']}")
    lines.append(f"Findings: {summary['findings']}")
    by_sev = summary["by_severity"]
    lines.append(
        f"  HIGH: {by_sev['HIGH']}  MEDIUM: {by_sev['MEDIUM']}  "
        f"LOW: {by_sev['LOW']}  INFO: {by_sev['INFO']}"
    )
    lines.append("")
    lines.append(BAR)
    return "\n".join(lines)


def print_terminal_report(result: ScanResult, stream: TextIO = None) -> None:
    text = render_terminal_report(result)
    if stream is None:
        print(text)
    else:
        print(text, file=stream)


def write_json_report(results, path: str) -> None:
    """
    Write one or more ScanResults to a JSON file.

    `results` may be a single ScanResult (single `scan` command) or a list
    of ScanResults (batch mode). The on-disk shape always has a top-level
    "results" list so JSON consumers don't need to special-case single scans.
    """
    if isinstance(results, ScanResult):
        results = [results]
    payload = {
        "corsbreach_report_version": 1,
        "results": [r.to_dict() for r in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
