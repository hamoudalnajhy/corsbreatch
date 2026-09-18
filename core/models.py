"""
core.models
===========

Data structures shared across CORSBreach.

Everything here is a plain dataclass with no external dependencies. Keeping
the models separate from the scanning/analysis logic makes it easy to test
each piece independently and to serialize results to JSON.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class Severity:
    """
    Ordered severity levels used for every Finding.

    Severity is never assigned purely because a header exists - it always
    reflects a specific, documented combination of observed behavior. See
    core/analyzer.py for the exact rules that assign each level.
    """
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    _ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}

    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value in cls._ORDER

    @classmethod
    def rank(cls, value: str) -> int:
        return cls._ORDER.get(value, -1)


@dataclass
class Finding:
    """A single, evidence-backed CORS finding."""
    id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    test_name: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestOutcome:
    """Records that a test ran (or did not run) and what happened."""
    name: str
    status: str  # "ok", "skipped", "error"
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """The complete outcome of scanning a single target URL."""
    target: str
    scanner_version: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_status: str = "unknown"          # "reachable" | "unreachable"
    http_status: Optional[int] = None
    tests_performed: List[TestOutcome] = field(default_factory=list)
    observations: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def add_test(self, name: str, status: str, detail: str = "") -> None:
        self.tests_performed.append(TestOutcome(name=name, status=status, detail=detail))

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> Dict[str, Any]:
        by_severity = {s: 0 for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "tests_performed": len(self.tests_performed),
            "findings": len(self.findings),
            "by_severity": by_severity,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scanner_version": self.scanner_version,
            "timestamp": self.timestamp,
            "target_status": self.target_status,
            "http_status": self.http_status,
            "tests_performed": [t.to_dict() for t in self.tests_performed],
            "observations": self.observations,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
            "error": self.error,
        }
