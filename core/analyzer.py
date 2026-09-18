"""
core.analyzer
=============

Turns raw HTTP observations into structured, evidence-backed Findings.

DESIGN PRINCIPLE
-----------------
This module never assigns a severity just because a header exists. Every
Finding is produced by a documented rule that combines *multiple* observed
signals (which origin was sent, what came back, whether credentials are
allowed, whether the behavior repeats across origins). Ambiguous or benign
configurations produce no finding, or an INFO/LOW finding, not a HIGH one.

SEVERITY RULES (also summarized in README.md, section 13)
-----------------------------------------------------------
- F002 Wildcard Origin (ACAO: *)
    INFO by default. A wildcard with no credentials is often intentional for
    a public API. Escalated to MEDIUM only if paired with an unusual
    combination (see F005).

- F001 Reflected Arbitrary Origin
    The server echoes back whatever Origin the client sends, instead of
    checking it against an allowlist. MEDIUM on its own (an untrusted origin
    can read non-credentialed responses). Escalated to HIGH when credentials
    are also allowed (F003) or when reflection is confirmed for a second,
    unrelated origin (F008), because both increase real attacker capability.

- F003 Reflected Origin + Credentials Enabled
    HIGH. This is the classic dangerous CORS misconfiguration: any website
    can make the victim's browser send an authenticated, cookie-bearing
    request and read the response, because the server both trusts an
    attacker-chosen origin and allows credentials.

- F004 Null Origin Allowed
    The server accepts "Origin: null" (produced by sandboxed iframes, some
    redirects, and local files). MEDIUM if paired with credentials, else LOW,
    because "null" is comparatively easy for an attacker to produce.

- F005 Wildcard Combined With Credentials Flag
    MEDIUM. Per the Fetch/CORS specification, browsers must ignore
    "Access-Control-Allow-Credentials: true" when ACAO is "*", so this exact
    pairing cannot be exploited directly via a compliant browser. It is
    still flagged because it signals a careless/copy-pasted CORS policy that
    may behave dangerously if the origin logic changes later.

- F006 Overly Permissive Preflight Methods
    LOW/INFO observation only. State-changing methods (PUT/PATCH/DELETE)
    appearing in Access-Control-Allow-Methods for an untrusted origin are
    reported as evidence, not automatically as a vulnerability - real impact
    depends on what the endpoint does, which this scanner does not test.

- F007 Sensitive Request Header Allowed
    LOW/INFO observation only, for the same reason as F006. Authorization/
    Cookie-like headers being explicitly allowed is worth a human look, not
    an automatic "vulnerable" verdict.

- F008 Arbitrary Origin Reflection Confirmed (multiple origins)
    Fires only when TWO unrelated, attacker-chosen origins are BOTH
    reflected back verbatim. This is the strongest evidence that the server
    performs no real allowlist check at all, so the existing F001 finding
    for this target is escalated to HIGH (and this note is added) even
    without confirmed credential support.
"""

from typing import Dict, List, Optional

from core.models import Finding, Severity

# Methods that go beyond simple read access and are worth calling out
# when explicitly allowed for an untrusted, reflected origin.
SENSITIVE_METHODS = {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}

# Request headers that typically carry credentials or sensitive tokens.
SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token"}


# --------------------------------------------------------------------------
# Small, independently-testable parsing/detection helpers
# --------------------------------------------------------------------------

def parse_list_header(value: Optional[str]) -> List[str]:
    """Split a comma-separated header value into trimmed, non-empty tokens."""
    if not value:
        return []
    return [tok.strip() for tok in value.split(",") if tok.strip()]


def is_wildcard(acao: Optional[str]) -> bool:
    """True only if Access-Control-Allow-Origin is the literal '*'."""
    return acao is not None and acao.strip() == "*"


def is_reflected(acao: Optional[str], origin_sent: str) -> bool:
    """
    True if the server echoed the exact Origin value we sent back in ACAO.

    A wildcard is not reflection (handled separately), and an empty/missing
    ACAO is not reflection.
    """
    if acao is None or is_wildcard(acao):
        return False
    return acao.strip() == origin_sent.strip()


def credentials_enabled(acac: Optional[str]) -> bool:
    """True if Access-Control-Allow-Credentials is exactly 'true' (case-insensitive)."""
    return acac is not None and acac.strip().lower() == "true"


def is_null_origin_allowed(acao: Optional[str]) -> bool:
    """True if the server responded to 'Origin: null' with 'ACAO: null'."""
    return acao is not None and acao.strip().lower() == "null"


# --------------------------------------------------------------------------
# Finding builders (one function per finding type keeps each rule isolated
# and easy to unit test)
# --------------------------------------------------------------------------

def _f001_reflected_origin(origin: str, acao: str) -> Finding:
    return Finding(
        id="F001",
        title="Reflected Origin",
        severity=Severity.MEDIUM,
        description=(
            f"The server reflected the untrusted supplied Origin value "
            f"('{origin}') directly back in Access-Control-Allow-Origin, "
            f"instead of validating it against a fixed allowlist."
        ),
        evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
        recommendation=(
            "Validate the Origin header against an explicit server-side "
            "allowlist of trusted origins instead of reflecting it back "
            "unchanged."
        ),
        test_name="reflected_origin",
    )


def _f002_wildcard(acao: str) -> Finding:
    return Finding(
        id="F002",
        title="Wildcard Origin",
        severity=Severity.INFO,
        description=(
            "The server returns 'Access-Control-Allow-Origin: *', permitting "
            "any origin to read non-credentialed responses. This is only a "
            "concern if the endpoint returns sensitive data without "
            "requiring authentication, or if credentials are also enabled."
        ),
        evidence=f"Access-Control-Allow-Origin: {acao}",
        recommendation=(
            "Confirm this endpoint truly serves only public data. If it "
            "returns any sensitive or user-specific information, replace "
            "the wildcard with an explicit origin allowlist."
        ),
        test_name="wildcard_origin",
    )


def _f003_reflected_with_credentials(origin: str, acao: str) -> Finding:
    return Finding(
        id="F003",
        title="Reflected Origin with Credentials Enabled",
        severity=Severity.HIGH,
        description=(
            "The server both reflects an untrusted, attacker-chosen Origin "
            "and sets Access-Control-Allow-Credentials: true. A malicious "
            "website hosted at that origin can trigger the victim's browser "
            "to send an authenticated (cookie-bearing) request and read the "
            "response, effectively bypassing the Same-Origin Policy for "
            "logged-in users."
        ),
        evidence=(
            f"Origin: {origin}\n"
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: true"
        ),
        recommendation=(
            "Never combine a reflected/attacker-controlled origin with "
            "Access-Control-Allow-Credentials: true. Use a strict, "
            "server-side allowlist of trusted origins whenever credentials "
            "are enabled."
        ),
        test_name="credentials_analysis",
    )


def _f004_null_origin(acac_true: bool) -> Finding:
    severity = Severity.MEDIUM if acac_true else Severity.LOW
    cred_note = (
        " This is combined with Access-Control-Allow-Credentials: true, "
        "which is especially significant because 'null' origins are "
        "trivial for an attacker to produce (e.g. a sandboxed iframe or a "
        "local HTML file)."
        if acac_true else
        " Credentials were not observed to be enabled alongside it in this "
        "test, which reduces (but does not eliminate) practical impact."
    )
    return Finding(
        id="F004",
        title="Null Origin Allowed",
        severity=severity,
        description=(
            "The server responded to 'Origin: null' with "
            "'Access-Control-Allow-Origin: null'." + cred_note
        ),
        evidence=(
            "Origin: null\n"
            "Access-Control-Allow-Origin: null" +
            ("\nAccess-Control-Allow-Credentials: true" if acac_true else "")
        ),
        recommendation=(
            "Do not treat 'null' as a trusted origin. Reject requests with "
            "Origin: null unless there is a specific, documented reason to "
            "trust sandboxed contexts."
        ),
        test_name="null_origin",
    )


def _f005_wildcard_with_credentials_flag(acao: str, acac: str) -> Finding:
    return Finding(
        id="F005",
        title="Wildcard Combined With Credentials Flag",
        severity=Severity.MEDIUM,
        description=(
            "The server sets both 'Access-Control-Allow-Origin: *' and "
            "'Access-Control-Allow-Credentials: true' in the same response. "
            "Compliant browsers ignore the credentials flag when ACAO is a "
            "wildcard, so this specific pairing is not directly exploitable "
            "through a standard browser - but it indicates a careless or "
            "copy-pasted CORS policy that may become exploitable if the "
            "origin logic changes."
        ),
        evidence=(
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac}"
        ),
        recommendation=(
            "Remove the wildcard if credentials are genuinely required, and "
            "replace it with an explicit trusted-origin allowlist."
        ),
        test_name="credentials_analysis",
    )


def _f006_permissive_methods(methods: List[str]) -> Finding:
    sensitive = sorted(m for m in methods if m.upper() in SENSITIVE_METHODS)
    return Finding(
        id="F006",
        title="State-Changing Methods Allowed in Preflight",
        severity=Severity.LOW,
        description=(
            "The preflight response's Access-Control-Allow-Methods lists "
            f"state-changing method(s): {', '.join(sensitive)}. This is "
            "reported as an observation, not a confirmed vulnerability - "
            "actual impact depends on what those methods do on this "
            "endpoint and on the origin-validation findings above."
        ),
        evidence=f"Access-Control-Allow-Methods: {', '.join(methods)}",
        recommendation=(
            "Confirm state-changing methods are only reachable from trusted "
            "origins, and require additional protections (e.g. CSRF tokens) "
            "regardless of CORS policy."
        ),
        test_name="methods_analysis",
    )


def _f007_sensitive_headers(headers: List[str]) -> Finding:
    sensitive = sorted(h for h in headers if h.lower() in SENSITIVE_HEADERS)
    return Finding(
        id="F007",
        title="Sensitive Request Header Explicitly Allowed",
        severity=Severity.LOW,
        description=(
            "The preflight response's Access-Control-Allow-Headers "
            f"explicitly allows: {', '.join(sensitive)}. Reported as "
            "observed evidence only; whether this is exploitable depends on "
            "the origin-validation and credentials findings above."
        ),
        evidence=f"Access-Control-Allow-Headers: {', '.join(headers)}",
        recommendation=(
            "Only allow request headers the endpoint actually needs, and "
            "keep this list in sync with the trusted-origin allowlist."
        ),
        test_name="headers_analysis",
    )


def _f008_confirmed_arbitrary_reflection(origin1: str, origin2: str) -> Finding:
    return Finding(
        id="F008",
        title="Arbitrary Origin Reflection Confirmed",
        severity=Severity.HIGH,
        description=(
            f"Two unrelated, attacker-chosen origins ('{origin1}' and "
            f"'{origin2}') were both reflected back verbatim in "
            "Access-Control-Allow-Origin. This confirms the server performs "
            "no real origin allowlist check at all, rather than coincidentally "
            "matching one specific value."
        ),
        evidence=(
            f"Origin: {origin1} -> Access-Control-Allow-Origin: {origin1}\n"
            f"Origin: {origin2} -> Access-Control-Allow-Origin: {origin2}"
        ),
        recommendation=(
            "Replace origin reflection with a strict, explicit allowlist of "
            "trusted origins checked server-side."
        ),
        test_name="second_origin_comparison",
    )


# --------------------------------------------------------------------------
# Top-level entry point used by core/scanner.py
# --------------------------------------------------------------------------

def analyze(observations: Dict) -> List[Finding]:
    """
    Consume the observations dict produced by core/scanner.py and return the
    list of Findings supported by that evidence. Pure function - no network
    or I/O - which makes it fully unit-testable with hand-built input.
    """
    findings: List[Finding] = []

    origin1 = observations.get("origin1_value")
    origin2 = observations.get("origin2_value")
    reflected = observations.get("reflected")  # dict: acao, acac for origin1 response
    second = observations.get("second_origin")  # dict: acao, acac for origin2 response
    null_origin = observations.get("null_origin")  # dict: acao, acac
    preflight = observations.get("preflight")  # dict: acao, acac, acam, acah

    reflects1 = False
    reflects2 = False

    # --- Reflection / wildcard on the first untrusted origin ---
    if reflected:
        acao = reflected.get("acao")
        acac = reflected.get("acac")
        if is_wildcard(acao):
            findings.append(_f002_wildcard(acao))
            if credentials_enabled(acac):
                findings.append(_f005_wildcard_with_credentials_flag(acao, acac))
        elif is_reflected(acao, origin1):
            reflects1 = True
            findings.append(_f001_reflected_origin(origin1, acao))
            if credentials_enabled(acac):
                findings.append(_f003_reflected_with_credentials(origin1, acao))

    # --- Second, unrelated untrusted origin ---
    if second:
        acao2 = second.get("acao")
        if is_reflected(acao2, origin2):
            reflects2 = True

    if reflects1 and reflects2:
        findings.append(_f008_confirmed_arbitrary_reflection(origin1, origin2))
        # Escalate the original F001 (if present) to HIGH, since arbitrary
        # reflection is now confirmed rather than a single coincidental match.
        for f in findings:
            if f.id == "F001":
                f.severity = Severity.HIGH

    # --- Null origin ---
    if null_origin:
        acao_null = null_origin.get("acao")
        acac_null = null_origin.get("acac")
        if is_null_origin_allowed(acao_null):
            findings.append(_f004_null_origin(credentials_enabled(acac_null)))

    # --- Preflight: methods and headers (observations, not verdicts) ---
    if preflight:
        methods = parse_list_header(preflight.get("acam"))
        headers = parse_list_header(preflight.get("acah"))
        if any(m.upper() in SENSITIVE_METHODS for m in methods):
            findings.append(_f006_permissive_methods(methods))
        if any(h.lower() in SENSITIVE_HEADERS for h in headers):
            findings.append(_f007_sensitive_headers(headers))

    return findings
