# CORSBreach

**A pure-Python CORS Misconfiguration Scanner** — a university cybersecurity
project for identifying and documenting Cross-Origin Resource Sharing (CORS)
misconfigurations on authorized targets.

---

## 1. Project Name

**CORSBreach** — CORS Misconfiguration Scanner.

## 2. Problem

Cross-Origin Resource Sharing (CORS) is one of the most frequently
misconfigured browser security controls. Developers often relax CORS
policies to "make things work" during development — reflecting any
`Origin`, trusting `null`, or combining a wildcard with credentials — and
those relaxed policies make it to production. A misconfigured policy can let
an attacker's website read data from a victim's authenticated session in
another origin, silently defeating the Same-Origin Policy the browser is
supposed to enforce.

Most students first encounter this class of vulnerability abstractly. There
is value in a small, transparent tool that actually sends the relevant
requests, shows exactly which header combinations are dangerous and which
are not, and explains *why* — rather than a black box that prints "VULNERABLE".

## 3. Project Idea

CORSBreach sends a small, fixed set of safe, read-only HTTP requests to a
target URL — varying only the `Origin` header and using `OPTIONS` for
preflight — and inspects the CORS-related response headers it gets back. An
analysis layer, with explicit and documented rules, turns those raw
observations into a small number of **evidence-backed findings**, each with
its own severity, description, evidence, and recommendation.

## 4. Objective

- Detect and explain CORS misconfigurations without guessing or overclaiming.
- Distinguish **normal**, **suspicious**, and **potentially dangerous**
  configurations using explicit rules, not "any header present = vulnerable".
- Work against real authorized targets — primarily the
  [PortSwigger Web Security Academy](https://portswigger.net/web-security)
  CORS labs — using nothing but the Python standard library.
- Be small enough that every line can be explained in a project defense.

## 5. CORS Background

CORS (Cross-Origin Resource Sharing) is a browser mechanism that lets a
server tell browsers which *other* origins are allowed to read the
responses of requests made to it. Without CORS, the Same-Origin Policy (see
below) would block a page on `https://a.example` from reading a response
from `https://b.example` via JavaScript, even if the browser is allowed to
*send* the request. CORS is the server opting back into sharing specific
data with specific (or all) other origins, via response headers.

## 6. Same-Origin Policy

The **Same-Origin Policy (SOP)** is the browser's default: JavaScript
running on one origin (`scheme://host:port`) cannot read the response body
of a request to a different origin, even though the browser may still send
the request (with cookies, if any). SOP is what keeps `evil.example` from
reading your bank's dashboard just because your browser is logged in there.
CORS is the *controlled exception* to that rule — every misconfiguration in
this tool is really a case of that exception being granted too broadly.

## 7. CORS Headers

| Header | Sent by | Meaning |
|---|---|---|
| `Origin` | Browser (request) | The origin the request is coming from. |
| `Access-Control-Allow-Origin` (ACAO) | Server (response) | Which origin(s) may read the response — a specific origin, or `*`. |
| `Access-Control-Allow-Credentials` (ACAC) | Server (response) | Whether cookies/HTTP auth may be included in the request and whether the response may be read when they are. |
| `Access-Control-Allow-Methods` (ACAM) | Server (preflight response) | Which HTTP methods are allowed for the actual request. |
| `Access-Control-Allow-Headers` (ACAH) | Server (preflight response) | Which request headers the actual request may include. |
| `Access-Control-Request-Method` / `-Headers` | Browser (preflight request) | What the actual request intends to use, so the server can approve or reject it in advance. |

A **preflight** is an automatic `OPTIONS` request the browser sends before
certain cross-origin requests (e.g. ones using custom headers or methods
other than simple GET/POST), asking the server for permission first.

## 8. Scanner Architecture

```
corsbreach.py  (CLI: argparse, config loading, logging, error handling)
   |
   +--> core/http_client.py   (stdlib-only HTTP/HTTPS transport)
   +--> core/scanner.py       (sends the fixed test sequence, builds observations)
   +--> core/analyzer.py      (pure functions: observations -> Findings)
   +--> core/models.py        (Finding / ScanResult / Severity data classes)
   +--> output/reporter.py    (terminal text report + JSON report)
```

`core/analyzer.py` has **no network code at all** — it is a pure function of
a plain dictionary, which is what makes it fully unit-testable without a
server (see `tests/test_analyzer.py`).

### Request budget

The brief describes nine conceptual tests. Several of them examine
*different aspects of the same HTTP response* rather than needing a new
request — reflection, wildcard detection, and credentials analysis for a
given `Origin` value are all read from one response. CORSBreach therefore
sends exactly **five** real requests per target:

1. `GET` with no `Origin` — baseline.
2. `GET` with `Origin: <origin1>` — reflection + wildcard + credentials.
3. `GET` with `Origin: null` — null-origin behavior.
4. `GET` with `Origin: <origin2>` — second-origin comparison.
5. `OPTIONS` with `Origin`, `Access-Control-Request-Method`,
   `Access-Control-Request-Headers` — preflight + methods + headers.

This keeps the tool polite to shared lab infrastructure while still covering
every test in the brief.

## 9. Features

- Pure Python 3 standard library — zero third-party dependencies.
- CLI with `scan` and `batch` commands, `--help`, `--version`, `--config`,
  `--log-level`, `--timeout`, `--output`.
- Plain-text terminal report and structured JSON report.
- Documented, multi-signal severity model (`core/analyzer.py`).
- Local, fully offline CORS lab for development and unit testing.
- Batch scanning of multiple authorized targets from a text file.
- Graceful handling of invalid URLs, DNS failures, timeouts, TLS errors,
  and malformed configuration — no raw tracebacks in normal use.

## 10. Project Structure

```
CORSBreach/
├── corsbreach.py            CLI entry point
├── core/
│   ├── scanner.py           Orchestrates the test sequence
│   ├── http_client.py       stdlib-only HTTP(S) client
│   ├── analyzer.py          Detection rules + severity model
│   └── models.py            Finding / ScanResult / Severity
├── output/
│   └── reporter.py          Terminal + JSON reporting
├── config/
│   └── config.json          Default configuration
├── logs/                    Log file written here at runtime
├── tests/
│   ├── test_scanner.py
│   ├── test_analyzer.py
│   └── test_http_client.py
├── lab/
│   └── local_cors_lab.py    Offline CORS lab for dev/testing
├── README.md
├── DISCUSSION_NOTES.md
├── requirements.txt
└── .gitignore
```

## 11. Installation

Requires Python 3.8+. No packages to install.

```bash
git clone <this-repo>
cd CORSBreach
python3 corsbreach.py --version
```

## 12. CLI Usage

```bash
python corsbreach.py --help
python corsbreach.py --version

# Scan a single target
python corsbreach.py scan https://example.web-security-academy.net

# With options (--config/--log-level may appear before OR after the subcommand)
python corsbreach.py scan https://example.web-security-academy.net --timeout 10
python corsbreach.py scan https://example.web-security-academy.net --output report.json
python corsbreach.py scan https://example.web-security-academy.net --config config/config.json
python corsbreach.py scan https://example.web-security-academy.net --log-level DEBUG

# Scan every target in a file
python corsbreach.py batch targets.txt --output batch_report.json
```

## 13. Configuration

`config/config.json`:

```json
{
  "timeout": 10,
  "user_agent": "CORSBreach/1.0",
  "test_origins": ["https://evil.example", "https://attacker.example", "null"],
  "follow_redirects": true,
  "verify_tls": true,
  "log_level": "INFO",
  "batch_delay_seconds": 1.0
}
```

`verify_tls: false` disables certificate verification. It exists **only**
for a legitimate local test environment with a self-signed certificate and
is `true` by default — CORSBreach never disables TLS verification
automatically. Any invalid value in the config file (wrong type, unknown
log level, negative timeout) is silently replaced with its default rather
than crashing the scan; a **missing or unparsable file passed via
`--config`** is reported as a clean `[ERROR]` and stops the run.

## 14. Logging

`--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}` controls what appears on
the console. Regardless of that setting, a full `DEBUG`-level log — including
tracebacks for unexpected errors — is always written to
`logs/corsbreach.log`, so nothing is lost even when the console stays quiet.

## 15. JSON Reporting

`--output report.json` writes a structured report:

```json
{
  "corsbreach_report_version": 1,
  "results": [
    {
      "target": "...",
      "scanner_version": "1.0.0",
      "timestamp": "...",
      "target_status": "reachable",
      "http_status": 200,
      "tests_performed": [ { "name": "...", "status": "ok", "detail": "..." } ],
      "observations": { "...": "raw header values collected" },
      "findings": [ { "id": "F001", "title": "...", "severity": "...", "...": "..." } ],
      "summary": { "tests_performed": 9, "findings": 2, "by_severity": { "...": 0 } },
      "error": null
    }
  ]
}
```

`batch` writes every scanned target's result into the same `results` list.

## 16. Batch Scanning

`targets.txt`:

```
# Authorized targets
https://lab1.web-security-academy.net
https://lab2.web-security-academy.net
```

Blank lines and lines starting with `#` are ignored. A small delay
(`batch_delay_seconds`, default 1 second) is inserted between targets so the
tool doesn't hammer shared lab infrastructure.

## 17. Local Lab

`lab/local_cors_lab.py` is a small, stdlib-only HTTP server with endpoints
demonstrating each CORS pattern this tool detects (`/secure`, `/wildcard`,
`/reflect`, `/reflect-credentials`, `/null-origin`, `/preflight`, `/plain`).
It requires no external network access and is what the automated test suite
scans against.

```bash
python lab/local_cors_lab.py 8000
python corsbreach.py scan http://127.0.0.1:8000/reflect-credentials
```

## 18. PortSwigger Testing

PortSwigger Web Security Academy labs are the **authorized, real-world
validation environment** for this project — the local lab above is only for
offline development. Manual validation workflow:

1. Open an authorized CORS lab on PortSwigger Web Security Academy.
2. Copy the lab's URL.
3. Run: `python corsbreach.py scan <lab-url>`.
4. Read the reported findings and their evidence.
5. Compare the scanner's findings against the lab's intended vulnerability
   class (e.g. "CORS vulnerability with basic origin reflection attack").
6. Record the terminal or JSON output as evidence for the project
   presentation.

CORSBreach never scrapes PortSwigger's solution pages, never hard-codes a
lab ID or an expected answer, and never submits anything to PortSwigger on
your behalf — every finding comes from analyzing the HTTP responses the
scanner itself received.

## 19. Unit Testing

```bash
python -m unittest discover -s tests
```

49 tests cover URL validation, the HTTP client (against the local lab),
every detection rule and severity outcome in the analyzer (pure, no
network), end-to-end scans of each local lab endpoint, configuration
validation, and batch target-file parsing.

## 20. Error Handling

Every expected failure mode produces a single-line `[ERROR] ...` message on
the console — never a raw traceback:

- Invalid URL / unsupported scheme
- DNS resolution failure
- Connection refused / connection failure
- Request timeout
- TLS/SSL handshake failure
- Missing or malformed configuration file
- Missing target file / empty target list in `batch` mode

An unexpected exception is caught at the top level too: its full traceback
goes to `logs/corsbreach.log`, and the console only sees a short message.

## 21. Limitations

- CORSBreach reports **observed evidence**, not confirmed real-world impact.
  A finding like "PUT is allowed" or "Authorization header is allowed" is a
  fact about the response headers, not proof that exploiting it does
  anything — that depends on what the endpoint actually does, which this
  scanner intentionally does not test.
- It only tests what a small set of `Origin` values produce; a server could
  theoretically behave differently for other origins it wasn't asked about.
- It does not attempt to determine whether an endpoint requires
  authentication, so a wildcard's real risk (public vs. sensitive data) must
  still be judged by a human.

## 22. Ethical / Authorized Use

CORSBreach is a **defensive/auditing tool**. Only scan targets you own or
are explicitly authorized to test — such as your own applications, or
PortSwigger Web Security Academy labs assigned to you. It never attempts
account takeover, credential theft, data deletion, denial of service, or any
action beyond safe `GET`/`OPTIONS` requests needed to observe CORS headers.

## 23. Example Output

```
==================================================
CORSBreach v1.0.0
CORS Misconfiguration Scanner
==================================================

Target:
https://example.web-security-academy.net

Target Status:
Reachable

HTTP Status:
200

--------------------------------------------------
CORS TESTS
--------------------------------------------------

[+] Baseline Request
[!] Reflected Origin
[+] Wildcard
[!] Credentials
[+] Null Origin
[+] Second Origin
[+] Preflight
[+] Allowed Methods
[+] Allowed Headers

--------------------------------------------------
FINDINGS
--------------------------------------------------

[F001] Reflected Origin
Severity: MEDIUM

Evidence:
Origin: https://evil.example
Access-Control-Allow-Origin: https://evil.example

Description:
The server reflected the untrusted supplied Origin value back in
Access-Control-Allow-Origin, instead of validating it against a fixed
allowlist.

Recommendation:
Validate the Origin header against an explicit server-side allowlist of
trusted origins instead of reflecting it back unchanged.

--------------------------------------------------

Summary:
Tests Performed: 9
Findings: 1
  HIGH: 0  MEDIUM: 1  LOW: 0  INFO: 0

==================================================
```
