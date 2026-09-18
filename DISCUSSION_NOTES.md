# DISCUSSION_NOTES.md

Study notes for explaining CORSBreach in class — simple explanations, not
formal documentation. Read this alongside README.md.

---

### What is CORS?

CORS (Cross-Origin Resource Sharing) is a set of HTTP response headers that
let a server tell browsers "these other websites are allowed to read
responses from me." It exists because browsers normally block that by
default (see Same-Origin Policy below).

### Why do browsers enforce the Same-Origin Policy?

Without it, any website you visit could use JavaScript to quietly read data
from every other site you're logged into — your email, your bank, your
social media — because your browser sends your cookies automatically. The
Same-Origin Policy says: JavaScript on origin A cannot read responses from
origin B, unless B explicitly allows it.

### What does "Origin" mean?

An origin is `scheme://host:port` — for example `https://example.com` and
`http://example.com` are *different* origins (different scheme), and so are
`https://example.com` and `https://api.example.com` (different host).

### What does Access-Control-Allow-Origin do?

It's the server's answer to "who may read this response?" It can be one
specific origin, or `*` (anyone). If it doesn't match the browser's current
origin, the browser hides the response from JavaScript — even though the
request may have already happened.

### What does Access-Control-Allow-Credentials do?

It tells the browser whether cookies/HTTP auth may be sent on the
cross-origin request *and* whether the response may then be read. This is
the header that turns "an attacker can see public data" into "an attacker
can see the victim's private, logged-in data."

### What is a preflight request?

For requests that aren't "simple" (custom headers, methods other than
GET/POST/HEAD, etc.), the browser first sends an `OPTIONS` request asking
"if I sent this for real, would you allow it?" The server answers with
`Access-Control-Allow-Methods` / `-Headers`, and only if that answer is
favorable does the browser send the real request.

### Why is OPTIONS used for this?

OPTIONS is a safe, side-effect-free HTTP method by convention — it's meant
for exactly this kind of "asking permission" exchange, not for performing an
action. CORSBreach only ever sends the preflight question itself, never a
real PUT/DELETE/etc.

### How does CORSBreach send requests?

`core/http_client.py` wraps Python's built-in `urllib.request` (plus `ssl`
and `socket` for error handling) — no third-party HTTP library. It sends
plain GET and OPTIONS requests with a controlled `Origin` header, and
normalizes whatever comes back (success, HTTP error, or connection failure)
into one `HttpResponse` shape.

### How are response headers extracted?

`HttpResponse.get_header(name)` does a case-insensitive lookup, because HTTP
header names are case-insensitive but Python dicts are not — `Access-
Control-Allow-Origin` and `access-control-allow-origin` must be treated as
the same header.

### How does the analyzer work?

`core/analyzer.py` takes a plain dictionary of what was observed (which
Origin was sent, what ACAO/ACAC/ACAM/ACAH came back) and runs small,
independent detection functions (`is_wildcard`, `is_reflected`,
`credentials_enabled`, ...) over it. It has no network code at all, which is
what makes it a *pure function* — same input always gives the same output,
and it's fully testable without a server.

### How are findings generated?

Each finding type has its own small builder function (e.g.
`_f001_reflected_origin`), so every rule is isolated, documented, and easy
to test on its own. `analyze()` calls the right builders based on which
combination of signals was actually observed.

### How is severity calculated?

Never from a single header's presence — always from a *combination*:

- Wildcard alone → INFO (often intentional for public APIs).
- Reflected origin alone → MEDIUM (an untrusted site can read the response).
- Reflected origin **+ credentials enabled** → HIGH (a real, working attack
  against logged-in users).
- Two different untrusted origins both reflected → escalates the finding to
  HIGH, because it proves there's no real allowlist at all.
- `null` origin allowed → LOW normally, MEDIUM if combined with credentials
  (because `null` is trivial for an attacker to produce).
- Unusual preflight methods/headers → reported as evidence only, never
  automatically "vulnerable," since real impact depends on the endpoint.

### How does error handling work?

Every place the client could fail (bad URL, DNS failure, connection
refused, timeout, TLS error) raises one of a small set of custom exceptions
defined in `http_client.py`. `corsbreach.py` catches those at the top level
and prints one clean `[ERROR] ...` line — the full traceback still gets
written to `logs/corsbreach.log` at DEBUG level, so nothing is lost, but a
normal user never sees it.

### Why only the Python standard library?

Three reasons worth being able to explain: (1) it's an explicit academic
requirement for this project, (2) it removes an entire category of supply-
chain risk (a malicious or outdated third-party package) from a *security*
tool, and (3) it forces a clear understanding of what's actually happening
at the HTTP level instead of hiding it behind a library like `requests`.

### How was the project tested with PortSwigger Academy?

Development and automated unit tests run entirely against
`lab/local_cors_lab.py`, a tiny local HTTP server with one endpoint per CORS
pattern (secure allowlist, wildcard, reflection, reflection+credentials,
null origin, permissive preflight). Once the local tests passed, the same
CLI command (`python corsbreach.py scan <url>`) was run against assigned,
authorized PortSwigger Web Security Academy CORS labs as the real-world
validation step, and the reported findings were compared against each lab's
described vulnerability to confirm the analyzer's rules hold outside the
local lab too.
