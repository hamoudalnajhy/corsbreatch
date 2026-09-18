"""
lab.local_cors_lab
===================

A tiny, pure-standard-library HTTP server that exposes several endpoints,
each demonstrating a different CORS configuration. It exists so CORSBreach
can be developed and unit-tested WITHOUT touching any external site -
PortSwigger Academy labs remain the authorized, real-world validation step
(see README.md, "PortSwigger Testing").

Endpoints
---------
/secure               - Explicit allowlist; only "https://trusted.example"
                         is ever echoed back. No credentials.
/wildcard              - Always returns "Access-Control-Allow-Origin: *".
/reflect               - Reflects whatever Origin was sent, no credentials.
/reflect-credentials   - Reflects Origin AND sets
                         "Access-Control-Allow-Credentials: true"
                         (the classic dangerous misconfiguration).
/null-origin           - Returns "Access-Control-Allow-Origin: null" only
                         when the request's Origin is exactly "null".
/preflight             - Reflects Origin and, on OPTIONS, answers with
                         Allow-Methods (including PUT/DELETE) and
                         Allow-Headers (including Authorization) so preflight
                         analysis has something to parse.
/plain                 - No CORS headers at all (a "boring", non-CORS-enabled
                         endpoint used as a negative control in tests).

Run directly for manual testing:

    python lab/local_cors_lab.py [port]

Defaults to port 8000 on 127.0.0.1.
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


TRUSTED_ORIGIN = "https://trusted.example"


class CorsLabHandler(BaseHTTPRequestHandler):
    server_version = "CORSBreachLocalLab/1.0"

    # Silence default noisy logging; the lab is a test fixture, not a demo server.
    def log_message(self, format, *args):  # noqa: A002 - matches base class signature
        pass

    def _origin(self):
        return self.headers.get("Origin")

    def _send_common(self, status=200, extra_headers=None, body=b"OK"):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        origin = self._origin()

        if path == "/secure":
            headers = {}
            if origin == TRUSTED_ORIGIN:
                headers["Access-Control-Allow-Origin"] = TRUSTED_ORIGIN
                headers["Vary"] = "Origin"
            self._send_common(extra_headers=headers)

        elif path == "/wildcard":
            self._send_common(extra_headers={"Access-Control-Allow-Origin": "*"})

        elif path == "/reflect":
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Vary"] = "Origin"
            self._send_common(extra_headers=headers)

        elif path == "/reflect-credentials":
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Vary"] = "Origin"
            self._send_common(extra_headers=headers)

        elif path == "/null-origin":
            headers = {}
            if origin == "null":
                headers["Access-Control-Allow-Origin"] = "null"
            self._send_common(extra_headers=headers)

        elif path == "/preflight":
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Vary"] = "Origin"
            self._send_common(extra_headers=headers)

        elif path == "/plain":
            self._send_common()

        else:
            self._send_common(status=404, body=b"Not Found")

    def do_OPTIONS(self):
        path = self.path.split("?", 1)[0]
        origin = self._origin()
        headers = {}

        if path == "/preflight":
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Test-Header"
        elif path == "/reflect-credentials":
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Methods"] = "GET, POST"
            headers["Access-Control-Allow-Headers"] = "Content-Type"
        else:
            # Generic, low-privilege preflight response for other endpoints.
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Methods"] = "GET"

        self._send_common(status=204, extra_headers=headers, body=b"")


def run(host: str = "127.0.0.1", port: int = 8000) -> HTTPServer:
    server = HTTPServer((host, port), CorsLabHandler)
    return server


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = run(port=port)
    print(f"CORSBreach local CORS lab running at http://127.0.0.1:{port}")
    print("Endpoints: /secure /wildcard /reflect /reflect-credentials "
          "/null-origin /preflight /plain")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
