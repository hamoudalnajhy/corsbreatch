"""
core.http_client
=================

A minimal HTTP(S) client built entirely on the Python standard library
(urllib.request, urllib.parse, urllib.error, http.client, ssl, socket).

CORSBreach never imports requests, httpx, aiohttp, or any other third-party
HTTP library. This module is the single place that talks to the network;
everything else in the project works with the HttpResponse objects it
returns.
"""

import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class HttpClientError(Exception):
    """Base class for all errors raised by HttpClient."""


class InvalidURLError(HttpClientError):
    """The URL is malformed or missing required parts."""


class UnsupportedSchemeError(HttpClientError):
    """The URL scheme is not http:// or https://."""


class DNSError(HttpClientError):
    """The target hostname could not be resolved."""


class ConnectionFailedError(HttpClientError):
    """A TCP connection to the target could not be established."""


class ScanTimeoutError(HttpClientError):
    """The request exceeded the configured timeout."""


class TLSError(HttpClientError):
    """The TLS/SSL handshake failed (e.g. invalid or untrusted certificate)."""


# --------------------------------------------------------------------------
# Response model
# --------------------------------------------------------------------------

@dataclass
class HttpResponse:
    """A normalized HTTP response, regardless of which urllib code path produced it."""
    status: int
    headers: Dict[str, str]
    url: str
    body: bytes = b""

    def get_header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
        name_l = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_l:
                return value
        return None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Installed instead of the default redirect handler when follow_redirects=False."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Returning None tells urllib not to follow the redirect.


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

class HttpClient:
    """
    Small, dependency-free HTTP client used for every request CORSBreach sends.

    Only GET and OPTIONS are used by the scanner - CORSBreach never sends
    state-changing requests (POST/PUT/DELETE/PATCH) to a target; it only asks
    the target what it *would* allow, via preflight analysis.
    """

    def __init__(self, timeout: float = 10.0, user_agent: str = "CORSBreach/1.0",
                 verify_tls: bool = True, follow_redirects: bool = True):
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects

    # -- internal helpers ---------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        if self.verify_tls:
            return ssl.create_default_context()
        # Only intended for legitimate local/lab testing with self-signed
        # certificates. Documented clearly in README/config - never the
        # default.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_opener(self):
        handlers = [urllib.request.HTTPSHandler(context=self._build_ssl_context())]
        if not self.follow_redirects:
            handlers.append(_NoRedirectHandler())
        return urllib.request.build_opener(*handlers)

    @staticmethod
    def validate_url(url: str) -> urllib.parse.ParseResult:
        """Raise InvalidURLError / UnsupportedSchemeError for a bad URL, else return it parsed."""
        if not isinstance(url, str) or not url.strip():
            raise InvalidURLError("URL must be a non-empty string.")
        try:
            parsed = urllib.parse.urlparse(url.strip())
        except ValueError as exc:
            raise InvalidURLError(f"Could not parse URL: {exc}") from exc
        if not parsed.scheme or not parsed.netloc:
            raise InvalidURLError("URL must include a scheme and a host, e.g. https://host")
        if parsed.scheme not in ("http", "https"):
            raise UnsupportedSchemeError(f"Unsupported URL scheme: '{parsed.scheme}'")
        if not parsed.hostname:
            raise InvalidURLError("URL is missing a hostname.")
        return parsed

    # -- public API -----------------------------------------------------------

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Send a single HTTP request and return a normalized HttpResponse."""
        self.validate_url(url)
        headers = dict(headers or {})
        headers.setdefault("User-Agent", self.user_agent)

        req = urllib.request.Request(url, headers=headers, method=method.upper())
        opener = self._build_opener()

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read()
                return HttpResponse(
                    status=resp.status,
                    headers=dict(resp.headers.items()),
                    url=resp.geturl(),
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            # HTTPError is raised for non-2xx statuses, but it is still a real
            # response - CORS headers on a 403/404 are meaningful evidence,
            # so we capture them instead of treating this as a failure.
            body = b""
            try:
                body = exc.read()
            except Exception:
                pass
            return HttpResponse(
                status=exc.code,
                headers=dict(exc.headers.items()) if exc.headers else {},
                url=url,
                body=body,
            )
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLError):
                raise TLSError(f"TLS/SSL connection failed: {reason}") from exc
            if isinstance(reason, socket.timeout):
                raise ScanTimeoutError(f"Connection timed out after {self.timeout}s: {reason}") from exc
            if isinstance(reason, socket.gaierror):
                raise DNSError(f"DNS resolution failed: {reason}") from exc
            raise ConnectionFailedError(f"Connection failed: {reason}") from exc
        except socket.timeout as exc:
            raise ScanTimeoutError(f"Connection timed out after {self.timeout}s: {exc}") from exc
        except ssl.SSLError as exc:
            raise TLSError(f"TLS/SSL connection failed: {exc}") from exc
        except socket.gaierror as exc:
            raise DNSError(f"DNS resolution failed: {exc}") from exc
        except OSError as exc:
            raise ConnectionFailedError(f"Connection failed: {exc}") from exc

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        return self.request("GET", url, headers=headers)

    def options(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        return self.request("OPTIONS", url, headers=headers)
