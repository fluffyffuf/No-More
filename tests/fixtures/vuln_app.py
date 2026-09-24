"""Local vulnerable fixture for safe NOMORE testing.

This server intentionally exposes a few obvious misconfigurations, such as:
- debug endpoints
- an unauthenticated JSON API
- missing security headers and a version-revealing Server header
- a session cookie without HttpOnly / Secure / SameSite
- a CORS policy that reflects any Origin and allows credentials
- a reflective parameter in a query string
- a redirect to a host outside any sensible scope
- a /logout link (a GET a crawler must never follow)

It binds to 127.0.0.1 and is designed to be run locally in CI or a protected test
environment only.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOME_HTML = (
    "<html><head><meta name=\"generator\" content=\"VulnApp 1.0\"></head><body>"
    "<a href=\"/api/v1/users\">users</a> <a href=\"/debug\">debug</a> "
    "<a href=\"/reflect?q=hi\">reflect</a> <a href=\"/logout\">logout</a> "
    "<a href=\"/redirect-out\">out</a> <a href=\"https://elsewhere.invalid/x\">external</a>"
    "<form method=\"post\" action=\"/login\"></form></body></html>"
)


class VulnerableHandler(BaseHTTPRequestHandler):
    seen: list[str] = []  # every request path received (used by tests)

    def _reply(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin:  # deliberately unsafe: reflect any origin and allow credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path
        self.seen.append(self.path)

        if path == "/":
            self._reply(200, HOME_HTML.encode(), "text/html", {"Set-Cookie": "session=abc123; Path=/"})
        elif path == "/api/v1/users":
            self._reply(200, json.dumps([{"id": 1, "name": "alice"}]).encode(), "application/json")
        elif path == "/openapi.json":
            self._reply(200, json.dumps({"openapi": "3.0.0", "paths": {}}).encode(), "application/json")
        elif path == "/debug":
            self._reply(200, b"debug mode enabled\n", "text/plain")
        elif path == "/reflect":
            reflected = query.get("q", ["hello"])[0]
            self._reply(200, f"<html><body>{reflected}</body></html>".encode(), "text/html")
        elif path == "/redirect-out":
            self._reply(302, b"", "text/plain", {"Location": "http://evil.invalid/landing"})
        elif path == "/redirect-in":
            self._reply(302, b"", "text/plain", {"Location": "/debug"})
        elif path == "/logout":
            self._reply(200, b"logged out\n", "text/plain")
        else:
            self._reply(404, b"not found\n", "text/plain")

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def start_server(port: int = 0) -> tuple[HTTPServer, threading.Thread]:
    """Start the fixture on 127.0.0.1 (port 0 = pick a free port) in a background thread."""
    handler = type("Handler", (VulnerableHandler,), {"seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8765), VulnerableHandler)
    print("Vulnerable test server listening on http://127.0.0.1:8765")
    server.serve_forever()
