"""Local vulnerable fixture for safe NOMORE testing.

This server intentionally exposes a few obvious misconfigurations, such as:
- debug endpoints
- an unauthenticated JSON API
- a missing security header
- a reflective parameter in a query string

It is designed to be run locally in CI or a protected test environment only.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            body = json.dumps({"message": "home", "debug": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/v1/users":
            body = json.dumps([{"id": 1, "name": "alice"}]).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/debug":
            body = b"debug mode enabled\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/reflect":
            reflected = query.get("q", ["hello"])[0]
            body = f"<html><body>{reflected}</body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8765), VulnerableHandler)
    print("Vulnerable test server listening on http://127.0.0.1:8765")
    server.serve_forever()
