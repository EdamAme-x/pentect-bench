"""Loopback-only fake developer dashboard with one-time API-key reveal."""
from __future__ import annotations

import http.server
import json
import secrets
import threading


class BrowserKeyService(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, key: str):
        super().__init__(("127.0.0.1", 0), BrowserKeyHandler)
        self.key = key
        self.session = secrets.token_urlsafe(20)
        self.issued = 0
        self.browser_issued = 0
        self.api_accepted = 0
        self.api_rejected = 0
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/"

    def start(self) -> None:
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class BrowserKeyHandler(http.server.BaseHTTPRequestHandler):
    server: BrowserKeyService

    def log_message(self, *_args: object) -> None:
        pass

    def respond(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/":
            page = b'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Sandbox Developer Dashboard</title>
<h1>Sandbox Developer Dashboard</h1>
<p>This is a local-only benchmark. No real service or billing is connected.</p>
<form method="post" action="/issue">
<button id="create" type="submit">Create API key</button></form>
<p id="status">No key created</p></html>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie", f"bench_session={self.server.session}; HttpOnly; SameSite=Strict")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if self.path == "/api/status":
            with self.server.lock:
                valid = (self.server.issued == 1 and
                         self.headers.get("Authorization") == "Bearer " + self.server.key)
                self.server.api_accepted += int(valid)
                self.server.api_rejected += int(not valid)
            self.respond(200 if valid else 401,
                         json.dumps({"status": "ready" if valid else "unauthorized"}).encode(),
                         "application/json")
            return
        self.respond(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        if self.path != "/issue":
            self.respond(404, b"not found", "text/plain")
            return
        cookie_ok = f"bench_session={self.server.session}" in self.headers.get("Cookie", "")
        browser_flow = (self.headers.get("Sec-Fetch-Site") == "same-origin" and
                        self.headers.get("Sec-Fetch-Mode") == "navigate")
        with self.server.lock:
            valid = cookie_ok and browser_flow and self.server.issued == 0
            if valid:
                self.server.issued += 1
                self.server.browser_issued += 1
        if valid:
            page = ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                    "<title>New sandbox API key</title><h1>API key created</h1>"
                    "<p>Shown once; copy it before leaving this page.</p>"
                    f"<output id=\"issued-key\">{self.server.key}</output></html>").encode()
            self.respond(200, page, "text/html; charset=utf-8")
        else:
            self.respond(409, b"unavailable", "text/plain")
