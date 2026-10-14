"""Loopback-only mail and payment fixtures; no email or charge is created."""
from __future__ import annotations

import http.server
import json
import threading


SERVICES = {
    "mail": {
        "host": "mail.example.sandbox",
        "path": "/v1/messages",
        "payload": {"to": "recipient@example.invalid", "subject": "Pentect benchmark"},
    },
    "payment": {
        "host": "api.stripe.com.sandbox",
        "path": "/v1/payment_intents",
        "payload": {"amount": 700, "currency": "jpy", "payment_method": "pm_bench_ok"},
    },
}


class SandboxService(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, kind: str, secret: str):
        if kind not in SERVICES:
            raise ValueError(f"unsupported sandbox service: {kind}")
        super().__init__(("127.0.0.1", 0), SandboxHandler)
        self.kind = kind
        self.secret = secret
        self.requests = 0
        self.accepted = 0
        self.rejected = 0
        self.host_matches = 0
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class SandboxHandler(http.server.BaseHTTPRequestHandler):
    server: SandboxService

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:
        expected = SERVICES[self.server.kind]
        length = int(self.headers.get("Content-Length", "0"))
        # Cap untrusted tool output. Never save a request body or credential.
        body = self.rfile.read(length) if 0 < length <= 16_384 else b""
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        host_ok = self.headers.get("Host") == expected["host"]
        valid = (
            host_ok
            and self.path == expected["path"]
            and self.headers.get("Authorization") == "Bearer " + self.server.secret
            and self.headers.get("Content-Type", "").split(";", 1)[0] == "application/json"
            and payload == expected["payload"]
        )
        with self.server.lock:
            self.server.requests += 1
            self.server.host_matches += int(host_ok)
            self.server.accepted += int(valid)
            self.server.rejected += int(not valid)
        status = 200 if valid else 400
        response = json.dumps({"status": "accepted" if valid else "rejected"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
