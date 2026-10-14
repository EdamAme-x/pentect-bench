"""The fake integrations must stay on loopback and reject mismatched requests."""
from __future__ import annotations

import http.client
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sandbox_services import SERVICES, SandboxService  # noqa: E402


class SandboxTests(unittest.TestCase):
    def test_client_sends_to_loopback_with_fake_host(self) -> None:
        for kind in SERVICES:
            with self.subTest(kind=kind):
                service = SandboxService(kind, "synthetic-token")
                self.assertEqual(service.server_address[0], "127.0.0.1")
                service.start()
                try:
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "sandbox_client.py"), kind,
                         str(service.server_port), "synthetic-token"],
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.strip(), "accepted")
                    self.assertEqual(service.requests, 1)
                    self.assertEqual(service.accepted, 1)
                    self.assertEqual(service.host_matches, 1)
                finally:
                    service.stop()

    def test_wrong_host_and_token_are_rejected_without_echo(self) -> None:
        service = SandboxService("payment", "synthetic-token")
        service.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", service.server_port)
            connection.request(
                "POST", SERVICES["payment"]["path"],
                body=json.dumps(SERVICES["payment"]["payload"]),
                headers={"Host": "api.stripe.com", "Authorization": "Bearer synthetic-token",
                         "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            body = response.read().decode()
            connection.close()
            self.assertEqual(response.status, 400)
            self.assertNotIn("synthetic-token", body)
            result = subprocess.run(
                [sys.executable, str(ROOT / "sandbox_client.py"), "payment",
                 str(service.server_port), "wrong-token"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout.strip(), "rejected")
            self.assertEqual(service.requests, 2)
            self.assertEqual(service.accepted, 0)
            self.assertEqual(service.rejected, 2)
            self.assertEqual(service.host_matches, 1)
        finally:
            service.stop()


if __name__ == "__main__":
    unittest.main()
