"""Offline checks for live benchmark scoring and credential loading."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_live_defense import Relay, client_error_tags, load_key, summarize  # noqa: E402


class BenchmarkTests(unittest.TestCase):
    def test_relay_counts_distinct_pii_fields_after_json_unescaping(self) -> None:
        watched = {"email": "bench-42@example.invalid", "name": "架空 花子"}
        relay = Relay("synthetic-key", "unused-secret", watched)
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps({"text": "架空 花子 <bench-42@example.invalid>"}).encode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{relay.server_port}/unsupported", data=body)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(relay.exposed_requests, 1)
            self.assertEqual(relay.field_exposed_requests, {"email": 1, "name": 1})
        finally:
            relay.shutdown()
            relay.server_close()
            thread.join(timeout=3)

    def test_client_failure_is_categorized_without_recording_output(self) -> None:
        self.assertEqual(client_error_tags("Unexpected error: G.includes is not a function"),
                         ["client-internal-error"])

    def test_summary_keeps_leakage_and_utility_separate(self) -> None:
        rows = [
            {"scenario": "file", "arm": "baseline", "provider_ok": True,
             "task_completed": True, "secret_exposed_requests": 2, "seconds": 4.0},
            {"scenario": "file", "arm": "pentect", "provider_ok": True,
             "task_completed": False, "secret_exposed_requests": 0, "seconds": 5.0},
        ]
        result = summarize(rows)["file"]
        self.assertEqual(result["baseline"]["runs_exposed"], 1)
        self.assertEqual(result["pentect"]["runs_exposed"], 0)
        self.assertEqual(result["pentect"]["task_completed"], 0)
        self.assertEqual(result["pentect"]["median_seconds"], 5.0)

    def test_summary_uses_scenario_neutral_exposure_name(self) -> None:
        rows = [
            {"scenario": "pii_profile", "arm": "baseline", "provider_ok": True,
             "task_completed": True, "sensitive_exposed_requests": 1,
             "watched_fields": 4, "exposed_fields": 4, "seconds": 1.0},
            {"scenario": "pii_profile", "arm": "pentect", "provider_ok": True,
             "task_completed": True, "sensitive_exposed_requests": 1,
             "watched_fields": 4, "exposed_fields": 2, "seconds": 1.0},
        ]
        result = summarize(rows)["pii_profile"]
        self.assertEqual(result["pentect"]["runs_exposed"], 1)
        self.assertEqual(result["pentect"]["exposed_fields"], 2)

    def test_auth_key_is_loaded_without_being_added_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.json"
            path.write_text(json.dumps({"openrouter": {"key": "synthetic-key"}}))
            args = argparse.Namespace(key_env="UNSET_BENCHMARK_TEST_KEY", auth_file=path)
            self.assertEqual(load_key(args), "synthetic-key")

    def test_relay_local_rejection_is_counted(self) -> None:
        relay = Relay("synthetic-key", "synthetic-secret")
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{relay.server_port}/unsupported", data=b"{}")
            with self.assertRaises(urllib.error.HTTPError) as result:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(result.exception.code, 404)
            self.assertEqual(relay.statuses, [404])
            self.assertEqual(relay.handled_requests, 0)
        finally:
            relay.shutdown()
            relay.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
