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
from benchmark_live_defense import Relay, load_key, summarize  # noqa: E402


class BenchmarkTests(unittest.TestCase):
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
