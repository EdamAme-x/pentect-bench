"""Offline checks for live benchmark scoring and credential loading."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark_live_defense  # noqa: E402
from benchmark_live_defense import (  # noqa: E402
    ETHICAL_SCENARIOS, ETHICAL_SYSTEM_PROMPT, Relay, browser_task_utility, client_error_tags,
    fatal_provider_status,
    load_key, scenario_timeout, stored_task_completed, summarize,
)


class BenchmarkTests(unittest.TestCase):
    def test_http_402_stops_before_the_other_arm_or_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pentect = Path(directory) / "pentect.exe"
            opencode = Path(directory) / "opencode.exe"
            pentect.touch()
            opencode.touch()
            argv = ["benchmark_live_defense.py", "--pentect", str(pentect),
                    "--opencode", str(opencode), "--scenario", "file",
                    "--scenario", "log", "--trials", "1"]
            fake_result = {"provider_statuses": [402]}
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(benchmark_live_defense, "load_key", return_value="unused"), \
                 mock.patch.object(benchmark_live_defense, "run_arm",
                                   return_value=fake_result) as run_arm, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(benchmark_live_defense.main(), 4)
            self.assertEqual(run_arm.call_count, 1)
            self.assertIn("HTTP 402", errors.getvalue())

    def test_billing_and_authentication_failures_stop_the_matrix(self) -> None:
        self.assertEqual(fatal_provider_status([200, 402]), 402)
        self.assertEqual(fatal_provider_status([401]), 401)
        self.assertEqual(fatal_provider_status([403]), 403)
        self.assertIsNone(fatal_provider_status([200, 429, 502]))

    def test_browser_scenarios_keep_a_realistic_timeout_floor(self) -> None:
        self.assertEqual(scenario_timeout("browser_issue_key", 75), 180)
        self.assertEqual(scenario_timeout("browser_dom_debug", 240), 240)
        self.assertEqual(scenario_timeout("file", 75), 75)

    def test_completed_artifact_does_not_require_final_phrase(self) -> None:
        row = {"scenario": "control", "task_completed": False, "exit_code": 0,
               "result_file_exact": True, "completion_marker": False}
        self.assertTrue(stored_task_completed(row))
        self.assertFalse(stored_task_completed({**row, "exit_code": None}))
        self.assertFalse(stored_task_completed({**row, "result_file_exact": False}))
        self.assertFalse(stored_task_completed({**row, "scenario": "prompt"}))

    def test_browser_refresh_accepts_one_rejected_navigation_replay(self) -> None:
        self.assertTrue(browser_task_utility("browser_key_refresh", 1, 1, 2, 2, 1, True))
        self.assertTrue(browser_task_utility("browser_key_refresh", 1, 1, 1, 1, 1, True))
        for counters in ((2, 2, 2, 2, 1, True),  # a second key was issued
                         (1, 1, 2, 1, 1, True),  # non-browser retry
                         (1, 1, 3, 3, 1, True),  # repeated retries
                         (1, 1, 2, 2, 0, True),  # key not used
                         (1, 1, 2, 2, 1, False)):
            with self.subTest(counters=counters):
                self.assertFalse(browser_task_utility("browser_key_refresh", *counters))
        self.assertFalse(browser_task_utility("browser_issue_key", 1, 1, 2, 2, 1, True))
        self.assertTrue(browser_task_utility("browser_key_duplicate", 1, 1, 2, 2, 1, True))

    def test_ethical_policy_is_counted_only_in_system_or_developer_role(self) -> None:
        self.assertEqual(ETHICAL_SCENARIOS, {"ethical_file", "ethical_log"})
        relay = Relay("synthetic-key", "synthetic-secret")
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        try:
            for role in ("user", "system"):
                body = json.dumps({"messages": [{"role": role,
                    "content": ETHICAL_SYSTEM_PROMPT}]}).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{relay.server_port}/unsupported", data=body)
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(request, timeout=3)
            self.assertEqual(relay.ethical_system_seen_requests, 1)
        finally:
            relay.shutdown()
            relay.server_close()
            thread.join(timeout=3)

    def test_ethical_tasks_require_only_the_public_status_value(self) -> None:
        for scenario in ETHICAL_SCENARIOS:
            prompt = benchmark_live_defense.SCENARIOS[scenario]
            self.assertIn("characters after STATUS=", prompt)
            self.assertIn("no STATUS= label, quotes, newline, or explanation", prompt)
            self.assertIn("Check the file and correct it if needed", prompt)

    def test_database_and_zip_tasks_specify_the_public_lookup(self) -> None:
        self.assertIn("settings(name TEXT PRIMARY KEY, value TEXT)",
                      benchmark_live_defense.SCENARIOS["sqlite_db"])
        self.assertIn("WHERE name='status'", benchmark_live_defense.SCENARIOS["sqlite_db"])
        self.assertIn("ZipFile", benchmark_live_defense.SCENARIOS["zip_archive"])
        self.assertIn("config.json", benchmark_live_defense.SCENARIOS["zip_archive"])

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

    def test_ethical_refusal_is_distinct_from_failed_task(self) -> None:
        rows = [
            {"scenario": "ethical_file", "arm": "baseline", "provider_ok": True,
             "task_completed": False, "ethical_refusal": True,
             "ethical_system_seen_requests": 2, "sensitive_exposed_requests": 1,
             "seconds": 1.0},
            {"scenario": "ethical_file", "arm": "pentect", "provider_ok": True,
             "task_completed": True, "ethical_refusal": False,
             "ethical_system_seen_requests": 3, "sensitive_exposed_requests": 0,
             "seconds": 1.0},
        ]
        result = summarize(rows)["ethical_file"]
        self.assertEqual(result["baseline"]["ethical_refusals"], 1)
        self.assertEqual(result["baseline"]["task_completed"], 0)
        self.assertEqual(result["pentect"]["ethical_refusals"], 0)
        self.assertEqual(result["pentect"]["system_prompt_verified"], 1)

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
