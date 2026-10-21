"""Offline tests for model selection and value-free matrix scoring."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_matrix import (CORE_SCENARIOS, EXTENDED_SCENARIOS, SCENARIOS,
                        aggregate, markdown, paired_task_outcomes, read_models,
                        report_name, validate_models)  # noqa: E402


class MatrixTests(unittest.TestCase):
    def test_core_suite_is_fixed_fifty_with_extended_cases_available(self) -> None:
        self.assertEqual(len(CORE_SCENARIOS), 50)
        self.assertEqual(len(SCENARIOS), 55)
        self.assertEqual(set(CORE_SCENARIOS) | EXTENDED_SCENARIOS, set(SCENARIOS))
        self.assertFalse(set(CORE_SCENARIOS) & EXTENDED_SCENARIOS)
        self.assertIn("private_note_triage", CORE_SCENARIOS)
        self.assertIn("private_note_translation", CORE_SCENARIOS)
        self.assertIn("ethical_log", CORE_SCENARIOS)
        self.assertIn("browser_issue_key", CORE_SCENARIOS)

    def test_paired_utility_excludes_baseline_failure_and_audits_it(self) -> None:
        rows = []
        for trial, (direct, protected) in enumerate(((True, True), (True, False),
                                                       (False, False), (False, True))):
            for arm, completed in (("baseline", direct), ("pentect", protected)):
                rows.append({"scenario": "file", "trial": trial, "arm": arm,
                             "task_completed": completed})
        outcomes = paired_task_outcomes(rows)
        self.assertEqual(outcomes["baseline_success_pairs"], 2)
        self.assertEqual(outcomes["protected_on_baseline_success"], 1)
        self.assertEqual(outcomes["both_failed_pairs"], 1)
        self.assertEqual(outcomes["protected_only_success_pairs"], 1)
        self.assertEqual(outcomes["direct_only_success_pairs"], 1)

    def test_historical_browser_refresh_is_rescored_without_mutating_row(self) -> None:
        rows = [{"scenario": "browser_key_refresh", "trial": 0, "arm": arm,
                 "task_completed": False, "exit_code": 0, "completion_marker": True,
                 "browser_issued": 1, "browser_issue_attempts": 2,
                 "browser_attempts": 2, "browser_api_accepted": 1,
                 "result_file_exact": True} for arm in ("baseline", "pentect")]
        self.assertEqual(paired_task_outcomes(rows)["protected_on_baseline_success"], 1)
        self.assertFalse(rows[0]["task_completed"])

    def test_public_identifiers_count_utility_but_not_leak_denominator(self) -> None:
        report = {"model": "example/model", "discarded_pairs": 0,
                  "incomplete_pairs": 0, "summary": {
            "public_identifiers": {
                "baseline": {"runs": 1, "task_completed": 1, "runs_exposed": 0},
                "pentect": {"runs": 1, "task_completed": 1, "runs_exposed": 0}},
            "nested_json": {
                "baseline": {"runs": 1, "task_completed": 1, "runs_exposed": 1},
                "pentect": {"runs": 1, "task_completed": 1, "runs_exposed": 0}},
        }}
        row = aggregate([report])[0]
        self.assertEqual(row["task_runs"], 2)
        self.assertEqual(row["sensitive_runs"], 1)
        self.assertEqual(row["direct_exposed_runs"], 1)

    def test_task_groups_keep_plaintext_and_refusal_cases_separate(self) -> None:
        report = {"model": "example/model", "discarded_pairs": 0,
                  "incomplete_pairs": 0, "summary": {
            "file": {"baseline": {"runs": 1, "task_completed": 1},
                     "pentect": {"runs": 1, "task_completed": 1}},
            "private_note_translation": {
                "baseline": {"runs": 1, "task_completed": 1},
                "pentect": {"runs": 1, "task_completed": 0}},
            "ethical_log": {"baseline": {"runs": 1, "task_completed": 0},
                            "pentect": {"runs": 1, "task_completed": 1}},
        }}
        row = aggregate([report])[0]
        self.assertEqual(row["direct_completed"], row["pentect_completed"])
        self.assertEqual(row["task_groups"]["plaintext_required"], {
            "runs": 1, "direct_completed": 1, "pentect_completed": 0})
        self.assertEqual(row["task_groups"]["ethical_refusal"], {
            "runs": 1, "direct_completed": 0, "pentect_completed": 1})
        rendered = markdown([row])
        self.assertIn("Plaintext interpretation required | 100.0% (1/1) | 0.0% (0/1)", rendered)
        self.assertIn("Stop after seeing raw secret | 0.0% (0/1) | 100.0% (1/1)", rendered)

    def test_model_list_rejects_duplicates_and_unsafe_ids(self) -> None:
        with self.assertRaises(ValueError):
            validate_models(["openai/gpt-4o", "openai/gpt-4o"])
        with self.assertRaises(ValueError):
            validate_models(["../other"])
        self.assertEqual(validate_models(["example/model:free"]), ["example/model:free"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models.txt"
            path.write_text("# comment\nopenai/gpt-4o\n\nqwen/qwen3-coder-next\n")
            self.assertEqual(read_models(path),
                             ["openai/gpt-4o", "qwen/qwen3-coder-next"])

    def test_report_names_do_not_collide_for_similar_slugs(self) -> None:
        self.assertNotEqual(report_name("a/b-c"), report_name("a-b/c"))

    def test_aggregate_excludes_incomplete_pairs_and_preserves_utility(self) -> None:
        report = {
            "model": "example/model", "discarded_pairs": 2, "incomplete_pairs": 1,
            "summary": {
                "prompt": {"baseline": {"runs": 2, "runs_exposed": 2},
                           "pentect": {"runs": 2, "runs_exposed": 0}},
                "file": {"baseline": {"runs": 3, "runs_exposed": 3,
                                      "task_completed": 3},
                         "pentect": {"runs": 3, "runs_exposed": 1,
                                     "task_completed": 2}},
                "mail": {"baseline": {"runs": 3, "runs_exposed": 3,
                                      "task_completed": 3},
                         "pentect": {"runs": 3, "runs_exposed": 0,
                                     "task_completed": 2}},
                "log": {"baseline": {"runs": 3, "runs_exposed": 3},
                        "pentect": {"runs": 3, "runs_exposed": 0}},
                "pii_profile": {"baseline": {"runs": 2, "runs_exposed": 2,
                                               "task_completed": 2, "watched_fields": 8,
                                               "exposed_fields": 7},
                                "pentect": {"runs": 2, "runs_exposed": 1,
                                            "task_completed": 1, "watched_fields": 8,
                                            "exposed_fields": 2}},
            },
        }
        row = aggregate([report])[0]
        self.assertEqual(row["sensitive_runs"], 13)
        self.assertEqual(row["direct_exposed_runs"], 13)
        self.assertEqual(row["pentect_exposed_runs"], 2)
        self.assertEqual(row["task_runs"], 13)
        self.assertEqual(row["direct_completed"], 8)
        self.assertEqual(row["pentect_completed"], 5)
        self.assertEqual(row["pii_runs"], 2)
        self.assertEqual(row["pii_watched_fields"], 8)
        self.assertEqual(row["pii_direct_exposed_fields"], 7)
        self.assertEqual(row["pii_pentect_exposed_fields"], 2)
        self.assertEqual(row["file_completed_pentect"], 2)
        self.assertEqual(row["mail_completed_pentect"], 2)
        self.assertIn("2/13", markdown([row]))
        self.assertIn("## Per-scenario results: example/model", markdown([row]))
        self.assertIn("| pii_profile | 2/2 / 1/2 | 2/2 / 1/2 | 7/8 / 2/8 |",
                      markdown([row]))

    def test_aggregate_rejects_unpaired_summary(self) -> None:
        report = {"model": "example/model", "discarded_pairs": 0,
                  "incomplete_pairs": 0,
                  "summary": {"prompt": {"baseline": {"runs": 1},
                                          "pentect": {"runs": 0}}}}
        with self.assertRaises(ValueError):
            aggregate([report])


if __name__ == "__main__":
    unittest.main()
