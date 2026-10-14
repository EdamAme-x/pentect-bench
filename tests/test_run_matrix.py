"""Offline tests for model selection and value-free matrix scoring."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_matrix import aggregate, markdown, read_models, report_name, validate_models  # noqa: E402


class MatrixTests(unittest.TestCase):
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
            },
        }
        row = aggregate([report])[0]
        self.assertEqual(row["sensitive_runs"], 11)
        self.assertEqual(row["direct_exposed_runs"], 11)
        self.assertEqual(row["pentect_exposed_runs"], 1)
        self.assertEqual(row["task_runs"], 11)
        self.assertEqual(row["direct_completed"], 6)
        self.assertEqual(row["pentect_completed"], 4)
        self.assertEqual(row["file_completed_pentect"], 2)
        self.assertEqual(row["mail_completed_pentect"], 2)
        self.assertIn("1/11", markdown([row]))

    def test_aggregate_rejects_unpaired_summary(self) -> None:
        report = {"model": "example/model", "discarded_pairs": 0,
                  "incomplete_pairs": 0,
                  "summary": {"prompt": {"baseline": {"runs": 1},
                                          "pentect": {"runs": 0}}}}
        with self.assertRaises(ValueError):
            aggregate([report])


if __name__ == "__main__":
    unittest.main()
