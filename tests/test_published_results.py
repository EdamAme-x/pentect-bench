"""Check committed evidence remains value-free and internally consistent."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmark_live_defense import summarize  # noqa: E402


class PublishedResultsTests(unittest.TestCase):
    def test_raw_reports_have_no_values_and_recompute(self) -> None:
        reports = sorted((ROOT / "results" / "raw-2026-10-14").glob("*.json"))
        self.assertEqual(len(reports), 12)
        models = set()
        for path in reports:
            raw = path.read_text(encoding="utf-8")
            self.assertNotRegex(raw, r"sk-[A-Za-z0-9_-]{12,}")
            self.assertNotIn("C:\\Users\\", raw)
            self.assertNotIn("Authorization: Bearer", raw)
            report = json.loads(raw)
            models.add(report["model"])
            self.assertEqual(report["summary"], summarize(report["results"]))
        self.assertEqual(len(models), 12)


if __name__ == "__main__":
    unittest.main()
