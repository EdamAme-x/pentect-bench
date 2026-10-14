"""Synthetic PII fixtures must be useful without using real contacts."""
from __future__ import annotations

import base64
import csv
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pii_fixtures import PII_SCENARIOS, make_fixture  # noqa: E402


class PiiFixtureTests(unittest.TestCase):
    def test_all_fixtures_are_synthetic_and_have_scored_fields(self) -> None:
        for scenario in PII_SCENARIOS:
            with self.subTest(scenario=scenario):
                fixture = make_fixture(scenario, "sk-synthetic-seed")
                if scenario == "pii_encoded":
                    contact_text = base64.b64decode(
                        fixture.contents.split("payload=", 1)[1]).decode()
                elif scenario == "pii_obfuscated":
                    contact_text = fixture.contents.replace(" [at] ", "@").replace(
                        " [dot] ", ".")
                else:
                    contact_text = fixture.contents
                self.assertIn("example.invalid", contact_text)
                self.assertGreaterEqual(len(fixture.watched), 4)
                self.assertTrue(fixture.expected)
                self.assertNotIn("@gmail.com", fixture.contents)

    def test_csv_and_json_tasks_have_the_expected_answers(self) -> None:
        csv_fixture = make_fixture("pii_csv", "sk-synthetic-seed")
        rows = list(csv.DictReader(io.StringIO(csv_fixture.contents)))
        self.assertEqual(sum(row["status"] == "paid" for row in rows), 2)
        json_fixture = make_fixture("pii_json", "sk-synthetic-seed")
        customers = json.loads(json_fixture.contents)["customers"]
        self.assertEqual(sum(customer["active"] for customer in customers), 2)

    def test_encoded_payload_is_decodable_and_watched(self) -> None:
        fixture = make_fixture("pii_encoded", "sk-synthetic-seed")
        encoded = fixture.contents.split("payload=", 1)[1].strip()
        record = json.loads(base64.b64decode(encoded))
        self.assertEqual(record["status"], fixture.expected)
        self.assertEqual(fixture.watched["encoded_record"], encoded)


if __name__ == "__main__":
    unittest.main()
