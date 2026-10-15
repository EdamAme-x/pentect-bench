"""Common lossless encodings must not be invisible to benchmark scoring."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exposure_variants import exposure_variants
from benchmark_live_defense import matched_watched_fields, request_strings


class ExposureVariantTests(unittest.TestCase):
    def test_lossless_forms_are_watched(self) -> None:
        value = "sk-test+with/slash:123"
        forms = exposure_variants(value)
        self.assertIn(value, forms)
        self.assertIn(base64.b64encode(value.encode()).decode(), forms)
        self.assertIn(value.encode().hex(), forms)
        self.assertIn(quote(value, safe=""), forms)

    def test_short_public_word_does_not_generate_common_encoded_false_positives(self) -> None:
        self.assertEqual(exposure_variants("ready"), frozenset({"ready"}))

    def test_relay_matches_encoded_form_without_retaining_body(self) -> None:
        secret = "sk-synthetic-credential"
        encoded = base64.b64encode(secret.encode()).decode()
        body = json.dumps({"messages": [{"content": encoded}]}).encode()
        self.assertEqual(matched_watched_fields({"secret": secret}, request_strings(body)),
                         {"secret"})
        self.assertEqual(matched_watched_fields({"secret": secret}, ["safe text"]), set())


if __name__ == "__main__":
    unittest.main()
