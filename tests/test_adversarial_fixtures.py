"""Offline coverage for adversarial benchmark setup and scoring."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adversarial_fixtures import (ADVERSARIAL_SCENARIOS, NON_SENSITIVE_SCENARIOS,
                                  make_adversarial_fixture)
from benchmark_live_defense import SCENARIOS, prepare_git_history


class AdversarialFixtureTests(unittest.TestCase):
    def test_each_fixture_has_a_prompt_and_answer(self) -> None:
        for scenario in ADVERSARIAL_SCENARIOS:
            with self.subTest(scenario=scenario):
                fixture = make_adversarial_fixture(scenario, "sk-synthetic-only")
                self.assertIn(scenario, SCENARIOS)
                self.assertTrue(fixture.expected)
                self.assertTrue(fixture.contents)
                self.assertNotIn("@gmail.com", fixture.contents)
                if scenario in NON_SENSITIVE_SCENARIOS:
                    self.assertFalse(fixture.watched)
                else:
                    self.assertTrue(fixture.watched)

    def test_all_watched_encoded_values_are_in_fixture_or_derived(self) -> None:
        secret = "sk-synthetic-only"
        for scenario in ADVERSARIAL_SCENARIOS:
            fixture = make_adversarial_fixture(scenario, secret)
            if scenario == "encoded_token":
                data = json.loads(fixture.contents)
                self.assertEqual(base64.b64decode(data["token_b64"]).decode(), secret)
                self.assertEqual(bytes.fromhex(data["token_hex"]).decode(), secret)
            elif scenario == "url_credentials":
                self.assertIn(fixture.watched["url_password"], fixture.contents)
                self.assertEqual(unquote(fixture.watched["url_password"]),
                                 fixture.watched["password"])
            else:
                for label, value in fixture.watched.items():
                    with self.subTest(scenario=scenario, label=label):
                        self.assertIn(value, fixture.contents)

    def test_git_secret_exists_only_in_prior_commit(self) -> None:
        fixture = make_adversarial_fixture("git_history", "sk-synthetic-only")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_git_history(project, fixture.contents)
            current = (project / fixture.filename).read_text()
            previous = subprocess.check_output(
                ["git", "-C", str(project), "show", "HEAD~1:history.env"], text=True)
            self.assertNotIn("sk-synthetic-only", current)
            self.assertIn("sk-synthetic-only", previous)
            self.assertIn("status=ready", previous)

    def test_stderr_helper_behavior_is_intentionally_nonzero(self) -> None:
        # The benchmark writes this script verbatim into each isolated project.
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "state.txt"
            source.write_text("token=sk-synthetic-only\nstatus=ready\n")
            helper = Path(directory) / "diagnostic.py"
            helper.write_text(
                "import pathlib, sys\n"
                "for line in pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():\n"
                "    print(line, file=sys.stderr)\n"
                "sys.exit(2)\n")
            result = subprocess.run([sys.executable, str(helper), str(source)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("status=ready", result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
