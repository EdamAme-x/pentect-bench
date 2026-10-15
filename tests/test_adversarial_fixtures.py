"""Offline coverage for adversarial benchmark setup and scoring."""
from __future__ import annotations

import base64
from contextlib import closing
import gzip
import html
import json
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adversarial_fixtures import (ADVERSARIAL_SCENARIOS, NON_SENSITIVE_SCENARIOS,
                                  make_adversarial_fixture)
from benchmark_live_defense import SCENARIOS, prepare_git_diff, prepare_git_history


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
            elif scenario == "jwt_payload":
                jwt = json.loads(fixture.contents)["jwt"]
                self.assertEqual(jwt, fixture.watched["jwt"])
                self.assertEqual(jwt.split(".")[1], fixture.watched["payload"])
                payload = fixture.watched["payload"]
                decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
                self.assertEqual(json.loads(decoded)["secret"], secret)
            elif scenario == "pem_block":
                self.assertEqual(base64.b64decode(fixture.watched["pem_body"]).decode(), secret)
            elif scenario == "html_entities":
                self.assertIn(fixture.watched["html_entities"], fixture.contents)
                self.assertEqual(html.unescape(fixture.watched["html_entities"]), secret)
            elif scenario == "unicode_escaped_json":
                self.assertIn(fixture.watched["unicode_escapes"], fixture.contents)
                self.assertEqual(json.loads(fixture.contents)["token"], secret)
            elif scenario == "env_dump":
                self.assertNotIn(secret, fixture.contents)
                self.assertEqual(fixture.watched["environment_token"], secret)
            elif scenario == "chunked_token":
                parts = json.loads(fixture.contents)["secret_parts"]
                self.assertEqual("".join(parts), fixture.watched["reconstructed"])
                self.assertEqual(parts, [fixture.watched["part_one"],
                                         fixture.watched["part_two"]])
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

    def test_git_diff_contains_secret_only_in_worktree(self) -> None:
        fixture = make_adversarial_fixture("git_diff", "sk-synthetic-only")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_git_diff(project, fixture.contents)
            old = subprocess.check_output(
                ["git", "-C", str(project), "show", "HEAD:config.env"], text=True)
            diff = subprocess.check_output(
                ["git", "-C", str(project), "diff", "--", "config.env"], text=True)
            self.assertNotIn("sk-synthetic-only", old)
            self.assertIn("sk-synthetic-only", diff)

    def test_archive_and_database_fixtures_roundtrip(self) -> None:
        secret = "sk-synthetic-only"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zipped = make_adversarial_fixture("zip_archive", secret)
            with zipfile.ZipFile(root / zipped.filename, "w") as archive:
                archive.writestr("config.json", zipped.contents)
            with zipfile.ZipFile(root / zipped.filename) as archive:
                self.assertEqual(json.loads(archive.read("config.json"))["api_token"], secret)
            gzipped = make_adversarial_fixture("gzip_archive", secret)
            with gzip.open(root / gzipped.filename, "wt", encoding="utf-8") as stream:
                stream.write(gzipped.contents)
            with gzip.open(root / gzipped.filename, "rt", encoding="utf-8") as stream:
                self.assertEqual(json.load(stream)["api_token"], secret)
            database_fixture = make_adversarial_fixture("sqlite_db", secret)
            with closing(sqlite3.connect(root / database_fixture.filename)) as database:
                database.executescript(database_fixture.contents)
                value = database.execute(
                    "SELECT value FROM settings WHERE name = 'api_token'").fetchone()[0]
            self.assertEqual(value, secret)


if __name__ == "__main__":
    unittest.main()
