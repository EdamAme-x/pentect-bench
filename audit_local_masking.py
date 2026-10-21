"""Value-free deterministic screening of textual adversarial fixtures.

This is a fast detector screen, not an agent-task or gateway benchmark. It
reports watched fixture labels only; synthetic values and handles stay local.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from adversarial_fixtures import (
    ADVERSARIAL_SCENARIOS,
    NON_SENSITIVE_SCENARIOS,
    make_adversarial_fixture,
)


SKIP_NON_TEXT = frozenset((
    "git_history", "git_diff", "sqlite_db", "zip_archive", "gzip_archive",
    "env_dump", "browser_key_refresh", "browser_key_duplicate",
))


def mask(pentect: Path, source: str) -> str:
    result = subprocess.run(
        [str(pentect), "mask", "--kind", "text"],
        input=source.encode("utf-8"), capture_output=True, check=True,
    )
    return result.stdout.decode("utf-8")


def wrapped(source: str) -> str:
    lines = source.splitlines()
    numbered = "\n".join(f"{index}: {line}" for index, line in enumerate(lines, 1))
    return (
        "<path>C:\\fixture\\source.txt</path>\n<type>text</type>\n<content>\n"
        f"{numbered}\n\n(End of file - total {len(lines)} lines)\n</content>"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument("--scenario", action="append", choices=ADVERSARIAL_SCENARIOS)
    args = parser.parse_args()
    synthetics = (
        "sk-" + "Ab3_" * 9,
        "sk-" + "q7N_bR2XvP5mT8cL4eD6hJ9sY3wK1zA0uF",
        "tok_" + "6f3A9cB2dE7hJ4kL8mN1pQ5rS0tV6wX9yZ2aC",
    )
    results = []
    for seed_index, synthetic in enumerate(synthetics):
        for scenario in args.scenario or ADVERSARIAL_SCENARIOS:
            if scenario in SKIP_NON_TEXT or scenario in NON_SENSITIVE_SCENARIOS:
                continue
            fixture = make_adversarial_fixture(scenario, synthetic)
            for shape, source in (("plain", fixture.contents),
                                  ("opencode_read", wrapped(fixture.contents))):
                output = mask(args.pentect, source)
                watched = {name: value for name, value in fixture.watched.items()
                           if value and value in source}
                survivors = sorted(name for name, value in watched.items() if value in output)
                results.append({
                    "scenario": scenario, "shape": shape, "seed_index": seed_index,
                    "watched_literal_fields": len(watched), "survivor_labels": survivors,
                })
                print(json.dumps(results[-1], sort_keys=True))
    print(json.dumps({
        "summary": {"checks": len(results),
                    "checks_with_survivors": sum(bool(item["survivor_labels"])
                                                  for item in results)}
    }))
    return int(any(item["survivor_labels"] for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
