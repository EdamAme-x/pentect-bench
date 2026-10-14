#!/usr/bin/env python3
"""Run the paired live benchmark across models and aggregate value-free reports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from benchmark_live_defense import sha256_file


MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]*$")
SCENARIOS = ("prompt", "file", "log", "mail", "payment", "control")


def read_models(path: Path) -> list[str]:
    models = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    return validate_models(models)


def validate_models(models: list[str]) -> list[str]:
    if not models or len(models) != len(set(models)):
        raise ValueError("model list must be nonempty and contain no duplicates")
    if any(not MODEL_PATTERN.fullmatch(model) or ".." in model or "/" not in model
           for model in models):
        raise ValueError("model IDs must be plain provider/model slugs")
    return models


def report_name(model: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")[:60]
    digest = hashlib.sha256(model.encode()).hexdigest()[:10]
    return f"{slug}-{digest}.json"


def aggregate(reports: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for report in reports:
        summary = report.get("summary", {})
        direct_exposed = protected_exposed = sensitive_runs = 0
        direct_completed = protected_completed = task_runs = 0
        for scenario in SCENARIOS:
            arms = summary.get(scenario, {})
            direct = arms.get("baseline", {})
            protected = arms.get("pentect", {})
            if direct.get("runs", 0) != protected.get("runs", 0):
                raise ValueError(f"unpaired result for {report['model']}: {scenario}")
            task_runs += protected.get("runs", 0)
            direct_completed += direct.get("task_completed", 0)
            protected_completed += protected.get("task_completed", 0)
            if scenario == "control":
                continue
            sensitive_runs += protected.get("runs", 0)
            direct_exposed += direct.get("runs_exposed", 0)
            protected_exposed += protected.get("runs_exposed", 0)
        file_arms = summary.get("file", {})
        mail_arms = summary.get("mail", {})
        payment_arms = summary.get("payment", {})
        rows.append({
            "model": report["model"],
            "direct_exposed_runs": direct_exposed,
            "pentect_exposed_runs": protected_exposed,
            "sensitive_runs": sensitive_runs,
            "task_runs": task_runs,
            "direct_completed": direct_completed,
            "pentect_completed": protected_completed,
            "file_completed_direct": file_arms.get("baseline", {}).get("task_completed", 0),
            "file_completed_pentect": file_arms.get("pentect", {}).get("task_completed", 0),
            "file_runs": file_arms.get("pentect", {}).get("runs", 0),
            "mail_completed_direct": mail_arms.get("baseline", {}).get("task_completed", 0),
            "mail_completed_pentect": mail_arms.get("pentect", {}).get("task_completed", 0),
            "mail_runs": mail_arms.get("pentect", {}).get("runs", 0),
            "payment_completed_direct": payment_arms.get("baseline", {}).get("task_completed", 0),
            "payment_completed_pentect": payment_arms.get("pentect", {}).get("task_completed", 0),
            "payment_runs": payment_arms.get("pentect", {}).get("runs", 0),
            "discarded_pairs": report["discarded_pairs"],
            "incomplete_pairs": report["incomplete_pairs"],
        })
    return rows


def markdown(rows: list[dict[str, object]]) -> str:
    def rate(count: int, total: int) -> str:
        return f"{count / total:.1%} ({count}/{total})" if total else "N/A"

    lines = [
        "# Live Pentect benchmark results",
        "",
        "Only synthetic secrets were used. Each row compares paired direct and Pentect",
        "runs through the same OpenCode client and OpenRouter model route. Counts are",
        "observations in this run, not a security guarantee or model-quality ranking.",
        "",
        "| Model | Task success direct / Pentect | Leaks direct / Pentect | File copy direct / Pentect | Fake mail direct / Pentect | Fake payment direct / Pentect | Discarded | Incomplete |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        n = row["sensitive_runs"]
        f = row["file_runs"]
        direct_leak = rate(row["direct_exposed_runs"], n)
        pentect_leak = rate(row["pentect_exposed_runs"], n)
        file_result = (f"{row['file_completed_direct']}/{f} / "
                       f"{row['file_completed_pentect']}/{f}") if f else "N/A"
        mail_runs = row["mail_runs"]
        mail_result = (f"{row['mail_completed_direct']}/{mail_runs} / "
                       f"{row['mail_completed_pentect']}/{mail_runs}") if mail_runs else "N/A"
        payment_runs = row["payment_runs"]
        payment_result = (f"{row['payment_completed_direct']}/{payment_runs} / "
                          f"{row['payment_completed_pentect']}/{payment_runs}") if payment_runs else "N/A"
        task_runs = row["task_runs"]
        task_result = (f"{rate(row['direct_completed'], task_runs)} / "
                       f"{rate(row['pentect_completed'], task_runs)}") if task_runs else "N/A"
        lines.append(
            f"| {row['model']} | {task_result} | "
            f"{direct_leak} / {pentect_leak} | "
            f"{file_result} | "
            f"{mail_result} | {payment_result} | "
            f"{row['discarded_pairs']} | {row['incomplete_pairs']} |"
        )
    lines += [
        "",
        "A leak means the exact generated secret appeared in at least one outbound",
        "model-request body. The file task passes only when the destination contains",
        "exactly the requested value. Failed provider pairs are discarded and retried;",
        "incomplete pairs are excluded from denominators.",
        "Fake mail and payment pass only when exactly one authenticated request",
        "reaches the loopback fixture with the expected Host header and payload.",
        "Local shell copies can avoid",
        "a model request even without Pentect, so compare task behavior as well as leaks.",
        "The runner does not measure token usage or actual spend.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pentect", type=Path, required=True)
    parser.add_argument("--opencode", type=Path, required=True)
    parser.add_argument("--auth-file", type=Path)
    parser.add_argument("--key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--models-file", type=Path, default=Path(__file__).with_name("models.txt"))
    parser.add_argument("--model", action="append", help="Override models file; repeat for multiple models")
    parser.add_argument("--scenario", choices=SCENARIOS, action="append")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-provider-retries", type=int, default=2)
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    parser.add_argument("--resume", action="store_true", help="Reuse existing per-model reports")
    parser.add_argument("--fail-on-leak", action="store_true")
    args = parser.parse_args()
    if args.trials < 1 or args.timeout < 1 or args.max_provider_retries < 0:
        parser.error("trials and timeout must be positive; retries must be nonnegative")
    try:
        models = validate_models(args.model) if args.model else read_models(args.models_file)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if not args.pentect.is_file() or not args.opencode.is_file():
        parser.error("--pentect and --opencode must be executable files")
    args.report_dir.mkdir(parents=True, exist_ok=True)
    pentect_hash = sha256_file(args.pentect)
    opencode_hash = sha256_file(args.opencode)
    scenarios = args.scenario or list(SCENARIOS)
    reports = []
    runner = Path(__file__).with_name("benchmark_live_defense.py")
    for index, model in enumerate(models, 1):
        destination = args.report_dir / report_name(model)
        if not (args.resume and destination.is_file()):
            command = [
                sys.executable, str(runner), "--pentect", str(args.pentect),
                "--opencode", str(args.opencode), "--model", model,
                "--trials", str(args.trials), "--timeout", str(args.timeout),
                "--max-provider-retries", str(args.max_provider_retries),
                "--key-env", args.key_env, "--report", str(destination),
            ]
            if args.auth_file:
                command += ["--auth-file", str(args.auth_file)]
            for scenario in args.scenario or []:
                command += ["--scenario", scenario]
            print(f"[{index}/{len(models)}] {model}", flush=True)
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, creationflags=flags)
            if not destination.is_file():
                print(f"{model}: runner failed before a report (exit {result.returncode})",
                      file=sys.stderr)
                continue
        report = json.loads(destination.read_text(encoding="utf-8"))
        if (report.get("schema_version") != 2 or report.get("model") != model
                or report.get("trials") != args.trials
                or report.get("scenarios") != scenarios
                or report.get("pentect_sha256") != pentect_hash
                or report.get("opencode_sha256") != opencode_hash):
            parser.error(f"stale/incompatible report: {destination}")
        reports.append(report)
        print(f"{model}: {report['incomplete_pairs']} incomplete, "
              f"{report['discarded_pairs']} discarded", flush=True)
    rows = aggregate(reports)
    summary = {"schema_version": 2, "trials_requested": args.trials,
               "scenarios": scenarios, "models_requested": models,
               "pentect_sha256": pentect_hash, "opencode_sha256": opencode_hash,
               "models_reported": [report["model"] for report in reports], "rows": rows}
    (args.report_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.report_dir / "summary.md").write_text(markdown(rows), encoding="utf-8")
    if len(reports) != len(models) or any(row["incomplete_pairs"] for row in rows):
        return 2
    if args.fail_on_leak and any(row["pentect_exposed_runs"] for row in rows):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
