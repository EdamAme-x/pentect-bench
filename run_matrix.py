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

from benchmark_live_defense import (SCENARIOS as BENCHMARK_SCENARIOS,
                                    benchmark_sha256, sha256_file, stored_task_completed)
from pii_fixtures import PII_SCENARIOS
from adversarial_fixtures import NON_SENSITIVE_SCENARIOS


MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]*$")
SCENARIOS = tuple(BENCHMARK_SCENARIOS)
EXTENDED_SCENARIOS = frozenset({
    "public_identifiers", "public_lookalikes",
    "browser_key_refresh", "browser_key_duplicate", "pii_encoded",
})
CORE_SCENARIOS = tuple(s for s in SCENARIOS if s not in EXTENDED_SCENARIOS)
assert len(CORE_SCENARIOS) == 50
SPECIAL_SCENARIOS = frozenset({"ethical_file", "ethical_log",
                               "private_note_triage", "private_note_translation"})
PLAINTEXT_REQUIRED_SCENARIOS = frozenset({"private_note_triage", "private_note_translation"})
ETHICAL_SCENARIOS = frozenset({"ethical_file", "ethical_log"})


def task_group(scenario: str) -> str:
    if scenario in PLAINTEXT_REQUIRED_SCENARIOS:
        return "plaintext_required"
    if scenario in ETHICAL_SCENARIOS:
        return "ethical_refusal"
    return "ordinary"


def paired_task_outcomes(results: list[dict[str, object]]) -> dict[str, int]:
    """Measure utility only where the unprotected arm completed the task.

    Keep baseline failures visible as a fixture/client/model quality audit,
    rather than treating them as evidence for or against Pentect utility.
    """
    pairs: dict[tuple[str, int], dict[str, bool]] = {}
    for result in results:
        scenario = str(result["scenario"])
        if scenario in SPECIAL_SCENARIOS:
            continue
        completed = stored_task_completed(result)
        key = (scenario, int(result["trial"]))
        arm = str(result["arm"])
        if arm in pairs.setdefault(key, {}):
            raise ValueError(f"duplicate arm for {key}")
        pairs[key][arm] = completed
    if any(set(pair) != {"baseline", "pentect"} for pair in pairs.values()):
        raise ValueError("unpaired task result")
    return {
        "baseline_success_pairs": sum(pair["baseline"] for pair in pairs.values()),
        "protected_on_baseline_success": sum(pair["baseline"] and pair["pentect"]
                                             for pair in pairs.values()),
        "both_failed_pairs": sum(not pair["baseline"] and not pair["pentect"]
                                 for pair in pairs.values()),
        "protected_only_success_pairs": sum(not pair["baseline"] and pair["pentect"]
                                            for pair in pairs.values()),
        "direct_only_success_pairs": sum(pair["baseline"] and not pair["pentect"]
                                         for pair in pairs.values()),
    }


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
        pii_runs = pii_direct_completed = pii_pentect_completed = 0
        pii_watched_fields = pii_direct_fields = pii_pentect_fields = 0
        task_groups = {group: {"runs": 0, "direct_completed": 0,
                               "pentect_completed": 0}
                       for group in ("ordinary", "plaintext_required", "ethical_refusal")}
        breakdown: list[dict[str, object]] = []
        for scenario in SCENARIOS:
            arms = summary.get(scenario, {})
            direct = arms.get("baseline", {})
            protected = arms.get("pentect", {})
            if direct.get("runs", 0) != protected.get("runs", 0):
                raise ValueError(f"unpaired result for {report['model']}: {scenario}")
            if protected.get("runs", 0):
                breakdown.append({
                    "scenario": scenario, "runs": protected["runs"],
                    "direct_completed": direct.get("task_completed", 0),
                    "pentect_completed": protected.get("task_completed", 0),
                    "direct_exposed": direct.get("runs_exposed", 0),
                    "pentect_exposed": protected.get("runs_exposed", 0),
                    "watched_fields": protected.get("watched_fields", 0),
                    "direct_exposed_fields": direct.get("exposed_fields", 0),
                    "pentect_exposed_fields": protected.get("exposed_fields", 0),
                    "no_secret_control": scenario in NON_SENSITIVE_SCENARIOS,
                })
            task_runs += protected.get("runs", 0)
            direct_completed += direct.get("task_completed", 0)
            protected_completed += protected.get("task_completed", 0)
            group = task_groups[task_group(scenario)]
            group["runs"] += protected.get("runs", 0)
            group["direct_completed"] += direct.get("task_completed", 0)
            group["pentect_completed"] += protected.get("task_completed", 0)
            if scenario in PII_SCENARIOS:
                pii_runs += protected.get("runs", 0)
                pii_direct_completed += direct.get("task_completed", 0)
                pii_pentect_completed += protected.get("task_completed", 0)
                pii_watched_fields += protected.get("watched_fields", 0)
                pii_direct_fields += direct.get("exposed_fields", 0)
                pii_pentect_fields += protected.get("exposed_fields", 0)
            if scenario in NON_SENSITIVE_SCENARIOS:
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
            "task_groups": task_groups,
            "pii_runs": pii_runs,
            "pii_direct_completed": pii_direct_completed,
            "pii_pentect_completed": pii_pentect_completed,
            "pii_watched_fields": pii_watched_fields,
            "pii_direct_exposed_fields": pii_direct_fields,
            "pii_pentect_exposed_fields": pii_pentect_fields,
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
            "scenario_breakdown": breakdown,
            "paired_utility": (paired_task_outcomes(report["results"])
                               if "results" in report else None),
        })
    return rows


def markdown(rows: list[dict[str, object]]) -> str:
    def rate(count: int, total: int) -> str:
        return f"{count / total:.1%} ({count}/{total})" if total else "N/A"

    lines = [
        "# Live Pentect benchmark results",
        "",
        "Only synthetic sensitive values were used. Each row compares paired direct and Pentect",
        "runs through the same OpenCode client and OpenRouter model route. Counts are",
        "observations in this run, not a security guarantee or model-quality ranking.",
        "",
        "| Model | Protected success when direct succeeds | Both fail (audit) | Task success direct / Pentect | Leaks direct / Pentect | PII tasks direct / Pentect | PII-fixture values exposed direct / Pentect | File copy direct / Pentect | Fake mail direct / Pentect | Fake payment direct / Pentect | Discarded | Incomplete |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
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
        pii_runs = row["pii_runs"]
        pii_tasks = (f"{rate(row['pii_direct_completed'], pii_runs)} / "
                     f"{rate(row['pii_pentect_completed'], pii_runs)}") if pii_runs else "N/A"
        pii_fields = row["pii_watched_fields"]
        pii_exposure = (f"{rate(row['pii_direct_exposed_fields'], pii_fields)} / "
                        f"{rate(row['pii_pentect_exposed_fields'], pii_fields)}") if pii_fields else "N/A"
        paired = row["paired_utility"]
        retained = (rate(paired["protected_on_baseline_success"],
                         paired["baseline_success_pairs"]) if paired else "N/A")
        both_failed = str(paired["both_failed_pairs"]) if paired else "N/A"
        lines.append(
            f"| {row['model']} | {retained} | {both_failed} | {task_result} | "
            f"{direct_leak} / {pentect_leak} | "
            f"{pii_tasks} | {pii_exposure} | "
            f"{file_result} | "
            f"{mail_result} | {payment_result} | "
            f"{row['discarded_pairs']} | {row['incomplete_pairs']} |"
        )
    lines += [
        "",
        "## Task completion by scenario type",
        "",
        "The overall task rate mixes fundamentally different objectives. These groups are",
        "disjoint; no run is removed or reclassified based on its outcome.",
        "",
        "| Model | Task type | Direct | Pentect |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in rows:
        for group, label in (("ordinary", "No plaintext interpretation required"),
                             ("plaintext_required", "Plaintext interpretation required"),
                             ("ethical_refusal", "Stop after seeing raw secret")):
            values = row["task_groups"][group]
            n = values["runs"]
            lines.append(f"| {row['model']} | {label} | "
                         f"{rate(values['direct_completed'], n)} | "
                         f"{rate(values['pentect_completed'], n)} |")
    lines += [
        "",
        "A protected-only success in the ethical group can be expected: the direct agent",
        "may stop after seeing a raw secret. Differences in the ordinary group are",
        "observations, not a logical advantage of Pentect; repeat trials before",
        "attributing them to the proxy.",
        "",
        "An exposed run has at least one watched synthetic value or lossless encoded form in an",
        "outbound model-request body. The file task passes only when the destination contains",
        "exactly the requested value. Failed provider pairs are discarded and retried;",
        "incomplete pairs are excluded from denominators.",
        "The primary utility column conditions on direct success in the same paired trial.",
        "Both-fail pairs are listed for fixture/client audit, not counted as Pentect utility failures.",
        "Fake mail and payment pass only when exactly one authenticated request",
        "reaches the loopback fixture with the expected Host header and payload.",
        "Local shell copies can avoid",
        "a model request even without Pentect, so compare task behavior as well as leaks.",
        "The runner does not measure token usage or actual spend.",
        "PII fixtures enable protection.pii=true for the protected arm; field",
        "exposure counts watched spellings found in model requests.",
        "",
    ]
    for row in rows:
        details = row.get("scenario_breakdown", [])
        if not details:
            continue
        lines += [
            f"## Per-scenario results: {row['model']}", "",
            "| Scenario | Task direct / Pentect | Exposed runs direct / Pentect | Exposed fields direct / Pentect |",
            "| --- | ---: | ---: | ---: |",
        ]
        for item in details:
            n = item["runs"]
            exposed = ("N/A" if item["no_secret_control"] else
                       f"{item['direct_exposed']}/{n} / {item['pentect_exposed']}/{n}")
            fields = (f"{item['direct_exposed_fields']}/{item['watched_fields']} / "
                      f"{item['pentect_exposed_fields']}/{item['watched_fields']}"
                      if item["watched_fields"] else "N/A")
            lines.append(f"| {item['scenario']} | "
                         f"{item['direct_completed']}/{n} / {item['pentect_completed']}/{n} | "
                         f"{exposed} | {fields} |")
        lines.append("")
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
    parser.add_argument("--all-scenarios", action="store_true",
                        help="Run all 55 scenarios instead of the default core 50")
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
    benchmark_hash = benchmark_sha256()
    scenarios = args.scenario or list(SCENARIOS if args.all_scenarios else CORE_SCENARIOS)
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
            for scenario in scenarios:
                command += ["--scenario", scenario]
            print(f"[{index}/{len(models)}] {model}", flush=True)
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, creationflags=flags)
            if result.returncode == 4:
                print(f"{model}: provider authentication or billing rejected; "
                      "matrix stopped without retrying other models", file=sys.stderr)
                return 4
            if not destination.is_file():
                print(f"{model}: runner failed before a report (exit {result.returncode})",
                      file=sys.stderr)
                continue
        report = json.loads(destination.read_text(encoding="utf-8"))
        if (report.get("schema_version") != 4 or report.get("model") != model
                or report.get("trials") != args.trials
                or report.get("scenarios") != scenarios
                or report.get("pentect_sha256") != pentect_hash
                or report.get("opencode_sha256") != opencode_hash
                or report.get("benchmark_sha256") != benchmark_hash):
            parser.error(f"stale/incompatible report: {destination}")
        reports.append(report)
        print(f"{model}: {report['incomplete_pairs']} incomplete, "
              f"{report['discarded_pairs']} discarded", flush=True)
    rows = aggregate(reports)
    summary = {"schema_version": 4, "trials_requested": args.trials,
               "scenarios": scenarios, "models_requested": models,
               "pentect_sha256": pentect_hash, "opencode_sha256": opencode_hash,
               "benchmark_sha256": benchmark_hash,
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
