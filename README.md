# Pentect Bench

Paired, live benchmark for an AI coding agent with and without
[Pentect](https://github.com/EdamAme-x/pentect). It measures two separate
outcomes: whether a synthetic secret reached the model provider, and whether
the agent completed the requested local task. The initial client is OpenCode;
the provider route is OpenRouter.

The repository includes no credentials, real secret values, client transcripts,
or request bodies. Live runs use freshly generated synthetic secrets. A local
relay observes each outbound model request before forwarding it and records
only counts and statuses. The real OpenRouter key stays in the benchmark
process and is never passed to OpenCode or Pentect.

## Run

Requirements: Python 3.11+, installed OpenCode and Pentect executables, an
OpenRouter API key, and network access. **A live run makes paid API calls.**
Start with one model and one trial before running the full matrix.

```sh
python run_matrix.py \
  --pentect /path/to/pentect \
  --opencode /path/to/opencode \
  --model openai/gpt-4o-mini \
  --trials 1 \
  --report-dir reports/smoke
```

Set `OPENROUTER_API_KEY` in the calling environment. As an alternative, pass
`--auth-file /path/to/opencode/auth.json`; the runner reads
`{"openrouter":{"key":"..."}}` without writing that value to a report.
Do not put a real key in commands, the model list, or this repository.

Omit `--model` to run every model in [models.txt](models.txt), or repeat
`--model` to choose a subset. `--scenario` can select any of `prompt`, `file`,
`log`, and `control`; the default is all four. `--resume` reuses matching
per-model reports, so omit it for a fresh measurement. `--fail-on-leak` returns
exit code 3 if a completed Pentect trial exposed a synthetic secret.

```sh
python run_matrix.py \
  --pentect /path/to/pentect \
  --opencode /path/to/opencode \
  --trials 3 \
  --report-dir reports/full
```

The output directory contains one value-free JSON report per model plus
`summary.json` and `summary.md`. It is gitignored by default. Exit code 2
means at least one paired trial remained incomplete after provider retries.
Do not compare incomplete rows as if every model had the same sample size.

## Scenarios and scoring

| Scenario | Synthetic input | Utility check |
| --- | --- | --- |
| Prompt | Credential in user instruction | Final marker |
| File | `TEST_TOKEN` in `.env` | Destination contains exactly its value |
| Log | Bearer token in local log | Local read and final marker |
| Control | No secret | Requested file contains `ready` |

Each trial creates separate homes and projects for direct and Pentect runs.
Their order alternates. A pair is discarded and retried if either provider
arm fails. The leak metric counts a trial once when the exact generated secret
appears in any outbound model-request body. Utility is scored independently;
locally writing a value does not prove it stayed out of model requests.

This is an end-to-end workflow test, **not** a proof of security or a general
intelligence benchmark. It observes only traffic through its model relay, and
exact-string matching misses encoded, transformed, partial, image-only, or
other out-of-band disclosures. The runner does not measure tokens, actual API
charges, or Pentect-only CPU overhead. Three trials per scenario are too few
to estimate a stable success rate. Provider routing and model behavior can
change between runs.

## Offline tests

```sh
python -m unittest discover -s tests -v
```

Offline CI never contacts OpenRouter. The first broad live sweep is recorded
in [results/2026-10-14.md](results/2026-10-14.md).
