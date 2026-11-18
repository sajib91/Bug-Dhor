# Benchmark Harness

`run_coding_benchmark.py` is a contract validator and evidence-bundle emitter. It deliberately does not invent model
generations, detector findings, repairs, or verification evidence.

## Current behavior

- Loads `../configs/coding-benchmark-v1.json` and the ten task files.
- Computes a stable canonical config hash that ignores `_documentation` keys.
- Rejects prompts containing declared ground-truth terms.
- Checks only the presence of required environment variable names; values are never read into reports.
- Writes a complete bundle whose outcomes are `not_run` when prerequisites are absent.
- Records every declared metric as `{"value": null, "measured": false, "reason": "not_run"}`.

## Invocation

```bash
.venv/bin/python benchmarks/harness/run_coding_benchmark.py \
  --config benchmarks/configs/coding-benchmark-v1.json \
  --output benchmarks/results/coding-benchmark-v1-readiness
```

## Output bundle

| File | Purpose |
|------|---------|
| `manifest.json` | Run id, config hash, git commit, environment, prerequisites, contract issues |
| `config.json` | Exact pinned configuration used for this bundle |
| `results.json` | Declared conditions, tasks, metrics, evidence references, and limitations |
| `tasks/catalog.json` | Task definitions and per-task hashes |
| `raw/prompts.jsonl` | Original prompts without ground truth |
| `raw/generations.jsonl` | Reserved for real model outputs; empty when not run |
| `raw/detections.jsonl` | Reserved for real Bug Dhor detector output; empty when not run |
| `raw/repairs.jsonl` | Reserved for proposal-only repair output; empty when not run |
| `raw/verification.jsonl` | Reserved for independent verification output; empty when not run |
| `README.md` | Plain-language warning that the bundle is not a benchmark result |

## Execution prerequisites

Execution scoring requires all of the following:

1. A configured model provider and an exact resolved model revision.
2. Pinned analyzer rule-pack hash.
3. An explicitly configured sandbox profile.
4. A registered executor that can drive generation, Bug Dhor detection, proposal-only repair, and independent verification.

Without these, execution results remain `not_run`. The harness never falls back to host execution of untrusted project
tests.
