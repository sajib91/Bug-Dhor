# Benchmarks

Benchmark task definitions, harness code, configurations, dataset cards, and results for Bug Dhor.

## Status

The benchmark protocol is defined but **not executed**. No benchmark result is bundled with this repository. The generated
readiness bundle records `status: not_run`, `claimKind: null`, and `null` values for every metric. It is not evidence that
Bug Dhor improves, degrades, or leaves unchanged the security of AI-generated code.

## Structure

| Path | Purpose |
|------|---------|
| `configs/coding-benchmark-v1.json` | Pinned conditions E0-E7, model binding, metrics, leakage controls, and evidence requirements |
| `datasets/` | Dataset cards and access instructions; no data blobs |
| `harness/run_coding_benchmark.py` | Contract validation and non-fabricating bundle emission |
| `tasks/` | Ten realistic coding tasks with prompts held separate from vulnerability ground truth |
| `results/` | Generated results; gitignored by default |

## Conditions

| Condition | Description | Existing experiment group |
|-----------|-------------|---------------------------|
| E0 | Original AI-generated code | E0 |
| E1 | Security-prompted generation | E1 |
| E2 | AI generation plus static analysis | E2 |
| E3 | AI generation plus single-feature steering | E3 |
| E4 | AI generation plus multi-feature analysis | E4 |
| E5 | AI generation plus interaction-aware steering | E5 |
| E6 | Automated proposal-only repair | E6 |
| E7 | Full Bug Dhor workflow | E8 |

E7 uses the published E8 group internally so the existing E0-E8 experiment registry is unchanged.

## Tasks

The ten tasks cover authentication, REST APIs, database queries, file uploads, user input processing, command execution,
web applications, authorization, cryptographic operations, and repository-level modifications. Each task stores:

- the original coding task and prompt;
- a separate `groundTruth` block with CWE IDs, vulnerability classes, and localization targets;
- the repository snapshot reference and functional test command;
- token/time/trial budgets and verification requirements.

Ground truth is never placed in a prompt. The harness rejects a task whose prompt contains any declared
`forbiddenPromptTerms`.

## Running the readiness bundle

From the repository root:

```bash
.venv/bin/python benchmarks/harness/run_coding_benchmark.py
```

The runner writes `benchmarks/results/coding-benchmark-v1-readiness/` containing `manifest.json`, `config.json`,
`results.json`, the task catalog, empty raw-output streams, and a README. It exits successfully because `not_run` is the
honest outcome when no model provider, exact revision, analyzer rule pack, sandbox, or registered executor is available.

Environment variable **names** are checked for presence only; values are never written into reports.

## Rules

- Results must be reproducible from a recorded manifest (model revision, SAE hash, seeds, analyzer versions, dataset split hash).
- Security claims must name the analyzer/detector and version.
- Functional claims must name the test command and baseline.
- Negative and null results are retained.
- No benchmark number may be published without a linked experiment bundle and documented limitations.
- Execution-based scores remain `not_run` until a sandboxed executor is registered and independently verified.
