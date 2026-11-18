# End-to-end test report

- Date: 2026-11-18
- Worktree HEAD: `709c92b00d8c17fe4ba32c977f4bdb312d2c8ae5`
- State: all integration changes are uncommitted
- Overall result: **the implemented local A–L integration path passes end-to-end; the research system is not complete**

## 1. Environment

| Component | Value |
|---|---|
| OS | macOS 26.3.1 arm64 |
| Python | 3.11.14 |
| Node | 25.9.0 |
| VS Code | `/Applications/Visual Studio Code.app/Contents/MacOS/Code` |
| Backend | Real local FastAPI server started by the integration harness |
| Extension | Loaded as a development extension in a real Extension Host |

The Extension Host harness started a real backend on an ephemeral port, created a disposable workspace, configured the extension to use that backend, and shut both down after the run.

## 2. Commands and results

| Command | Result |
|---|---|
| `../.venv/bin/python -m pytest` in `security-engine/` | **638 passed, 0 failed** |
| `npm run extension:test` | **295 passed, 0 failed** |
| `npm run extension:lint` | **clean** |
| `npm run extension:test:integration` | **passed**, `Exit code: 0` |
| `.venv/bin/python research/experiments/model_compatibility/run_compatibility_matrix.py` | completed; config hash unchanged |
| `.venv/bin/python benchmarks/harness/run_coding_benchmark.py --config benchmarks/configs/coding-benchmark-v1.json --output benchmarks/results/coding-benchmark-v1-readiness` | completed with `status: not_run` and `contractIssues: []` |
| Prettier check on all changed JavaScript files | clean; changed files were formatted where needed |
| Repository-wide `npm run format:check` | **fails on a pre-existing baseline**: 57 files would be reformatted, 178 already formatted |
| Ruff on changed Python files using project config | 129 findings, down from 137 at HEAD; no new net violations |

The repository-wide format failure was not introduced by this integration pass, and unrelated files were not reformatted. The Python files changed by this work have fewer Ruff findings than their committed versions.

## 3. Defects found and fixed during e2e

1. **Real finding rejected before publication.** The backend serialized optional `sourceReferences` fields as `null`; the extension validator treated those as invalid strings and silently dropped the finding. Fixed by treating null optional fields as absent while continuing to validate supplied values. Added a regression test.
2. **Diagnostic assertion timing.** VS Code diagnostic collection updates are observable asynchronously. The harness now bounded-polls for the diagnostic and reports useful context on failure. No production behavior was changed for this issue.
3. **Risk laundering resistance.** Client normalization rejects any attempt to relabel a heuristic index as calibrated probability. Tests cover both acceptance of labelled heuristic evidence and rejection of mislabelled evidence.

## 4. Workflow coverage

### 4.1 Editor and transport

The e2e run verified:

- backend health against the real service;
- graceful handling of an unreachable backend;
- unsaved-editor source hashing against the buffer rather than the disk copy;
- explicit source-sharing consent gates;
- workspace and selection scans;
- dashboard singleton tab opening;
- cancellation, debouncing, save-triggered scans, pasted changes, concurrent document independence, and unsupported/skipped paths in unit tests.

### 4.2 Real detection path

A vulnerable Python fixture produced a real backend finding:

- CWE: `CWE-89`
- Rule: `ast.dynamic-sql-query`
- Evidence sources included `bugdhor.ast` and `bugdhor.dfg`
- Risk: `scoreKind=heuristic_index`, `probability=null`, `probabilityKind=null`
- Config hash observed for risk enrichment: `422b0ac3f07f036154012a9a59aee928ba3c578853d6a83cc129f1994c7415f8`

The real finding became a native VS Code diagnostic. Hover displayed backend explanation, CWE, evidence, source information, and the heuristic risk label without presenting it as a probability.

### 4.3 Explanation

Explanation for the matching backend finding returned:

- `analysisAvailable: true`
- `claimKinds: ["observation"]`
- graph sections including `why_detected`, `source_to_sink_paths`, and `limitations`

Explanation remains **Partial**: it is an evidence report, not model-internal attribution, calibrated risk, or a localization score. Unmatched client-supplied finding IDs return `analysisAvailable: false` and no graph.

### 4.4 Honest research stubs

The e2e run verified that SAE, counterfactual, and steering HTTP workflows remain honest stubs. They produced no invented features, effects, validity estimates, steering plans, or evaluations.

### 4.5 Repair and verification

The real backend probe observed:

- repair state: `INCONCLUSIVE`
- patch: `None`
- `requiresApproval: true`
- `analysisAvailable: false` for the repair result

This is an explicit unavailable proposal result, not a successful repair and not a clean scan.

Verification with an explicit caller-supplied patch observed:

- verdict: `inconclusive`
- classification: `inconclusive_verification`
- `analysisAvailable: true`
- declared sandbox backend: `docker`

The fixture source remained unchanged after the repair/verification workflow. No patch was applied automatically, and no patch was marked secure.

### 4.6 Feedback and research separation

Feedback recording was exercised through the real backend. Monitoring hooks and research tracking record bounded metadata and hashes; they do not publish diagnostics or attribute edits to a person or model.

## 5. Stage A–L evidence

| Stage | E2e evidence |
|---|---|
| A change_detection | Real VS Code document events, version tracking, and monitor statistics |
| B region_identification | Function-level scoping observed for pasted code |
| C syntax_analysis | Real vulnerable Python fixture parsed |
| D ast_analysis | `ast.dynamic-sql-query` finding |
| E cfg_dfg_analysis | DFG evidence source on the real finding |
| F taint_analysis | Potential-flow analysis available; no exploitability claim |
| G static_analysis | Optional analyzers reported explicitly; no synthetic clean stage |
| H sae_features | Honest unavailable stub |
| I counterfactual_analysis | Honest unavailable stub |
| J evidence_fusion | Heuristic risk index observed |
| K classification | Real CWE-89 finding |
| L diagnostic_export | Native diagnostic, hover, repair command path, and workspace containment |

## 6. Harness results

### Compatibility

The compatibility matrix rerun produced config hash `10b8282eac8a9c104fd8bdfb0b936078f3f2021e0868fcdc92c31472e8d1d540`. Registered production targets and all assistant integration targets remain `unavailable`. Local 0.5B Qwen checkpoints are research probes only (`LIM-COMPAT-01`).

### Benchmark readiness

The benchmark harness produced:

- config hash: `3432152cc3ad0ea5ed45c456031b38cc6c04705ce3de3dcb0f6b593ac454e09c`
- `contractIssues: []`
- overall `status: not_run`
- `claimKind: null`
- every metric `value: null`, `measured: false`, `reason: "not_run"`

Reasons include missing model path/revision environment variables, unresolved model revision, missing sandbox profile, unpinned analyzer rule pack, and no registered benchmark executor. This is a readiness bundle, not a benchmark result.

## 7. Not covered

The following were not demonstrated and must not be inferred from the passing e2e run:

- live hosted assistant provider generation;
- production model or SAE checkpoint execution through the extension;
- D/E/F activation, SAE, or steering hooks in the operational path;
- calibrated probability;
- paper-level counterfactual screening or causal claims;
- adequate-sandbox execution of untrusted code;
- verified secure patch application;
- benchmark or empirical research results;
- Windows, Python 3.12–3.14, native CodeQL/Joern, browser matrix, and assistive-technology checks.

## 8. Final determination

The Extension Host e2e run provides real evidence for the implemented local path: editor monitoring, backend transport, preprocessing/program analysis, real CWE-89 detection, heuristic risk, native diagnostics, hover, honest research stubs, proposal-only repair, explicit-patch verification, feedback recording, and unchanged source.

It does **not** establish research completion, security guarantees, calibrated risk, causal effects, model-internal explanations, autonomous repair, verified secure patches, or benchmark performance.
