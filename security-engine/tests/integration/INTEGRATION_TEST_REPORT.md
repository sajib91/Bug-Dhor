# CRAFT-Sec End-to-End Integration Test Report

**Date:** 2026-11-16  
**Workspace:** `/Users/md.khayrulislamsajib/Downloads/CRAFT-Sec` (git repo, darwin)  
**Scope:** Integration wiring across VS Code extension interfaces, FastAPI backend, preprocessing/parsing, AST/CFG/DFG, taint analysis, static-analysis adapters, vulnerability detection, explainability, repair workflow, independent verification, and experimental/evaluation module availability; with orchestration, error propagation, cancellation/progress infrastructure, structured logging, and result persistence.

> This report is based on actual local test runs in this environment. No benchmark outcomes, p-values, confidence intervals, or simulated component outputs were fabricated. Components unavailable in this environment are reported as unavailable/inconclusive/not run.

## 1. Components and documented interfaces

| Component | Implementation / interface | Integration status | Notes |
|---|---|---|---|
| VS Code extension | `vscode-extension/src/api/{apiClient,securityEngineService,securityResultService}.js`, `extension.js` | **Interface-aligned (existing contract preserved)** | Extension calls versioned HTTP endpoints (`/api/v1/health`, `/scan/*`, `/detection/analyze`, `/explanation/analyze`, `/features/extract`, `/counterfactual/analyze`, `/prevention/steer`, `/repair/generate`, `/verification/run`) and validates responses. No extension-side behavior changes were required for backend integration; backend responses remain schema-compatible. Extension not executed in this environment (UI/VS Code runtime). |
| FastAPI backend | `security-engine/src/craftsec/api/app.py`, routes under `api/routes/*`, schemas under `api/schemas/*` | **Integrated** | App initializes `Orchestrator` and `JobStore` (`app.state.job_store`) with structured JSON logging (`craftsec.core.logging`) and request middleware. Jobs routes added: `GET /api/v1/jobs/{job_id}`, `GET /api/v1/jobs/{job_id}/result`, `POST /api/v1/jobs/{job_id}/cancel`. |
| Code preprocessing / parsing | `craftsec.parsing.parser.parse_source` | **Integrated** | Scan/detection/explanation run parsing per analyzed source and report `preprocessing` stage status/data. |
| AST / CFG / DFG analysis | `craftsec.program_analysis.analysis.analyze_parsed` | **Integrated** | Program analysis executed per source and reported in `program_analysis` stage. |
| Taint analysis | `craftsec.program_analysis.taint.analyze_taint` | **Integrated** | Taint analysis executed (when program analysis succeeds) and passed into detection; reported in `program_analysis`/`detection` coverage. |
| Static-analysis tools | `craftsec.static.runner.StaticAnalysisRunner`, `SemgrepAdapter`, `BanditAdapter` (best-effort, configured adapters) | **Integrated (honest availability)** | Runner attempts configured adapters; in this environment executables are missing, reported as `static_evidence: unavailable` with explicit tool statuses/reasons (no fabricated clean scan). CodeQL/Joern not auto-configured (require explicit config/license/DB/query artifacts). |
| Vulnerability detection | `craftsec.detection.engine.DetectionEngine` (evidence fusion over program analysis/taint/static coverage) | **Integrated** | Detection runs on real analyzed sources and returns API findings/evidence sources/coverage where available. Findings are engine-produced (not simulated); coverage/gaps reported. |
| SAE feature extraction | `features_extract` pipeline stage/model capture/SAE artifacts | **Unavailable (explicit)** | No model runtime or compatible SAE artifact configured; endpoint returns explicit unavailable stages, no features fabricated. |
| Counterfactual interaction analysis | `counterfactual_analyze` pipeline stage | **Unavailable (explicit)** | No counterfactual engine/model intervention runtime configured; endpoint reports unavailable stages (requires valid intervention schema). |
| Adaptive activation steering | `prevention_steer` pipeline stage | **Unavailable (explicit)** | No steering planner/evaluation harness configured; endpoint reports unavailable stages (requires explicit opt-in/schema). |
| Explainability | `craftsec.explain.engine.explain_finding` (evidence-grounded) | **Integrated (path implemented)** | Explanation path analyzes target file and builds explanation from real/selected finding and taint/program evidence when a target finding is available; falls back to explicit unavailable/partial explanation if not. |
| Automated repair | `craftsec.repair.workflow.RepairWorkflow`, `repair_generate` | **Integrated (workflow/proposal only)** | Integrated workflow executes as proposal/verification pipeline; patches never applied to user source, `requiresApproval=true`. Candidate patches (including user-supplied) are validated/verified in isolated copies per workflow/sandbox/consent constraints. |
| Independent verification | `craftsec.verification.engine.IndependentVerificationEngine`, sandbox executor | **Integrated** | Static/independent verification runs over provided source/patch context with explicit verdict/classification/limitations and sandbox backend reporting; execution-dependent checks remain constrained by consent/sandbox availability. |
| Experimental evaluation | `craftsec.experiments.*`, `craftsec.evaluation.*` | **Implemented modules, not executed as benchmark** | Evaluation/statistics/ablation/comparison/reporting framework is present in codebase; no datasets/benchmark runs executed in this integration test and no metrics/results fabricated. |

## 2. Orchestration, error propagation, cancellation, progress, logging, persistence

- **Pipeline orchestration:** `Orchestrator` executes real per-file analysis for scan/detection/explanation (preprocessing → AST/CFG/DFG → taint → static evidence → detection → explanation as applicable) and declared stages for feature/counterfactual/steering/verification; repair uses integrated workflow. Stage reports/warnings/status are aggregated into operation responses.
- **Progress reporting:** `core/jobs.py` (`JobStore`, `ProgressEvent`) records timestamped stage/status/messages/percent/data; orchestrator emits progress callbacks during operations (and to structured logs). Jobs API exposes progress/status for tracked jobs.
- **Cancellation:** `CancellationToken`/`JobStore.cancel` provide cooperative cancellation; orchestrator checks tokens between/around major steps and raises conflict (`E_CANCELLED`) when cancelled.
- **Error propagation:** `AppError` subclasses propagate with typed codes/status/details; unexpected failures are logged and surfaced as sanitized internal errors; analysis/tool failures are captured as explicit stage failures/partial/unavailable with reasons/warnings rather than fabricated success.
- **Structured logging:** JSON structured logging via `craftsec.core.logging`/`craftsec.api.access` (request/operation context such as requestId/method/path/status/duration and operation progress) to stderr, without secrets/source bodies.
- **Result persistence:** `JobStore` persists job records/results under `settings.data_dir/jobs` and `settings.data_dir/results`; orchestrator also persists operation responses to `data_dir/results/{operation}-{requestId}.json` when a job store is available (routes pass app job store).

## 3. Controlled samples (real)

Located at `security-engine/tests/integration/samples/`:
- `vulnerable_sql.py` — intentionally vulnerable SQL query construction via string formatting.
- `secure_sql.py` — parameterized query variant.
- `vulnerable_cmd.js` — intentionally vulnerable command execution with concatenated user input.
- `secure_cmd.js` — safer `execFile` argument passing variant.

## 4. Integration tests executed and observed results

Environment notes: Python `.venv` used; `semgrep`/`bandit` executables **not installed**; no model/SAE/steering artifacts or sandbox Docker-dependent functional execution configured for this run.

### 4.1 Automated API/integration flow (TestClient, `create_app()`)

**Commands run (representative):**
- `PYTHONPATH=security-engine/src .venv/bin/python -m py_compile ...` (modified core/api/orchestrator/routes/jobs modules) — **passed**.
- `PYTHONPATH=security-engine/src .venv/bin/python /private/var/.../run_integration_check.py` — initial run identified detection integration bug (`detect_source` kwarg mismatch), which was fixed.
- Targeted post-fix scan checks via `fastapi.testclient.TestClient` over `/api/v1/scan/file` for all four controlled samples.

**Observed post-fix scan/detection results (actual):**

| Sample | Overall status | Findings | Detection stage | Preprocessing / Program analysis / Taint | Static evidence |
|---|---:|---:|---|---|---|
| `vulnerable_sql.py` | `partial` | 1 | `ok` | `ok / ok / taint=1` | `unavailable` (`E_TOOL_MISSING`: semgrep, bandit not found) |
| `secure_sql.py` | `partial` | 1 | `ok` | `ok / ok / taint=1` | `unavailable` (`E_TOOL_MISSING`) |
| `vulnerable_cmd.js` | `partial` | 1 | `ok` | `ok / ok / taint=1` | `unavailable` (`E_TOOL_MISSING`) |
| `secure_cmd.js` | `partial` | 0 | `ok` | `ok / ok / taint=1` | `unavailable` (`E_TOOL_MISSING`) |

- Result persistence verified: operation result JSON files written under app `data_dir/results/` (e.g. `scan_file-*.json`) during route-backed scans.
- `GET /api/v1/health` returned `status=ok` with capabilities reflecting integrated local analysis/repair/verification and unavailable model/SAE/counterfactual/steering.

**Example finding (engine-produced, vulnerable SQL sample):** medium severity, `CWE-89`, SQL injection finding with evidence/explanation derived from fused analysis (exact IDs/messages as returned by engine).

**Important observation:** the controlled `secure_sql.py` (parameterized query) also produced a SQL-injection finding in this run (false positive relative to sample intent). This is reported as an actual engine outcome, not a simulated/curated result.

### 4.2 Endpoint contract checks (representative)

- `POST /api/v1/features/extract` on controlled sample: **200** with `status=partial`, stages explicitly unavailable (`E_MODEL_UNAVAILABLE`, `E_SAE_UNAVAILABLE`, `E_FEATURE_UNAVAILABLE`), `analysisAvailable=false`, no features.
- `POST /api/v1/counterfactual/analyze`, `/api/v1/prevention/steer`, `/api/v1/verification/run`, `/api/v1/repair/generate` validation depends on required schema fields (e.g. interventions kind/featureIndices, `explicitOptIn`, verification target/profile, repair finding context). Requests sent with incomplete payloads in exploratory script returned **422 `E_VALIDATION`** with field-level details (correct error propagation/contract enforcement). A request with a valid target finding/payload is required to exercise full workflow paths.
- `GET /api/v1/jobs/{job_id}` for nonexistent ID: **404 `E_NOT_FOUND`** (correct).

### 4.3 Existing automated tests (not fully rerun post-integration)

- Previously validated baseline (earlier): 104 targeted tests passed for repair/verification/API/pipeline subset.
- **Post-integration note:** scan/detection/explanation behavior was intentionally changed from "declared unavailable stages" to real local analysis integration. Some existing unit/pipeline tests that assert prior unavailable behavior may require updates; a full regression suite was **not** executed in this session.

## 5. Component/interface verification summary

- **Backend ↔ analysis libraries:** parsing, program analysis (AST/CFG/DFG), taint, static runner/adapters, detection engine, and explain engine are invoked through in-process Python interfaces from `Orchestrator`.
- **Backend ↔ verification/repair/sandbox:** integrated workflow uses `RepairWorkflow`, `IndependentVerificationEngine`, `RepositoryContextBuilder`, and `IsolatedExecutor`/consent model; no host application of patches.
- **Backend ↔ persistence/logging/jobs:** `JobStore` and structured logging wired into app/orchestrator/routes.
- **Extension ↔ backend:** HTTP/JSON contracts remain versioned and schema-validated by extension client/service layer; job/progress/cancel/result endpoints added on backend (additive) for tracked operations.

## 6. Unavailable components and limitations (explicit)

- **Static analyzers (semgrep/bandit):** executables not present in environment → reported unavailable with reasons; no findings fabricated. CodeQL/Joern require explicit configuration/license/DB/query artifacts and were not auto-run.
- **SAE feature extraction, counterfactual interaction analysis, adaptive activation steering, model capture/runtime:** no configured model/SAE artifacts or runtime → reported unavailable; no simulated outputs.
- **Sandbox/functional execution:** dependent on configured backend (Docker/process), explicit user consent, and environment support; not fully exercised beyond schema/workflow wiring in this run.
- **Detection quality:** results are produced by the current engine/rules/taint and may include false positives/negatives (observed on controlled samples); coverage gaps are reported.
- **Evaluation/benchmarks:** no experimental datasets run, no benchmark metrics/statistical results produced.
- **Extension UI/runtime:** not executed; integration verified at interface/contract and backend behavior level.

## 7. Artifacts produced

- Controlled samples: `security-engine/tests/integration/samples/{vulnerable_sql.py,secure_sql.py,vulnerable_cmd.js,secure_cmd.js}`
- Initial run log/output capture: `security-engine/tests/integration/integration_run_results.json`
- Persisted operation results (per app data dir during runs): `.../results/scan_file-*.json` (and other operations when invoked)
- This report: `security-engine/tests/integration/INTEGRATION_TEST_REPORT.md`
