# Bug Dhor User Guide

**Project:** Bug Dhor — Counterfactual Risk Analysis and Feature-aware Steering for Secure Code Generation  
**Documentation scope:** This guide describes the repository and implemented interfaces as they exist in this workspace. It distinguishes implemented, configurable, and currently unavailable capabilities. It does **not** claim that unimplemented features are available, and it does **not** claim security guarantees.

> **No screenshots:** Accurate application screenshots were not available in the repository at the time of writing, so none are included.

---

## 1. Project introduction

Bug Dhor is a local-first research-oriented system for explainable software vulnerability analysis and related security research workflows. The repository contains:

- **VS Code extension (`vscode-extension/`)**: a JavaScript extension that provides Bug Dhor commands, an Activity Bar/sidebar launcher, a Security Dashboard webview, and native diagnostics/hover/code actions derived from validated backend scan results.
- **Security engine (`security-engine/`)**: a Python/FastAPI backend exposing a versioned `/api/v1` HTTP API for health checks, file/workspace scanning, detection/explanation requests, feature/counterfactual/steering/repair/verification operations, proposal-only secure recommendations, and job status/progress/result/cancellation.
- **Shared contracts/schemas and research modules**: typed schemas, program analysis, detection/explanation, repair/verification/sandbox, SAE/counterfactual/steering libraries, and experimental/evaluation/statistical frameworks.

The system is designed to report honest analysis states (`ok`, `partial`, `unavailable`, `failed`, etc.) and explicit limitations rather than fabricating results.

## 2. Research motivation

Bug Dhor is motivated by the need for security tooling that is not only detection-oriented but also **explainable**, **evidence-grounded**, and **research-reproducible**. The project direction (as reflected in repository docs and module structure) targets:

- combining program-analysis and static evidence for vulnerability findings;
- studying sparse autoencoder (SAE) features and their associations/interventions in model-internal representations (when model/SAE artifacts are available);
- analyzing single-feature, pairwise, and higher-order counterfactual interventions under explicit experimental controls;
- exploring interaction-aware/adaptive activation steering for secure generation research (when supported runtimes exist);
- supporting repository-aware repair proposals and **independent** security/functional verification with explicit approval and isolation constraints;
- enabling reproducible experimental evaluation with honest reporting of prerequisites, missing data, and limitations.

These are research goals and engineering directions; not all are fully operational in a default local setup without required models, artifacts, analyzers, datasets, or sandbox infrastructure.

## 3. System architecture

### 3.1 High-level components

| Layer | Component | Role |
|---|---|---|
| Client | VS Code extension | User commands/UI, dashboard, diagnostics, hover explanations, repair quick-fix triggers, backend HTTP client, response validation, privacy controls for source sharing. |
| Transport/API | FastAPI app (`bugdhor.api`) | Versioned endpoints, request validation, auth/CORS/body limits (configured), middleware, structured errors, job/result interfaces. |
| Orchestration | `bugdhor.core.orchestrator` / jobs | Pipeline coordination, stage status/progress, cooperative cancellation, result persistence, capability reporting, honest unavailable handling. |
| Analysis | Parsing, program analysis, taint, static adapters, detection, explainability | Source preprocessing/parsing, AST/CFG/DFG/taint, best-effort external static tools, evidence fusion/detection, evidence-grounded explanations. |
| Model/research (artifact-dependent) | Models, SAE, features, counterfactual, steering/prevention | Local HF model adapter, SAE training/association/interpretation, counterfactual and steering engines; require compatible checkpoints/artifacts/configuration. |
| Repair/verification | Repair context/engine/workflow, sandbox, independent/functional verification | Diff/proposal generation and ranking, repository context, proposal-only workflow, explicit approval required, isolated execution with consent, independent verdicts. |
| Evaluation | Experiments/evaluation modules | Dataset/split/experiment-group config, metrics, statistics, ablations/comparisons, reporting/export; requires actual data/tools/capabilities. |

### 3.2 Data and control flow (implemented/integrated paths)

1. User invokes a Bug Dhor command in VS Code (scan/explain/analyze features/counterfactual/generate secure code/repair/verify/dashboard/status/logs).
2. Extension validates editor/workspace/selection context, applies privacy/source-sharing rules, and sends an HTTP request to the configured running backend (it does **not** start the backend).
3. Backend validates request/path/size/auth (if configured), runs orchestrated analysis/workflow, emits stage/progress information, and returns a validated JSON response with operation status and explicit stage availability.
4. Extension validates and renders results: diagnostics/problems, hovers, quick fixes, and dashboard state are driven only by supplied/validated backend data. Unavailable analysis is reported as unavailable (not as a clean/secure result).
5. Repair candidates are proposals only: backend/workflow does not auto-apply patches to user source; applying a patch requires explicit user action in the client flow and local validation checks.

### 3.3 State, jobs, and persistence

- Job APIs support status/progress/result retrieval and cancellation for tracked operations (`/api/v1/jobs/...`).
- The engine can persist job/result artifacts under the configured data directory (e.g. jobs/results subdirectories). Treat persisted artifacts/logs as potentially sensitive because they may contain analysis metadata/evidence derived from source.
- In-process analysis caching may reuse parse/AST-CFG-DFG/taint results for unchanged content within a process lifetime to improve responsiveness; this does not remove analysis stages.

## 4. Supported programming languages

Language support depends on the capability:

| Capability | Supported/handled languages (current implementation) | Notes |
|---|---|---|
| Source detection | **Python, JavaScript, TypeScript, Java, C, C++, PHP, Go, Rust, C#, Ruby, Kotlin, Swift** | Detected from extension, editor language id, shebang, or conservative content signals. Detection does not imply parsing. |
| Parsing / AST extraction | **Python, JavaScript, TypeScript** (including TSX grammar selection) | Only installed tree-sitter grammars are used. Functions, classes, imports, source locations, and syntax diagnostics are extracted for these languages. |
| Program analysis (CFG/DFG/taint) | **Python and JavaScript only** | TypeScript has parsing support but no implemented CFG/DFG/taint layers. Analysis is intraprocedural/bounded (see [program analysis](program-analysis.md)). |
| Static adapters | Semgrep and Bandit are wired into scans; CodeQL and Joern require explicit CLI/database/query configuration | Missing/unconfigured tools are reported as unavailable/failed with reasons, never as clean scans. Installed linters/type checkers without adapters are reported as `E_NO_ADAPTER` gaps. |
| General-bug/security AST enrichment | Conservative parser/AST rules for all parsed languages | Off by default. Enable with `DetectionConfig(enrich_general_bugs=True)` in the engine API. Findings use epistemic labels (`observation`/`inference`/`hypothesis`) plus uncertainty text, not calibrated probabilities. |
| VS Code file commands | Operate on active/saved workspace `file:` editors as validated by extension command logic | Some commands require saved files inside an open workspace folder and/or a non-empty selection. Background monitoring eligibility is currently Python/JavaScript only. |

Languages that are detected but have no installed parser are reported as
`no_installed_parser` skips in repository metadata and as explicit gaps in the
capability report. They are never treated as clean or analysed source. Query
`GET /api/v1/health` and read `analysisCapabilities` for the runtime view of
detected languages, installed parsers, program-analysis layers, static tools,
linter/type-checker adapter gaps, manual-only dependency checks, and general-bug
configuration. The older boolean `capabilities` map still describes wired
operation paths only.

## 5. Installation instructions

### 5.1 Prerequisites

- **Git** (repository is a git repo).
- **Python 3.11–3.14** (3.11 is the verified baseline in repo docs; other versions may work but were not fully exercised).
- **Node.js 22.13+ or 24+** (Node 24 LTS recommended by repo docs; Node 23 is unsupported) and npm.
- **VS Code 1.90+** for extension development/use.
- Optional: **Semgrep/Bandit/CodeQL/Joern** binaries/config for static analysis capabilities when available; **Docker** (or configured sandbox backend) for isolated functional execution; local **Hugging Face model checkpoints** and/or **SAE artifacts** for model/SAE/counterfactual/steering research workflows.

### 5.2 Repository setup (recommended)

From the repository root:

```bash
npm run setup -- --cpu --with-analyzers
npm run doctor
```

- `--cpu` installs CPU-only PyTorch (appropriate for many development environments).
- `--with-analyzers` installs available Python analyzer dependencies (e.g. Semgrep/Bandit where supported). Omit for a lighter setup.
- Setup/doctor do **not** download model weights.

### 5.3 Manual Python environment (alternative)

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
```

Adjust extras and PyTorch installation for your platform/GPU needs.

### 5.4 Extension dependencies

From the repository root (npm workspaces):

```bash
npm install
npm run extension:test
```

For Extension Host integration tests (when environment supports it): `npm run extension:test:integration` from the root. The Extension Host test may download a VS Code build unless `BUGDHOR_VSCODE_EXECUTABLE` is set to a local installation.

## 6. Python backend setup

### 6.1 Start the engine

Run from `security-engine/` using the project virtual environment:

```bash
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765
# or, if installed in environment:
bugdhor --host 127.0.0.1 --port 8765
```

You can also configure host/port via environment variables (e.g. `BUGDHOR_HOST`, `BUGDHOR_PORT`) as supported by settings.

### 6.2 Key runtime settings (environment-backed)

Settings use the `BUGDHOR_` prefix (and accept some conventional aliases such as `HF_TOKEN`). Common settings include:

| Setting | Purpose | Default/notes |
|---|---|---|
| `BUGDHOR_HOST`, `BUGDHOR_PORT` | Bind address/port | Default `127.0.0.1:8765` (local-first). |
| `BUGDHOR_WORKSPACE_ROOTS` | Allowed roots for file/workspace inspection | JSON array or comma-separated paths; defaults to current working directory behavior in settings. Set to folders the backend may inspect. |
| `BUGDHOR_API_TOKEN` (or `BUGDHOR_ENGINE_TOKEN`) | Optional bearer token for `/api/*` | If set, requests must include `Authorization: Bearer <token>`. |
| `BUGDHOR_CORS_ORIGINS` | Allowed CORS origins | Empty by default; wildcard `*` rejected; origins must be scheme/host/port only. |
| `BUGDHOR_MAX_REQUEST_BYTES`, `BUGDHOR_MAX_FILE_BYTES`, `BUGDHOR_MAX_WORKSPACE_FILES` | Request/resource limits | Enforced by middleware/validation/path logic. |
| `BUGDHOR_DATA_DIR`, `BUGDHOR_LOG_DIR` | Data/log directories | Used for persistence/logs as configured. |
| `BUGDHOR_SANDBOX_BACKEND`, `BUGDHOR_SANDBOX_TIMEOUT_SECONDS` | Sandbox execution settings | Default backend `docker` in settings; functional execution requires available backend and explicit consent. |
| `BUGDHOR_SEMGREP_PATH`, `BUGDHOR_BANDIT_PATH`, `BUGDHOR_CODEQL_PATH`, `BUGDHOR_JOERN_PATH` | Analyzer executables/config paths | Missing/unconfigured tools lead to explicit unavailable/failed tool statuses. |

See `.env.example` and `docs/api.md` for the full/current contract.

### 6.3 API basics

- Base URL: `http://127.0.0.1:8765` (default)
- Prefix: `/api/v1`
- OpenAPI: `GET /openapi.json`, docs: `GET /docs`, `GET /redoc`
- Error responses: RFC 9457 problem details (`application/problem+json`) for API errors.

The extension appends `/api/v1` to `bugdhor.backend.url`.

## 7. LLM model configuration

Bug Dhor includes a **lazy, local-first model runtime** (`bugdhor.models`) for Hugging Face Transformers-compatible workflows. Importing/configuring does not automatically download weights.

### 7.1 Supported/declared checkpoints (as documented)

`docs/models.md` documents exact checkpoint keys/IDs and license/access notes (verify and comply with each license/terms before use), including:

- `llama-3.1-8b-instruct` → `meta-llama/Llama-3.1-8B-Instruct` (gated/licensed terms apply)
- `qwen2.5-coder-7b-instruct` → `Qwen/Qwen2.5-Coder-7B-Instruct` (Apache-2.0 per upstream metadata; verify)
- `deepseek-coder-6.7b-instruct` → `deepseek-ai/deepseek-coder-6.7b-instruct` (license terms apply)

### 7.2 Configuration principles

- **`local_files_only` defaults to true** in model configuration patterns: provision checkpoints locally and explicitly opt into remote resolution only if intended and permitted.
- Use environment/settings such as `BUGDHOR_MODEL_ID`, `BUGDHOR_MODEL_REVISION`, `BUGDHOR_DEVICE` (`auto|cpu|cuda|mps`), and `BUGDHOR_HF_TOKEN`/`HF_TOKEN` when gated access/download workflows are explicitly used and authorized.
- Bug Dhor does **not** redistribute model weights.

### 7.3 Availability and limitations

- Model-dependent features (e.g. SAE feature extraction on model activations, counterfactual interventions, steering/prevention, LLM-based repair generation, parts of E0–E8 experiments) require a compatible loaded model/runtime, and often additional artifacts (SAE checkpoints), configuration, and compute resources.
- If not configured/available, endpoints should report explicit unavailable/partial states with reasons; they must not fabricate model outputs or results.
- Generation/steering can change behavior under intervention but does **not** by itself prove vulnerability remediation, semantic meaning of features, or causal security improvement.

## 8. Security scanning tutorial

### 8.1 Prerequisites

- Backend running and reachable (default `http://127.0.0.1:8765`).
- `BUGDHOR_WORKSPACE_ROOTS` includes the target workspace/folder.
- In VS Code: open a workspace folder and (for file/selection scans) a saved `file:` document inside it.
- `bugdhor.privacy.sendSourceText` controls whether current buffer/selection text is sent for explicitly invoked file/selection commands; workspace scans send folder metadata, not file contents (per extension docs).

### 8.2 Scan current file (VS Code)

1. Start the backend.
2. Open the target file in the workspace.
3. Run **Bug Dhor: Scan Current File** from the Command Palette.
4. Review progress/result notifications and the **Problems** panel. Diagnostics are published only from validated backend scan results.

**Expected behavior:** The backend performs real inspection/analysis stages available in the current environment (e.g. preprocessing, program analysis/taint, detection; static tools only if installed/configured). Results may be `partial` if some tools/stages are unavailable.

### 8.3 Scan selection (VS Code)

1. Select a non-empty code region in a supported saved workspace file.
2. Run **Bug Dhor: Scan Selection**.
3. The extension sends selection context according to privacy settings; backend analyzes the relevant file/selection request.

### 8.4 Scan workspace (VS Code)

1. Ensure one or more local workspace folders are open and allowed by backend roots.
2. Run **Bug Dhor: Scan Workspace**.
3. Review findings/summary in dashboard/problems as returned by backend. Large workspaces may take longer; progress/cancellation are supported where provided by the command/job flow.

### 8.5 Scan via API (example)

```bash
curl -sS -X POST "http://127.0.0.1:8765/api/v1/scan/file" \
  -H "Content-Type: application/json" \
  -d '{
    "workspaceRoot": "/absolute/path/to/workspace",
    "filePath": "/absolute/path/to/workspace/file.py",
    "sourceText": null
  }'
```

Adjust payload to match the current OpenAPI schema (include an auth header if `BUGDHOR_API_TOKEN` is enabled). Prefer using paths within configured workspace roots.

### 8.6 Interpreting results honestly

- **`analysisAvailable: false` / unavailable stages:** indicates specific analyses were not run or not supported with current configuration; do **not** interpret as "no vulnerabilities."
- **`partial`:** some stages completed, others unavailable/failed or limited (e.g. external static analyzers missing).
- Findings are evidence-based outputs of the configured engine/rules/analyzers and can include **false positives or false negatives**.
- General-bug/security AST enrichment is opt-in. Its findings are structural observations with epistemic confidence labels and explicit uncertainty; they are not type-checker, linter, or calibrated-probability results.
- Inspect `analysisCapabilities` in the health response to see which languages are parsed, which have CFG/DFG/taint, which analyzers are actually available, and which checks remain manual or adapter-less.

### 8.7 Model-independent workspace monitoring (VS Code, opt-in)

Bug Dhor can watch eligible workspace files while you edit. It is **disabled by default** and is intended as a background aid, not a replacement for an explicit scan. It does not matter whether code came from Copilot, Cursor, Claude, ChatGPT pasted text, OpenCode, another assistant, or manual typing: the extension sees only ordinary workspace documents.

- Enable it with `bugdhor.monitoring.enabled`. A single workspace coordinator then registers the official VS Code events: document open, change, save, close, file create, file delete, and workspace-folder change. No private API or reverse engineering is used.
- Edits are debounced (`bugdhor.monitoring.debounceMs`, minimum 100 ms) and tracked by document version so rapid changes or pasted blocks produce a single scan of the latest buffer, never one scan per keystroke. A newer edit cancels any superseded request. Saves supersede pending edits with an immediate bounded file scan.
- Analysis is scoped to the enclosing function, the changed lines, or the whole file (`bugdhor.monitoring.analysisScope`). Set `bugdhor.monitoring.onSaveOnly` to analyze only on save. Large files, generated paths, and languages outside the extension's current Python/JavaScript eligibility are skipped. The backend can still detect the broader 13-language set and reports parser gaps separately.
- New eligible source files are opened through the documented `workspace.openTextDocument` API and scanned once. Deletes cancel pending work, forget tracking state, and clear that file's diagnostics. Folder changes always prune stale state; `bugdhor.monitoring.fullScanOnWorkspaceChange` is an opt-in for one debounced, metadata-only full workspace scan.
- Opening a document does **not** trigger a scan unless `bugdhor.monitoring.scanOnOpen` is explicitly enabled. Watch/create behavior can be disabled with `bugdhor.monitoring.watchWorkspaceFiles` and `bugdhor.monitoring.scanNewFiles`.
- Binary extensions, generated artifacts (minified bundles, source maps, generated files, lockfiles), vendored directories, virtual environments, build/cache directories, and out-of-workspace paths are skipped by default. Workspace-level full scans are bounded by `bugdhor.monitoring.maxConcurrentScans` and `bugdhor.monitoring.maxWorkspaceFiles`.
- Findings come only from validated backend results and are published to the native **Problems** panel (clearing stale findings); a non-blocking notification appears when findings exist. An unavailable analysis publishes nothing. See [the workspace scanning audit](workspace-scanning-audit.md) and [implementation plan](workspace-scanning-implementation-plan.md) for the full event and settings map.

**Attribution:** the monitor never claims to identify an AI assistant, model, or human author. Multi-line insertions are described only by their edit shape. The [provider matrix](ai-assistant-integration.md#workspace-monitoring-provider-matrix) records `attribution: 'none'` for every supported workflow.

**Privacy:** background analysis sends source text **only** when both `bugdhor.monitoring.allowAutomaticSourceSharing` and `bugdhor.privacy.sendSourceText` are enabled. Leave either off and the monitor tracks versions locally but makes no engine call. Workspace scans send folder metadata only; the backend reads allowlisted files from disk. Reachability/health checks never send source code.

## 9. Vulnerability explanation tutorial

### 9.1 What explanation provides (when available)

The explainability engine builds structured/human-readable explanations from supplied/derived finding evidence. It preserves evidence boundaries (AST/CFG/DFG/taint/static records, explicit inferences, separately labeled LLM/SAE/counterfactual evidence when present) and does not execute generated code implicitly.

### 9.2 How to request an explanation

- **VS Code:** run **Bug Dhor: Explain Vulnerability** in the context of a finding/editor as supported by the command/backend contract. If no valid finding/context is available, the backend may return partial/unavailable explanation.
- **API:** `POST /api/v1/explanation/analyze` with the required request schema (typically includes file/finding context).

### 9.3 Reading explanations

- Treat direct analysis evidence separately from hypotheses or optional model-derived evidence.
- `security impact`/exploitability is not assumed unless supported by provided evidence.
- Unavailable evidence must be shown as unavailable, not inferred.

## 10. SAE feature analysis tutorial

SAE-related capabilities include training/association/interpretation libraries and feature extraction APIs, but **end-to-end feature extraction in the running system requires compatible model runtime and SAE artifacts/checkpoints**.

### 10.1 Prerequisites (when running feature extraction)

- Locally available compatible model checkpoint and runtime dependencies.
- Trained/compatible SAE checkpoint/manifest for the target model/layer/dimensions.
- Correct engine configuration and any required request fields expected by `/api/v1/features/extract`.

### 10.2 Using the API/command

- **VS Code:** **Bug Dhor: Analyze Security Features** invokes the backend feature extraction flow; if prerequisites are missing, expect explicit unavailable/partial responses.
- **API:** `POST /api/v1/features/extract` with a valid request payload.

**Important current status:** in the default integrated orchestrator, `features_extract` declares `model_capture`, `sae_features`, and `feature_aggregation` as unavailable (`E_MODEL_UNAVAILABLE`, `E_SAE_UNAVAILABLE`, `E_FEATURE_UNAVAILABLE`) and returns no features. The SAE training/analysis/interpretation libraries exist for programmatic research use when you supply activations and checkpoints; do not expect the running API to fabricate features.

### 10.3 Research interpretation cautions

- SAE latents/statistics are **not** semantic vulnerability labels by default.
- Associations do not imply causation; interpretation requires separate controlled evidence and validation.
- Use `docs/sae.md`, `docs/sae-feature-analysis.md`, and `docs/sae-feature-interpretation.md` for method details and limitations.

## 11. Counterfactual analysis tutorial

Counterfactual modules support reproducible intervention experiments (single/pairwise/higher-order) under explicit controls. API/extension access depends on backend implementation state, configured model/SAE/runtime, and valid request schemas.

### 11.1 Prerequisites

- Compatible local model and SAE artifacts where required.
- Explicit intervention specification (features, mode/values, target positions/layer as applicable), outcome definitions, and reproducibility parameters as required by the engine/schema.
- Understanding that outputs are controlled intervention comparisons on declared scales, not automatic proof of true vulnerability/status changes.

### 11.2 Using the API/command

- **VS Code:** **Bug Dhor: Counterfactual Analysis** requires appropriate editor context/selection and a backend capable of the requested analysis; otherwise it will report unavailable/failed states per backend response.
- **API:** `POST /api/v1/counterfactual/analyze` with schema-compliant payload.

**Important current status:** in the default integrated orchestrator, `counterfactual_analyze` declares the `counterfactual` stage unavailable (`E_COUNTERFACTUAL_UNAVAILABLE`) and does not fabricate intervention outputs. The counterfactual libraries (`bugdhor.counterfactual.*`) are available programmatically for configured model/SAE runs.

### 11.3 Interpreting results

- Report outcome scale, design, replicates/uncertainty (if computed), and provenance.
- No p-values/significance claims unless produced by implemented, appropriate statistical procedures on real observations (descriptive uncertainty in some modules is not a significance test).

## 12. Secure code generation tutorial

Bug Dhor has two distinct generation paths. Do not conflate them:

1. **Provider-backed secure recommendation** — implemented as a proposal-only workflow with mandatory verification.
2. **Steering/prevention research path** — available only for genuine local D/E/F access with configured model, SAE, and evaluators. The HTTP API always reports steering as not applied.

### 12.1 Provider-backed secure recommendation (VS Code)

**Bug Dhor: Generate Secure Code** works when the active saved editor contains a
finding published by a validated backend scan and a configured generation
provider exposes capabilities B and C. The editor-monitor provider exposes only
A and is rejected before any generation request.

The command:

1. asks `POST /api/v1/recommendations/generate` for the backend-built secure prompt;
2. sends that prompt to the configured provider;
3. extracts only valid unified diffs for the target file;
4. submits at most three candidates back to the backend for syntax, static, functional, CWE, and ranking verification; and
5. shows the accepted result in the dashboard as an unapplied proposal.

No source is changed by generation. If there is no validated finding, no
available B/C provider, no usable prompt, no applicable diff, or no candidate
that passes every mandatory gate, no patch is recommended.

### 12.2 API usage

Use `POST /api/v1/recommendations/generate` directly for a backend-built prompt
or to submit candidate diffs for verification. The response always has
`requiresApproval: true`; a rejected result has `verified: false` and
`repairedCode: null`. See [api.md](api.md#secure-recommendations) for the request
and result fields.

### 12.3 Steering/prevention limitations

The orchestrator's `prevention_steer` path declares the steering plan/evaluation
stages as unavailable in the default integrated pipeline. The standalone
steering libraries (`bugdhor.steering.*`) and adaptive policy/risk-control
components exist and can be used programmatically when a compatible model, SAE,
and evaluators are configured, but the end-to-end API flow must not be assumed
operational. Check the returned stage statuses/reasons.

Steering does **not** guarantee secure or functionally correct code.
SAE/counterfactual evidence is hypothesis-level, and API-driven steering is
never applied. Treat all generated output as an untrusted proposal subject to
review and independent verification.

## 13. Automated repair tutorial

### 13.1 Principles (implemented design)

- Repair is **proposal/verification-oriented**, not automatic source modification by the backend.
- `RepairEngine`/workflow can generate or evaluate patch candidates with constraints/ranking when configured (may require a local model adapter for generation).
- Every proposal requires **explicit user approval** before application in the client.
- Independent verification is required for verified claims; without passing evidence, candidates remain pending/unverified as appropriate.

### 13.2 How to request repair

- **VS Code:** run **Bug Dhor: Repair Vulnerability** (optionally from an eligible diagnostic quick-fix context). The extension may open preview/apply flows subject to local validation and user confirmation.
- **API:** `POST /api/v1/repair/generate` with a valid `RepairRequest` (includes finding/context and any workflow inputs required by schema).

### 13.3 Applying patches safely

- Review diffs carefully; apply only to intended files/ranges.
- The extension includes diff/path validation safeguards, but patch handling should still be treated cautiously.
- Do not assume a generated patch is secure, correct, or minimal without independent verification and human review.

## 14. Verification tutorial

### 14.1 What verification means in Bug Dhor

- **Independent security verification** compares evidence (e.g. static/taint findings before/after) without granting authority to the generator’s rationale.
- **Functional verification** (when available) is consent-gated and must run in an isolated sandbox; untrusted code/tests must not run on the host.
- Verdicts/states distinguish verified improvement, partial/inconclusive results, failures, and unavailable checks. `FULLY_VERIFIED`/strong claims require all mandatory checks to pass per workflow rules.

### 14.2 How to run verification

- **VS Code:** **Bug Dhor: Verify Repair** (workspace/editor context as required by command/backend contract).
- **API:** `POST /api/v1/verification/run` with schema-compliant target/profile/consent fields.

**Important current status:** health reports `verification_run` as a registered integrated interface, but an individual response still depends on analyzers, profile, consent, and sandbox availability. An unavailable or inconclusive result is not verification success. Independent verification also runs inside the repair and secure-recommendation workflows, where mandatory gates reject candidates that lack passing evidence.

### 14.3 Prerequisites

- Available analyzers/evidence sources for security checks as applicable.
- For functional execution: explicit consent, non-destructive/non-privileged request, and an available/configured sandbox backend (e.g. Docker). If unavailable, results must be reported as not run/unavailable/inconclusive as appropriate.

### 14.4 Continuous feedback loop

The VS Code extension maintains a bounded feedback loop after a patch is
explicitly applied:

- Diagnostics publish only validated backend findings. Hook events record
  metadata only and never create, resolve, or attribute findings.
- The feedback controller deduplicates a hook/monitor pair reporting the same
  scan, then tracks each finding through `patched`, `rescan_clean`,
  `verification_passed`, and `resolved` states.
- One immediate self-induced scan for an applied document hash is suppressed,
  and exactly one bounded follow-up rescan is scheduled. Analysis for a document
  can also be cancelled explicitly.
- A finding is resolved only after an explicitly applied Bug Dhor patch, a clean
  rescan, and passing verification. A later recurrence reopens it as
  `regressed`.

Notifications are controlled by `bugdhor.feedback.notifyOnPatchApplied` and
`bugdhor.feedback.notifyOnResolution` (both default to `true`). Functional-test
controls are described in
[secure recommendations and feedback](secure-recommendation-and-feedback.md#6-bounded-continuous-feedback-loop).

## 15. Experiment configuration

Bug Dhor includes experimental/evaluation frameworks in code (`bugdhor.experiments`, `bugdhor.evaluation`) for **honest, reproducible** studies when inputs are available.

### 15.1 Implemented building blocks

- **Datasets/loaders/validation:** local, licensed/available datasets only; normalization, deduplication, and leakage checks where implemented.
- **Splits:** repository-level, temporal (metadata-dependent), CWE-based, cross-language strategies with explicit unsupported/partial handling.
- **Experiment groups:** E0–E8 definitions and prerequisite checks (e.g. model/SAE/static/repair dependencies vary by group).
- **Configuration/tracking:** config hashing, manifests, environment/tool metadata, raw output recording.
- **Metrics/statistics:** detection/localization/repair/explainability/performance metrics from provided observations; assumption checks, bootstrap CIs, paired/nonparametric tests, effect sizes, and multiple-comparison corrections where computable; no fabricated p-values/CIs/effect sizes.
- **Ablations/comparisons/reporting:** A1–A8-style ablation analyses and cross-model/cross-dataset comparison utilities with dependence-aware options; export to JSON/CSV and Excel-compatible outputs when supported.

### 15.2 How to configure and run (research workflow)

1. Prepare **licensed, local** datasets and document IDs/versions/hashes; do not embed or fabricate unavailable data.
2. Provision required models/SAE artifacts/analyzers/sandbox and record versions/hashes/config.
3. Define experiment configuration (groups E0–E8, splits, seeds, budgets, evaluation profile) using the framework APIs/modules; capture manifests and raw outputs.
4. Run only groups whose prerequisites are satisfied; record unavailable prerequisites and null/unmeasured metrics explicitly.
5. Export bundles/reports from actual observations and include sample sizes, missing data, assumptions, corrections, and limitations.

No benchmark results are included in this guide; any future results must be traceable to real run artifacts.

## 16. Troubleshooting

### 16.1 Backend/connection issues

- **Extension cannot reach backend:** ensure backend is running, `bugdhor.backend.url` is a valid HTTP(S) origin, and firewall/port settings allow local access.
- **401 Unauthorized:** set matching `BUGDHOR_API_TOKEN` in backend and provide token in extension host environment (as supported) or request headers for API calls.
- **Path rejected / outside workspace:** configure `BUGDHOR_WORKSPACE_ROOTS` to include the target folder; use allowed file paths.
- **Validation errors (422):** verify request payload matches current schema (OpenAPI docs at `/docs`).

### 16.2 Scan/analysis behavior

- **No findings but status unavailable/partial:** analysis may be unavailable or incomplete (e.g. analyzers missing, model artifacts absent). This is not proof of safety.
- **Static tools missing:** install/configure Semgrep/Bandit/CodeQL/Joern as needed; missing tools are reported explicitly. Use `/health.analysisCapabilities` to distinguish missing executables from installed linters that have no adapter and from manual-only dependency checks.
- **Slow scans on large workspaces:** expect higher latency; caching helps repeated unchanged analysis in-process; consider narrowing scope.

### 16.3 Repair/verification issues

- **Repair/verification unavailable or pending:** may require model runtime, consent, sandbox backend, or sufficient evidence; read returned reasons/limitations.
- **Patch not applied:** ensure preview/approval flow completed, target document unchanged, and diff/path validation passes.

### 16.4 Extension development/runtime

- Use **Run and Debug → Run Bug Dhor Extension** in VS Code for Extension Development Host.
- Packaging uses `npm run package:vsix`, which builds from a clean staging copy and stages the declared production dependency closure; do not run `vsce` directly from the npm workspace.
- See `vscode-extension/README.md` and `docs/development-setup.md` for known issues (Node version, venv, Semgrep PATH, Docker availability, Windows notes).

## 17. Privacy and security considerations

- **Local-first defaults:** backend defaults to loopback; do not expose without appropriate network controls, authentication, and hardening.
- **Optional API auth:** enable `BUGDHOR_API_TOKEN` where required; default deployments may have no auth.
- **Source sharing:** `bugdhor.privacy.sendSourceText` controls sending active buffer/selection for explicitly invoked file/selection requests; disabling sends paths/ranges so backend reads saved files (subject to backend access). Workspace scans avoid sending file contents per design. Opt-in real-time monitoring (§8.7) additionally requires `bugdhor.monitoring.allowAutomaticSourceSharing` before any changed source text is sent automatically; monitoring itself is off by default.
- **Sensitive artifacts:** logs, job records, persisted results, caches, and exported bundles may contain sensitive source fragments, paths, or findings; protect storage, access, and retention appropriately.
- **LLM/prompt injection:** repository content and findings are untrusted inputs; prompt hardening reduces but does not eliminate risk. Treat all generated patches/code as untrusted.
- **Patch application:** never auto-trust or auto-apply generated diffs; require review and explicit approval.
- **Execution isolation:** do not run untrusted tests/code on the host; functional execution requires explicit consent and isolated sandbox (availability/configuration dependent).
- **No security guarantee:** passing tests or static analysis does not prove the system or analyzed code is secure.

## 18. Known limitations

- **Feature availability depends on environment:** model checkpoints, SAE artifacts, static analyzers, CodeQL/Joern configuration, Docker/sandbox, datasets, and licenses may be missing; unavailable components must be reported, not simulated.
- **Detection accuracy:** analysis can produce false positives/negatives; results are bounded by supported languages, rules, analyzers, and analysis precision.
- **Program/static analysis scope:** intraprocedural/approximate behaviors, unresolved calls/aliases/flows, and tool-specific limitations apply (see `docs/program-analysis.md`, `docs/architecture.md`, `docs/research-alignment.md`).
- **Research components:** SAE semantics are not established by activations alone; counterfactual effects are intervention/design/outcome-scale dependent; steering does not prove security or causality.
- **Repair/verification:** proposals may be incorrect/incomplete; verification coverage is bounded by configured checks and sandbox/profile; inconclusive/not-run outcomes are possible.
- **UI/runtime validation:** not all extension-host/end-to-end UI flows, detector-produced live diagnostics scenarios, or platform/browser matrices have been exhaustively tested in every environment.
- **Performance/scalability:** optimizations (e.g. caching, bounded fanout) improve some cases but large repositories/files, external tool latency, and model workloads remain challenging; persistent incremental indexing and broader scaling work may be incomplete.
- **Documentation status:** implementation evolves; always consult `docs/api.md`, `docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md`, integration reports, and OpenAPI for current behavior.

---

## Related documentation

- `README.md`, `docs/README.md`, `docs/architecture.md`, `docs/api.md`
- `docs/development-setup.md`, `docs/models.md`, `docs/program-analysis.md`
- `docs/sae.md`, `docs/sae-feature-analysis.md`, `docs/sae-feature-interpretation.md`
- `docs/counterfactual.md`, `docs/pairwise-counterfactual.md`, `docs/higher-order-counterfactual.md`, `docs/steering.md`
- `docs/explain.md`, `docs/repair.md`, `docs/secure-recommendation-and-feedback.md`, `docs/research-alignment.md`
- `docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md`, `research/evaluation/README.md`
- `security-engine/tests/integration/INTEGRATION_TEST_REPORT.md`
