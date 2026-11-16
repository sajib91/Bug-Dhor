# CRAFT-Sec Security Audit and Performance Report

**Date:** 2026-11-16 (workspace local execution)  
**Scope:** VS Code extension (`vscode-extension/`), FastAPI backend/API (`security-engine/src/craftsec/api`, `core`, routes/schemas), analysis/repair/verification/sandbox components, temp/log/persistence handling, dependencies, and local performance characteristics.  
**Method:** Static code review, targeted code hardening/optimization, available automated checks/tests, and controlled runtime measurements.

> **Important:** This report does **not** claim that CRAFT-Sec is secure. Passing static analysis, linting, or targeted tests does **not** prove the absence of vulnerabilities, correctness issues, prompt-injection resilience, sandbox escapes, or unsafe behavior in untested environments/configurations.

## 1. Executive Summary

- **Implemented mitigations (this pass):** hardened LLM repair prompt construction against prompt injection by treating repository/source/evidence/finding content as untrusted data with explicit delimiters/instructions (`security-engine/src/craftsec/repair/engine.py`); tightened VS Code repair patch path normalization/validation before diff preview/apply (`vscode-extension/src/repair/patchApplication.js`); added in-process file-analysis caching and workspace scan efficiency controls (cached parse/AST-CFG-DFG/taint reuse, reduced progress overhead, bounded static-analyzer target fanout, cache metrics in stage reports) in `security-engine/src/craftsec/core/orchestrator.py`; updated affected API contract tests to match integrated honest behavior (`security-engine/tests/api/test_analysis.py`, `security-engine/tests/api/test_health.py`).
- **Validated:** `py_compile` for modified Python modules; `node --check` for modified extension module; extension unit tests (**230 passed**); focused backend API/integration suites (**30 passed**: `tests/api/test_analysis.py`, `tests/api/test_health.py`, `tests/integration`); `python -m pip check` clean; `npm audit --omit=dev` reports 0 vulnerabilities.
- **Not fully validated / unavailable:** Semgrep/Bandit executables not installed in this environment; no CodeQL/Joern configured; no model/SAE/counterfactual/steering runtime artifacts; sandbox/functional execution environment-dependent (Docker/backend consent required); VS Code extension UI/runtime end-to-end flows not executed here; full regression suite not rerun after behavior/integration changes; no licensed benchmark dataset experiments executed.
- **Residual risk remains** in auth deployment posture, LLM/prompt-injection handling, sandbox isolation guarantees, dependency supply chain, large-input/resource exhaustion, sensitive-data persistence, and untested integration paths.

## 2. Environment and Reproducibility

| Item | Value |
|---|---|
| Platform | macOS 26.3.1 arm64 (`Darwin`) |
| CPU | arm / 10 logical CPUs (reported by Python) |
| Python | 3.11.14 (`.venv`) |
| Pip | 26.3 (`python -m pip check`: no broken requirements) |
| Node | 11.13.0 (workspace-reported npm) |
| Ruff | 0.17.4 |
| Semgrep | not installed |
| Bandit | not installed |
| pip-audit / safety | not installed |
| Workspace | `/Users/md.khayrulislamsajib/Downloads/CRAFT-Sec` (git repo; working tree contains pre-existing and in-progress modifications) |

## 3. Audit Findings and Mitigations by Area

### 3.1 VS Code Webview security
- **Observed controls:** Webviews use strict per-render nonce CSP (`vscode-extension/src/webviews/csp.js`: `default-src 'none'`, nonce script-src, local style-src only, no connect/img/frame/object/worker/form). HTML/state serialization escapes attributes and script JSON payloads (`vscode-extension/src/webviews/html.js`). Dashboard executes only an allowlisted set of engine-backed command IDs (`EXECUTABLE_COMMANDS` in `vscode-extension/src/webviews/dashboardPanel.js`) and ignores arbitrary command IDs/args from webview messages.
- **Mitigations implemented:** No CSP weakening. Repair diff preview/apply path handling hardened in `vscode-extension/src/repair/patchApplication.js` (path normalization, traversal/absolute-path rejection, empty/hunk validation) to reduce unsafe patch handling in webview-triggered flows.
- **Residual risks:** Webview attack surface still depends on message handlers, command implementations, extension host trust boundaries, and any future UI changes; not penetration-tested.

### 3.2 Content Security Policy
- **Observed:** Strong restrictive CSP helper and nonce generation in `vscode-extension/src/webviews/csp.js`; sidebar/dashboard HTML builders consume CSP/nonce (`dashboardHtml.js`, `sidebarHtml.js` observed in context).
- **Residual risks:** CSP effectiveness depends on consistent use across all webviews and no unsafe dynamic HTML insertion outside escaping helpers.

### 3.3 Backend API authentication where required
- **Observed:** Optional per-launch bearer token enforced by `BearerTokenMiddleware` for `/api/*` when `CRAFTSEC_API_TOKEN` is configured (`security-engine/src/craftsec/api/middleware/auth.py`, wired in `api/app.py`); constant-time comparison via `secrets.compare_digest`; 401 problem response on missing/invalid token.
- **Residual risks:** **No auth by default** (local-development posture). No RBAC/multi-user auth, no rate limiting/throttling middleware observed, and CORS is configurable (wildcard rejected in settings validation). If exposed beyond trusted localhost, endpoints could be abused for resource consumption or unauthorized analysis/repair/verification operations.

### 3.4 API input validation
- **Observed:** Pydantic v2 schemas with bounded field sizes/counts in scan/repair contexts (e.g. `ScanWorkspaceRequest` max folders, `RepairRequest` patch max 5,000,000 chars, consent/timeout bounds), FastAPI request validation handlers (`api/middleware/error_handlers.py`), request body size limiting (`RequestSizeLimitMiddleware`, default `max_request_bytes`), workspace/file path containment checks (`core/paths.py`), selection validation, and file-size/source extension controls.
- **Residual risks:** Validation does not guarantee semantic safety of untrusted code, patches, prompts, or analysis outputs; some operations accept large structured payloads and expensive scans.

### 3.5 Path traversal
- **Observed:** `core/paths.py` resolves/contains paths within allowed workspace roots and rejects symlink escapes (`ensure_allowed_root`, `resolve_file`, traversal-safe discovery behavior). Patch application in verification applies in temp directories and constrains target basenames for single-file verification (`verification/engine.py`). Extension patch application now normalizes and rejects `..`, absolute, and drive-prefixed paths (`vscode-extension/src/repair/patchApplication.js`).
- **Residual risks:** Any new file-write or artifact path handling must preserve containment checks; repair workflow/patch engines have complex diff parsing logic that should be fuzz-tested.

### 3.6 Command injection
- **Observed:** Static/sandbox subprocess execution uses argv lists with `shell=False`, sanitized environments, NUL-byte checks, bounded capture, and timeouts (`security-engine/src/craftsec/static/execution.py`, `sandbox/executor.py`). No direct `os.system`/`shell=True` usage found in engine source review.
- **Residual risks:** External analyzer binaries (semgrep/bandit/codeql/joern) and container runtime behavior are outside application control; misconfiguration of executable paths/arguments could still create risk.

### 3.7 Subprocess execution
- **Observed:** Centralized safe execution helpers and isolated executor abstractions. `IsolatedExecutor.run_host_check` is limited to controlled temp-dir checks per code intent, while untrusted workspace test execution is gated on explicit consent and isolated backend availability.
- **Residual risks:** Untrusted code execution safety fundamentally depends on sandbox backend strength, image/configuration, mounts, and host environment; Docker unavailability correctly degrades to unavailable/denied paths but must be verified per deployment.

### 3.8 Secret management
- **Observed:** Secrets modeled as `SecretStr` (`api_token`, `hf_token`) in settings; `redacted()` omits secrets; logs are structured JSON without request bodies/tokens; extension reads optional API token from host environment (not settings storage) per client design. Quick secret-pattern scan found no hardcoded production credentials (matches were test fixtures/docs/lockfile strings).
- **Residual risks:** Users may place secrets in environment/config files; result persistence/artifacts can contain sensitive code/evidence and should be treated as sensitive local data.

### 3.9 Temporary file management
- **Observed:** Extensive use of `tempfile.TemporaryDirectory(...)` for verification, repair evaluation, and workflow patch application; temp dirs are cleaned by context managers in normal paths.
- **Residual risks:** Crash/kill scenarios may leave temp remnants depending on runtime; some components hardcode `/tmp` in sandbox writable paths (container context) and should remain least-privilege reviewed.

### 3.10 LLM prompt injection
- **Observed risk:** Repair prompt previously embedded source, findings, evidence, and repo context directly into prompt text.
- **Mitigation implemented:** `RepairPromptBuilder.build` now frames system/task instructions, explicitly treats all `<untrusted_*>` content (finding, security evidence, repository context metadata, source file) as data, instructs model to ignore embedded instructions/role changes/secret requests, and requires unified-diff-only output (`security-engine/src/craftsec/repair/engine.py`).
- **Residual risks:** Prompt hardening **reduces but does not eliminate** prompt injection/jailbreak/model-misbehavior risk. Generated patches remain untrusted and must pass independent validation/verification and explicit user approval before application.

### 3.11 Workspace data exposure
- **Observed controls:** `craftsec.privacy.sendSourceText` controls source/selection sharing from extension; workspace scans send folder metadata only per service comments; backend enforces workspace-root containment and file size/type limits; CORS/auth/size limits reduce exposure in configured deployments.
- **Residual risks:** Source text may be transmitted to local backend when enabled; job/result artifacts and logs (on failure paths in dependencies) can expose sensitive project information to local disk/users with filesystem access.

### 3.12 Generated patch application
- **Observed controls:** Engine/repair workflow states patches are proposals only; no automatic server-side source modification; explicit user approval required in UI before apply; document hash/version checks and single-file target checks in dashboard panel flow; diff context/deletion matching required by `applyUnifiedPatch`.
- **Mitigations implemented:** Stricter patch path normalization/validation and malformed-patch rejection in `vscode-extension/src/repair/patchApplication.js`.
- **Residual risks:** Unified-diff application is custom logic (not a full git-apply implementation) and should be fuzz/property-tested; multi-file/complex patches remain intentionally constrained.

### 3.13 Test execution isolation
- **Observed controls:** `IsolatedExecutor` denies execution without explicit consent, rejects privileged/destructive consent, requires available sandbox backend (Docker), runs containers with `--network none` by default, read-only rootfs, tmpfs mounts, and no-new-privileges; `FunctionalVerifier` reports consent/sandbox unavailability and does not run untrusted project tests on host when isolated execution is unavailable.
- **Residual risks:** Isolation guarantees depend on container runtime/kernel configuration; tests may still have side effects within allowed mounted workspace copies; not validated with Docker in this environment.

### 3.14 Dependency vulnerabilities
- **Checks run:** `python -m pip check` → no broken requirements. `cd vscode-extension && npm audit --omit=dev` → 0 vulnerabilities.
- **Residual risks:** No `pip-audit`/`safety`/Semgrep supply-chain SCA tooling installed; dev dependencies and transitive/runtime ecosystem risks may exist outside checked scope; lockfile freshness and CI scanning should be enforced.

### 3.15 Logging of sensitive source code
- **Observed controls:** Structured logging formatter emits metadata (ts/level/logger/message/request context, method/path/status/duration/operation) and exception text; no request-body logging observed in middleware/app access logs.
- **Residual risks:** Exception messages/tracebacks could contain sensitive paths/data in some failure cases; persisted job/result JSON (`data_dir/jobs`, `data_dir/results`, operation result files) may include analysis artifacts/evidence derived from source and should be treated as sensitive; consider configurable redaction/retention/encryption-at-rest for production-like use.

## 4. Available Security Tools and Test Results

| Check | Result |
|---|---|
| `python3 -m py_compile` (modified engine files) | Passed (`security-engine/src/craftsec/core/orchestrator.py`, `security-engine/src/craftsec/repair/engine.py`) |
| `node --check` (modified extension file) | Passed (`vscode-extension/src/repair/patchApplication.js`) |
| `node --test vscode-extension/test/unit/*.test.js` | **230 passed, 0 failed** |
| `pytest security-engine/tests/api/test_analysis.py security-engine/tests/api/test_health.py security-engine/tests/integration -q` | **30 passed, 0 failed** (after updating tests for honest integrated scan/detection/explanation/capability behavior) |
| `python -m pip check` | No broken requirements |
| `npm audit --omit=dev` (extension) | 0 vulnerabilities |
| `ruff check` (modified files) | `orchestrator.py` has many pre-existing style issues (not introduced by this change set to avoid churn); `repair/engine.py` prompt-hardening formatting issues fixed; full ruff baseline not remediated here |
| Semgrep / Bandit / pip-audit / safety | Not available in environment |

**Note:** Earlier behavior-changing integration/performance work caused 3 legacy API tests to fail against old expectations; they were updated to assert honest integrated behavior. Full historical baseline suites were not rerun end-to-end in this pass.

## 5. Performance Investigation and Optimizations

### 5.1 Investigated areas
- **Large repository/file scanning:** full file discovery/read/parse/AST-CFG-DFG/taint/detection loops in `Orchestrator.scan_workspace` and `scan_file`; static analyzers invoked per root.
- **Large source files:** governed by `max_file_bytes` and schema `source_text` limits; parsing/analysis cost scales with file size/complexity.
- **Model loading / GPU-CPU memory / SAE extraction / counterfactual complexity:** research/model stages remain unavailable without configured runtime/artifacts; no model/SAE/counterfactual computation executed.
- **Static-analysis latency:** external tool startup/scan cost dominates when available; unavailable in this environment and reported explicitly.
- **Repair generation / verification overhead:** LLM generation not exercised; verification runs independent static/taint comparisons and optional isolated functional execution (consent/sandbox dependent).

### 5.2 Implementations (scientifically/behaviorally valid)
1. **Caching (valid):** in-process file-analysis cache keyed by analysis cache version + path + source SHA-256 + language to reuse parse/AST-CFG-DFG/taint results for unchanged content within process lifetime (`core/orchestrator.py`). No analysis stage removed.
2. **Progress/batching efficiency:** reduced per-file progress event volume (periodic updates) during workspace scans.
3. **Resource limits/responsiveness:** bounded static-analyzer target fanout per root to 500 discovered targets for very large repositories, with explicit warning recorded; detection still runs on analyzed discovered files.
4. **Cancellation:** existing cooperative cancellation checks preserved/invoked at key scan boundaries (`token.raise_if_cancelled()`).
5. **Asynchronous execution:** operation/job infrastructure (`JobStore`, jobs routes) remains available for tracked/cancellable execution interfaces; synchronous request paths preserved for compatibility.
6. **Incremental scanning support:** hash-based reuse provides incremental benefit for repeated/unchanged scans in-process; persistent cross-process incremental index not fully implemented.
7. **Memory management:** cache stores analysis objects in memory (process-scoped) for reuse; disk persistence of complex analysis objects avoided for safety/serialization complexity.
8. **Progress reporting:** stage reports now include cache metrics (`cached` counts) for preprocessing/program analysis transparency.

### 5.3 Benchmarks (controlled local measurements)

Measurements used FastAPI `TestClient` with a temporary workspace (2 controlled Python files + 30 synthetic Python modules, total 32 files), `Settings(workspace_roots=[tmp], data_dir=tmp/data)`, same process (so second calls exercise in-process cache).

| Scenario | Duration (ms) | HTTP | Operation status | Notes |
|---|---:|---:|---|---|
| `POST /api/v1/scan/file` (first, `vuln.py`) | 39.50 | 200 | partial | static analyzers unavailable in env |
| `POST /api/v1/scan/file` (cached, same content) | 6.22 | 200 | partial | reused cached parse/analysis |
| `POST /api/v1/scan/workspace` (32 files, first) | 42.62 | 200 | partial | `filesScanned=32` |
| `POST /api/v1/scan/workspace` (32 files, cached repeat) | 27.69 | 200 | partial | preprocessing/program_analysis reported `cached=32/32` |

**Interpretation:** Caching reduced repeated file-analysis overhead substantially in-process (especially single-file repeat and analysis reuse in workspace scans). End-to-end workspace latency still includes discovery, static-analyzer detection attempts, detection fusion, and response assembly. Results are environment-specific and not evidence of scalability for very large repositories.

### 5.4 Not implemented / constrained (by design)
- Did **not** remove required analysis stages to improve reported speed.
- Did **not** simulate unavailable analyzers, model/SAE/counterfactual/steering components, benchmarks, or security outcomes.
- Did **not** add distributed/background worker execution that could hide correctness/resource issues.

## 6. Unresolved Risks and Recommended Follow-ups

1. **Default no-auth local API:** enforce/guide `CRAFTSEC_API_TOKEN`, bind to loopback, and add rate limiting/throttling for exposed deployments.
2. **Prompt injection / model safety:** add stricter output schema enforcement, allowlist-based diff constraints, content filtering/red-teaming, and never trust LLM output without independent checks.
3. **Sandbox assurance:** validate Docker/VM isolation with adversarial tests; harden images, mounts, seccomp/apparmor, resource quotas, and egress controls per deployment.
4. **Path/diff handling robustness:** fuzz unified-diff parsing/apply in both engine and extension; enforce canonical target mapping across multi-file scenarios (currently constrained).
5. **Sensitive data lifecycle:** add configurable redaction, retention, encryption, and access controls for job/result/log artifacts and caches.
6. **Large-scale performance:** implement persistent incremental indexes (mtime/hash manifests), parallel/batched file analysis with deterministic aggregation, streaming/static-tool scoping, and cancellation-aware static runs.
7. **Static analysis/tooling gaps in this env:** install/run Semgrep, Bandit, CodeQL (where licensed/configured), pip-audit/safety, and CI SAST/SCA; keep results evidence-based.
8. **VS Code end-to-end validation:** exercise extension-host flows (scan/explain/repair preview/apply/verify, job progress/cancel) against running backend; add contract/integration UI tests.
9. **Regression coverage:** rerun broader legacy suites and add tests for new caching/limit behavior and security edge cases (path traversal in patches, prompt-injection fixtures, consent/sandbox denial paths).

## 7. Final Statement

CRAFT-Sec includes meaningful safeguards (workspace containment, request limits, optional API token auth, strict webview CSP/command allowlisting, isolated execution controls, independent verification design, and honest unavailable-state reporting), but **it must not be claimed secure merely because static analysis passes**. Security depends on correct configuration, trusted deployment boundaries, sandbox/runtime guarantees, dependency hygiene, model/prompt robustness, and comprehensive validation that was only partially possible in this environment.
