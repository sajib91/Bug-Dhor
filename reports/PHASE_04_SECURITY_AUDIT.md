# BUG-DHOR — PHASE 04: SECURITY AND PRIVACY RELEASE AUDIT

**Date:** 2026-11-19
**Repository:** https://github.com/sajib91/Bug-Dhor.git
**Scope:** VS Code extension (`vscode-extension/`) and separately distributed Python backend (`src/`, `security-engine/`, shared schemas, scripts, tests)
**Commit reviewed:** `e15e67a4a7370d26d5135dc1ffc6e2112d39a9c8`
**Decision:** **NO-GO for publication** — release-blocking findings are open.

> **Statement on audit status:** This is an internal source review and automated-check report, not a third-party penetration test, certification, or formal security audit. No security certification, compliance attestation, CVE-free guarantee, or externally validated result is claimed. Tool limitations are recorded in §7.3. Nothing was published, committed, or pushed.

> **Post-Phase-09 update:** A root MIT `LICENSE` now exists; the earlier “no license” statement is
> stale. The security findings and the NO-GO decision below are unchanged and were rechecked at
> current HEAD during Phase 09.

> **Post-remediation update (2026-11-20):** All 19 findings have been addressed in code or given a
> documented residual-risk statement. Detailed per-finding evidence, final test output, the
> re-audit matrix, and the release-gate disposition are in
> `reports/PHASE_04_SECURITY_REMEDIATION.md`. The historical findings below are retained for traceability.
> The decision line above is intentionally unchanged. When this note was first written,
> publisher/Marketplace Trusted Publishing, OIDC publish receipts, Windows tests, and the GitHub
> Actions SCA run were unverified. **Current disposition (2026-11-20, §§12–13):** hosted Windows/macOS/Linux
> compatibility evidence now exists, the hosted SCA run was observed and failed, the final
> gate implementation is uncommitted, and publisher/OIDC gates remain unverified. Section 13 is the
> final reconciliation and supersedes stale statements in §§3–11 where they conflict. No publish was performed.

---

## 1. Executive summary

The implementation has a strong security baseline: loopback-by-default transport, env-only credentials, strict backend URL parsing, allowlisted request fields, typed response contracts, no shell execution for user-controlled input, restrictive webview CSP, DOM-only rendering, modal patch approval with hash checks, bounded repository scanning, and unusually honest capability reporting.

However, the audit found **2 CRITICAL**, **4 HIGH**, **6 MEDIUM**, **4 LOW**, and **3 INFORMATIONAL** findings. The release blockers are:

| ID     | Severity     | Blocker                                                                                                                                                                       |
| ------ | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-01 | **CRITICAL** | Absolute `filePath` causes real workspace files to be overwritten during repair functional verification, before consent is checked.                                           |
| SEC-02 | **CRITICAL** | Absolute `filePath` causes real workspace files to be overwritten during recommendation candidate validation, before patch containment is checked.                            |
| SEC-03 | **HIGH**     | No workspace-trust gate; security-sensitive settings are `machine-overridable`, allowing an untrusted workspace to enable background source egress to a remote HTTP endpoint. |
| SEC-04 | **HIGH**     | Backend API authentication is optional by design, and non-loopback binding is allowed without requiring a token or TLS.                                                       |
| SEC-05 | **HIGH**     | Full response payloads containing source code and prompts are persisted to disk with default permissions.                                                                     |
| SEC-06 | **HIGH**     | Workspace snapshots for functional verification dereference symlinks, copying files outside the allowlisted root.                                                             |

All four HIGH backend/extension issues compound the same core problem: source content and execution behavior can cross the user's intended trust boundary without an explicit host-level decision.

Positive controls that should be preserved: ordinary scans are user-invoked and source text is opt-in; workspace scans send metadata only; background monitoring requires two separate consent flags; verification verdicts cannot be fabricated; SAE/model-internal claims are not asserted over the HTTP path.

---

## 2. Methodology

- Manual source review of all 19 audit areas across both components.
- Two independent parallel source audits (extension and backend), followed by direct verification of every CRITICAL/HIGH finding against exact source lines.
- Automated dependency and static checks listed in §7.
- Artifact inspection of the VSIX produced by the audited packaging pipeline.

Severity scale: **CRITICAL** = unauthorized write/execution or equivalent immediate harm; **HIGH** = realistic privilege/trust-boundary or privacy breach; **MEDIUM** = meaningful weakening or claim-integrity risk; **LOW** = defense-in-depth gap; **INFORMATIONAL** = adequately implemented or not applicable.

---

## 3. Release-blocking findings

### SEC-01 — CRITICAL — Unintended workspace write during repair verification

**Area:** Path traversal / patch application / test isolation
**Component:** Python backend

**Evidence chain (verified):**

1. `file_path` is only a bounded string at the API boundary — `security-engine/src/bugdhor/api/schemas/scan.py:27` (`file_path: str = Field(min_length=1, max_length=4096)`).
2. `resolve_file()` explicitly accepts absolute paths and only checks containment — `security-engine/src/bugdhor/core/paths.py:184-200`.
3. `_inspect()` verifies containment but preserves the raw request value; the raw `request.file_path` is passed into the workflow — `security-engine/src/bugdhor/core/orchestrator.py:1417-1433`, `:1717-1724`.
4. `RepairWorkflow.run()` passes it to `FunctionalVerifier.verify_patch()` — `security-engine/src/bugdhor/repair/workflow.py:245-254`.
5. The verifier writes **before** checking consent — `security-engine/src/bugdhor/verification/functional.py:118-126` writes original and patched source; consent is checked only at `:139-145`.
6. The write helper uses `root / file_path` — `security-engine/src/bugdhor/verification/functional.py:241-244`:

```python
target = root / file_path
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(source, encoding="utf-8")
```

With an absolute `filePath`, `pathlib` discards the temporary root and writes to the real file inside the allowlisted workspace. This contradicts the documented proposal-only contract (`security-engine/src/bugdhor/repair/workflow.py:299-320`; `security-engine/src/bugdhor/api/app.py:63-69`).

**Impact:** Caller-supplied patched source can overwrite a real workspace file without approval or consent.

**Remediation:** Reject absolute `filePath` at the API boundary or convert it to a verified relative path; derive write targets only from `snapshot.path.relative_to(root)`; make all verification writes temp-only; add a regression test asserting the target file hash is unchanged after `repair_generate`.

---

### SEC-02 — CRITICAL — Unintended workspace write during recommendation validation

**Area:** Path traversal / patch validation
**Component:** Python backend

**Evidence chain (verified):**

1. Raw `request.file_path` is passed to the recommendation engine — `security-engine/src/bugdhor/core/orchestrator.py:1542-1557`.
2. `_apply_and_validate()` writes the source before any patch containment check — `security-engine/src/bugdhor/recommendation/engine.py:846-856`:

```python
root = Path(directory)
target = root / file_path
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(source_text, encoding="utf-8")
apply_patch(root, patch)
```

3. Path rejection in `_apply_patch()` occurs only after the first write — `security-engine/src/bugdhor/repair/engine.py:382-396`.
4. The same `root / file_path` pattern exists in `_evaluate()` — `security-engine/src/bugdhor/repair/engine.py:313-323`.

**Impact:** Same unauthorized real-file overwrite as SEC-01, via the recommendation path. API tests already use absolute paths (`security-engine/tests/api/conftest.py:33`), so the input shape is reachable.

**Remediation:** Same as SEC-01; validate all patch target paths before any write; use one canonical patch-application routine with containment and hash checks.

---

### SEC-03 — HIGH — No workspace-trust gate; untrusted workspace can enable source egress

**Area:** Untrusted workspace behavior / source transmission / localhost API / command execution
**Component:** VS Code extension

**Evidence (verified):**

- Source-wide grep for `isTrusted|workspaceTrust` in `vscode-extension/src/**/*.js` returned **no** matches.
- All security-sensitive settings are `machine-overridable` (verified from `vscode-extension/package.json`):

```text
bugdhor.backend.url                              default http://127.0.0.1:8765
bugdhor.privacy.sendSourceText                   default true
bugdhor.monitoring.enabled                       default false
bugdhor.monitoring.allowAutomaticSourceSharing   default false
bugdhor.repository.autoScanOnWorkspaceOpen       default false
bugdhor.recommendations.allowSandboxedExecution  default false
bugdhor.localEngine.enabled                      default false
bugdhor.localEngine.pythonPath                   default python
bugdhor.localEngine.allowSourceWrite             default false
```

- Settings are read directly without a trust check — `vscode-extension/src/config.js:81`, `:84-110`, `:163-166`; `src/extension.js:36-55`.
- Background monitoring sends source text when two consent flags are true — `src/monitoring/realtimeMonitor.js:686-690` (`hasSourceConsent`) and `:578-601` (`sourceText: text` → `scanFile`/`scanSelection`).
- The monitoring path has **no loopback check**, unlike repository scans (`src/commands/repositoryCommands.js:74-79`, `:403-408`). Loopback detection is string-based (`src/api/configurationService.js:225-237`).
- Non-loopback backend URLs produce only a log warning — `src/extension.js:179-185`.
- The local engine can be given a workspace-controlled Python path and import path (`src/phase6/localEngine.js:44-58`, `:160-170`) once enabled.

**Impact:** A malicious `.vscode/settings.json` in an untrusted workspace can set a remote HTTP backend, enable monitoring and automatic source sharing, and cause editor source text to leave the machine without an explicit host-level trust decision. It can also attempt to enable auto-scan, sandboxed execution, and local-engine behavior.

**Existing mitigations:** All high-risk features default to disabled (except `sendSourceText`, which applies only to user-invoked scans); repository scans require loopback; local writes require modal confirmation and exact `patch_id`.

**Remediation:** Add a central `vscode.workspace.isTrusted` guard; treat untrusted workspaces as local-only/read-only; require loopback for all source-bearing requests; require HTTPS for non-loopback endpoints; change the highest-risk settings to `machine` or `application` scope; add untrusted-workspace integration tests.

---

### SEC-04 — HIGH — Backend API unauthenticated by default; non-loopback bind unrestricted

**Area:** API key handling / localhost API security
**Component:** Python backend

**Evidence (verified):**

- Authentication is pass-through when no token is configured — `security-engine/src/bugdhor/api/middleware/auth.py:27-35`. Constant-time comparison is used when a token exists (`:37-45`).
- Loopback is only a default — `security-engine/src/bugdhor/core/settings.py:46`; operators can override `--host`/`--port` via `security-engine/src/bugdhor/main.py:18-22`, `:40-45`.
- Token is optional — `security-engine/src/bugdhor/core/settings.py:53-56`.
- CORS rejects wildcards but is otherwise explicit — `security-engine/src/bugdhor/core/settings.py:104-121`; `security-engine/src/bugdhor/api/app.py:131-144`.
- Docs/OpenAPI are exposed by default — `security-engine/src/bugdhor/api/app.py:113-121`.

**Impact:** With no token, any local process can analyze files under the default root (`Path.cwd()`, `settings.py:49`). With a non-loopback bind, the unauthenticated source-analysis API becomes network-reachable over plain HTTP.

**Remediation:** Fail startup if `host` is non-loopback and `api_token` is unset; require TLS for non-loopback; disable docs/redoc/openapi by default in production; prefer a Unix-domain socket for local IPC.

---

### SEC-05 — HIGH — Source and prompt payloads persisted with default permissions

**Area:** Sensitive information / privacy
**Component:** Python backend

**Evidence (verified):**

- Full result payloads are written to disk — `security-engine/src/bugdhor/core/orchestrator.py:394-410`.
- Job results persist full mappings — `security-engine/src/bugdhor/core/jobs.py:203-209`; result directories use default permissions (`:82-88`).
- Recommendation responses include `original_code`, `repaired_code`, `prompt`, and candidates — `security-engine/src/bugdhor/api/schemas/recommendation.py:37-51`; prompt text is added at `orchestrator.py:1563-1564`.

**Impact:** Proprietary source and generated prompts can be retained on disk indefinitely with permissive file modes, outside the user's privacy-setting control.

**Remediation:** Disable full-payload persistence by default; persist hashes/metadata only; use `0600`/`0700` permissions; add retention/expiry and secret redaction before persistence.

---

### SEC-06 — HIGH — Workspace snapshot dereferences symlinks

**Area:** Symlink handling / repository scanning boundaries / test isolation
**Component:** Python backend

**Evidence (verified):**

- `_copy_workspace_snapshot()` skips only ignored directory names, not symlinks — `security-engine/src/bugdhor/verification/functional.py:225-239`.
- `shutil.copytree()` defaults to `symlinks=False`, so symlinked files and directories are dereferenced (`:235`).
- The snapshot is later bind-mounted into Docker — `security-engine/src/bugdhor/sandbox/executor.py:166-168`.

**Impact:** A symlink inside the allowed root can copy files from outside the root into the verification tree and expose them to project tests in the container. This bypasses the otherwise strong symlink rejection in discovery (`security-engine/src/bugdhor/core/paths.py:184-200`, `:281-314`, `:317-397`).

**Remediation:** Skip `item.is_symlink()` at every level; use `shutil.copytree(..., symlinks=True)` or re-check containment after resolution; add symlink regression tests.

---

## 4. Non-blocking findings

### SEC-07 — MEDIUM — Direct file inspection is not limited to source files

**Area:** Repository scanning boundaries
`security-engine/src/bugdhor/core/paths.py:218-278` calls `resolve_file()` but not `is_source_file()`, unlike explicit workspace inspection (`:371-372`). Any regular UTF-8 file inside the root, including config or credential-bearing files, can be inspected via `scan_file`. Remediation: apply the source extension allowlist and add secret-file deny rules.

### SEC-08 — MEDIUM — HTTP response size cap is character-based and post-buffering

**Area:** HTTP request/response validation / file size limits
`vscode-extension/src/api/apiClient.js:12-13`, `:352-398` call `response.text()` and then compare `responseText.length` to `maxResponseBytes`. The body is fully buffered first and the counter measures JavaScript string units, not bytes. Remediation: stream with a byte counter and abort at the limit; add JSON depth/array-length caps.

### SEC-09 — MEDIUM — Error, stderr, and exception text can leak context

**Area:** Sensitive logs / malformed input
Backend exception text is embedded in warnings and stage details (`security-engine/src/bugdhor/core/orchestrator.py:546`, `:775-784`, `:852-856`); tool stderr is appended to warnings (`security-engine/src/bugdhor/static/semgrep.py:172-174`, `bandit.py:164-165`); sandbox command tuples include `-e KEY=value` entries (`security-engine/src/bugdhor/sandbox/executor.py:175-176`, `:193-201`). The extension incorporates backend `detail`/`title` into user-facing errors (`vscode-extension/src/api/apiClient.js:147-188`) without a length cap or control-character sanitization. Remediation: central redaction, reason codes instead of raw stderr, capped details.

### SEC-10 — MEDIUM — Execution verification is silently skipped in the static verification engine

**Area:** Verification claims / capability honesty
`security-engine/src/bugdhor/verification/engine.py:257-271` returns `status="skipped"` when `run_execution=True` or `profile="sandbox"`. This is **honest** but can be misread as execution verification by callers. Remediation: reject those inputs as unsupported or expose an explicit `executionExecuted: false` field. Do not report execution verification from this path.

### SEC-11 — MEDIUM — Semgrep may fetch remote rules

**Area:** Analyzer supply chain
`security-engine/src/bugdhor/static/semgrep.py:32-39`, `:91-92` default to `--config=auto`. Metrics and version checks are disabled, but rules are not pinned or offline-enforced. Remediation: pin reviewed local rule paths for offline deployments.

### SEC-12 — MEDIUM — Dependency/SCA gaps

**Area:** Dependency vulnerabilities
Python dependencies use broad ranges with no hash-pinned lockfile (`security-engine/pyproject.toml:10-26`, `:31-50`); the capability report correctly states automated SCA is not shipped (`security-engine/src/bugdhor/core/capability_report.py:103-111`). `npm audit` reports 3 moderate **development-only** advisories (`@vscode/vsce`, `glob`, `minimatch`); production audits report 0. Remediation: add a Python lockfile, CI SCA, and SBOM; evaluate the semver-major `@vscode/vsce@4.1.1` upgrade.

### SEC-13 — LOW — Credential handling residuals

**Area:** API key handling
Extension `registry.js:100-103` accepts a programmatic `config.apiKey` even though no settings path populates it (`vscode-extension/src/integrations/registry.js:93-103`). Backend tokens are static with no rotation or entropy policy (`security-engine/src/bugdhor/api/middleware/auth.py:14-45`). No credential values were found in `package.json` or workspace settings; only variable names are stored (`vscode-extension/package.json:660-664`). Remediation: forbid programmatic key injection; use `SecretStorage`; add rotation guidance.

### SEC-14 — LOW — Lexical-only path containment in the extension

**Area:** Path traversal / symlink handling
`vscode-extension/src/security/paths.js:5-28` is explicitly lexical; repository inventory does skip symlinks (`src/repository/repositoryInventory.js:506-515`, `:597-608`), but other file-open and dashboard location checks do not resolve realpaths. The Phase 6 session path may be absolute (`src/phase6/localEngine.js:160-165`). Remediation: add realpath checks at file-operation boundaries; reject absolute session paths.

### SEC-15 — LOW — Full-file replacement is a wider repair trust surface

**Area:** Repair patch validation
`vscode-extension/src/webviews/dashboardPanel.js:659-690` can use backend-provided `repairedText` instead of a unified diff. It is still gated by modal approval and base-hash checks, but has no explicit size cap or full diff preview. Remediation: prefer unified diffs; enforce maximum replacement size; revalidate immediately before apply.

### SEC-16 — LOW — Verification is requested but not awaited into repair state

**Area:** Patch application and rollback
`vscode-extension/src/webviews/dashboardPanel.js:730-756` requests a fresh verification run without recording its verdict. No false success is claimed, but states remain ambiguous. Remediation: distinguish `applied`, `verification requested`, `verified passed`, `verified failed`, and `inconclusive`.

### SEC-17 — INFORMATIONAL — Webview CSP and XSS controls are adequate

`vscode-extension/src/webviews/csp.js:10-12`, `:24-45` uses a 16-byte per-render nonce with `default-src 'none'`, `connect-src 'none'`, and no inline/script/frame/worker/form allowances. `src/webviews/html.js:9-16`, `:28-35` escapes attributes and serialized state; `media/dashboard.js` uses DOM text nodes and no dynamic `innerHTML`, `eval`, `fetch`, or WebSocket. Backend returns typed JSON/problem responses with no HTML rendering.

### SEC-18 — INFORMATIONAL — Capability honesty is preserved

Backend explicitly reports unavailable stages without invented findings (`security-engine/src/bugdhor/api/app.py:80-90`; `core/orchestrator.py:118-143`), labels scores `heuristic_index` (`:590-597`), declares SCA manual-only (`core/capability_report.py:103-111`), and skips execution verification honestly (`verification/engine.py:257-271`). Extension forces `steeringValidated = false` over HTTP (`src/api/securityEngineService.js:338-344`) and requires repair approval (`src/api/securityResultService.js:586-601`). Integration tests reject fabricated SAE/model-internal claims (`test/integration/index.js:466-469`, `:486-501`). No SAE or model-internal capability is asserted as validated.

### SEC-19 — INFORMATIONAL — Packaging hygiene is adequate

The extension has one runtime dependency (`ajv ^8.20.0`); the VSIX stages only the five-package production closure and excludes dev/test/model/secret artifacts (`.vscodeignore:18-45`, `:56-79`; `scripts/stageRuntimeDeps.js:38-56`; `scripts/packageVsix.js:30-49`). No API keys, `.env`, Python backend files, or parent-directory paths are present in the archive.

---

## 5. Coverage matrix — all 19 required areas

|   # | Area                                  | Classification             | Status / key evidence                                                                                                                                                     |
| --: | ------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|   1 | Source-code transmission              | **HIGH**                   | Ordinary scans are user-invoked and opt-in; workspace scans metadata-only; monitoring requires 2 flags — but no trust gate and no loopback check in monitoring (SEC-03).  |
|   2 | API key handling                      | **LOW**                    | Env-only tokens and variable-name-only settings; programmatic `config.apiKey` residual (SEC-13).                                                                          |
|   3 | Localhost API security                | **HIGH**                   | Loopback default and CORS controls; optional auth, unrestricted host override, no TLS (SEC-03, SEC-04).                                                                   |
|   4 | Backend endpoint validation           | **LOW**                    | Strict URL shape parsing; path/query/fragment/credentials rejected (`configurationService.js:42-92`); API prefix enforced (`apiClient.js:283-288`). Policy gap in SEC-03. |
|   5 | HTTP request/response validation      | **MEDIUM**                 | Strong typed contracts; response cap is character-based and post-buffering (SEC-08).                                                                                      |
|   6 | Path traversal protection             | **CRITICAL / LOW**         | Backend absolute-path writes (SEC-01, SEC-02); extension lexical checks and absolute session path (SEC-14).                                                               |
|   7 | Symlink handling                      | **HIGH / LOW**             | Backend snapshot dereferences symlinks (SEC-06); extension repository inventory skips them correctly, other boundaries lexical (SEC-14).                                  |
|   8 | Repository scanning boundaries        | **MEDIUM**                 | Allowlisted roots, gitignore, counts/size limits, symlink skip; auto-scan is workspace-overridable (SEC-03, SEC-07).                                                      |
|   9 | File size limits                      | **MEDIUM**                 | Backend 2 MiB request / 1 MiB file / 50k files and streaming limit tests pass; extension response cap inaccurate (SEC-08).                                                |
|  10 | Malicious or malformed source input   | **MEDIUM**                 | Binary/NUL/UTF-8 checks, tree-sitter data-only parsing, bounded diagnostics; error text leakage (SEC-09).                                                                 |
|  11 | Webview Content Security Policy       | **INFORMATIONAL**          | Strict nonce CSP; no network/frame/worker/form sources (SEC-17).                                                                                                          |
|  12 | HTML injection and XSS                | **INFORMATIONAL**          | Escaped attributes/state, DOM-only rendering, no dangerous sinks (SEC-17).                                                                                                |
|  13 | Command execution and shell injection | **LOW**                    | `execFile`/fixed argv, `shell=False`, Docker argv hardening; workspace-overridable local-engine settings (SEC-03, SEC-14).                                                |
|  14 | Repair patch validation               | **CRITICAL / LOW**         | Backend write-before-validate (SEC-01, SEC-02); extension patch path/hunk/context validation and approval (SEC-15).                                                       |
|  15 | Patch application and rollback        | **CRITICAL / LOW**         | Real writes despite proposal-only contract (SEC-01, SEC-02); extension modal approval, stale and applied-hash checks (SEC-16).                                            |
|  16 | Functional test execution isolation   | **CRITICAL / HIGH**        | Writes before consent and symlink snapshot (SEC-01, SEC-06); consent defaults off, Docker hardened, integration tests isolated.                                           |
|  17 | Sensitive information in logs         | **HIGH / MEDIUM**          | Full payload persistence (SEC-05); error/stderr leakage (SEC-09); API client logs no bodies or tokens.                                                                    |
|  18 | Dependency vulnerabilities            | **MEDIUM / INFORMATIONAL** | Python SCA/lockfile gap and 3 dev-only npm advisories (SEC-12); production audits clean.                                                                                  |
|  19 | Untrusted workspace behavior          | **HIGH**                   | No trust gate; machine-overridable high-risk settings (SEC-03).                                                                                                           |

---

## 6. Special requirements verification

| Requirement                                            | Result                                | Evidence                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Never silently upload user source code                 | **Pass with caveat**                  | Explicit scans require user invocation; `sourceText` gated by `sendSourceText` (`workspaceService.js:123-164`, `securityEngineService.js:220-270`); workspace scans metadata-only (`:553-654`); monitoring requires 2 consent flags (`realtimeMonitor.js:686-690`). Caveat: untrusted-workspace override (SEC-03). |
| Preserve explicit privacy settings                     | **Pass**                              | Defaults preserved: `sendSourceText=true`, `monitoring.enabled=false`, `allowAutomaticSourceSharing=false`. No settings were changed during this audit. Caveat: scope allows workspace override (SEC-03).                                                                                                          |
| No credentials in `package.json` or workspace settings | **Pass**                              | Only environment-variable names are stored (`package.json:660-664`); backend token is env-driven (`core/settings.py:53-56`). §2 of the extension audit found no key values.                                                                                                                                        |
| Avoid shell execution for user-controlled input        | **Pass**                              | `execFile` with fixed argv (`gitChangedFiles.js:49-56`, `:114-122`; `localEngine.js:67-80`); backend `shell=False` (`static/execution.py:114-123`) and argv-based Docker (`sandbox/executor.py:155-178`).                                                                                                          |
| Treat model-generated patches as untrusted             | **Pass**                              | Patch path/hunk/context validation (`patchApplication.js:7-100`), single-file target enforcement (`dashboardPanel.js:692-698`), backend containment check (`repair/engine.py:382-396`). Caveat: SEC-01/SEC-02 write before validation.                                                                             |
| Require review before modifying source                 | **Pass (extension) / Fail (backend)** | Extension modal approval + hash checks (`dashboardPanel.js:664-782`); backend writes before consent (SEC-01/SEC-02).                                                                                                                                                                                               |
| No unverified repair claims                            | **Pass**                              | Verification verdict enum enforced, repair proposals must require approval (`securityResultService.js:586-601`, `:676-687`), verification does not resolve findings (`test/integration/index.js:526-565`). Caveat: SEC-10 semantics.                                                                               |
| No unvalidated SAE/model-internal claims               | **Pass**                              | Steering validation forced false over HTTP (`securityEngineService.js:338-344`); integration tests reject fabricated claims; capability report marks SCA manual-only.                                                                                                                                              |

---

## 7. Automated checks

### 7.1 Commands and results

| Command                                                                                | Result                                                                                                                                                               |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm ci` (root and extension)                                                          | Pass — `added 408 packages, and audited 410 packages in 5s`; 3 moderate dev advisories reported.                                                                     |
| `npm test` (extension)                                                                 | Pass — `tests 403 / pass 403 / fail 0`, duration ~2.9 s.                                                                                                             |
| `npm run lint` (extension)                                                             | Pass — no findings.                                                                                                                                                  |
| `npm audit` (root)                                                                     | 3 moderate, 0 high, 0 critical: `@vscode/vsce`, `glob` (`GHSA-3g3m-2fjr-6pw4`), `minimatch` (`GHSA-g3hv-75wg-m249`); fix requires semver-major `@vscode/vsce@4.1.1`. |
| `npm audit --omit=dev` (root and extension)                                            | `{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}`.                                                                                                   |
| `PYTHONPATH=src:security-engine/src .venv/bin/python -m pytest -q`                     | `1090 passed in 11.30s`.                                                                                                                                             |
| `.venv/bin/python -m bandit -q -r src security-engine/src tests security-engine/tests` | Exit 1 — 66,195 LOC; Undefined 0, **Low 3487, Medium 6, High 0**.                                                                                                    |
| `.venv/bin/python -m pip check`                                                        | `No broken requirements found.`                                                                                                                                      |
| `.venv/bin/python -m compileall -q src security-engine/src`                            | Exit 0.                                                                                                                                                              |
| `.venv/bin/python -m ruff check src security-engine tests`                             | Exit 1 — 493 findings (predominantly `I001` import-ordering style); not treated as security findings.                                                                |
| `unzip -t bug-dhor-0.1.0.vsix`                                                         | `No errors detected`.                                                                                                                                                |

A bare `.venv/bin/python -m pytest -q` fails with 28 collection errors (`ModuleNotFoundError: No module named 'bugdhor_ast'`) because the source paths are not on `PYTHONPATH`; the correct invocation above passes.

### 7.2 Notable Bandit medium findings (first-party code)

```text
B614:pytorch_load              security-engine/src/bugdhor/models/activations.py:350:15
B614:pytorch_load              security-engine/src/bugdhor/sae/checkpoint.py:44:18
B615:huggingface_unsafe_download  security-engine/src/bugdhor/models/compatibility_probes.py:651:12
B615:huggingface_unsafe_download  security-engine/src/bugdhor/models/compatibility_probes.py:657:16
B108:hardcoded_tmp_directory   security-engine/src/bugdhor/sandbox/executor.py:46:39
B608:hardcoded_sql_expressions security-engine/tests/integration/samples/vulnerable_sql.py:7:12  (intentional fixture)
```

The `torch.load(..., weights_only=False)` and unpinned Hugging Face downloads are real supply-chain concerns if untrusted model artifacts are supplied; no claim is made that validated SAE/model internals exist.

### 7.3 Tool limitations (not claimed as completed)

- **Semgrep unavailable:** `.venv/bin/semgrep` has a stale shebang pointing to `/Users/md.khayrulislamsajib/Downloads/CRAFT-Sec/.venv/bin/python`; `python -m semgrep scan` exits 2 with `No such file or directory execvp pysemgrep`. No Semgrep results are reported.
- **Python SCA unavailable:** `pip-audit` (`No module named pip_audit`) and `safety` (`No module named safety`) are not installed; `osv-scanner` and `trivy` are unavailable. Therefore **no Python dependency CVE scan was completed**, consistent with the backend's own manual-only SCA declaration.

---

## 8. Release artifact integrity

During this audit the on-disk VSIX was found to have drifted from the Phase 01 artifact:

```text
observed before rebuild: 96 entries, 326,004 bytes, SHA-256 321afa57...,
                         0 node_modules entries (no runtime dependency closure)
```

It was rebuilt using the audited wrapper (`npm run package:vsix`):

```text
after rebuild:           245 entries, 490,330 bytes,
                         149 node_modules entries, unzip -t OK
```

The sorted file-entry list is identical to the Phase 01 artifact (`cmp` exit 0). The SHA-256 differs from the Phase 01 value because `vsce` does not produce a byte-deterministic archive (entry ordering/timestamps vary); release verification should compare the file-entry set and counts, or make the build deterministic. No bypass flags (`--skip-license`, `--no-dependencies`) are used; the missing-license warning remains visible.

No source files were deleted. The extension identity was re-verified as `bug-dhor` / `sajib91` / `Bug-Dhor: AI Code Security Analyzer` after a transient concurrent workspace edit was reverted.

---

## 9. Release gates — NO-GO

Publication must remain blocked until all of the following are satisfied:

1. **Fix SEC-01 and SEC-02 (CRITICAL)** — eliminate all real-file writes before consent/containment; add hash-unchanged regression tests.
2. **Fix SEC-03 through SEC-06 (HIGH)** — workspace-trust enforcement and loopback/TLS policy; backend auth requirement; disable source/prompt persistence by default; symlink-safe snapshots.
3. **Resolve or formally accept MEDIUM findings** — especially SEC-08, SEC-09, SEC-10, SEC-11, and SEC-12.
4. **Re-run the full test suites and audits after fixes** — 403 extension tests, 1,090 Python tests, npm audits, Bandit, and artifact inspection.
5. **Complete Python SCA** using an available tool, or document the accepted gap.
6. **Resolve the Phase 01 non-code gates:** no repository license exists (no license was invented), and `sajib91` publisher ownership must be verified.
7. **Rebuild and re-verify the VSIX** from the clean staging pipeline immediately before any publication.

No publish, commit, or push was performed during this audit.

---

## 10. Closing statement

This report documents an internal review against the 19 requested areas with the evidence actually collected. It does not claim any external certification, penetration-test result, CVE-free status, or validated SAE/model-internal capability. The strongest parts of the codebase — containment checks, contract validation, CSP, approval gates, and capability honesty — should be preserved while the identified write-before-consent and trust-boundary issues are fixed.

---

## 11. Post-remediation verification (2026-11-20)

The original findings above are retained as the historical record. The code-level remediation was completed and re-audited across all 19 areas; full evidence is in `reports/PHASE_04_SECURITY_REMEDIATION.md`.

### 11.1 Final local checks

| Command | Result |
|---|---|
| `PYTHONPATH=src:security-engine/src .venv/bin/python -m pytest -q` | `1106 passed in 11.26s` |
| `npm test` | `439 tests`, `439 pass`, `0 fail` |
| `npm run extension:lint` | Pass — no findings |
| `npm run extension:test:integration` | `Bug Dhor Extension Host checks passed.` |
| `npm --workspace vscode-extension run test:integration:vsix` | `Bug Dhor VSIX smoke checks passed.` |
| `npm audit --omit=dev --json` | `0` total vulnerabilities |
| `.venv/bin/python -m pip check` | `No broken requirements found.` |
| `.venv/bin/python -m compileall -q security-engine/src security-engine/tests` | Exit 0 |
| `pip-compile --no-header --allow-unsafe --generate-hashes --extra ml --extra dev ...` | Empty lock diff |
| `pip-audit --require-hashes -r requirements.lock.txt --strict` | `No known vulnerabilities found` |
| Bandit (`-q -r src security-engine/src tests security-engine/tests`) | Undefined 0, Low 3536, Medium 11, **High 0** |
| Repository Ruff | 486 style findings remain; new security modules and regression suite pass targeted Ruff |
| `unzip -t vscode-extension/bug-dhor-0.1.0.vsix` | `No errors detected` |

Final VSIX: `vscode-extension/bug-dhor-0.1.0.vsix`, 240 entries, 492,783 bytes, SHA-256 `94ccd60ab553cab8d161339b29cdf0eaa54bd780827f7ef4a37282149534efd6`.

### 11.2 Gate disposition

- SEC-01 through SEC-06 and all MEDIUM/LOW findings are resolved in code or carry an explicit documented residual in the remediation report.
- Local code gates, regression tests, production dependency audit, Python SCA, and artifact checks pass.
- At the time §11 was written, publisher ownership, Marketplace Trusted Publishing/OIDC policy and receipts, Windows tests, the GitHub Actions SCA run, and a real VS Code untrusted-host test remained unverified. The local untrusted-host test has since passed and hosted three-OS compatibility evidence exists; see §12 for the current distinction.
- The security-critical files were untracked when §11 was written; they are committed in HEAD `7b312f9b72889a36401400d61c59a30e6afce3ce`. The newer gate-manifest and untrusted-test files are the currently uncommitted change set.

**Decision unchanged:** **NO-GO for publication** until every release gate, including publisher/Marketplace Trusted Publishing, is verified. No publish was performed. Section 12 records the current evidence-based status.

---

## 12. Current final-gate status (2026-11-20)

This section adds a dated current status without rewriting the historical NO-GO findings above.

### 12.1 Repository state

- HEAD and `origin/main` were `7b312f9b72889a36401400d61c59a30e6afce3ce` at the start of this review.
- The Phase 04 security remediation is committed in that HEAD; the stale claim that `core/safe_patch.py`, `core/redaction.py`, `core/persistence.py`, the extension security modules, the SCA workflow, rules, and regression suite are untracked is resolved by `git ls-tree`.
- The final-gate implementation added during this review is **not committed**: three workflows and `vscode-extension/package.json` are modified, and four gate scripts/tests are untracked. No commit, push, tag, or publish was performed by this review.

### 12.2 GitHub-hosted CI evidence actually observed

| Run | Workflow / input | Hosted result | Evidence and interpretation |
|---|---|---|---|
| [`44606156782`](https://github.com/sajib91/Bug-Dhor/actions/runs/44606156782) | `Extension compatibility tests`, push on `7b312f9` | **Success** | All 12 jobs succeeded: lint, unit, package validation, and Extension Host + installed-VSIX integration on `macos-latest`, `windows-latest`, and `ubuntu-latest`. Log lines include `Bug Dhor Extension Host checks passed.` and `Bug Dhor VSIX smoke checks passed.` on all three OSes. This is hosted evidence for the old job names; it does not contain the new structured-manifest jobs. |
| [`44606156254`](https://github.com/sajib91/Bug-Dhor/actions/runs/44606156254) | `Python dependency SCA`, push on `7b312f9` | **Failure** | The single job failed because `pip-compile` regenerated the lock with platform-specific `nvidia-*`, `torch`, and `triton` entries. The local empty-diff result did not reproduce on GitHub. The workflow was changed locally to install and audit the committed hash lock directly; that change has **not** been re-run on GitHub. |
| [`44673317664`](https://github.com/sajib91/Bug-Dhor/actions/runs/44673317664) | `Publish extension (OIDC Trusted Publishing)`, `confirm_publish=false` | **Success** | Validation-only run: lint, unit checks, identity/metadata validation, clean staging, VSIX build, and integrity passed (`VSIX integrity OK: 240 entries, 491617 bytes`). The `Publish with OIDC` job was skipped. No Marketplace publish occurred. |
| [`44673435565`](https://github.com/sajib91/Bug-Dhor/actions/runs/44673435565) | `Publish extension (OIDC Trusted Publishing)`, `confirm_publish=true` | **Failure** | Validation reached the historical prose gate and failed with `Phase 04 still records a NO-GO publication decision.` The `Publish with OIDC` job was skipped. That grep gate has been replaced locally by a structured manifest; the replacement has **not** been re-run on GitHub. |

### 12.3 Local evidence completed in this review

| Check | Result |
|---|---|
| Clean Python 3.11 environment with `security-engine[dev,ml]` plus `requirements-ast.txt` | `PYTHONPATH=src:security-engine/src python -m pytest -q`: **1106 passed in 29.10s** |
| `npm test` | Engine-local pytest **742 passed**, extension unit tests **439 pass / 0 fail** |
| `npm --workspace vscode-extension run test:integration:untrusted` | **Pass** — real local VS Code was spawned without `--disable-workspace-trust`; `Untrusted workspace Extension Host checks passed.` |
| `node --check` on four new JavaScript files | Pass |
| YAML parse of all three modified workflows | Pass |
| Synthetic manifest evidence checks | Pass — NO-GO decision, sidecar SHA-256, decision consistency, stale-evidence rejection |
| `git diff --check` | Pass |

The root test job needed two dependency corrections: `requirements-ast.txt` supplies `tree_sitter_java/c/cpp/go`, and the `ml` extra supplies `torch`. Both are now in the modified `extension-tests.yml`; neither has hosted evidence yet.

### 12.4 Publisher, Marketplace, and OIDC status

- GitHub facts only: the authenticated `gh` account is `sajib91`, and `sajib91/Bug-Dhor` is a public repository owned by `sajib91`. No token value was printed or stored in a report.
- `npx --no-install @vscode/vsce show sajib91.bug-dhor --json` returned `undefined`; no public listing metadata was available. This does **not** prove Marketplace publisher ownership either way.
- Marketplace Trusted Publishing policy, repository/workflow policy fields, OIDC issuer/audience authorization, and an actual OIDC publish receipt remain **UNVERIFIED**.
- Official VS Code publishing documentation requires the policy to name repository owner `sajib91`, repository `Bug-Dhor`, workflow `publish-extension.yml`, and an empty GitHub environment. The Marketplace OIDC credential expires after 15 minutes and each GitHub OIDC token can be exchanged once. The publish job alone has `id-token: write`; validation and manifest jobs do not.

### 12.5 Structured release-gate manifest

The grep on report prose was removed from the publish workflow and replaced by `scripts/generateReleaseManifest.js` plus `scripts/verifyReleaseManifest.js`:

- 16 mandatory evidence gates: lint/unit/package/integration on three OSes, plus `python-tests`, `python-sca`, `npm-audit`, and `untrusted-workspace`.
- Evidence JSON is machine-generated inside each CI job and validated for schema, gate name, commit SHA, run ID, run URL, TTL, and required fields. Report prose is never read.
- The generator emits `release-gate-manifest.json` and a SHA-256 sidecar. The verifier checks freshness, hash consistency, exact commit/repository, all gate statuses, and then rechecks the recorded run and every gate job conclusion through the GitHub Actions API before publication. Its strict default still requires a `GO` decision and zero blockers; `--allow-no-go` is used only by the validation workflow to report authorization state.
- Three external blockers remain explicit and fail-closed: `oidc-publish-receipt`, `publisher-ownership`, and `trusted-publishing-policy`. They are cleared only by a passing `evidence-<gate>` artifact for the same commit and run; a manifest may not pair evidence with a blocker for the same gate. No such evidence exists here, so the current manifest is NO-GO. Untrusted workspace behavior is no longer an external blocker because it is a mandatory CI gate with its own evidence artifact.
- Manual dispatch, explicit `confirm_publish`, local/remote duplicate tag checks, Marketplace version checks, OIDC confined to the publish job, and exact validated-VSIX checksum comparison are preserved. The OIDC job additionally requires `needs.validate-release.outputs.authorized == 'true'`; a NO-GO validation reports a warning and skips publication.

### 12.6 Remaining unverified gates and decision

Unverified: hosted execution of the modified workflows and manifest artifact; Marketplace publisher ownership; Marketplace Trusted Publishing policy; OIDC issuer/audience trust; an authorized OIDC publish receipt; Semgrep executable availability (accepted residual). The historical SCA run failed and has only a local fix awaiting hosted re-run.

**Current decision remains NO-GO for publication.** Local passing checks and the successful historical compatibility run do not substitute for the unresolved external gates or for a hosted run of the new manifest implementation. No publication command was executed.

---

## 13. Final reconciliation and release-readiness decision (2026-11-20)

**Final decision: NO-GO for publication.** This is unchanged from the original audit and §12. GO is not claimed because hosted run `44710375008` produced a NO-GO manifest, and the `oidc-publish-receipt`, `publisher-ownership`, and `trusted-publishing-policy` gates remain unverified. The follow-up workflow change makes that NO-GO a clear authorization warning with publication skipped rather than a validation-job failure; it does not authorize release.

Status meanings used below:

- **PASS** — verifiable evidence exists for the stated scope. “Local” or “committed workflow” scope is stated explicitly.
- **FAIL** — an observed check failed, or a required release-control file is absent from Git.
- **NOT VERIFIED** — no verifiable evidence is available; this is not treated as a pass.

### 13.1 Reconciliation of outdated or conditional statements

| Earlier statement | Final disposition |
|---|---|
| §3 and §9 describe SEC-01–SEC-06 as open release blockers. | Historical finding record retained. Code remediation is complete and regression-tested; see §13.2 and `PHASE_04_SECURITY_REMEDIATION.md` §§3–6. This does not authorize publication. |
| §7.3 says Python SCA was unavailable. | Superseded. An isolated local `pip-audit --require-hashes --strict` run passed, but the hosted SCA workflow failed before install/audit. The modified workflow has not run on GitHub. |
| §9 says “no repository license exists.” | Superseded. A root MIT `LICENSE` is present and the publish workflow verifies it. |
| §9 and §7.1 quote 403 extension tests and 1,090 Python tests. | Superseded by the final local runs: **1,106 Python tests** and **439 extension unit tests**; root `npm test` also reports **742 engine pytest tests** passing. |
| §11.1 records an empty `pip-compile` diff as a final local check. | Local-only and historical. Hosted run `44606156254` failed on platform-specific regeneration. The final workflow audits the committed hash lock directly and has no hosted evidence. |
| §11.2 calls the real untrusted-host test a residual. | Locally resolved: the untrusted Extension Host test passed again on 2026-11-20. Hosted execution of the new `untrusted-workspace` CI job remains NOT VERIFIED. |
| §11.2 says the security-critical files were untracked. | Partly superseded: the six core remediation files are tracked in HEAD, but the four final-gate scripts/tests are still untracked. |
| §12.4 says `vsce show` returned `undefined`. | Still true, and supplemented by a direct Marketplace gallery query returning `count: 0`. Neither result proves or disproves publisher ownership. |
| Remediation §3 SEC-12 and §5 row 18 imply a hosted-equivalent clean regeneration/SCA result. | Corrected in `PHASE_04_SECURITY_REMEDIATION.md` §10: the empty diff is local-only, hosted SCA failed, and the corrected workflow is unhosted. |

### 13.2 SEC-01 through SEC-19 individual disposition

| Finding | Status | Final evidence and remaining qualification |
|---|---|---|
| SEC-01 | **PASS** | Canonical workspace-relative `filePath`; absolute/drive/traversal paths rejected before writes; consent before temp creation; hash-unchanged regression tests. Python suite: `1106 passed in 12.19s`. |
| SEC-02 | **PASS** | Shared patch boundary validates all targets before any write; patch-first/temp-only application; repair and recommendation original-file hash tests pass. |
| SEC-03 | **PASS** | Deny-by-default trust policy, health-only untrusted API, 51 `machine` / 0 `machine-overridable` settings, and real VS Code untrusted-host test passed. Hosted `untrusted-workspace` CI job is separately NOT VERIFIED. |
| SEC-04 | **PASS** | Non-loopback bind rejected unless token plus explicit HTTPS termination are configured; docs disabled in production; model and `create_app()` validation tests pass. Actual production HTTPS termination is deployment-scoped and NOT VERIFIED. |
| SEC-05 | **PASS** | Metadata/hash-only persistence allowlist, source/prompt/patch exclusion, `0600` files and `0700` directories; persistence tests pass. |
| SEC-06 | **PASS** | Verification snapshots skip symlinks at every level, copy with `symlinks=True`, and recheck realpath containment; regression test passes. |
| SEC-07 | **PASS** | Direct inspection uses the source allowlist; non-source files return `415 E_UNSUPPORTED_FILE`; regression test passes. |
| SEC-08 | **PASS** | Streaming byte-capped responses, `content-length` precheck, abort on exceed, and UTF-8-safe chunk decoding; four `apiClient` tests pass. |
| SEC-09 | **PASS** | Shared backend/extension redaction for problems, errors, stderr, sandbox commands, and dashboard notices; redaction tests pass. |
| SEC-10 | **PASS** | `executionExecuted` is explicit and defaults to `false`; no execution success is claimed. Residual: no current producer sets it `true`. |
| SEC-11 | **PASS** | Pinned local Semgrep rule path with `require_local_rules=True`; `auto` rejected; test passes. A Semgrep executable scan is separately NOT VERIFIED because the local executable has a stale interpreter path. |
| SEC-12 | **FAIL** | Hosted SCA run `44606156254` failed at lock regeneration and skipped install/audit. Local isolated `pip-audit` passed on the committed lock (`1e19c4c…`), and the workflow was corrected locally, but there is no hosted green SCA run. |
| SEC-13 | **PASS** | Programmatic `apiKey` ignored; env-only token tests pass; no credential values exposed in reports or settings. |
| SEC-14 | **PASS** | Realpath containment at file-operation boundaries; canonical relative API paths; path-security tests pass. |
| SEC-15 | **PASS** | Only accepted/verified candidates may apply; failed/inconclusive states win; 2 MiB full-text cap and base-text revalidation tests pass. |
| SEC-16 | **PASS** | Verification verdicts are recorded and surfaced with distinct status fields; no false success is claimed; dashboard tests pass. |
| SEC-17 | **PASS** | Strict nonce CSP, escaped state, DOM-only rendering; CSP/XSS tests pass. |
| SEC-18 | **PASS** | Capability honesty preserved; steering validation remains false over HTTP; no SAE/model-internal claim is validated; capability tests pass. |
| SEC-19 | **PASS** | Local VSIX: 240 entries, 492,783 bytes, SHA-256 `94ccd60ab553cab8d161339b29cdf0eaa54bd780827f7ef4a37282149534efd6`, `unzip -t` clean, packaged smoke pass. Hosted validation-only run `44673317664` also reported `VSIX integrity OK: 240 entries, 491617 bytes`. No publication occurred. |

### 13.3 Fresh local regression and control evidence

The following commands were re-run during the final review:

```text
$ PYTHONPATH=src:security-engine/src .venv/bin/python -m pytest -q
1106 passed in 12.19s

$ npm test
engine pytest: 742 passed in 10.33s
extension unit tests: tests 439 / pass 439 / fail 0 / skipped 0

$ npm --workspace vscode-extension run test:integration
Bug Dhor Extension Host checks passed.
Exit code:   0

$ npm --workspace vscode-extension run test:integration:vsix
Bug Dhor VSIX smoke checks passed.
Exit code:   0

$ npm --workspace vscode-extension run test:integration:untrusted
Using local VS Code: /Applications/Visual Studio Code.app/Contents/MacOS/Code
Launching VS Code with workspace trust ENABLED (no --disable-workspace-trust).
Untrusted workspace Extension Host checks passed.

$ npm audit --omit=dev --json | jq '{metadata:.metadata.vulnerabilities}'
{"metadata":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}

$ pip-audit --require-hashes -r security-engine/requirements.lock.txt --strict
No known vulnerabilities found

$ shasum -a 256 security-engine/requirements.lock.txt
1e19c4cb7d07a2feac34a9e4810caade45c1d33ed0651da12baa9739091e4131  security-engine/requirements.lock.txt

$ unzip -t vscode-extension/bug-dhor-0.1.0.vsix | tail -n 1
No errors detected in compressed data of vscode-extension/bug-dhor-0.1.0.vsix.

$ node --check <four new JavaScript files>; YAML parse <three workflows>; git diff --check
all passed / no output from git diff --check
```

The untrusted test asserts `vscode.workspace.isTrusted === false`, verifies the trust gate blocks 11 source-bearing operations, confirms a hostile workspace `settings.json` cannot override machine-scoped settings, confirms no source marker reaches the request recorder, and confirms no workspace-supplied command marker is created.

Fail-closed scan:

```text
$ rg -n 'continue-on-error|if: false|exit 0|set \+e' .github/workflows
(no output)
```

### 13.4 Hosted CI and release authorization evidence

```text
$ gh api repos/sajib91/Bug-Dhor/actions/runs/44606156782 --jq ...
{"conclusion":"success","event":"push","head_sha":"7b312f9b72889a36401400d61c59a30e6afce3ce","html_url":"https://github.com/sajib91/Bug-Dhor/actions/runs/44606156782","id":44606156782,"name":"Extension compatibility tests","status":"completed"}

$ gh api repos/sajib91/Bug-Dhor/actions/runs/44606156254 --jq ...
{"conclusion":"failure","event":"push","head_sha":"7b312f9b72889a36401400d61c59a30e6afce3ce","html_url":"https://github.com/sajib91/Bug-Dhor/actions/runs/44606156254","id":44606156254,"name":"Python dependency SCA","status":"completed"}
```

Hosted compatibility run `44606156782` had 12 successful jobs, including:

```text
135850284172  Lint (windows-latest)                 completed  success
135850284340  Unit tests (windows-latest)            completed  success
135850284393  Package validation (windows-latest)    completed  success
135850776566  Extension integration (windows-latest) completed  success
135850776601  Extension integration (ubuntu-latest)  completed  success
135850776691  Extension integration (macos-latest)   completed  success
```

Windows job log evidence:

```text
> bug-dhor@0.1.0 test:integration
> node test/integration/runTest.js
Bug Dhor Extension Host checks passed.
Extension host test runner exit code: 0
Exit code:   0

> bug-dhor@0.1.0 test:integration:vsix
Bug Dhor VSIX smoke checks passed.
Exit code:   0
```

SCA job `135850281317` in run `44606156254`:

```text
Install SCA tooling                     completed  success
Verify the hash lock is current         completed  failure
Install dependencies with hash verification completed  skipped
Audit locked dependencies               completed  skipped
```

Failure lines included `diff -u requirements.lock.txt /tmp/bugdhor-requirements.lock.txt`, added platform-specific `nvidia-*`/`triton` packages, and `##[error]Process completed with exit code 1.` This is a workflow failure, not a dependency vulnerability result.

Publish validation evidence:

```text
44673317664  confirm_publish=false  success  Publish with OIDC: skipped
44673435565  confirm_publish=true   failure  Publish with OIDC: skipped
```

The confirmed-publish failure was the fail-closed guard:

```text
Phase 04 still records a NO-GO publication decision.
##[error]Process completed with exit code 1.
```

The local replacement verifier still requires `manifest.decision === 'GO'`, `blockers.length === 0`, all 16 gates passing, and a fresh GitHub API recheck of the recorded run and job conclusions.

### 13.5 Tracked-file status

Six core remediation files are tracked in HEAD:

```text
security-engine/src/bugdhor/core/persistence.py
security-engine/src/bugdhor/core/redaction.py
security-engine/src/bugdhor/core/safe_patch.py
security-engine/tests/api/test_security_remediation.py
vscode-extension/src/security/trustGate.js
vscode-extension/src/security/trustPolicy.js
```

The following required final-gate files are **not tracked**:

```text
scripts/generateReleaseManifest.js
scripts/verifyReleaseManifest.js
vscode-extension/test/integration/runUntrustedTest.js
vscode-extension/test/integration/untrustedWorkspace.js
```

Exact verification:

```text
$ git ls-files --error-unmatch <four files>
error: pathspec 'scripts/generateReleaseManifest.js' did not match any file(s) known to git
error: pathspec 'scripts/verifyReleaseManifest.js' did not match any file(s) known to git
error: pathspec 'vscode-extension/test/integration/runUntrustedTest.js' did not match any file(s) known to git
error: pathspec 'vscode-extension/test/integration/untrustedWorkspace.js' did not match any file(s) known to git
```

### 13.6 Marketplace ownership, Trusted Publishing, and OIDC

GitHub facts only:

```text
$ gh api repos/sajib91/Bug-Dhor --jq '{full_name,owner:.owner.login,private,html_url,default_branch,archived}'
{"full_name":"sajib91/Bug-Dhor","owner":"sajib91","private":false,"html_url":"https://github.com/sajib91/Bug-Dhor","default_branch":"main","archived":false}
```

Marketplace queries:

```text
$ npx --no-install @vscode/vsce show sajib91.bug-dhor --json
undefined

$ curl -fsS -X POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery ...
{"count":0,"first":null}
```

These results do not establish or negate ownership of the `sajib91` publisher; publisher management is authenticated and was not used.

Official documentation consulted: <https://code.visualstudio.com/api/working-with-extensions/publishing-extension>. It requires a Marketplace Trusted Publishing policy with exact repository owner `sajib91`, repository `Bug-Dhor`, workflow `publish-extension.yml`, and an empty GitHub environment when no environment is used. The Marketplace OIDC credential expires after 15 minutes, and each GitHub OIDC token can be exchanged once. The workflow grants `id-token: write` only to the `publish` job and confines `confirm_publish=true` to that job, but no policy or receipt was verified.

| External gate | Status | Reason |
|---|---|---|
| `publisher-ownership` | **NOT VERIFIED** | No authenticated Marketplace publisher-management evidence was produced. |
| `trusted-publishing-policy` | **NOT VERIFIED** | No verified policy record for owner/repository/workflow/environment was produced. |
| `oidc-publish-receipt` | **NOT VERIFIED** | No successful OIDC publication occurred; the only confirmed run failed before publish. |
| OIDC issuer/audience trust | **NOT VERIFIED** | No Marketplace-side trust configuration evidence was produced. |

### 13.7 Final release-gate matrix

| Gate | Status | Evidence / qualification |
|---|---|---|
| SEC-01 | **PASS** | Code and regression tests. |
| SEC-02 | **PASS** | Code and regression tests. |
| SEC-03 | **PASS** | Code, tests, real local untrusted-host run. Hosted job listed separately. |
| SEC-04 | **PASS** | Code and tests; production HTTPS termination is deployment-scoped and not claimed. |
| SEC-05 | **PASS** | Code and regression tests. |
| SEC-06 | **PASS** | Code and regression tests. |
| SEC-07 | **PASS** | Source allowlist and regression test. |
| SEC-08 | **PASS** | Streaming byte-cap tests. |
| SEC-09 | **PASS** | Redaction tests. |
| SEC-10 | **PASS** | Explicit non-affirmative execution field. |
| SEC-11 | **PASS** | Pinned local rule policy; Semgrep execution separately NOT VERIFIED. |
| SEC-12 | **FAIL** | Hosted SCA run failed; local fix only. |
| SEC-13 | **PASS** | Env-only credential tests. |
| SEC-14 | **PASS** | Realpath containment tests. |
| SEC-15 | **PASS** | Candidate and full-text cap tests. |
| SEC-16 | **PASS** | Verification-state tests. |
| SEC-17 | **PASS** | CSP/XSS tests. |
| SEC-18 | **PASS** | Capability-honesty tests. |
| SEC-19 | **PASS** | VSIX integrity and smoke checks. |
| All mandated regression suites (local) | **PASS** | 1,106 Python; 742 engine pytest; 439 extension; host/VSIX/untrusted integration. |
| Windows CI on committed workflow | **PASS** | Run `44606156782`, job `135850776566`. |
| Windows/manifest CI on modified working tree | **NOT VERIFIED** | No hosted run; changes are uncommitted. |
| GitHub Actions SCA on committed workflow | **FAIL** | Run `44606156254`. |
| GitHub Actions SCA on corrected working tree | **NOT VERIFIED** | Local `pip-audit` passed; no hosted re-run. |
| VS Code untrusted behavior (local host) | **PASS** | Real Extension Host with workspace trust enabled. |
| `untrusted-workspace` hosted CI gate | **NOT VERIFIED** | New job has no hosted run. |
| Structured manifest generation/verification (local) | **PASS** | Syntax, YAML, synthetic gate cases, fail-closed logic. |
| Structured manifest hosted artifact | **NOT VERIFIED** | No hosted run for modified workflow. |
| `oidc-publish-receipt` | **NOT VERIFIED** | No successful OIDC publish. |
| `publisher-ownership` | **NOT VERIFIED** | Authenticated Marketplace evidence absent. |
| `trusted-publishing-policy` | **NOT VERIFIED** | Marketplace policy evidence absent. |
| Core remediation files tracked | **PASS** | Six files verified in HEAD. |
| All required final-gate files tracked | **FAIL** | Four files are untracked. |
| Fail-closed authorization preserved | **PASS** | Historical guard failure plus local verifier assertions; no bypass flags found. |
| Repository license | **PASS** | Root MIT `LICENSE` present and validated. |
| Tracked credential-like content scan | **PASS** | Word-boundary scan found only deliberate masked test-fixture values in `tests/test_explain_repair_ai.py`. Earlier `risk-*` matches were substring false positives; no live secret value was printed or stored. |
| VSIX rebuild/integrity | **PASS** | Local and hosted validation evidence; artifact is not published. |
| No commit/push/tag/publish | **PASS** | No such command was executed in this review. |

**Final decision remains NO-GO for publication.** The four blocker classes are: hosted SCA FAIL/unhosted fix, unhosted modified workflow and manifest, untracked final-gate files, and unverified Marketplace/OIDC external gates. No publication command was executed.
