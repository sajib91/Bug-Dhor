# BUG-DHOR — PHASE 04 SECURITY REMEDIATION REPORT

**Date:** 2026-11-20
**Repository:** https://github.com/sajib91/Bug-Dhor.git
**Scope:** All 19 findings in `reports/PHASE_04_SECURITY_AUDIT.md`, covering the VS Code extension and separately distributed Python backend.
**Release decision:** **NO-GO for publication** — code remediation is complete and locally verified, but external release gates are not verified.
**Commit state:** All changes remain uncommitted. No commit, push, or publish was performed.

> This is an internal source review and automated-check report. It is not a penetration test, certification, compliance attestation, CVE-free guarantee, or externally validated security audit. External gates that cannot be verified locally are listed in §7. The exact NO-GO decision in `reports/PHASE_04_SECURITY_AUDIT.md` is preserved.

---

## 1. Executive summary

All 19 Phase 04 findings have been addressed in code or formally documented with a residual-risk statement:

- **2 CRITICAL** findings are resolved: absolute/traversal `filePath` and patch targets are rejected before any write; all patch application is patch-first and temp-only; original file hashes are unchanged in regression tests.
- **4 HIGH** findings are resolved: workspace trust is deny-by-default for source-bearing operations, non-loopback backend binding requires both a token and explicit HTTPS termination, persisted artifacts are metadata/hash-only with private permissions, and verification snapshots skip symlinks at every level.
- **6 MEDIUM** findings are resolved or resolved with an explicitly documented residual: source-only direct inspection, streaming byte-capped HTTP responses, shared redaction, explicit `executionExecuted`, pinned offline Semgrep rules, and a reproducible hash-pinned Python lock with CI SCA.
- **4 LOW** findings are resolved: env-only credentials, realpath containment, accepted/verified candidate gating with a 2 MiB full-text cap, and explicit verification-status notices.
- **3 INFORMATIONAL** findings were rechecked and remain accurate; capability reporting was updated for the new SCA workflow.

Final local verification is green: **1,106 Python tests**, **439 extension tests**, extension lint, extension-host integration, packaged VSIX smoke, production npm audit, Python SCA, pip check, compileall, and VSIX archive integrity all pass. Bandit reports **0 High** findings; its 11 Medium findings are accepted/documented below. Repository-wide Ruff still reports style findings; the newly added security modules and regression suite are clean.

Publication must nevertheless remain **NO-GO**. Publisher ownership, Marketplace Trusted Publishing policy/OIDC trust, an actual OIDC publish run, Windows tests, and the GitHub Actions SCA run have not been verified. Local passing checks do not substitute for those gates.

---

## 2. Remediation method

1. Preserved the original audit as the historical finding record; added this report for post-fix evidence.
2. Centralized safety boundaries instead of adding scattered checks:
   - Backend: `bugdhor.core.safe_patch`, `bugdhor.core.redaction`, `bugdhor.core.persistence`.
   - Extension: `src/security/trustPolicy.js`, `src/security/trustGate.js`, `src/security/redaction.js`, `src/security/paths.js`.
3. Added regression tests for each critical/high path and the material medium/low paths.
4. Re-audited all 19 original areas against the final source.
5. Rebuilt the VSIX and ran both extension-host integration and packaged-VSIX smoke checks against final extension source.
6. Did not delete tests, weaken controls, suppress findings, fabricate results, commit, push, or publish.

---

## 3. Finding-by-finding remediation

| ID | Severity | Status | Fix summary | Primary evidence |
|---|---|---|---|---|
| SEC-01 | **CRITICAL** | **Resolved** | Canonical workspace-relative `filePath` at `FileContext`; absolute/drive/traversal paths rejected globally; consent decided before temporary directories or files are created; verification writes only to temp roots; verification target absolute paths rejected. | `api/schemas/scan.py`, `core/safe_patch.py`, `verification/functional.py`, `verification/engine.py`; tests `test_api_rejects_absolute_file_path_at_the_boundary`, `test_repair_generate_never_changes_original_file_hash`, `test_verification_engine_rejects_absolute_target_path`. |
| SEC-02 | **CRITICAL** | **Resolved** | One shared patch boundary validates every target before any write; patch-first in-memory application; repository context and temp writes rechecked for containment and symlinks. | `core/safe_patch.py`, `repair/engine.py`, `recommendation/engine.py`, `verification/engine.py`; tests `test_recommendation_generate_never_changes_original_file_hash`, `test_absolute_patch_targets_are_rejected_before_any_write`. |
| SEC-03 | **HIGH** | **Resolved in code** | Central trust policy and VS Code trust gate; untrusted workspaces may call only `health`; source egress, monitoring, auto-scan, assistant, local engine, and execution settings forced off; all high-risk settings are `machine` scope; non-loopback endpoints forbidden when untrusted and require HTTPS when trusted. | `security/trustPolicy.js`, `security/trustGate.js`, `api/configurationService.js`, `extension.js`, `package.json`; `workspaceTrust.test.js`, `configurationService.test.js`, `assistantIntegration.test.js`. Setting scope audit: **51 machine, 0 machine-overridable**. |
| SEC-04 | **HIGH** | **Resolved** | `Settings` and `create_app()` reject non-loopback binding unless `BUGDHOR_API_TOKEN` is set and `BUGDHOR_REMOTE_TRANSPORT=https-terminated`; docs/redoc/openapi only when `environment="development"`. | `core/settings.py`, `api/app.py`; tests `test_non_loopback_binding_requires_token_and_explicit_https`, `test_create_app_revalidates_programmatic_non_loopback_settings`, `test_production_docs_are_disabled_by_default`. |
| SEC-05 | **HIGH** | **Resolved** | Metadata/hash-only persistence allowlist; source, prompts, patches, and raw tool output excluded; analysis cache sanitized with the same rule; `0600` files and `0700` directories; full-payload persistence defaults off. | `core/persistence.py`, `core/jobs.py`, `core/orchestrator.py`; tests `test_persisted_results_are_metadata_only_and_private`, `test_analysis_cache_persists_metadata_without_source_text`. |
| SEC-06 | **HIGH** | **Resolved** | Verification snapshots skip symlinked files and directories at every level, copy with `symlinks=True`, and recheck realpath containment after copying; `_write_target()` rejects symlink targets and escaping parents. | `verification/functional.py`; test `test_verification_snapshot_skips_symlinked_files_and_directories`. |
| SEC-07 | **MEDIUM** | **Resolved** | Direct file inspection now applies the recognized-source allowlist; non-source files return `415 E_UNSUPPORTED_FILE`. | `core/paths.py`, `core/errors.py`; test `test_direct_inspection_rejects_non_source_files`. |
| SEC-08 | **MEDIUM** | **Resolved** | Responses are read incrementally with a byte counter, `content-length` precheck, abort/cancel on exceed, fatal UTF-8 decoding across chunk boundaries, and byte-checked text fallback. | `api/apiClient.js`; tests in `apiClient.test.js` covering streaming byte caps, oversized `content-length`, split multi-byte UTF-8, and text-only byte counting. |
| SEC-09 | **MEDIUM** | **Resolved** | Shared redaction on both components; RFC 9457 problem title/detail/details redacted; raw exception text redacted in orchestrator, repair/recommendation stages, analyzer parsers, verification, sandbox command/stdout/stderr/detail, and dashboard notices/logs. | `core/redaction.js`, `core/redaction.py`, `api/middleware/problem.py`, `sandbox/executor.py`, `core/orchestrator.py`; tests `test_redaction_removes_secret_values`, `test_problem_details_are_redacted`, `test_sandbox_recorded_command_redacts_environment_values`, `redaction.test.js`. |
| SEC-10 | **MEDIUM** | **Resolved with documented residual** | `executionExecuted` is now explicit in the verification schema and model and defaults to `false`; static verification cannot imply execution. | `api/schemas/verification.py`, `verification/engine.py`. Residual: no current producer sets it `true`; execution remains honestly skipped/inconclusive. |
| SEC-11 | **MEDIUM** | **Resolved** | Semgrep defaults to a reviewed pinned local rule file with `require_local_rules=True`; `auto` is rejected; metrics disabled and version check off. | `static/semgrep.py`, `semgrep-rules/bugdhor.yml`; test `test_semgrep_uses_pinned_offline_rules_by_default`. Residual: local Semgrep executable has a stale shebang, so no Semgrep scan result is claimed. |
| SEC-12 | **MEDIUM** | **Resolved locally** | Python 3.11 hash lock generated reproducibly with `pip-tools==7.7.0` from `--extra ml --extra dev`; analyzers excluded because Semgrep's `mcp==1.29.0` transitive pin has known advisories; CI workflow regenerates, diffs, installs with hashes, and runs `pip-audit --strict`. | `requirements.lock.txt`, `.github/workflows/python-sca.yml`, `core/capability_report.py`; isolated local SCA: empty lock diff and `No known vulnerabilities found`. Production npm audit: 0 vulnerabilities. Residual: GitHub Actions run not observed locally. |
| SEC-13 | **LOW** | **Resolved** | Programmatic `config.apiKey` is ignored; credentials are read only from extension-host environment variables and never written to settings, logs, or responses. | `integrations/registry.js`, `api/configurationService.js`; tests `provider registry ignores programmatic API keys from settings`, `the token is read only from the extension host environment`. |
| SEC-14 | **LOW** | **Resolved** | Realpath containment adopted at file-operation boundaries; extension sends canonical workspace-relative `filePath`; outside/symlink-escaping paths are rejected. | `security/paths.js`, `api/securityEngineService.js`, repository inventory, git changed files, realtime monitor, workspace service, monitor filter, repository commands; `pathSecurity.test.js`. |
| SEC-15 | **LOW** | **Resolved** | Patch-first application; only backend-accepted or independently verified candidates may be applied; explicit rejection/failed/inconclusive states win; full-text fallback capped at 2 MiB; base text revalidated immediately before apply. | `webviews/dashboardPanel.js`; tests for rejected candidate, verified full-text fallback, and >2 MiB rejection. |
| SEC-16 | **LOW** | **Resolved** | Verification results are recorded and surfaced with distinct status/verdict fields and explicit notices; no false success is claimed. | `webviews/dashboardPanel.js`, `api/schemas/verification.py`; dashboardPanel tests for verification recording and notices. |
| SEC-17 | **INFORMATIONAL** | **Verified unchanged** | Strict nonce CSP with `default-src 'none'`, no script/style/network/frame/worker allowances beyond the nonce, escaped state, DOM-only rendering. | `webviews/csp.js`, `webviews/html.js`, `media/dashboard.js`; dashboard CSP test. |
| SEC-18 | **INFORMATIONAL** | **Verified and updated** | Capability honesty preserved; SCA capability now reports CI lockfile auditing; steering validation remains forced false over HTTP; no SAE/model-internal claim is asserted. | `core/capability_report.py`, `api/securityEngineService.js`; integration capability tests. |
| SEC-19 | **INFORMATIONAL** | **Verified** | Final VSIX rebuilt from final extension source: 240 files, 492,783 bytes, SHA-256 `94ccd60ab553cab8d161339b29cdf0eaa54bd780827f7ef4a37282149534efd6`; `unzip -t` clean; packaged smoke passed. | `vscode-extension/bug-dhor-0.1.0.vsix`; VSIX archive and smoke logs. |

---

## 4. Detailed control changes

### 4.1 Path and patch safety (SEC-01, SEC-02, SEC-14, SEC-15)

`bugdhor.core.safe_patch` is now the single backend boundary for path and patch operations:

- `reject_absolute_file_path()` rejects POSIX/Windows absolute, drive-qualified, NUL-bearing, empty-component, `.` and `..` segments.
- `canonical_relative_path()` additionally rejects existing symlink components and escaping realpaths.
- `normalize_patch()` and `patch_paths()` validate every `+++` target before a patch can be used.
- `apply_patch_to_sources()` applies patches against an in-memory mapping; no host file is touched.
- `apply_patch_in_temp()` writes only inside a fresh `TemporaryDirectory`, then rechecks containment and symlinks before returning patched text.

The extension sends canonical workspace-relative `filePath` via `relativeFilePathForApi()`, which uses `isRealPathWithinRoot()`. The same realpath check was adopted in repository inventory, Git changed-file discovery, realtime monitor, workspace service, monitor file filter, repository commands, and API service.

The dashboard now filters repair candidates through `isApplicableRepairCandidate()`. Rejected candidates and failed/inconclusive verification never reach apply. Full-text fallback is gated by state and a 2 MiB byte cap, with base-text revalidation before the edit.

### 4.2 Workspace trust and endpoint policy (SEC-03, SEC-04, SEC-13)

- `trustPolicy.js` is the pure deny-by-default policy: untrusted workspaces allow only `health`; all source-bearing settings are forced off.
- `trustGate.js` reads `vscode.workspace.isTrusted`, fails closed when the API is missing, subscribes to trust changes, and wraps the service with a capability-checking proxy.
- `package.json` declares `capabilities.untrustedWorkspaces.supported: true`; all high-risk settings use `machine` scope (**51 machine, 0 machine-overridable**).
- `endpointPolicyViolation()` rejects untrusted remote endpoints (`E_UNTRUSTED_REMOTE_ENDPOINT`) and non-HTTPS trusted remote endpoints (`E_INSECURE_REMOTE_ENDPOINT`); malformed URLs produce `E_INVALID_BACKEND_URL`.
- Backend non-loopback validation is enforced both in the Pydantic model and again in `create_app()`, covering programmatic `Settings` mutation.
- `config.apiKey` is ignored; only `BUGDHOR_API_TOKEN`/`BUGDHOR_ENGINE_TOKEN` from the extension-host environment are accepted.

### 4.3 Privacy persistence and redaction (SEC-05, SEC-09)

`core.persistence.sanitize_for_persistence()` keeps only an explicit metadata/hash allowlist. Source text, prompts, patches, and raw tool output are not written. `_kind`, `language_id`, and `parsed_ok` are retained as non-sensitive cache metadata. `write_json_private()` uses atomic `0600` writes; job/result/cache directories are `0700`.

Central redaction is applied to RFC 9457 problem responses, orchestrator warnings and stage details, repair/recommendation failure reasons, static analyzer parse warnings, verification limitations, sandbox `-e KEY=value` command entries, stdout/stderr/detail, and every dashboard error/log path that previously interpolated raw exception text.

### 4.4 Verification honesty and analyzer supply chain (SEC-10, SEC-11, SEC-12)

- `executionExecuted: false` is explicit in the verification contract; the static engine never reports execution from a skipped path.
- Semgrep uses `security-engine/semgrep-rules/bugdhor.yml` with `require_local_rules=True`; `auto` configuration is rejected.
- `security-engine/requirements.lock.txt` is hash-pinned and reproducible. The SCA workflow verifies the lock with the same pip-tools version used locally, installs with `--require-hashes`, and audits with `pip-audit --strict`.
- Analyzer CLIs are excluded from the runtime lock because the Semgrep dependency chain pins `mcp==1.29.0` with known advisories. This is documented in `requirements.txt` and the workflow.

---

## 5. Re-audit matrix — all 19 required areas

| # | Area | Post-remediation classification | Final evidence |
|--:|---|---|---|
| 1 | Source-code transmission | **Pass** | Trust gate blocks source operations in untrusted workspaces; source text requires trusted workspace plus `sendSourceText`; monitoring requires trust plus two consent flags; non-loopback requires HTTPS. |
| 2 | API key handling | **Pass** | Env-only credentials; programmatic `apiKey` ignored; no token values in settings or logs; token normalized and attached only as bearer header. |
| 3 | Localhost API security | **Pass (local); deployment unverified** | Loopback default; non-loopback fails without token and explicit HTTPS termination; docs off in production; `create_app()` revalidates. Actual HTTPS termination not verified. |
| 4 | Backend endpoint validation | **Pass** | Strict origin parsing, no credentials/path/query/fragment; `/api/v1` enforced; trust-aware endpoint policy with explicit error codes. |
| 5 | HTTP request/response validation | **Pass** | Typed schemas; streaming byte cap with `content-length` precheck, abort, UTF-8-safe decoding, and text fallback. |
| 6 | Path traversal protection | **Pass** | Absolute/traversal paths rejected at API boundary and in shared patch helpers; canonical relative paths; realpath containment in extension. |
| 7 | Symlink handling | **Pass** | Backend discovery resolves and rejects escaping symlinks; verification snapshots skip symlinks; extension realpath checks at operation boundaries. |
| 8 | Repository scanning boundaries | **Pass** | Allowlisted roots, gitignore, count/size limits, symlink skip; auto-scan gated by workspace trust and `machine` setting scope. |
| 9 | File size limits | **Pass** | Backend 2 MiB request / 1 MiB file / 50k files; response cap measured in bytes before buffering; full-text replacement capped at 2 MiB. |
| 10 | Malicious or malformed source input | **Pass** | Binary/NUL/UTF-8 checks, data-only parsing, bounded diagnostics; exception and stderr details redacted. |
| 11 | Webview Content Security Policy | **Pass** | Strict nonce CSP retained; no unsafe inline, network, frame, worker, or form sources. |
| 12 | HTML injection and XSS | **Pass** | Escaped attributes/state, DOM text nodes, no dangerous dynamic sinks. |
| 13 | Command execution and shell injection | **Pass** | `execFile` with fixed argv; backend `shell=False`; argv-based Docker; local engine and sandboxed execution gated by trust and explicit consent. |
| 14 | Repair patch validation | **Pass** | Patch-first validation in shared backend boundary; target scope and context checks before any write; extension accepts only accepted/verified candidates. |
| 15 | Patch application and rollback | **Pass** | No host writes during proposal/verification; extension approval, stale snapshot detection, and applied-hash feedback retained. |
| 16 | Functional test execution isolation | **Pass** | Temp-only trees, consent before writes, symlink-safe snapshots, Docker argv hardening, no host execution. |
| 17 | Sensitive information in logs | **Pass** | Metadata/hash-only persistence with private modes; shared redaction across backend problem responses, stages, analyzers, sandbox, and dashboard. |
| 18 | Dependency vulnerabilities | **Pass locally; CI unverified** | Reproducible hash lock, empty regeneration diff, `pip-audit --strict` clean, npm production audit 0. GitHub Actions run not observed. |
| 19 | Untrusted workspace behavior | **Pass in code; host test residual** | Deny-by-default trust policy, health-only untrusted service, machine-scoped settings, sanitized settings consumers. Real VS Code untrusted-host integration test not executed. |

---

## 6. Regression and automated-check evidence

### 6.1 Final commands and results

| Command | Final result |
|---|---|
| `PYTHONPATH=src:security-engine/src .venv/bin/python -m pytest -q` | **1106 passed in 11.26s** |
| `npm test` | **439 tests, 439 pass, 0 fail, 0 skipped** |
| `npm run extension:lint` | Pass — ESLint no findings |
| `npm run extension:test:integration` | `Bug Dhor Extension Host checks passed.` |
| `npm --workspace vscode-extension run test:integration:vsix` against the final VSIX | `Bug Dhor VSIX smoke checks passed.` (exit 0) |
| `npm audit --omit=dev --json` | `info 0, low 0, moderate 0, high 0, critical 0, total 0` |
| `.venv/bin/python -m pip check` | `No broken requirements found.` |
| `.venv/bin/python -m compileall -q security-engine/src security-engine/tests` | Exit 0 |
| `pip-compile --no-header --allow-unsafe --generate-hashes --extra ml --extra dev ... pyproject.toml` | Exit 0; `diff -u requirements.lock.txt <regenerated>` empty |
| `pip-audit --require-hashes -r requirements.lock.txt --strict` | `No known vulnerabilities found` |
| `.venv/bin/python -m bandit -q -r src security-engine/src tests security-engine/tests` | Undefined 0, **Low 3536, Medium 11, High 0** |
| `.venv/bin/python -m ruff check src security-engine tests` | 486 style findings remain; new security modules and regression suite pass a targeted Ruff check |
| `unzip -t vscode-extension/bug-dhor-0.1.0.vsix` | `No errors detected in compressed data` |

The isolated SCA run used a temporary virtual environment with `pip-tools==7.7.0` and `pip-audit`; it did not modify repository dependencies. The lock SHA-256 is `1e19c4cb7d07a2feac34a9e4810caade45c1d33ed0651da12baa9739091e4131` (2,032 lines).

### 6.2 Added/updated regression coverage

Backend (`security-engine/tests/api/test_security_remediation.py`):

- absolute `filePath` rejected at API boundary;
- repair and recommendation original file hashes unchanged, including absolute patch targets;
- absolute patch targets rejected before any write;
- symlinked files/directories excluded from verification snapshots;
- metadata-only persisted results with `0600`/`0700`;
- production docs disabled;
- non-loopback binding requires token and explicit HTTPS termination;
- `create_app()` revalidates programmatic settings;
- pinned offline Semgrep rules;
- shared redaction and RFC 9457 problem redaction;
- analysis cache excludes source text;
- verification rejects absolute targets;
- sandbox recorded command redacts environment values.

Extension:

- `pathSecurity.test.js` — realpath containment and outside-workspace rejection;
- `workspaceTrust.test.js` — deny-by-default untrusted policy, allowed health operation, endpoint policy codes;
- `redaction.test.js` — secret values removed from errors, process details, and tool output;
- `apiClient.test.js` — streaming byte cap, `content-length` precheck, split UTF-8, text fallback byte counting;
- `configurationService.test.js` — env-only token and trust-aware endpoint policy;
- `assistantIntegration.test.js` — programmatic API keys ignored;
- `dashboardPanel.test.js` — rejected candidate blocked, verified full-text fallback, >2 MiB full-text rejected, accepted recommendation applies with feedback;
- integration harness — canonical relative `filePath` and `ConfigurationTarget.Global`.

### 6.3 VSIX artifact

```text
path:    vscode-extension/bug-dhor-0.1.0.vsix
entries: 240
size:    492,783 bytes
sha256:  94ccd60ab553cab8d161339b29cdf0eaa54bd780827f7ef4a37282149534efd6
unzip -t: No errors detected
VSIX smoke: Bug Dhor VSIX smoke checks passed.
```

The artifact was rebuilt after the final extension-source changes. Subsequent changes were Python-only and did not affect the VSIX hash.

---

## 7. Accepted residuals and unverified gates

These items do not negate the code fixes, but they prevent a local GO claim:

1. **Publisher / Marketplace Trusted Publishing not verified.** `sajib91` publisher ownership, Marketplace Trusted Publishing eligibility/policy, and the OIDC trust relationship have not been checked. No PAT or long-lived publish secret was introduced.
2. **No publish run performed.** Receipts from an actual OIDC publish would be required; none exist.
3. **Windows test matrix not run.** Local verification was performed on macOS only.
4. **GitHub Actions SCA run not observed.** The local equivalent passed, but the workflow itself has not been executed in GitHub CI.
5. **Real VS Code untrusted-host integration test not executed.** Trust behavior is covered by unit tests with fakes; a real untrusted extension host was not driven. `trustGate.assertEndpoint()` is currently unused, while the same policy is enforced in `configurationService.js`.
6. **Semgrep executable unavailable locally.** `.venv/bin/semgrep` has a stale shebang pointing to a non-existent `CRAFT-Sec` interpreter. The pinned local rule configuration is validated by test, but no Semgrep scan result is claimed.
7. **Execution verification remains non-affirmative.** `executionExecuted` is exposed and defaults to `false`; no current producer sets it `true`. Static verification remains inconclusive for execution rather than claiming it.
8. **Security-critical new files are untracked.** No commit was permitted. A tracked-only release would omit `core/safe_patch.py`, `core/redaction.py`, `core/persistence.py`, the new extension security modules, SCA workflow, rules, and regression suite.
9. **Bandit Medium findings are accepted/documented:** two `torch.load` findings, two unpinned Hugging Face downloads, one hardcoded temp directory in sandbox probe code, five test-only `0.0.0.0` literals in validation tests, and one intentional vulnerable SQL fixture. No Bandit High findings remain.
10. **Repository Ruff style findings remain.** The repository-wide run reports 486 style findings; targeted checks of the new security modules and regression suite pass. These are not treated as security findings, but the repository is not Ruff-clean.
11. **Development npm advisories remain.** `npm audit --omit=dev` is clean; the earlier development-only advisories were not resolved by a semver-major upgrade.
12. **Trusted Publishing is the only allowed path.** No PAT, token, or long-lived publish credential was added or used.

---

## 8. Release gate disposition

| Gate from original audit | Local status | External status |
|---|---|---|
| Fix SEC-01/SEC-02 | Satisfied | N/A |
| Fix SEC-03–SEC-06 | Satisfied in code | Real untrusted-host test not run |
| Resolve/accept MEDIUM findings | Satisfied/documented | GitHub CI SCA and Semgrep executable not verified |
| Re-run full tests and audits | Satisfied locally | Windows matrix not run |
| Complete Python SCA | Satisfied locally using isolated tooling | GitHub Actions run not observed |
| License and publisher ownership | Root MIT license present | Publisher ownership unverified |
| Rebuild/re-verify VSIX | Satisfied | Marketplace Trusted Publishing/OIDC run unverified |

Because external gates remain open, the decision remains **NO-GO for publication**. No commit, push, or publish was performed.
