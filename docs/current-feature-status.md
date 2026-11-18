# Current feature status

**Date:** 2026-11-18  
**Purpose:** one current, evidence-bound status source for the workspace
scanning work. Older audit and report documents remain useful as point-in-time
records, but their commit hashes and test counts are not authoritative here.

## 1. Overall determination

The local engineering path is **implemented and tested**. It provides
model-independent workspace monitoring, validated HTTP transport, real
allowlisted file/workspace inspection, native diagnostics, proposal-only repair
and recommendations, and an explicitly gated feedback lifecycle.

The research system is **not complete**. SAE, counterfactual, steering, and
mathematics libraries are real offline implementations, but the HTTP research
routes are explicit stubs, no production checkpoint or calibrated artifact
ships, no benchmark has been run, and no calibrated probability, causal effect,
or security guarantee is claimed.

## 2. Status matrix

| Area | Status | Evidence / boundary |
|---|---|---|
| Official VS Code document/file events | **Implemented** | `WorkspaceMonitor` owns `onDidOpenTextDocument`, `onDidChangeTextDocument`, `onDidSaveTextDocument`, `onDidCreateFiles`, `onDidDeleteFiles`, and `onDidChangeWorkspaceFolders`; close is optional. |
| Incremental analysis executor | **Implemented** | `RealtimeMonitor` tracks versions/ranges, debounces, cancels superseded work, deduplicates by hash, scopes to function/changed lines/file, and publishes only validated backend findings. |
| New-file and delete handling | **Implemented** | New source files are opened through `workspace.openTextDocument` and scanned once per version; deletes cancel work, forget state, and clear diagnostics. |
| Full workspace rescan on folder change | **Implemented, opt-in** | `bugdhor.monitoring.fullScanOnWorkspaceChange` defaults to `false`; when enabled, folder changes schedule a debounced metadata-only `/api/v1/scan/workspace` request. |
| Provider independence / attribution | **Implemented** | `providerMatrix.js` covers Copilot, Cursor, Claude, ChatGPT, OpenCode, other assistants, and manual code with `attribution: 'none'`. No private API or reverse engineering is used. |
| File filtering and bounded work | **Implemented** | `fileFilter.js` excludes vendored, virtual-environment, build, cache, binary, generated, oversized, and out-of-workspace paths; `scanScheduler.js` bounds concurrency and coalesces work. |
| Consent and privacy | **Implemented** | Monitoring is off by default. Automatic source scans require both `bugdhor.monitoring.allowAutomaticSourceSharing` and `bugdhor.privacy.sendSourceText`. Workspace scans send folder metadata only. |
| Backend file/workspace scanning | **Implemented** | Strict root/path containment, binary and NUL rejection, size/count limits, real SHA-256 metadata, detection of 13 languages with installed parsers for Python/JavaScript/TypeScript, Python/JavaScript CFG/DFG/taint, Semgrep/Bandit, opt-in general-bug AST rules, and detection fusion. |
| Language capability reporting | **Implemented** | `GET /api/v1/health` exposes `analysisCapabilities`: detected languages, installed parsers, implemented program-analysis layers, static-tool availability, `E_NO_ADAPTER` linter/type-checker gaps, manual-only dependency checks, and opt-in general bugs. The existing boolean `capabilities` map is unchanged. |
| Detected-but-unparsed languages | **Explicitly reported** | Java, C, C++, PHP, Go, Rust, C#, Ruby, Kotlin, and Swift are detectable but have no installed grammar; repository metadata records `no_installed_parser` skips and never presents them as clean scans. |
| General-bug/security AST enrichment | **Implemented, opt-in** | `DetectionConfig(enrich_general_bugs=True)` enables conservative parser/AST rules for syntax, undefined/unused variables, type/null risks, resource handling, control flow, common mistakes, sensitive exposure, SSRF, and unsafe uploads. It is off by default and reports epistemic confidence plus uncertainty, not calibrated probabilities. |
| Diagnostics, hover, Quick Fix | **Implemented** | Findings come only from backend results; malformed/out-of-workspace findings are rejected; `analysisAvailable: false` is never treated as clean. |
| Selection detection and explanations | **Implemented, partial coverage** | Real backend routes exist and are wired; explanations are observation graphs, not model-internal attribution. |
| Repair and verification | **Partial by design** | Repair is proposal-only and requires explicit approval to apply. Verification is independent but static-only in practice; the sandbox executor exists but is not used for untrusted execution by the verification engine. |
| Risk scoring | **Partial** | Real `heuristic_index`; `probability` stays `null` because no validated calibration artifact ships. |
| CodeQL / Joern | **Partial** | Real adapters exist, require external CLI/database/query configuration, and are not in orchestrator defaults. |
| Job queue and HTTP cancellation | **Partial / effectively unreachable** | `JobStore` and `/jobs/*` endpoints exist, but routes never create jobs and result filenames do not match retrieval. Client-side monitor cancellation is implemented separately. |
| SAE / counterfactual / steering libraries | **Implemented offline** | Real PyTorch/NumPy code and stored artifacts under `research/`; not mocks. |
| SAE / counterfactual / steering HTTP workflows | **Unavailable** | `features/extract`, `counterfactual/analyze`, and `prevention/steer` return explicit empty stubs. |
| Production model / SAE artifacts | **Unavailable** | Registered production checkpoints are absent; local Qwen 0.5B checkpoints are compatibility probes only. |
| Benchmark execution and E0–E8 results | **Not run** | Readiness bundle has `status: not_run` and null metrics. |
| Animated insect indicator | **Not implemented** | Static shield/check marks only; the status bar spinner is VS Code's `$(sync~spin)` during health checks. |
| Backend process supervision | **Not implemented** | Settings are reserved; the extension connects to an already-running backend. |

## 3. Verification record

| Check | Result |
|---|---|
| `npm --workspace vscode-extension test` | **325 passed, 0 failed** |
| `npm --workspace vscode-extension run lint` | **clean** |
| `../.venv/bin/python -m pytest -q` from `security-engine/` | **717 passed, 0 failed** |
| `security-engine/.venv/bin/python -m pytest -q` from repository root | **806 passed, 0 failed** (engine + mathematical regressions) |
| `npm run format:check` | **fails on the pre-existing baseline**: 55 files would be reformatted, 184 already formatted. No file changed by this work appears in the reformat list. |

The mathematical regression suite previously failed because the stored artifact
contained an absolute checkpoint path from another checkout. The test now
resolves a missing path to the same-named artifact beside the stored result and
aliases the legacy `craftsec` module namespace to `bugdhor` when loading real
checkpoints. The research implementation and artifacts were not replaced.

## 4. Documentation updated by this work

- Added `docs/workspace-scanning-audit.md`,
  `docs/current-feature-status.md`, and
  `docs/workspace-scanning-implementation-plan.md`.
- Updated `vscode-extension/README.md` with the official event list, file
  filtering, provider matrix, new settings, and the current unit-test count.
- Updated `docs/user-guide.md` with workspace-file monitoring behavior and
  opt-in settings.
- Corrected `docs/ai-assistant-integration.md`: the consent settings are
  `bugdhor.monitoring.allowAutomaticSourceSharing` and
  `bugdhor.privacy.sendSourceText`, not
  `bugdhor.monitoring.sendSourceText`.
- Indexed the three new documents in `docs/README.md`.
- Added `security-engine/src/bugdhor/core/capability_report.py` and exposed it as
  `analysisCapabilities` on `/health`, with pass-through validation in the
  extension.
- Rewrote language detection/parser capability reporting for the 13 requested
  languages, TSX grammar selection, explicit parse gaps, and `no_installed_parser`
  repository-metadata skips.
- Added opt-in `DetectionConfig.enrich_general_bugs` AST/parser rules and
  additive finding fields for category, coordinates, epistemic confidence,
  uncertainty, detection method, and remediation.

## 5. Claim boundaries

Do not describe the system as research-validated, calibrated, causal,
model-internal, autonomously repairing, benchmarked, or release-ready. The
operative statement remains: **operational within the declared local engineering
scope; partial heuristic security layer; research contributions and empirical
validation still missing.**
