# Workspace scanning audit

**Date:** 2026-11-18  
**Scope:** VS Code extension, FastAPI engine, diagnostics/contracts, research
artifacts, and the documentation that describes them. This is an evidence
audit, not a claim that the research system is complete.

## 1. Executive summary

Bug Dhor can already scan code in a workspace independently of its author. The
engine ingests allowlisted files from disk, validates paths and sizes, runs real
parsing/program-analysis/static/detection stages, and returns validated finding
envelopes. The extension publishes only those validated findings as native VS
Code diagnostics.

The audited gaps were in **event coverage and documentation**, not in the
analysis engine:

- The existing `RealtimeMonitor` handled only `onDidChangeTextDocument`,
  `onDidSaveTextDocument`, and optional `onDidCloseTextDocument`. It did not
  observe open documents, new files on disk, deleted files, or workspace-folder
  changes.
- There was no single owner of event registration, so adding new listeners
  directly to `RealtimeMonitor` would have duplicated change/save scans and
  broken existing tests.
- File eligibility was split between `changeAnalyzer.js` globs and ad hoc rules;
  binary, generated, and vendored paths were not consistently excluded before a
  file was opened.
- There was no documented, provider-independent capability matrix for code that
  arrives from Copilot, Cursor, Claude, ChatGPT, OpenCode, other assistants, or
  manual edits.
- Three requested status/plan documents did not exist, and older docs contained
  a nonexistent setting name (`bugdhor.monitoring.sendSourceText`) and a stale
  claim that program analysis is not invoked by any scan.

The implemented remedy is a `WorkspaceMonitor` orchestrator that owns all
official VS Code events, a pure `fileFilter`, normalized `settings`, a bounded
`scanScheduler`, and a provider matrix with `attribution: 'none'`. The existing
`RealtimeMonitor` remains the incremental analysis executor.

## 2. Extension boundary

### 2.1 Activation and client responsibilities

`vscode-extension/src/extension.js` activates on startup, commands, and the
sidebar view. It starts no Python process. `backend.pythonPath` and
`backend.autoStart` are reserved settings; activation only logs a warning when
`autoStart` is enabled. The client creates a `SecurityEngineService`,
`Diagnostics`, a feedback controller, assistant providers, commands, the
dashboard, and the workspace monitor.

The client never performs vulnerability analysis locally. It builds validated
requests, calls the versioned HTTP API, checks responses, and publishes
backend findings.

### 2.2 Request construction and privacy

- `createEditorRequest()` sends `workspaceRoot`, `filePath`, `documentUri`,
  `languageId`, `documentVersion`, optional `selection`, and — only when
  `bugdhor.privacy.sendSourceText` is enabled — `sourceText`/`selectedText`.
- `createWorkspaceRequest()` sends only `{ name, path, uri }` for each local
  `file:` workspace folder. It deduplicates folders, rejects virtual schemes and
  non-absolute paths, and caps the list at 50 folders.
- `GET /api/v1/health` sends no source code.
- Background monitoring requires **both**
  `bugdhor.monitoring.allowAutomaticSourceSharing` and
  `bugdhor.privacy.sendSourceText`. Without both, the monitor tracks metadata
  locally but makes no engine call.

### 2.3 Diagnostics and availability

`src/diagnostics/` accepts only backend findings that pass the finding model.
Findings outside an open workspace or with non-`file:` URIs are rejected.
Severity mapping is fixed (`critical`/`high` → error, `medium` → warning,
`low` → information, `info` → hint). Stale diagnostics are cleared only for
explicitly covered URIs.

An empty findings list is **not** a clean scan when `analysisAvailable: false`
or `status: 'unavailable'`. The extension preserves those states and publishes
no fabricated finding.

## 3. Engine boundary

### 3.1 Endpoints

The FastAPI router prefix is `/api/v1`. Scanning endpoints
(`security-engine/src/bugdhor/api/routes/scan.py:20-50`) are:

| Endpoint | Request | Notes |
|---|---|---|
| `POST /api/v1/scan/file` | `workspaceRoot`, `filePath`, optional `documentUri`, `languageId`, `documentVersion`, `selection`, `selectedText`, `sourceText` | `sourceText` is hashed in place of disk bytes, but the path must still resolve to an existing file inside an allowed root. |
| `POST /api/v1/scan/workspace` | `workspaceFolders: [{ name, path, uri }]`, 1–50 entries | No `sourceText` field; extra fields are rejected with 422. The engine reads allowlisted files from disk. |

Selection analysis uses `POST /api/v1/detection/analyze`. Both scan endpoints
return `OperationResponse` envelopes with `operation`, `status`, `apiVersion`,
`requestId`, `stages`, `warnings`, and `result`; scan results add `findings`,
`scope`, `filesScanned`, `analysisAvailable`, and file metadata.

### 3.2 Path safety and bounds

`security-engine/src/bugdhor/core/paths.py` enforces:

- strict resolution of configured workspace roots (`ensure_allowed_root`);
- rejection of paths and escaping symlinks outside a root (`resolve_file`);
- maximum file bytes, NUL-byte detection, and UTF-8 decoding;
- workspace discovery with `os.walk(followlinks=False)`, fixed ignored
  directories, source-extension filtering, per-file size skipping, and a
  configurable file-count cap (default 50,000);
- selection range validation against the inspected text.

Defaults in `core/settings.py` are loopback `127.0.0.1:8765`, 2 MiB request
body limit, 1 MiB file limit, and 50,000 workspace files. Workspace scans cap
static targets at 500 per root for responsiveness.

### 3.3 Real and unavailable stages

Wired scan stages include snapshot, preprocessing, `program_analysis`
(Python/JavaScript CFG, DFG, taint), `static_evidence` (Semgrep and Bandit in
the orchestrator defaults), and `detection` (deterministic evidence fusion).
The parser registry detects 13 languages and parses Python, JavaScript, and
TypeScript with installed grammars; the other detected languages are explicit
`no_installed_parser` gaps. CodeQL and Joern adapters exist but require explicit
CLI/database/query setup and are not wired into the default scan path.

`analysisAvailable` becomes true only when a `program_analysis` or `detection`
stage reports `OK` or `PARTIAL`. Static-evidence-only success does not set it.
SAE, counterfactual, steering, model capture, and calibration stages are
declared unavailable; their HTTP routes return explicit empty stubs.

### 3.4 Jobs and cancellation

`core/jobs.py` and `/api/v1/jobs/*` exist, but `JobStore.create()` is never
called by any HTTP route. Scan routes execute synchronously without a job ID,
and persisted result filenames do not match `JobStore.get_result()`. The job
surface is therefore **partial/effectively unreachable**, not a working queue.
Monitor-level cancellation is client-side only: newer work cancels its token,
and the API client aborts the in-flight HTTP request.

## 4. Data-flow summary

| Trigger | Client payload | Backend reads | Source leaves extension? |
|---|---|---|---|
| Opened/edited/saved document, consented | File or selection request with optional `sourceText`/`selectedText` | Inspected text is hashed; path must be inside an allowed root | Yes, only with both consent settings |
| Same trigger, consent withheld | No engine call | Nothing | No |
| New file on disk | Document is opened via documented API, then same as edited document | Same as file scan | Only with both consent settings |
| Workspace folder change, full-scan opt-in | Folder metadata only | Allowlisted files from disk | Folder metadata only; file contents are read server-side |
| Health check | None | Nothing | No |

No trigger uses provider metadata. No code path infers an assistant, model, or
human author.

## 5. Exclusion and bounded-work findings

The extension now excludes, by default:

- `node_modules`, `bower_components`, `.git`, `.venv`, `venv`,
  `site-packages`, `__pycache__`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `dist`, `out`, `build`, `target`, `obj`, `.next`, `.turbo`,
  `coverage`, `vendor`, and `.bugdhor-data` via globs;
- binary extensions (images, archives, media, fonts, compiled objects,
  databases, `.pyc`, and similar) without reading file content;
- generated artifacts such as `*.min.js`, bundles, source maps, generated
  files, and lockfiles;
- files outside open `file:` workspace folders, documents above `maxFileBytes`,
  and languages outside the extension's current Python/JavaScript monitoring
  eligibility. The backend separately detects 13 languages and reports
  installed-parser and program-analysis gaps through `analysisCapabilities`.

Work is bounded by per-document debounce, one active scan per document,
in-flight cancellation, content hashing/deduplication, changed-line/function
scoping with file-level fallback, and a concurrency limit for workspace-level
scans.

## 6. Research integrity boundary

Real SAE/counterfactual work exists under `research/`: PyTorch `.pt`
checkpoints, `real_model_validation.json` with measured effects and stability
records, and an independent NumPy regression suite. These are **not** mocks and
must not be replaced with mocks. They are also not exposed through the wired
HTTP research routes, which remain explicit stubs.

The local Qwen 0.5B checkpoints are compatibility probes, not registered
production artifacts. No calibrated probability artifact ships, so risk scores
remain `heuristic_index` with `probability: null`. No benchmark has been
executed; the readiness bundle remains `not_run` with null metrics.

## 7. Documentation findings

Before this work, `docs/workspace-scanning-audit.md`,
`docs/current-feature-status.md`, and
`docs/workspace-scanning-implementation-plan.md` were absent. Other findings:

- `docs/ai-assistant-integration.md:63` named the nonexistent setting
  `bugdhor.monitoring.sendSourceText`; the real gates are
  `bugdhor.privacy.sendSourceText` and
  `bugdhor.monitoring.allowAutomaticSourceSharing`.
- `docs/program-analysis.md:3-7` said no API route, workspace scan, or command
  invokes program analysis; the engine and end-to-end report show CFG/DFG/taint
  in wired scans.
- Several historical/result files embed stale absolute `/Users/.../CRAFT-Sec`
  paths and older commit IDs/test counts. They are point-in-time records, not
  current status sources.
- The mathematical regression suite failed because a stored checkpoint path
  pointed at a different checkout. The test now remaps a missing absolute path
  to the same-named artifact beside the stored result and aliases the old
  `craftsec` module namespace to `bugdhor` for loading real checkpoints. No
  mock was introduced.

## 8. Verification evidence

| Suite | Result |
|---|---|
| `npm --workspace vscode-extension test` | 325 passed, 0 failed |
| `../.venv/bin/python -m pytest -q` from `security-engine/` | 717 passed, 0 failed |
| `security-engine/.venv/bin/python -m pytest -q` from repository root (engine + mathematical regressions) | 806 passed, 0 failed |

Lint and formatting checks are recorded in `docs/current-feature-status.md`.

## 9. Audit conclusion

The workspace-scanning boundary is sound when it stays within the official VS
Code event model and the engine's allowlisted, validated file access. Author
attribution is neither available nor needed: scanning is triggered by code
being present in a workspace, not by knowing who wrote it. The remaining
research limitations are deliberate and documented; they must not be converted
into claims of calibrated risk, causal model-internal explanations, or
release-ready research validation.
