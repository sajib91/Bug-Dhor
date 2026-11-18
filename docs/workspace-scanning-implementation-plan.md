# Workspace scanning implementation plan

**Status:** implemented on 2026-11-18  
**Companion documents:** [audit](workspace-scanning-audit.md) and
[current feature status](current-feature-status.md).

## 1. Goal and non-goals

**Goal.** Scan code once it exists in a VS Code workspace, regardless of where
it came from: Copilot, Cursor, Claude, ChatGPT pasted code, OpenCode, another
assistant, or a human edit. Use only official VS Code APIs and only provider
adapters that are explicitly configured and documented.

**Non-goals.**

- Detect or claim AI authorship, model identity, or a person responsible for an
  edit.
- Reverse-engineer an assistant, call a private VS Code/extension API, or
  intercept another extension's internals.
- Make a specific provider required for scanning.
- Replace real SAE/counterfactual work with mocks or convert research stubs into
  claimed production capabilities.
- Add commands; the existing manual scan commands already satisfy manual scans.

## 2. Architecture decisions

| Decision | Rationale |
|---|---|
| Add `WorkspaceMonitor` as the sole owner of VS Code event registration | Prevents duplicate scans and preserves the existing `RealtimeMonitor` tests and behavior. |
| Keep `RealtimeMonitor` as the incremental analysis executor | Its debounce, cancellation, consent, deduplication, and publication logic is already tested; no analysis logic was rewritten. |
| Add pure `settings.js`, `fileFilter.js`, `scanScheduler.js`, and `providerMatrix.js` | Makes defaults, eligibility, scheduling, and attribution rules testable in plain Node without importing `vscode`. |
| `settings.js` is the single source of truth; `realtimeMonitor.js` re-exports aliases | Existing callers and tests keep working while new settings have one normalized definition. |
| No new commands | `test/unit/manifest.test.js` asserts exactly ten `COMMAND_DEFINITIONS`; `scanCurrentFile`, `scanSelection`, and `scanWorkspace` cover manual scans. |
| Enable/disable and scope through settings | Avoids manifest command growth and lets users disable expensive behavior. |
| Preserve dual consent | Automatic source scans require both `bugdhor.monitoring.allowAutomaticSourceSharing` and `bugdhor.privacy.sendSourceText`. |
| `scanOnOpen: false`, `fullScanOnWorkspaceChange: false`; new-file/filesystem watches on when monitoring is enabled | Browsing files or changing folders should not create expensive scans by default, but newly created source files should be covered. |

## 3. Module responsibilities

### 3.1 `WorkspaceMonitor`

- Registers exactly one listener for each required official event.
- Converts an open document into one tracked version, scanning only if
  `scanOnOpen` is explicitly enabled.
- Routes changes and saves to `RealtimeMonitor`.
- Converts `onDidCreateFiles` into a documented
  `workspace.openTextDocument(uri)` call, then delegates to
  `RealtimeMonitor.handleCreate`.
- Handles deletes by cancelling pending/in-flight work, forgetting tracker
  state, removing creation markers, and clearing scoped diagnostics.
- Prunes out-of-workspace documents on folder changes and optionally schedules
  one metadata-only full workspace scan.
- Exposes metadata-only stats via the activation API.

### 3.2 `RealtimeMonitor` extensions

- `registerDocumentListeners: false` lets the orchestrator own event
  registration while the executor keeps its existing handlers.
- `handleOpen`, `handleCreate`, `handleDeleteUri`, and `pruneOutOfWorkspace`
  are public and side-effect bounded.
- Open/create plans use full-file scope; change plans keep function/changed-line
  scoping.
- Eligibility now goes through `fileFilter.evaluateFileEligibility`.
- `DocumentVersionTracker.observeOpen` records opens once per version so an
  open event cannot repeatedly trigger scans.

### 3.3 `fileFilter`

Pure path rules, no `vscode` import and no file reads:

- workspace containment via `isPathWithinRoot`;
- configurable exclude globs for vendored, virtual-environment, cache, build,
  coverage, generated, and Bug Dhor data directories;
- binary extension exclusion by path only;
- generated artifact exclusion (`*.min.js`, bundles, source maps, generated
  files, lockfiles);
- conservative extension-to-language fallback when `languageId` is absent;
- size limit check;
- unsupported-language rejection.

### 3.4 `scanScheduler`

- Coalesces work by stable key.
- Debounces with injectable timers for deterministic tests.
- Cancels superseded timers and tokens.
- Ignores results from obsolete generations.
- Bounds concurrent workspace-level scans (`maxConcurrentScans`).
- Records metadata-only history (key, generation, reason, status).
- Disposal cancels all pending and in-flight work.

### 3.5 `providerMatrix`

A static capability matrix mapping Copilot, Cursor, Claude, ChatGPT, OpenCode,
other assistants, and manual code to the same observation mode
(`workspace-document-events`) and `attribution: 'none'`. Optional adapters are
listed only as separately configured workflows; they never change scan results
or grant model-internal capabilities.

## 4. Settings

| Setting | Default | Purpose |
|---|---|---|
| `bugdhor.monitoring.enabled` | `false` | Master switch. |
| `bugdhor.monitoring.watchWorkspaceFiles` | `true` | Watch create/delete/folder events when enabled. |
| `bugdhor.monitoring.scanNewFiles` | `true` | Scan eligible newly created source files. |
| `bugdhor.monitoring.scanOnOpen` | `false` | Scan opened documents. |
| `bugdhor.monitoring.fullScanOnWorkspaceChange` | `false` | Allow full workspace rescan on folder changes. |
| `bugdhor.monitoring.fullScanDebounceMs` | `2000` | Debounce for workspace-level scans. |
| `bugdhor.monitoring.maxConcurrentScans` | `2` | Workspace-level concurrency bound. |
| `bugdhor.monitoring.maxWorkspaceFiles` | `2000` | Per-event new-file bound. |
| `bugdhor.monitoring.excludeBinaryFiles` | `true` | Skip common binary extensions by path. |
| `bugdhor.monitoring.excludeGeneratedFiles` | `true` | Skip generated artifacts and lockfiles. |
| `bugdhor.monitoring.excludeGlobs` | generated dirs | User-configurable path exclusions. |
| `bugdhor.monitoring.debounceMs` | `750` | Per-document edit debounce. |
| `bugdhor.monitoring.allowAutomaticSourceSharing` | `false` | Explicit automatic source-sharing consent. |
| `bugdhor.privacy.sendSourceText` | `true` | General source-sharing gate for explicit requests and monitoring. |

Settings changes call `WorkspaceMonitor.updateSettings`, which refreshes the
executor and scheduler limits, prunes out-of-workspace state, and cancels all
work when monitoring is disabled.

## 5. Event-to-action map

| Official event | Action |
|---|---|
| `onDidOpenTextDocument` | Observe once per document version; scan only with `scanOnOpen`. |
| `onDidChangeTextDocument` | Version/check change, debounce, scope, scan incrementally. |
| `onDidSaveTextDocument` | Supersede pending work with an immediate bounded file scan. |
| `onDidCreateFiles` | Check eligibility, deduplicate, open via documented API, scan once. |
| `onDidDeleteFiles` | Cancel work, forget state, clear diagnostics. |
| `onDidChangeWorkspaceFolders` | Always prune stale state; optionally schedule one debounced metadata-only full scan. |
| `onDidCloseTextDocument` | Cancel work, forget state, clear diagnostics (optional API availability). |

## 6. Privacy and safety controls

1. No source text is sent by a monitor unless both consent settings are true.
2. Workspace scans send folder metadata only; the engine reads allowlisted files
   from disk.
3. File/selection requests still require a path that resolves inside an allowed
   backend root, even when `sourceText` is supplied.
4. Findings are published only after strict response validation and workspace
   containment checks.
5. `analysisAvailable: false` and `status: 'unavailable'` are never clean scans.
6. Metadata-only stats never include source text, selected text, or code
   identifiers.
7. No provider identity is used for eligibility, scheduling, severity, or
   diagnostic decisions.

## 7. Test plan and results

| Layer | Coverage | Result |
|---|---|---|
| `settings.test.js` | Defaults, clamping, scope validation, frozen output | passing |
| `fileFilter.test.js` | Workspace containment, globs, binary/generated rules, language/size rules | passing |
| `scanScheduler.test.js` | Coalescing, debounce replacement, concurrency, cancellation, obsolete results, failure isolation, disposal | passing |
| `providerMatrix.test.js` | Required workflows, official events, no attribution | passing |
| `workspaceMonitor.test.js` | Event registration, open dedupe, paste routing, save supersession, new/delete files, folder changes, disable switch, settings update | passing |
| Existing monitor/diagnostic/config tests | Backward compatibility and consent semantics | passing |
| Language-capability tests | 13 detected languages, 3 installed parsers, TSX grammar selection, explicit parse gaps | passing |
| General-bug tests | 32 opt-in AST/parser rule cases plus opt-out and confidence-field checks | passing |
| Capability-report tests | Health `analysisCapabilities` contract and extension pass-through validation | passing |
| Full extension unit suite | `npm --workspace vscode-extension test` | 325 passed, 0 failed |
| Engine suite | pytest from `security-engine/` | 717 passed, 0 failed |
| Combined Python suite | pytest from repository root | 806 passed, 0 failed |
| Lint / format | ESLint clean; ruff format check still fails on 55 pre-existing files, none changed here | documented baseline |

## 8. Acceptance criteria

- [x] All required official events are registered exactly once.
- [x] Code from any assistant or manual edit is handled identically.
- [x] No author or model attribution is produced.
- [x] No private API, reverse engineering, or provider-specific dependency is required.
- [x] Automatic source scans require dual consent.
- [x] Debounce, deduplication, cancellation, incremental and full scans are covered by tests.
- [x] Large, binary, generated, vendored, virtual-environment, build, and out-of-workspace files are excluded by default.
- [x] Enabling/disabling and scope are configuration-driven.
- [x] Workspace-level scans are concurrency bounded and folder metadata only.
- [x] Research implementations remain real; HTTP research routes stay honest stubs.
- [x] Documentation and status artifacts are updated.

## 9. Follow-up work (not part of this change)

- Make the engine job/cancellation surface reachable or remove the misleading
  endpoints.
- Wire a validated calibration artifact before publishing any probability.
- Connect real D/E/F access and research artifacts only when explicitly
  configured and validated; keep HTTP stubs until then.
- Execute the benchmark protocol and E0–E8 conditions before making empirical
  claims.
- Address the repository-wide Prettier baseline in a separate formatting-only
  change.
