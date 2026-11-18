# Bug Dhor VS Code Extension

JavaScript VS Code client for the Bug Dhor security framework.

## Status

**Extension shell with a live local-backend transport, diagnostics pipeline, and proposal-only secure recommendations.** The extension activates, registers its commands, settings, output channel, status bar item, Activity Bar container, sidebar launcher, an editor-area **Bug Dhor Security Dashboard** panel, and native VS Code vulnerability diagnostics with hover explanations and repair Quick Fixes. The dashboard provides 11 navigable sections and renders only the state supplied by the extension host. Health checks, file scans, selection detection requests, workspace scans, and secure recommendations reach the real backend through a `SecurityEngineService`; analysis stages that are unconfigured report explicit `unavailable` states. **Bug Dhor: Generate Secure Code** is a custom provider-backed workflow that uses the backend-built prompt and returns an unapplied, verified proposal. The extension does **not** start the Python backend and never applies code without explicit user approval.

The extension produces no analysis result on its own: diagnostics, hover content, and repair Quick Fixes are generated only from validated backend scan results. The dashboard starts empty until a connected backend supplies state. An explicitly labeled demo preview can populate illustrative overview, finding, CWE, and scan-history values; it deliberately leaves SAE features, interactions, steering, explanations, repairs, recommendations, feedback lifecycle, verification checks, and reports empty. Commands show cancellable progress while they contact the backend and report transport or validation errors; they never show a placeholder success message. Backend findings may include a `heuristic_index` risk assessment; no probability is rendered unless a validated calibration artifact supplied one. An empty findings list with `analysisAvailable: false` is reported as unavailable analysis, never as a clean scan.

## Manifest contributions

| Contribution | Identifier | Purpose |
|---|---|---|
| Activity bar container | `bugdhor` | Bug Dhor entry in the Activity Bar |
| Sidebar webview | `bugdhor.sidebar` | Activity Bar launcher for the editor-area dashboard |
| Command | `bugdhor.showStatus` | Report the real extension and engine status |
| Command | `bugdhor.showLogs` | Open the Bug Dhor output channel |
| Command | `bugdhor.scanCurrentFile` | Scan the active saved file |
| Command | `bugdhor.scanSelection` | Scan the selected code |
| Command | `bugdhor.scanWorkspace` | Scan open workspace folders (client sends metadata; backend reads allowlisted files) |
| Command | `bugdhor.explainVulnerability` | Explain the vulnerability in context |
| Command | `bugdhor.analyzeSecurityFeatures` | Analyze security-relevant features |
| Command | `bugdhor.counterfactualAnalysis` | Compare a selected code region with counterfactual variants |
| Command | `bugdhor.generateSecureCode` | Generate a verified secure-code proposal from a validated finding using a configured B/C provider |
| Command | `bugdhor.repairVulnerability` | Generate a repair proposal |
| Command | `bugdhor.verifyRepair` | Verify a repair at workspace scope |
| Command | `bugdhor.openSecurityDashboard` | Open or reveal the Bug Dhor Security Dashboard panel |

All commands use the `Bug Dhor` category. The extension activates on startup, on any of its commands, and when the sidebar view is opened.

## Command validation and service wiring

- File, selection, analysis, generation, and repair commands require a saved `file:` editor inside an open workspace folder.
- `scanSelection` and `counterfactualAnalysis` also require a non-empty selection.
- `scanWorkspace` requires at least one local file-system workspace folder. `verifyRepair` requires an active saved editor because the backend verification contract extends the file context.
- Validation failures are logged as warnings and shown as error messages with a **Show Logs** action.
- Engine calls run under `window.withProgress` with a cancellable notification. Cancellation is logged and produces no error dialog.
- Every engine-backed command calls its declared `SecurityEngineService` method. `generateSecureCode` is the deliberate exception: it first asks the backend for a secure prompt, invokes a configured provider with capabilities B and C, and submits candidate diffs back to the backend for verification. Transport failures, timeouts, problem details, and schema mismatches are reported instead of inventing a result.
- Successful scan results are validated and published as diagnostics; failed or cancelled scans never alter the Problems panel.
- `bugdhor.repairVulnerability` accepts an optional finding context from a diagnostic Quick Fix while retaining its no-argument Command Palette and dashboard behavior. A finding for another file is rejected before the engine call.
- A single `CommandRegistry` owns all 13 registrations and is disposed with the extension.

## Backend transport and privacy

- `bugdhor.backend.url` points at an already-running backend. Only an HTTP(S) origin is accepted; credentials, paths, queries, and fragments are rejected.
- The client calls `GET /api/v1/health`, `POST /api/v1/scan/file`, `POST /api/v1/scan/workspace`, and the analysis routes under `/api/v1`. Timeouts abort the request and are reported to the user.
- An optional bearer token is read from the extension host environment (`BUGDHOR_API_TOKEN`, with `BUGDHOR_ENGINE_TOKEN` as a legacy alias). Tokens are never stored in settings or logs.
- File and selection requests include the current editor buffer as `sourceText` and the selected code as `selectedText` only when `bugdhor.privacy.sendSourceText` is enabled. The commands are always explicitly user-invoked. Disabling the setting sends only paths and ranges; the backend then reads the saved file from disk.
- Workspace scans send folder name, path, and file-URI metadata only, never file contents.
- Health checks send no source code.
- Every response is validated before use. The backend's `partial`/`unavailable` statuses and `analysisAvailable: false` are preserved; they are never converted into a clean scan.
- Background monitoring is off by default and sends no source text unless `bugdhor.monitoring.allowAutomaticSourceSharing` AND `bugdhor.privacy.sendSourceText` are both enabled.
- Secure recommendations call `POST /api/v1/recommendations/generate` twice when generating: once with no candidates for the prompt and once with extracted candidates for verification. No provider credential is sent in the request body; environment-backed API keys remain in the extension host.

### Secure recommendation and feedback settings

| Setting | Default | Effect |
|---|---|---|
| `bugdhor.feedback.notifyOnPatchApplied` | `true` | Notify when an explicitly applied patch is recorded. |
| `bugdhor.feedback.notifyOnResolution` | `true` | Notify when a finding reaches `resolved`. |
| `bugdhor.recommendations.runFunctionalTests` | `true` | Request functional tests; disabling them prevents recommendation rather than bypassing the gate. |
| `bugdhor.recommendations.allowSandboxedExecution` | `false` | Permit sandboxed test execution; network, privileged, and destructive operations stay forbidden. |
| `bugdhor.recommendations.testCommand` | `[]` | Optional argv list for the project's functional tests. |
| `bugdhor.recommendations.testTimeoutSeconds` | `120` | Per-run functional-test timeout (1–3600 seconds). |

Hosted assistants expose A/B/C only and never claim validated steering. Only
validated local D/E/F access with a real pipeline can support steering, and API
requests always report the steering pipeline as `None`.

The publisher is set to the explicit placeholder `your-publisher-id`. Replace it with the real Marketplace publisher ID before publishing; no publisher identity is claimed by this repository.

## Security dashboard

`bugdhor.openSecurityDashboard` opens (or reveals) a singleton editor-area webview panel titled **Bug Dhor Security Dashboard**. The Activity Bar sidebar is a launcher that sends one message, `openDashboard`.

The dashboard has 11 sections: Overview, Security Scan, Vulnerabilities, SAE Features, Feature Interactions, Security Steering, Explanations, Automated Repair, Verification, Research Reports, and Settings. Overview shows total findings, severity counts, vulnerability and CWE distributions, verification status, and recent scan history.

- **Empty by default.** Counts are `null` and lists are empty until a real scan result is supplied. The dashboard never estimates missing values.
- **Explicit demo preview.** The **Load demo preview** button requests a separately labeled data mode with 18 illustrative findings, matching severity and CWE totals, and scan history. It does not simulate SAE activations, feature interactions, steering, explanations, repairs, verification checks, or reports.
- **Backend-ready state.** The panel controller calls an injected `getState(dataMode)` function and merges validated live results into the empty baseline. Unavailable backend data is never fabricated.
- **Secure recommendations.** Verified proposals show the exact original and repaired source, what changed, why, remaining risks, verification and functional results, and prompt provenance. Recommendations are proposals only: every display states that no perfect security is guaranteed and that explicit approval is required. The dashboard itself never applies a patch.
- **Feedback lifecycle.** The same section shows tracked finding states and bounded-loop counters (validated scans, suppressed self-induced scans, follow-up rescans, approved patches, verifications, and resolutions). Resolution requires an applied patch, a clean rescan, and passing verification.
- **Counterfactual evidence view.** When a live state supplies measured `baselineRisk`, `singleFeatureEffects`, `pairwiseEffects`, `higherOrderEffects`, `activationChanges`, `cweResults`, and `metadata`, Feature Interactions renders native local SVG charts, uncertainty, evidence categories, provenance, and a selector for supplied code examples. Missing values are labeled **Unavailable evidence**; the UI never derives effects, probabilities, or vulnerability-status changes.
- **Restricted execution.** Dashboard action buttons can execute only the engine-backed commands in the controller's allowlist, with no arguments. The webview cannot execute arbitrary VS Code commands, write files, or start a backend. Patch buttons only post a message; the extension host applies a file change solely after an explicit approval, base-hash revalidation, target-path validation, and a successful `WorkspaceEdit`.
- **Validation.** Inbound messages are checked for shape and value. Unknown or malformed messages are logged and ignored. Engine command failures produce an error notice, never a success notice.
- **Webview security.** The shell uses a per-render nonce, a restrictive CSP (`default-src 'none'`, no network or inline execution), local resource roots, escaped embedded JSON, and DOM text APIs for dynamic content. The sidebar launcher has its own nonce CSP and can only post `openDashboard`.
- **Accessibility and theming.** Navigation uses an accessible vertical tablist with keyboard support, tables have captions and scoped headers, status changes use a live region, and styling uses VS Code theme tokens with reduced-motion and forced-colors handling.
- **Read-only settings.** Settings are displayed read-only; **Open VS Code Settings** and **Show logs** delegate to VS Code.

## Vulnerability diagnostics

The scan commands feed successful backend results into a native VS Code `DiagnosticCollection`. No finding is hardcoded in the extension: an empty backend result produces no diagnostics, and the extension is empty at activation.

- **Required result contract.** A scan result is either a findings array or `{ findings: [...], scope?: { uris: [...] } }`. Each finding requires `id`, `message`, `severity`, and a `location` with a `file:` URI and a zero-based `range`; `cwe`, `ruleId`, `evidence`, `explanation`, `sourceReferences`, and `repair` are optional.
- **Severity mapping.** `critical` and `high` become errors, `medium` becomes a warning, `low` becomes information, and `info` becomes a hint. Severity is taken from the backend, never inferred from the message.
- **Problems panel.** The diagnostic uses the backend range, the concise backend message, source `Bug Dhor`, and the CWE identifier as clickable diagnostic code when supplied. Related information carries backend evidence and source references.
- **Hover explanations.** Hovering a finding shows its message, severity, CWE, rule ID, backend explanation, evidence, source references, and repair eligibility. Missing explanation, sources, or repair metadata are stated explicitly rather than filled in.
- **Repair Quick Fix.** A Quick Fix appears only when the backend sets `repair.eligible` to `true`. It invokes the existing `bugdhor.repairVulnerability` command with the finding ID, document URI, range, CWE, and rule ID. The extension does not edit code or generate a patch itself.
- **Validation and containment.** Malformed findings are rejected and logged; a malformed result envelope is rejected without clearing existing diagnostics. Findings outside an open workspace folder and non-`file:` URIs are never published. `scope.uris` or the scanned document URI clears stale diagnostics for the covered files.
- **Model-internal evidence is not wired.** Scans, detection, explanation, repair proposals, and verification reach real backend paths whose availability is declared by `/health`. SAE features, counterfactual effects, and activation steering remain unavailable without compatible model artifacts and direct D/E/F access; the extension does not simulate them. Provider adapters are tested with backend-shaped fixtures.

## Model-independent workspace monitoring

`WorkspaceMonitor` is the single owner of official VS Code event registration. When `bugdhor.monitoring.enabled` is set, it observes:

- `onDidOpenTextDocument` — tracked once per document version; scanned only when `bugdhor.monitoring.scanOnOpen` is explicitly enabled.
- `onDidChangeTextDocument` — debounced, versioned, incremental analysis.
- `onDidSaveTextDocument` — supersedes pending work with an immediate bounded file scan.
- `onDidCreateFiles` — eligible new source files are opened with `workspace.openTextDocument` and scanned once.
- `onDidDeleteFiles` — cancels work, forgets state, and clears that file's diagnostics.
- `onDidChangeWorkspaceFolders` — prunes stale state; optionally schedules one debounced metadata-only full workspace scan.

`onDidCloseTextDocument` is also registered when available. No private API, reverse engineering, or provider-specific dependency is required. This works identically for code from Copilot, Cursor, Claude, ChatGPT pasted text, OpenCode, other assistants, or manual edits.

The incremental executor tracks document versions and ignores repeated or out-of-order events. Each batch identifies changed lines, then scopes analysis to the enclosing function (lexically detected for Python and JavaScript), to the changed lines, or to the whole file according to `bugdhor.monitoring.analysisScope`. Open, create, and save events use full-file scope; wide batches also fall back to a bounded file-level scan. Text is read once per debounced batch, and documents above `bugdhor.monitoring.maxFileBytes` are skipped.

Changes are debounced (`bugdhor.monitoring.debounceMs`, minimum 100 ms) so no scan runs per keystroke. At most one request per document is active: a newer edit cancels the superseded request through a cancellation token, and the API client aborts its in-flight HTTP call. Workspace-level scans are coalesced and bounded by `bugdhor.monitoring.maxConcurrentScans`. Analysis runs off the editor's event path, publishes backend findings to the native Problems panel with the document URI as scope, and shows a non-blocking notification when findings exist. Backend results remain the only source of findings; `analysisAvailable: false` or `status: 'unavailable'` never becomes a clean scan.

**Eligibility:** `fileFilter.js` skips paths outside open `file:` workspace folders, unsupported languages, binary extensions (by path only), generated artifacts such as `*.min.js`, bundles, source maps and lockfiles, and configurable exclude globs covering `node_modules`, `.git`, virtual environments, `site-packages`, caches, build/coverage directories, `vendor`, and `.bugdhor-data`. It never reads file bytes to guess a language author.

**Attribution:** every edit is treated as an ordinary document change. The monitor does not assume an AI assistant produced it, does not detect an "AI mode", and does not claim to identify the model or author responsible. `src/monitoring/providerMatrix.js` reports `workspace-document-events` and `attribution: 'none'` for every supported workflow; optional adapters are listed only for separately configured generation-metadata workflows and never alter scan results.

**Privacy:** monitoring is disabled by default. No background request containing source text is sent unless both the explicit `bugdhor.monitoring.allowAutomaticSourceSharing` consent and `bugdhor.privacy.sendSourceText` are enabled. With consent disabled, the monitor tracks versions locally but makes no engine call. Full workspace scans send folder metadata only; the backend reads allowlisted files from disk. Stats exposed on the activation API contain metadata only: no source text, selected text, or code identifiers.

See `docs/workspace-scanning-audit.md` and `docs/workspace-scanning-implementation-plan.md` at the repository root for the evidence boundary and full event/settings map.

## Settings

| Setting | Default | Behavior |
|---|---|---|
| `bugdhor.backend.url` | `http://127.0.0.1:8765` | Base URL of the already-running FastAPI backend; must be an HTTP(S) origin |
| `bugdhor.backend.requestTimeoutMs` | `30000` | Timeout for scan and analysis requests |
| `bugdhor.backend.healthTimeoutMs` | `3000` | Timeout for backend health checks |
| `bugdhor.privacy.sendSourceText` | `true` | Send the current buffer and selection with explicitly user-invoked file/selection requests |
| `bugdhor.backend.pythonPath` | empty | Reserved for a future backend process manager; the extension does not start an engine |
| `bugdhor.backend.autoStart` | `false` | Reserved; enabling it logs a warning because no engine is started |
| `bugdhor.logging.level` | `info` | Filters messages written to the Bug Dhor output channel |
| `bugdhor.ui.showStatusBarItem` | `true` | Shows or hides the Bug Dhor status bar item |
| `bugdhor.monitoring.enabled` | `false` | Enable background monitoring of document changes (off by default) |
| `bugdhor.monitoring.allowAutomaticSourceSharing` | `false` | Explicit consent to send changed source text automatically; required with `privacy.sendSourceText` |
| `bugdhor.monitoring.onSaveOnly` | `false` | Analyze only on save instead of after debounced edits |
| `bugdhor.monitoring.debounceMs` | `750` | Delay before a debounced scan runs (minimum 100 ms) |
| `bugdhor.monitoring.languages` | `["python", "javascript"]` | Language IDs eligible for monitoring |
| `bugdhor.monitoring.analysisScope` | `function` | Scope of incremental analysis: `changedLines`, `function`, or `file` |
| `bugdhor.monitoring.maxFileBytes` | `1048576` | Skip documents larger than this size |
| `bugdhor.monitoring.maxChangedLines` | `500` | Wider change batches fall back to a file-level scan |
| `bugdhor.monitoring.excludeGlobs` | generated dirs | Path globs excluded from monitoring (`*`, `**`, `?`) |
| `bugdhor.monitoring.watchWorkspaceFiles` | `true` | Watch official file create/delete and workspace-folder events when monitoring is enabled |
| `bugdhor.monitoring.scanNewFiles` | `true` | Scan eligible newly created source files once |
| `bugdhor.monitoring.scanOnOpen` | `false` | Scan an eligible document when opened; off by default so browsing does not trigger scans |
| `bugdhor.monitoring.fullScanOnWorkspaceChange` | `false` | Opt in to one debounced metadata-only full workspace scan on folder changes |
| `bugdhor.monitoring.fullScanDebounceMs` | `2000` | Debounce for workspace-level full scans |
| `bugdhor.monitoring.maxConcurrentScans` | `2` | Maximum concurrent workspace-level scans |
| `bugdhor.monitoring.maxWorkspaceFiles` | `2000` | Maximum new files observed from a single create event |
| `bugdhor.monitoring.excludeBinaryFiles` | `true` | Skip common binary extensions by path without reading file content |
| `bugdhor.monitoring.excludeGeneratedFiles` | `true` | Skip minified bundles, source maps, generated files, and lockfiles |
| `bugdhor.monitoring.notifyOnFindings` | `true` | Show a non-blocking notification when findings are published |

The backend must be started separately, for example from `security-engine/`:

```bash
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765
```

Set `BUGDHOR_WORKSPACE_ROOTS` to the folders the backend may inspect. Set the
same `BUGDHOR_API_TOKEN` in the extension host environment when backend bearer
authentication is enabled.

## Development

Set up the repository once from the root:

```bash
npm run setup -- --cpu --with-analyzers
```

Then use the root commands:

```bash
npm run extension:lint
npm run extension:test
npm run extension:test:integration
npm run build
```

The unit suite (325 tests) validates the manifest, command definitions and registration, editor/workspace validation, progress and error behavior, the unavailable and HTTP service contracts, backend URL/timeout/privacy configuration, request mapping and consent omission, API transport failures and cancellation, response schema validation, workspace metadata limits, shared identifiers, icon dimensions, the dashboard model and demo data, webview CSP/message handling, dashboard HTML and client-source constraints, the sidebar launcher, the backend finding contract, diagnostic publication and clearing, severity/CWE mapping, workspace containment, hover content and escaping, repair Quick Fix eligibility and arguments, provider registration/disposal, real-time monitoring (change analysis, version tracking, debouncing, cancellation, privacy gating), workspace monitoring (settings normalization, file filtering, scheduler coalescing/cancellation/concurrency, provider matrix, official events, open/create/delete/folder handling), secure recommendation request mapping and provider B/C gating, candidate extraction, feedback deduplication/resolution/lifecycle, one-shot suppression and bounded rescan, dashboard recommendation review and explicit approval, and the no-TypeScript constraint. The integration test launches a real VS Code Extension Host with `@vscode/test-electron`, starts the Python backend against a disposable workspace, points the extension at that backend, checks health and unreachable-backend handling, scans an unsaved buffer and verifies the returned SHA-256 matches the buffer rather than the disk copy, disables source sharing and verifies the backend falls back to the saved file, scans the workspace and a selection, verifies that unavailable analysis never publishes findings, produces a real SQL-injection finding and publishes it as a native diagnostic with hover and observation-only explanation, verifies honest SAE/counterfactual/steering stubs and proposal-only repair with explicit-patch verification, exercises real-time monitoring for rapid edits, paste, save, and concurrent documents, and opens the singleton dashboard tab. Tests never download models.

## Extension Development Host

1. Open the repository root in VS Code.
2. Install the recommended extensions from `.vscode/extensions.json` if prompted.
3. Open **Run and Debug** and select **Run Bug Dhor Extension** from `.vscode/launch.json`.
4. Press F5. The Extension Development Host loads `vscode-extension/` as the development extension.
5. Open the Bug Dhor shield in the Activity Bar or run a `Bug Dhor:` command from the Command Palette.

To run the integration test, use `npm run extension:test:integration`. It prefers a locally installed VS Code (`BUGDHOR_VSCODE_EXECUTABLE` overrides the path) and otherwise lets `@vscode/test-electron` download a stable build into `.vscode-test/`, which is gitignored.

## Packaging note

Build the VSIX from `vscode-extension/` with:

```bash
npm run package:vsix
```

The script runs `vsce package --no-dependencies --allow-missing-repository --skip-license`. `--no-dependencies` is required because npm workspaces hoist dependencies to the repository root; without it, `vsce` would package the entire repository. The current VSIX contains 45 files and about 102 KB, including the dashboard, launcher, and diagnostics modules. Tests, placeholders, lockfiles, secrets, local data, model weights, and other development files are excluded by `.vscodeignore`.

The extension has no runtime npm dependency: `ajv` is used only by the unit tests. Add a bundling step before importing a runtime dependency or publishing. The manifest still uses the placeholder publisher `your-publisher-id` and lacks a repository URL and license, so the VSIX is a development artifact only and is not Marketplace-ready. See `docs/release-checklist.md` at the repository root for the full release procedure, versioning policy, backend setup, and clean-install verification.

## Layout

| Path | Purpose |
|------|---------|
| `src/extension.js` | Activation entry point and disposable registration |
| `src/config.js` | Typed settings access and change subscription |
| `src/constants.js` | Command, container, and view IDs shared with tests |
| `src/commands/index.js` | Registers all commands and returns one composite disposable |
| `src/commands/definitions.js` | Canonical feature-command metadata and service mapping |
| `src/commands/registry.js` | Duplicate-safe registration and composite disposal |
| `src/commands/validation.js` | Re-exports the workspace validation and request builders |
| `src/commands/runEngineCommand.js` | Cancellable progress, cancellation, and error reporting |
| `src/commands/registerEngineCommand.js` | Binds a command definition to a service method |
| `src/commands/scanCommands.js` | Scan Current File, Scan Selection, Scan Workspace |
| `src/commands/analysisCommands.js` | Explain, security features, counterfactual analysis |
| `src/commands/repairCommands.js` | Generate secure code, repair, verify |
| `src/commands/dashboardCommand.js` | Open or reveal the dashboard panel |
| `src/commands/utilityCommands.js` | Show status and show logs |
| `src/api/securityEngineService.js` | Service contract, HTTP implementation, request mapping, unavailable fallback |
| `src/api/apiClient.js` | Fetch transport, timeouts, cancellation, problem details, bounded responses |
| `src/api/configurationService.js` | Backend URL/timeout validation, environment token, source-sharing setting |
| `src/api/securityResultService.js` | Health, envelope, scan, detection, and analysis response validation |
| `src/workspace/workspaceService.js` | Editor/workspace request builders, source consent, workspace metadata limits |
| `src/diagnostics/findingModel.js` | Backend finding validation, severity/CWE mapping, and range helpers |
| `src/diagnostics/diagnosticController.js` | DiagnosticCollection, finding store, scope clearing, and Problems panel publication |
| `src/diagnostics/hoverProvider.js` | Hover explanations built only from backend finding fields |
| `src/diagnostics/codeActionProvider.js` | Repair Quick Fixes for backend-eligible findings |
| `src/diagnostics/index.js` | Diagnostic provider registration and disposal |
| `src/recommendations/secureCodeGeneration.js` | Prompt retrieval, provider B/C validation, candidate extraction, and backend verification |
| `src/feedback/` | Finding lifecycle, applied-patch provenance, and bounded feedback controller |
| `src/integrations/` | Provider registry, capabilities A–F, hooks, and official manifest validation |
| `src/monitoring/workspaceMonitor.js` | Sole owner of official document and workspace event registration |
| `src/monitoring/settings.js` | Normalized monitoring defaults and single source of truth |
| `src/monitoring/fileFilter.js` | Pure workspace, glob, binary, generated, language, and size eligibility |
| `src/monitoring/scanScheduler.js` | Debounce, dedupe, cancellation, generation checks, and bounded concurrency |
| `src/monitoring/providerMatrix.js` | Provider/workflow matrix with `attribution: 'none'` |
| `src/monitoring/realtimeMonitor.js` | Debounced change analysis, suppression, bounded rescan, and cancellation |
| `src/security/paths.js` | Workspace containment checks for backend-supplied paths |
| `src/logging/output.js` | Log output channel and level filtering |
| `src/views/statusBar.js` | Status bar item and visibility setting |
| `src/webviews/sidebarView.js` | Activity Bar launcher provider and `openDashboard` validation |
| `src/webviews/sidebarHtml.js` | Nonce-CSP launcher markup |
| `src/webviews/dashboardPanel.js` | Singleton panel controller, message validation, and command allowlist |
| `src/webviews/dashboardModel.js` | 11-section navigation, actions, empty state, and labeled demo state |
| `src/webviews/dashboardHtml.js` | Accessible dashboard shell with nonce CSP and embedded state |
| `src/webviews/csp.js` | Nonce and Content Security Policy construction |
| `src/webviews/html.js` | Attribute/text escaping and safe inline JSON serialization |
| `src/backend/` | Engine process manager and handshake (future; the extension connects to an already-running backend) |
| `src/jobs/` | Job lifecycle and progress routing (future) |
| `src/workspace/` | Request builders now; snapshots and patch approval (future) |
| `src/security/` | Workspace path containment; shared webview helpers (future) |
| `media/` | Icons, dashboard CSS/JS, and sidebar launcher CSS/JS |
| `test/` | Unit and Extension Host integration tests |

See `docs/architecture.md` for the full design and
`docs/secure-recommendation-and-feedback.md` for the proposal-only recommendation
workflow, verification gates, and feedback lifecycle.
