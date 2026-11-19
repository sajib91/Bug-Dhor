# Development Setup

**Status:** The macOS path was executed and verified on 2026-11-10; command-layer, dashboard, diagnostics, and HTTP API verification was repeated on 2026-11-12. Packaging, Marketplace documentation, and OIDC publishing preparation were rechecked on 2026-11-19. The Windows commands are derived from upstream installers and published wheel metadata; they were **not executed on this macOS host**. Claims below distinguish verified behavior from expected behavior.

This repository is an early implementation. Setup installs the toolchain, and the VS Code extension with its dashboard and diagnostics pipeline can run in an Extension Development Host. The Python engine provides a tested, versioned FastAPI HTTP API with real file/workspace inspection, source preprocessing, program analysis, static-analyzer adapters, detection, explanation, proposal-only repair, and bounded verification. The extension uses a live HTTP client but does not start the backend process. SAE extraction, counterfactual analysis, and activation steering remain honest HTTP stubs that report `unavailable`; no production model/SAE artifact, calibration artifact, or adequate execution sandbox is present. No model weights, datasets, SAE artifacts, or benchmark results are downloaded or produced by setup.

## 1. Supported toolchain

| Component | Required                                  | Verified on this host            |
| --------- | ----------------------------------------- | -------------------------------- |
| Python    | `>=3.11,<3.15`                            | 3.11.14                          |
| Node.js   | 22.13+ or 24+ (24 LTS recommended)        | 25.9.0                           |
| npm       | Bundled with Node                         | 11.13.0                          |
| VS Code   | 1.90+                                     | 1.143.1; Extension Host launched |
| OS        | macOS or Windows                          | macOS 26.3.1, arm64              |
| Docker    | Optional, for future sandbox verification | 29.2.1 detected                  |
| Semgrep   | Optional                                  | 1.185.0                          |
| Bandit    | Optional                                  | 1.9.4                            |

Node 23 is intentionally excluded because ESLint 10 and `@vscode/vsce` 4 do not support it. `.nvmrc` pins Node 24 for nvm users. `.python-version` pins Python 3.11 as the most thoroughly verified interpreter.

Python 3.12–3.14 satisfy the declared range and have compatible wheels for PyTorch, Semgrep, and tree-sitter, but only Python 3.11.14 was exercised end-to-end in this verification run. Python 3.14.0 is installed on the host but was not used for the project virtual environment.

## 2. What setup does

`npm run setup` performs all of the following:

1. Finds a supported Python 3.11–3.14 interpreter.
2. Creates `.venv/` at the repository root (not inside `security-engine/`).
3. Upgrades `pip`, `setuptools`, and `wheel`.
4. Installs the CPU-only PyTorch wheel when `--cpu` is passed.
5. Installs `security-engine` in editable mode with the selected extras.
6. Runs `npm install` for the root workspace.
7. Creates `.env` from `.env.example` if `.env` does not already exist.

It does **not**:

- download Hugging Face models, tokenizers, datasets, or SAE artifacts;
- start the Python engine or the VS Code extension;
- install CodeQL or Joern;
- modify user source files;
- run analysis, counterfactual, steering, repair, or verification code.

Semgrep and Bandit are optional. Without `--with-analyzers`, setup skips the analyzer CLIs; adapters exist but report missing or failed tools explicitly.

## 3. macOS quick start (verified)

Install Node 22.13+ or 24+ from [nodejs.org](https://nodejs.org/), or use nvm. The repository `.nvmrc` selects Node 24. Install Python 3.11–3.14 from [python.org](https://www.python.org/downloads/) or Homebrew, for example:

```bash
brew install python@3.11
python3.11 --version
```

From the repository root:

```bash
cd /path/to/Bug Dhor
npm run setup -- --python python3.11 --cpu --with-analyzers
npm run doctor
npm test
```

The `--python` argument is optional. Without it, `scripts/dev.js` selects the first supported interpreter from `python3.12`, `python3.11`, `python3`, then `python` (and `py -3` on Windows). Use `--python` when multiple interpreters exist and you want a specific one.

The exact command verified on this host was:

```bash
npm run setup -- --python python3.11 --cpu --with-analyzers
```

Result: Python 3.11.14 environment created, CPU-only PyTorch 2.15.0 installed, Semgrep 1.185.0 and Bandit 1.9.4 installed, npm workspace installed, `.env` created, and no model downloads performed. The CPU wheel reports `torch.version.cuda is None`.

## 4. Windows quick start (PowerShell; not executed here)

Install the prerequisites:

- **Node.js:** install Node 22.13+ or 24 LTS from [nodejs.org](https://nodejs.org/). Confirm with `node --version`.
- **Python:** install Python 3.11–3.14 from [python.org](https://www.python.org/downloads/). Select **Add python.exe to PATH** during installation. Confirm the available launchers with `py -0p`.
- **VS Code:** install 1.90 or newer.

If PowerShell blocks npm scripts such as `npm.ps1`, allow locally created scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

From the repository root:

```powershell
cd C:\path\to\Bug Dhor
npm run setup -- --cpu --with-analyzers
npm run doctor
npm test
```

If the Python launcher selects an unsupported interpreter, point the setup at a specific executable:

```powershell
$env:BUGDHOR_PYTHON = "C:\Users\<you>\AppData\Local\Programs\Python\Python312\python.exe"
npm run setup -- --cpu --with-analyzers
```

To run Python tools manually, activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
python --version
```

Published Windows wheels were checked for the critical native packages:

- `torch-2.15.0+cpu-cp311-cp311-win_amd64.whl` is present on the PyTorch CPU index.
- Semgrep 1.185.0 publishes a `win_amd64` wheel.
- `tree-sitter-python`, `tree-sitter-javascript`, and `tree-sitter-typescript` publish Windows wheels.

Native Semgrep installation on Windows has not been executed here. If it fails, either omit `--with-analyzers` and use the engine without analyzer CLIs, or run the engine inside WSL2. Bandit is pure Python and is expected to work on Windows.

## 5. Manual setup (optional)

The setup script is the recommended path because it handles interpreter selection and CPU PyTorch. The equivalent manual commands are below.

### macOS / Linux

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
cd ..
npm install
cp .env.example .env
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
cd ..
npm install
Copy-Item .env.example .env
```

Do not run both the setup script and the manual commands against the same environment unless you intend to reinstall. The setup script reuses an existing `.venv` and leaves an existing `.env` unchanged.

## 6. Dependency profiles

| Goal                                                      | Command                                   | Verification status                                         |
| --------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------- |
| Full local development with CPU PyTorch and analyzer CLIs | `npm run setup -- --cpu --with-analyzers` | Executed and verified with Python 3.11 on macOS             |
| Core + dev + ML, no Semgrep/Bandit                        | `npm run setup -- --cpu`                  | Same path minus the analyzer extra; not separately executed |
| Static-only engine, no PyTorch/Transformers               | `npm run setup -- --static-only`          | Not separately executed                                     |
| Python environment only, skip npm                         | `npm run setup -- --cpu --skip-node`      | Not separately executed                                     |

The Python extras are declared in `security-engine/pyproject.toml`:

- Core: FastAPI, Uvicorn, Pydantic, SQLAlchemy, Alembic, NumPy, Pandas, tree-sitter and grammars, JSON Schema.
- `ml`: PyTorch, Transformers, safetensors.
- `analyzers`: Semgrep, Bandit.
- `dev`: pytest, pytest-cov, pytest-timeout, Ruff, import-linter, datamodel-code-generator, build.

## 7. Environment variables

Setup copies `.env.example` to `.env`. Never commit `.env`. The template sets CPU development as the default.

| Variable                          | Default in template    | Purpose                                                               |
| --------------------------------- | ---------------------- | --------------------------------------------------------------------- |
| `BUGDHOR_LOG_LEVEL`               | `INFO`                 | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`                    |
| `BUGDHOR_DATA_DIR`                | `./.bugdhor-data`      | Local data directory                                                  |
| `BUGDHOR_LOG_DIR`                 | `./.bugdhor-data/logs` | Local log directory                                                   |
| `BUGDHOR_HOST`                    | `127.0.0.1`            | API bind address; keep loopback for local use                         |
| `BUGDHOR_PORT`                    | `8765`                 | API port; `0` selects an ephemeral port                               |
| `BUGDHOR_CORS_ORIGINS`            | commented out          | Exact comma-separated origin allowlist; wildcards are rejected        |
| `BUGDHOR_WORKSPACE_ROOTS`         | commented out          | Allowed scan roots; defaults to the process working directory         |
| `BUGDHOR_MAX_REQUEST_BYTES`       | `2097152`              | Maximum JSON request body                                             |
| `BUGDHOR_MAX_FILE_BYTES`          | `1048576`              | Maximum inspected file size                                           |
| `BUGDHOR_MAX_WORKSPACE_FILES`     | `50000`                | Maximum files discovered per workspace scan                           |
| `BUGDHOR_API_TOKEN`               | commented out          | Optional bearer token for `/api/*` requests                           |
| `BUGDHOR_DEVICE`                  | `cpu`                  | `cpu`, `auto`, `cuda`, or `mps`; `auto` detects hardware              |
| `BUGDHOR_GPU_CONCURRENCY`         | `1`                    | Integer from 1 to 8                                                   |
| `BUGDHOR_MODEL_ID`                | commented out          | Hugging Face model identifier, only when a workflow needs it          |
| `BUGDHOR_MODEL_REVISION`          | commented out          | Immutable model revision, preferably a commit SHA                     |
| `BUGDHOR_HF_TOKEN` or `HF_TOKEN`  | commented out          | Optional gated-model token; redacted from serialized settings         |
| `BUGDHOR_SAE_MANIFEST`            | commented out          | Registered, compatible SAE manifest path                              |
| `BUGDHOR_SANDBOX_BACKEND`         | `docker`               | `docker`, `process`, or `none`; no sandbox backend is implemented yet |
| `BUGDHOR_SANDBOX_TIMEOUT_SECONDS` | `900`                  | Sandbox timeout                                                       |
| `BUGDHOR_SEMGREP_PATH`            | `semgrep`              | Semgrep executable or command                                         |
| `BUGDHOR_BANDIT_PATH`             | `bandit`               | Bandit executable or command                                          |

Relative paths are resolved from the process working directory. Run engine commands from the repository root unless a later component documents otherwise.

The settings layer is implemented and tested in `security-engine/src/bugdhor/core/settings.py`. It validates environment values, normalizes CORS and workspace allowlists, enforces HTTP and scan limits, creates data/log directories on request, and removes the Hugging Face and API tokens from `Settings.redacted()`. The tests do not download models or call external services.

## 8. Daily commands

Run these from the repository root after setup.

| Command                              | What it does                                                                                                            | Verified                        |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `npm run doctor`                     | Prints Node, npm, venv Python, installed packages, optional analyzers, Docker, and `.env` status; performs no downloads | Yes                             |
| `npm run structure:check`            | Validates required directories/files, package markers, JavaScript entry point, and absence of TypeScript                | Yes                             |
| `npm run lint`                       | Runs Ruff on `security-engine/src` and `security-engine/tests`, then ESLint on `vscode-extension`                       | Yes                             |
| `npm run format`                     | Writes Ruff and Prettier formatting                                                                                     | Yes                             |
| `npm run format:check`               | Checks formatting without writing                                                                                       | Yes                             |
| `npm test`                           | Runs pytest and VS Code extension unit tests                                                                            | Yes                             |
| `npm run build`                      | Builds the Python wheel and packages a development VSIX                                                                 | Yes                             |
| `npm run check`                      | Runs structure, lint, format check, and tests                                                                           | Yes                             |
| `npm run extension:test`             | Runs only extension unit tests                                                                                          | Yes (via the same command path) |
| `npm run extension:lint`             | Runs only extension ESLint                                                                                              | Yes (via the same command path) |
| `npm run extension:test:integration` | Launches a real VS Code Extension Host and validates activation, commands, views, and settings                          | Yes; VS Code 1.143.1 on macOS   |

Direct Python commands, after activation:

```bash
cd security-engine
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
python -m bugdhor --host 127.0.0.1 --port 8765
```

The last command starts the local engine API. OpenAPI is served at
`http://127.0.0.1:8765/openapi.json` and interactive docs at
`http://127.0.0.1:8765/docs`. See [api.md](api.md).

## 9. VS Code extension development

The extension is JavaScript, not TypeScript. Its entry point is `vscode-extension/src/extension.js`.

The manifest contributes:

- **Activity Bar container:** `bugdhor`, titled **Bug Dhor**, using `media/activitybar.svg`.
- **Sidebar launcher:** `bugdhor.sidebar`, titled **Security Dashboard**, rendered by `src/webviews/sidebarView.js` with a nonce CSP and local CSS/JS. Its only action posts `openDashboard`; it cannot execute commands or read analysis data.
- **Security dashboard panel:** opened on demand by `bugdhor.openSecurityDashboard`, not contributed as a manifest view. It is a singleton editor-area panel with 11 sections, theme-aware styling, and a restrictive nonce CSP.
- **Settings:** `bugdhor.backend.pythonPath`, `bugdhor.backend.autoStart`, `bugdhor.logging.level`, and `bugdhor.ui.showStatusBarItem`.
- **Extension icon:** `media/icon.png`, a valid 128×128 PNG used as the Marketplace icon. The manifest publisher is the approved ID `sajib91`; the Marketplace account still requires owner verification.

All commands use the **Bug Dhor** category:

| Command                           | Scope                                                                                  | Service method            |
| --------------------------------- | -------------------------------------------------------------------------------------- | ------------------------- |
| `bugdhor.showStatus`              | None                                                                                   | —                         |
| `bugdhor.showLogs`                | None                                                                                   | —                         |
| `bugdhor.scanCurrentFile`         | Saved file in a workspace folder                                                       | `scanFile`                |
| `bugdhor.scanSelection`           | Saved file with a non-empty selection                                                  | `scanSelection`           |
| `bugdhor.scanWorkspace`           | One or more workspace folders                                                          | `scanWorkspace`           |
| `bugdhor.explainVulnerability`    | Saved file in a workspace folder                                                       | `explainVulnerability`    |
| `bugdhor.analyzeSecurityFeatures` | Saved file in a workspace folder                                                       | `analyzeSecurityFeatures` |
| `bugdhor.counterfactualAnalysis`  | Saved file with a non-empty selection                                                  | `counterfactualAnalysis`  |
| `bugdhor.generateSecureCode`      | Saved file in a workspace folder                                                       | `generateSecureCode`      |
| `bugdhor.repairVulnerability`     | Saved file in a workspace folder; optional finding context from a diagnostic Quick Fix | `repairVulnerability`     |
| `bugdhor.verifyRepair`            | Saved file in a workspace folder                                                       | `verifyRepair`            |
| `bugdhor.openSecurityDashboard`   | None                                                                                   | —                         |

This table lists the original engine-backed commands. The current manifest contributes 27 commands in
total, including repository/changed-file scanning, assistant capability inspection, finding
navigation, and the opt-in local Phase 6 workflows; see
[`vscode-extension/package.json`](../vscode-extension/package.json) for the full list.

The extension activates on startup, its commands, and when the sidebar view is opened. Activation creates the output channel, status bar item, configuration service, HTTP security-engine service, diagnostics controller and providers, dashboard panel controller, command registry, settings listeners, and sidebar launcher provider. Deactivation records the transition; VS Code disposes the registered subscriptions, including the single command registry that owns all 27 registrations and the diagnostics feature. No Python process is started by the extension. Activation performs a non-blocking backend health check that sends no source code.

`bugdhor.openSecurityDashboard` calls the injected `DashboardPanelController`, which creates or reveals a singleton editor-area panel titled **Bug Dhor Security Dashboard**. The dashboard is empty by default: unknown counts are `null` and result lists are empty. The **Load demo preview** action requests a separately labeled state with 18 illustrative findings and matching severity/CWE totals; it intentionally leaves SAE features, interactions, steering, explanations, repairs, recommendations, feedback lifecycle, verification checks, and reports empty. Dashboard action buttons may execute only the nine engine-backed commands in the controller's allowlist, with no arguments; commands that fail produce an error notice, never a success notice. The webview cannot write source files; patch buttons only post a message, and the extension host applies a change solely after explicit approval, base-hash revalidation, target-path validation, and a successful `WorkspaceEdit`.

The dashboard shell is server-rendered and the client renders dynamic content with DOM text APIs. It uses a per-render nonce, `default-src 'none'`, no network or inline executable code, local resource roots, and escaped embedded JSON. Inbound webview messages are validated; unknown messages are ignored. The Activity Bar launcher has the same CSP discipline and can only send `openDashboard`.

Successful file, selection, and workspace scans pass the backend result to `DiagnosticController.publishScanResult`. The controller validates the result, rejects malformed findings and paths outside the workspace, publishes a `DiagnosticCollection` for the Problems panel, and stores normalized findings for hover and Quick Fix providers. File and selection scans replace diagnostics for the scanned document; workspace scans clear files named by the backend `scope.uris`. A failed or cancelled scan never changes diagnostics. Hover shows backend explanation, evidence, sources, risk assessment, and repair state. A repair Quick Fix appears only when the backend sets `repair.eligible` to `true` and invokes `bugdhor.repairVulnerability` with validated finding context; the extension does not edit source. Real detector findings are published when produced; `analysisAvailable: false` is shown as unavailable analysis, not as a clean scan.

Engine-backed commands validate the editor and workspace before calling the injected `SecurityEngineService`. Validation failures and service failures are logged and shown as error messages with a **Show Logs** action; cancelled commands are logged without an error dialog. Commands show a cancellable progress notification but never a success notification. The HTTP service uses the configured backend origin, applies request and health timeouts, and validates every response. File and selection requests include `sourceText`/`selectedText` only when `bugdhor.privacy.sendSourceText` is enabled; disabling it sends paths and ranges so the backend reads the saved file from disk. Workspace scans send folder metadata only. Transport failures report `E_BACKEND_UNAVAILABLE`, timeouts report `E_REQUEST_TIMEOUT`, cancellation is silent, and malformed responses are rejected without publishing diagnostics.

Use the **Run Bug Dhor Extension** launch configuration in `.vscode/launch.json` to start an Extension Development Host with `vscode-extension/` as the development path. The equivalent automated check is:

```bash
npm run extension:test:integration
```

This uses a locally installed VS Code when found (`BUGDHOR_VSCODE_EXECUTABLE` overrides it), otherwise it downloads stable VS Code into the gitignored `.vscode-test/` directory. The runner creates a disposable workspace, starts the Python backend on a free loopback port with `BUGDHOR_WORKSPACE_ROOTS` limited to that workspace, waits for `/api/v1/health`, and passes the backend URL to the Extension Host. The suite activates the extension, sets the workspace-scoped backend URL, verifies health and unreachable-backend handling, scans an unsaved editor buffer and checks that the returned SHA-256 matches the buffer rather than the saved file, disables source sharing and verifies the backend falls back to the disk copy, scans the workspace and a selection, verifies that unavailable analysis publishes no diagnostics, opens the dashboard, and verifies that a second invocation reuses the same tab. The backend is terminated and the temporary workspace removed afterwards. The workspace path deliberately contains spaces and non-ASCII characters, and the suite scans both Python and JavaScript files. A separate `npm run test:integration:vsix` installs the packaged VSIX into an isolated extensions directory and repeats activation, backend, and webview checks against the installed artifact.

The launch configuration itself was not clicked on this host, but the same development-extension path was loaded by the Extension Host integration test.

## 10. Build and packaging

```bash
npm run build
```

Outputs:

- Python wheel: `security-engine/dist/bugdhor_engine-0.1.0-py3-none-any.whl`
- VSIX: `vscode-extension/bug-dhor-0.1.0.vsix`

The VSIX is built by `scripts/packageVsix.js` from a clean staging copy containing only extension sources, media, `CHANGELOG.md`, and the declared production dependency closure. This workspace-aware staging avoids `--no-dependencies` and includes `ajv` with its runtime dependencies. A current build contains 236 entries, 472.35 KB as reported by `vsce`, and 483,685 bytes on disk. An existing `LICENSE`, `LICENSE.md`, or `LICENSE.txt` is staged automatically if added later. Today `vsce` still reports `WARNING LICENSE, LICENSE.md, or LICENSE.txt not found`; no license warning is suppressed and no bypass flag is used.

The development dependency is `@vscode/vsce` 4.1.1, which requires Node.js 22 or newer and supports `publish --oidc`. The manual-only release workflow is documented in [`PHASE_07_PUBLISHING_SETUP.md`](../reports/PHASE_07_PUBLISHING_SETUP.md). Do not publish until the Phase 04 gates, license, and publisher-identity decisions are resolved.

## 11. Verification record

Verified on macOS 26.3.1 arm64; environment verification on 2026-11-10, command-layer, dashboard, and diagnostics verification on 2026-11-12, and source-preprocessing, program-analysis, and taint verification on 2026-11-13/14:

| Check                                                         | Result                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run setup -- --python python3.11 --cpu --with-analyzers` | Succeeded; reused/created `.venv`; no model downloads                                                                                                                                                                                                                                  |
| `npm run structure:check`                                     | 50 required directories and 161 required files present; no TypeScript sources                                                                                                                                                                                                          |
| `npm run doctor`                                              | Python 3.11.14; Node 25.9.0; npm 11.13.0; all declared Python packages present; Semgrep 1.185.0; Bandit 1.9.4; Docker 29.2.1                                                                                                                                                           |
| CPU-only PyTorch                                              | `torch 2.15.0`, `torch.version.cuda is None`                                                                                                                                                                                                                                           |
| Tree-sitter grammars                                          | Python, JavaScript, TypeScript, and TSX grammars exercised by parsing tests; all 13 requested languages are detectable, but only those three language families are parsed and only Python/JavaScript have CFG/DFG/taint                                                                |
| `npm run lint`                                                | Root Ruff gate fails on the pre-existing repository baseline; extension ESLint is clean                                                                                                                                                                                                |
| `npm run format:check`                                        | Fails on a pre-existing baseline: 55 files would be reformatted, 184 already formatted; no file changed by this work appears in the reformat list                                                                                                                                      |
| `npm test`                                                    | Earlier aggregate run: 806 pytest tests passed from the repository root (engine + mathematical regressions), engine-only run passed 717 tests, and 325 Node unit tests passed. The Phase 06 recheck ran 411 extension unit tests with 0 failures; the aggregate command was not rerun. |
| Language and parsing unit tests                               | Coverage for 13-language detection, installed-parser capability reporting, TSX grammar selection, explicit `no_installed_parser` skips, BOM/CRLF source maps, UTF-16 positions, tokenization, function extraction, chunking, syntax diagnostics, and repository metadata               |
| Program-analysis unit tests                                   | 62 tests passed over Python/JavaScript basic blocks, branches, loops, exceptions, functions, exact locations, reaching definitions, calls, returns, closures, unresolved uses, graph invariants, determinism, and positive/negative taint flows for five vulnerability classes         |
| Detection unit tests                                          | 70 engine/fusion/contract/analysis tests, 81 contract and shared-schema tests, 32 opt-in general-bug rule tests, and 13 health/pipeline tests passed                                                                                                                                   |
| Static-adapter tests                                          | 32 tests passed over subprocess safety, timeouts, output capture, Semgrep/Bandit/SARIF/Joern parsing, CWE normalization, deduplication, missing/failed/unavailable statuses, CodeQL license/config gates, Joern version gates, and mocked end-to-end integrations                      |
| `npm run extension:test:integration`                          | Extension Host activated the extension; all 13 commands, Activity Bar container, sidebar view, settings, empty diagnostics at activation, dashboard tab, and dashboard singleton behavior verified; VS Code 1.143.1                                                                    |
| Dashboard runtime smoke test                                  | Headless Chrome rendered the empty and demo states across all 11 sections with no console or CSP errors; manual check, not part of `npm run check`                                                                                                                                     |
| `npm run check`                                               | Fails on the pre-existing root lint/format baseline; extension lint, backend 717/806 tests, and extension 325 tests pass                                                                                                                                                               |
| `npm run build`                                               | Python wheel built; VSIX packaged through clean staging (236 entries, 483,685 bytes in the current build)                                                                                                                                                                              |
| `npm audit --omit=dev`                                        | 0 production vulnerabilities                                                                                                                                                                                                                                                           |
| `npm audit`                                                   | 2 moderate advisories in development tooling only (`@vscode/vsce` / `minimatch`)                                                                                                                                                                                                       |
| Windows wheel availability                                    | Torch CPU `win_amd64`, Semgrep `win_amd64`, and tree-sitter Windows wheels present in metadata; not executed                                                                                                                                                                           |

The `minimatch` advisories affect the `@vscode/vsce` development dependency. They are not shipped in the VSIX because packaging stages only the declared production dependency closure. Revisit them when upstream releases a compatible fixed `@vscode/vsce`; do not force a downgrade to an older toolchain to silence the audit.

## 12. Troubleshooting

**`npm` scripts are blocked in PowerShell.** Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then open a new terminal.

**Python is missing or unsupported.** Run `py -0p` on Windows or `command -v python3.11 python3.12 python3.13 python3.14` on macOS. Set `BUGDHOR_PYTHON` to the executable, or pass `--python <path>` to setup.

**Node is too old.** Run `node --version`. Install Node 24 LTS if the version is below 22.13 or is Node 23.

**`npm run lint` says the virtual environment is missing.** Run `npm run setup` first. The lint and test commands use `.venv`, not the system Python.

**Semgrep is slow or missing from `PATH`.** Setup installs it into `.venv`. Doctor checks the venv binary directly, but your shell may not have it on `PATH`. On macOS use `.venv/bin/semgrep --version`; on Windows use `.\.venv\Scripts\semgrep.exe --version`. The first Semgrep invocation can take longer than later runs.

**Docker is missing.** Setup, lint, and unit tests still work. Execution-based verification is not attempted without an adequate sandbox; verification reports `inconclusive` with explicit limitations and never a pass verdict.

**The VSIX is unexpectedly huge.** Do not run `vsce` directly from `vscode-extension/`: npm workspace hoisting can make it traverse the repository root. Use `npm run package:vsix`, which builds from a clean staging copy and stages only the production dependency closure.

**A model download is requested.** Setup and doctor do not download models. Any later workflow that needs a model must request it explicitly and record the model ID and immutable revision.

## 13. Known limitations

- Windows setup commands were not executed on this macOS host.
- The VS Code **Run Bug Dhor Extension** launch configuration was not clicked manually; an equivalent Extension Host run passed through `@vscode/test-electron`.
- The extension connects to a separately started Python backend over the versioned HTTP API. It does not start or supervise that process. Detection, explanation, proposal-only repair, and bounded verification are wired; SAE extraction, counterfactuals, and steering remain `unavailable`.
- Python, JavaScript, and TypeScript preprocessing is invoked by scan, detection, and explanation stages. The detector can identify 13 languages, but only those three language families have installed parsers, and only Python/JavaScript have implemented CFG/DFG/taint layers. General-bug AST enrichment is opt-in and is not a type checker or linter. `GET /api/v1/health` exposes the full `analysisCapabilities` report.
- Diagnostics, hover explanations, and repair Quick Fixes are generated only from validated backend scan results. Current scans can publish real AST/CFG/DFG/taint-backed findings with a `heuristic_index` risk index; `analysisAvailable: false` remains explicit unavailable analysis, never a clean scan.
- Finding locations and source-reference file links are restricted to open workspace folders. A source reference outside the workspace is shown as text anchored at the finding instead of a clickable location. Symlink targets are not resolved.
- The diagnostics pipeline is exercised against the real backend with detector-produced findings in the Extension Host e2e test, including native diagnostics, hover, and explanation. Windows rendering and interaction behavior were not tested because development runs on macOS.
- The dashboard demo preview is illustrative interface data only. It is not a scan result, and it deliberately omits SAE activations, feature effects, steering results, explanations, repairs, verification checks, and reports.
- Explanation returns evidence-grounded observation claims only for a finding ID matching the current backend detection run. SAE, counterfactual, and steering stages remain `unavailable`. No calibrated probability or causal claim is produced.
- Command behavior is covered by unit tests with fake VS Code objects and by an Extension Host test that invokes engine-backed commands against the real backend. The Extension Host test does not inspect the rendered webview DOM.
- The headless Chrome dashboard smoke test is a manual verification and is not committed as a portable automated test; it does not replace a browser-matrix or assistive-technology audit.
- The FastAPI server, analyzer adapters, detector, explanation engine, repair workflow, and verifier are implemented and covered by backend tests. SAE/counterfactual/steering libraries exist but are unwired HTTP stubs; no production model, SAE artifact, calibration artifact, or adequate sandbox is present.
- Python 3.12–3.14 were not exercised end-to-end.
- Native Semgrep on Windows was not exercised.
- The development VSIX stages `ajv` and its runtime dependency closure, but it does not bundle the Python backend, model artifacts, analyzers, or sandbox.
- The extension icon is a valid 128×128 PNG and the publisher ID is `sajib91`; no Marketplace screenshots are bundled and the publisher account still requires owner verification.
- The repository has public GitHub URLs but no license, so it is not publishable. Phase 04 also records a NO-GO publication decision.
- No model weights, SAE artifacts, datasets, benchmarks, or research results are included.
