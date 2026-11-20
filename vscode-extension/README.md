# Bug-Dhor: AI Code Security Analyzer

![Bug-Dhor extension icon](https://raw.githubusercontent.com/sajib91/Bug-Dhor/main/vscode-extension/media/icon.png)

Bug-Dhor is a local-first VS Code extension for security analysis of source code. It connects to a
separately installed Python/FastAPI engine and turns validated backend results into native
diagnostics, hover explanations, and proposal-only repair workflows. It does **not** start or bundle
the backend, and it does not fabricate findings, model activations, risk probabilities, or security
guarantees.

> **Release status:** Version `0.2.0` is prepared as a release candidate. The repository MIT
> license is present, but publication remains blocked by open Phase 04 security findings,
> Marketplace publisher verification, and owner-side Trusted Publishing configuration. The intended
> identifier is `sajib91.bug-dhor`; do not assume the listing is live yet.

## Project overview

The project has two independently deployed parts:

- **VS Code extension** — commands, Activity Bar container, sidebar launcher, Security Dashboard,
  HTTP client, response validation, diagnostics, and privacy controls.
- **Python security engine** — a versioned `/api/v1` HTTP API for health checks, file/workspace
  scanning, program analysis, explanation, verification, and related research routes.

The extension is deliberately an honest client: empty backend state stays empty, `unavailable`
analysis is reported as unavailable, and a clean result means the configured engine returned no
findings — not that the code is secure.

## Key features

- Scan the active saved file, the selected code, the workspace, or a repository inventory through a
  running backend.
- Publish native VS Code diagnostics from validated backend findings, with hover explanations and
  Quick Fixes only for findings marked repair-eligible by the backend.
- Open an 11-section **Bug-Dhor Security Dashboard**. It starts with explicit empty states and merges
  only observed VS Code workspace data, file events, and validated backend responses. No demo or
  sample data is available.
- Opt in to model-independent workspace monitoring with debounced, version-aware, bounded analysis.
  Monitoring is off by default.
- Request evidence-grounded explanations and configured counterfactual evidence. Missing artifacts
  or unavailable stages are shown explicitly.
- Generate secure-code **proposals** through a configured provider with capabilities B and C, then
  submit candidates to the backend for verification. Nothing is applied without explicit approval.
- Use seven opt-in local Phase 6 commands for explanation, deterministic repair preview, apply,
  verify, revert, and history. These require a repository checkout with `src/bugdhor_ast` available;
  they are not bundled in the VSIX.
- Keep credentials in the extension-host environment, not in settings or logs.

## Architecture

```text
VS Code Extension Host
  -> SecurityEngineService (typed HTTP client)
    -> Python/FastAPI backend at bugdhor.backend.url
      -> parsing / program analysis / detection / explanation / verification
```

The manifest declares `extensionKind: ["workspace"]`. In SSH, WSL, and Codespaces, the extension
runs on the **remote** side of the workspace, so the backend must be reachable from that remote
environment. A loopback address on the local client is not sufficient. The backend runs separately
and must already be running; `bugdhor.backend.autoStart` and `bugdhor.backend.pythonPath` are
reserved settings and currently have no effect.

The baseline VS Code API requirement is `^1.90.0`. Production dependencies are staged in the VSIX;
the Python engine and any model, SAE, analyzer, or sandbox artifacts are not.

## Supported languages

Language support is capability-specific and deliberately narrow:

| Capability                                | Evidence-backed scope                                                                                                                                                                               |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend parsing / AST / CFG / DFG / taint | Python and JavaScript are exercised by the backend suites and the Extension Host smoke tests. TypeScript has parsing support only in the engine.                                                    |
| Java                                      | Detected and covered by the opt-in local Phase 6 deterministic repair strategy (`PreparedStatement`). The default backend has no installed Java parser and must not be described as analyzing Java. |
| Background monitoring                     | Python and JavaScript by default (`bugdhor.monitoring.languages`).                                                                                                                                  |
| Repository inventory                      | Files are discovered by extension and Git metadata; unsupported languages are reported as gaps, not analyzed.                                                                                       |

No language support is claimed for SAE feature extraction, counterfactual effects, or activation
steering. Those stages remain unavailable in the default integrated path without compatible
artifacts and direct model access.

## Requirements

- **VS Code:** 1.90 or newer.
- **Python backend:** Python 3.11–3.14; 3.11 is the verified baseline.
- **Backend dependencies:** installed from `security-engine/` (FastAPI, Uvicorn, parsers, and
  related packages). Optional analyzers and model/SAE artifacts are not bundled.
- **Workspace:** a local `file:` workspace folder for file, selection, and repository commands.
- **For building from source:** Node.js 22.13+ or 24+ and npm. Node 23 is not supported by the
  repository toolchain.
- **For remote development:** a backend reachable from the remote environment where the extension
  host runs.

## Installation from Marketplace

After publication, install with either of these methods:

```bash
code --install-extension sajib91.bug-dhor
```

Or open **Extensions**, search for `Bug-Dhor`, and choose the publisher `sajib91`. Verify the
publisher identity before installing. A local VSIX can also be installed for evaluation with
`code --install-extension bug-dhor-0.2.0.vsix`.

Installing the extension alone is not sufficient: continue with the separate backend installation
below.

## Separate Python backend installation

Clone the repository and create a virtual environment. On macOS/Linux:

```bash
git clone https://github.com/sajib91/Bug-Dhor.git
cd Bug-Dhor
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e "./security-engine[dev]"
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".\security-engine[dev]"
```

Omit the `dev` extra for a smaller install. Add `analyzers` or `ml` only when those tools and their
licenses are actually needed; setup does not download model weights. The repository also provides
`npm run setup -- --cpu --with-analyzers` from the root for a managed development setup.

## Backend startup

From `security-engine/` with the virtual environment active:

```bash
# macOS/Linux
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765

# Windows PowerShell
..\.venv\Scripts\python.exe -m bugdhor --host 127.0.0.1 --port 8765
```

Set `BUGDHOR_WORKSPACE_ROOTS` to the folders the backend may inspect. Keep it as narrow as
possible. If bearer authentication is enabled, set `BUGDHOR_API_TOKEN` in the backend environment
and the same value in the environment that launches VS Code; the extension reads the token from the
environment, not from a setting.

Verify connectivity:

```bash
curl -sS http://127.0.0.1:8765/api/v1/health
```

An HTTP 200 response with API version `v1` means the backend is reachable. Do not expose an
unauthenticated backend to a public network. For non-loopback access, use TLS and a token, and
configure the extension with an HTTPS origin.

## VS Code configuration

Open **Settings** and search for `Bug Dhor`. Key settings are:

| Setting                                                    | Default                    | Purpose                                                                                                                  |
| ---------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `bugdhor.backend.url`                                      | `http://127.0.0.1:8765`    | HTTP(S) origin of the running backend. The extension appends `/api/v1`. No credentials, path, query, or fragment.        |
| `bugdhor.backend.requestTimeoutMs`                         | `30000`                    | Timeout for scan and analysis requests.                                                                                  |
| `bugdhor.backend.healthTimeoutMs`                          | `3000`                     | Timeout for health checks.                                                                                               |
| `bugdhor.privacy.sendSourceText`                           | `true`                     | Send the active buffer/selection with explicitly invoked file/selection requests. Disable to send paths and ranges only. |
| `bugdhor.monitoring.enabled`                               | `false`                    | Enable background document monitoring.                                                                                   |
| `bugdhor.monitoring.allowAutomaticSourceSharing`           | `false`                    | Explicit consent for automatic background source sharing; requires `privacy.sendSourceText` too.                         |
| `bugdhor.monitoring.languages`                             | `["python", "javascript"]` | Eligible language IDs for monitoring.                                                                                    |
| `bugdhor.localEngine.enabled`                              | `false`                    | Opt in to the local Phase 6 commands.                                                                                    |
| `bugdhor.localEngine.allowSourceWrite`                     | `false`                    | Permit explicit local apply/revert; still requires a modal and exact `patch_id`.                                         |
| `bugdhor.backend.autoStart` / `bugdhor.backend.pythonPath` | `false` / empty            | Reserved; the extension does not start a backend.                                                                        |

In an SSH/WSL/Codespaces workspace, set the backend URL to an address reachable from the remote
host. `127.0.0.1` on the local machine will not work from the remote extension host.

## Scanning workflow

1. Start the backend and confirm `/api/v1/health`.
2. Open a workspace folder in VS Code and ensure it is inside `BUGDHOR_WORKSPACE_ROOTS`.
3. Run a command from the Command Palette:
   - **Bug Dhor: Scan Current File** — saved `file:` editor required.
   - **Bug Dhor: Scan Selection** — non-empty selection required.
   - **Bug Dhor: Scan Workspace** — sends folder metadata; the backend reads allowlisted files.
   - **Bug Dhor: Scan Full Repository**, **Scan Changed Files**, or **Scan Incremental Findings**.
4. Review validated results in the **Problems** panel and the Security Dashboard.
5. Use **Bug Dhor: Show Status** and **Bug Dhor: Show Logs** to inspect connectivity and errors.

A result with `analysisAvailable: false`, `partial`, or `unavailable` is not a clean scan. Cancelled
or failed requests do not alter existing diagnostics.

## Security analysis workflow

- Hover a diagnostic to see its backend message, severity, CWE, rule ID, explanation, evidence,
  source references, and repair eligibility. Missing fields are labeled rather than invented.
- Run **Bug Dhor: Explain Vulnerability** for evidence-grounded context when the backend supplies
  it. Explanations distinguish observed, derived, heuristic, and unavailable evidence.
- Run **Bug Dhor: Analyze Security Features** only when a compatible model and SAE artifact are
  configured. In the default integrated path this returns an explicit unavailable result.
- Static tools such as Semgrep and Bandit are optional. Missing tools are reported as unavailable,
  not as a clean result.

Bug-Dhor does not claim calibrated probabilities, causal security effects, exploitability proofs,
or a security guarantee from these workflows.

## Counterfactual analysis

**Bug Dhor: Counterfactual Analysis** compares a selected code region with counterfactual variants
when the backend supplies measured evidence. The dashboard can render supplied `baselineRisk`,
single/pairwise/higher-order effects, activation changes, CWE results, and provenance. It never
derives effects or probabilities from missing values, and it labels absent evidence as
**Unavailable evidence**.

The counterfactual libraries exist for configured research runs, but the default HTTP path reports
the stage as unavailable without the required model, SAE, and intervention artifacts. Do not treat
the command as a universally available feature.

## Repair and verification

- A **Quick Fix** appears only when a backend finding has `repair.eligible: true`. It invokes
  **Bug Dhor: Repair Vulnerability** with validated finding context.
- **Bug Dhor: Generate Secure Code** asks the backend for a prompt, calls a configured provider with
  capabilities B and C, and submits candidates back to the backend for syntax, security, functional,
  and contract checks. The result is an unapplied, reviewed proposal.
- **Bug Dhor: Verify Repair** runs backend verification at workspace scope. Verification is limited
  by the configured analyzers and tests; `inconclusive` is an explicit outcome.
- The seven **Local Engine** commands are opt-in and require `bugdhor.localEngine.enabled`. Apply and
  revert additionally require `allowSourceWrite`, a modal warning, and the exact `patch_id`.
  The local CLI runs without a shell and never executes generated source.

Local deterministic strategies cover Python SQL parameterization and process argument lists,
JavaScript HTML-to-`textContent`, and Java `PreparedStatement`. Static reanalysis verified the
measured JavaScript and Java forms; the Python forms remained flagged by the current syntax-only
taint engine. There is no functional, dynamic, sandbox, exploitability, or security guarantee.

## AI provider configuration

Provider capabilities are discovered; they are never assumed. Configure one of these under
`bugdhor.assistant.*`:

| Provider setting        | Use                                                                                                                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `editor`                | Document only the documented editor change events (capability A).                                                                           |
| `vscode-language-model` | Discover a model through the documented VS Code Language Model API; optional `vendor`, `family`, `id`, or `version` selector.               |
| `openai-compatible`     | Set `endpoint` and `model`; store the key in the environment variable named by `apiKeyEnvironmentVariable` (default `BUGDHOR_LLM_API_KEY`). |
| `local-hugging-face`    | Provide an absolute `modelPath` with `config.json`. Reading metadata does not grant activation or steering access.                          |
| `extension-api`         | Provide an explicit local manifest describing an official extension API and declared capabilities.                                          |

Hosted assistants expose A/B/C only. Validated local D/E/F access with a real pipeline would be
required for steering; API requests report the steering pipeline as `None`. Keys are never written
to settings, logs, or request bodies.

## Privacy controls

- The extension contains no built-in telemetry, analytics, crash reporting, or advertising SDK.
- Health checks send no source code. Workspace scans send folder name, path, and URI metadata only;
  the backend reads allowlisted files from disk.
- Explicit file and selection commands send the active buffer/selection only when
  `bugdhor.privacy.sendSourceText` is enabled. Disabling it sends paths and ranges instead.
- Background monitoring is off by default. It sends source text only when both
  `bugdhor.monitoring.enabled` and `bugdhor.monitoring.allowAutomaticSourceSharing` are enabled,
  together with `privacy.sendSourceText`.
- `BUGDHOR_API_TOKEN` and provider keys are read from the environment and are never stored in
  settings or logs.
- The opt-in local Phase 6 session defaults to `.bugdhor/phase6-session.json`, is written with
  owner-only permissions, and is never sent to the backend.

Treat backend result directories as potentially sensitive because the backend may persist analysis
metadata under its configured data directory.

## Troubleshooting

| Symptom                      | Check                                                                                                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `E_BACKEND_UNAVAILABLE`      | Backend running, correct `bugdhor.backend.url`, port 8765 reachable from the extension host.                                                              |
| `401` from `/api/v1`         | `BUGDHOR_API_TOKEN` must match in the backend and VS Code host environment; restart VS Code after changing it.                                            |
| Timeouts                     | Increase `bugdhor.backend.requestTimeoutMs` or reduce the scan scope.                                                                                     |
| `analysisAvailable: false`   | Required analyzer/model/parser is missing. This is not a clean scan.                                                                                      |
| No findings                  | Confirm the workspace is inside `BUGDHOR_WORKSPACE_ROOTS` and the file language is parsed. A Java file is detected but not parsed by the default backend. |
| Monitoring does nothing      | `bugdhor.monitoring.enabled` must be true; eligible language and file size must pass filters. Source sharing needs both consent settings.                 |
| Remote workspace cannot scan | The backend must be reachable from the remote extension host; check `extensionKind: ["workspace"]`.                                                       |
| Local Phase 6 command fails  | `bugdhor.localEngine.enabled` must be true, Python must expose `bugdhor_ast`, and the workspace must contain `src/bugdhor_ast`.                           |

Run **Bug Dhor: Show Status** and **Bug Dhor: Show Logs** for concrete transport and validation
errors.

## Known limitations

- The Python backend is not bundled and must be installed and started separately.
- SAE feature extraction, counterfactual effects, and activation steering are unavailable in the
  default integrated path without compatible artifacts and model access.
- Java is detected but has no installed default parser; do not expect backend AST/taint findings for
  Java.
- Repairs are proposals. Static reanalysis is not a functional, dynamic, or security proof; some
  Python local repairs remain flagged by the current taint engine.
- Windows and Linux runtime behavior is unverified locally and remains pending the three-OS CI
  matrix. macOS is verified only on the tested configuration.
- The extension is not bundled into a single JavaScript file; `vsce` reports a startup-performance
  advisory for the staged dependency files.
- No Marketplace screenshots are bundled yet.
- The repository MIT license is present, but publication remains blocked by the open Phase 04
  security findings, publisher-identity verification, and owner-side Trusted Publishing setup.

## Screenshots

No verified screenshots are available in the repository at this time, so none are included. This
section is intentionally left without image links rather than showing illustrative or synthetic
application output.

## License

This extension and the repository are distributed under the [MIT License](../LICENSE). Packaging
copies the repository license into the VSIX and does not use `--skip-license` or any equivalent
bypass.

## GitHub repository

- Repository: https://github.com/sajib91/Bug-Dhor
- Issues: https://github.com/sajib91/Bug-Dhor/issues
- Documentation: https://github.com/sajib91/Bug-Dhor/tree/main/docs
- Reports: https://github.com/sajib91/Bug-Dhor/tree/main/reports
