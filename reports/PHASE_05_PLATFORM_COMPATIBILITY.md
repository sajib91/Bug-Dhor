# BUG-DHOR — PHASE 05 PLATFORM COMPATIBILITY

Date: 2026-11-19

## 1. Objective and outcome

Verify Bug-Dhor on macOS, Windows, and Linux using the existing `@vscode/test-electron`
infrastructure, define a three-OS GitHub Actions matrix with separate Lint, Unit, Extension
integration, and Package validation jobs, and record only results that were actually observed.

**Outcome:** macOS is verified locally on the tested configuration. Windows and Linux are
**not verified** because no Windows or Linux runtime was available locally and the new CI workflow
has not yet produced a run. No support claim is made for Windows or Linux in this report.

Publication remains blocked by the Phase 04 release gates and publisher-identity verification. The
missing-license warning described below is stale: a root MIT `LICENSE` now exists. This phase did
not publish, commit, or push anything.

## 2. Verified environment

| Item                  | Value                                                   |
| --------------------- | ------------------------------------------------------- |
| Host OS               | macOS 26.3.1 (25D2128), arm64                           |
| Node.js               | v25.9.0                                                 |
| npm                   | 11.13.0                                                 |
| Python                | 3.11.14 (`.venv/bin/python`)                            |
| VS Code               | 1.146.0 (`/Applications/Visual Studio Code.app`)        |
| Integration runner    | `@vscode/test-electron` using the local VS Code install |
| Linux display support | `xvfb-run -a` configured in CI, not exercised locally   |

## 3. Platform status

| Platform                            | Local verification                                                             | CI job                                               | Support claim                                  |
| ----------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------- | ---------------------------------------------- |
| macOS 26.3.1 arm64, VS Code 1.146.0 | PASS: lint, 409 unit tests, Extension Host integration, VSIX build, VSIX smoke | `macos-latest` in all four jobs                      | **Verified on this tested configuration only** |
| Windows                             | Not runnable in this environment                                               | `windows-latest` in all four jobs                    | **Unverified** until CI passes                 |
| Linux                               | Not runnable in this environment                                               | `ubuntu-latest` in all four jobs, with `xvfb-run -a` | **Unverified** until CI passes                 |

The workflow file exists, but no GitHub Actions run result is available at the time of this report.
The matrix is therefore evidence of planned coverage, not evidence that Windows or Linux pass.

## 4. Task-by-task evidence

| #   | Task                                              | Status                                                          | Evidence                                                                                                                                                                                                                                                                                                                                  |
| --- | ------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | OS-specific dependencies and path handling        | Verified by inspection + tests on macOS                         | `repositoryInventory.js` rejects `/`, `\`, and NUL in entry names; `gitignore.js` converts `\` to `/`; `changeAnalyzer.isPathExcluded()` normalizes both separators; `patchApplication.normalizePatchPath()` normalizes Windows separators and rejects traversal; `gitChangedFiles.js` uses fixed `execFile` argv and normalizes to `/`.  |
| 2   | Python executable discovery                       | PASS on macOS; matrix-tested logic in unit tests                | New side-effect-free `test/integration/pythonDiscovery.js` resolves explicit `BUGDHOR_PYTHON`, then `.venv/Scripts/python.exe` on Windows or `.venv/bin/python` on POSIX, then `python` on Windows and `python3` on macOS/Linux. `runTest.js` now uses it. Unit tests exercise all three platforms from any host.                         |
| 3   | Virtual environment activation instructions       | Verified by inspection                                          | `docs/user-guide.md:108-115` documents `source .venv/bin/activate` and `.\.venv\Scripts\Activate.ps1`. `docs/development-setup.md` was updated to remove stale `--no-dependencies`, 50-file, and missing-`ajv` packaging claims.                                                                                                          |
| 4   | Local backend connectivity                        | PASS on macOS                                                   | Both Extension Host suites spawn the engine on a free loopback port, wait for `/api/v1/health`, run scans, and stop with `SIGTERM`/`SIGKILL` fallback. The original suite also verifies that `http://127.0.0.1:1` is reported as unavailable rather than as a clean analysis.                                                             |
| 5   | Extension installation from VSIX                  | PASS on macOS                                                   | `test:integration:vsix` installs the built VSIX with the VS Code CLI into an isolated extensions directory, verifies the installed manifest, then runs the installed extension in an Extension Host. Output: `Extension 'bug-dhor-0.1.0.vsix' was successfully installed.`                                                                |
| 6   | Activity Bar and webview rendering                | PASS on macOS                                                   | Both suites assert the Activity Bar container, sidebar webview contribution, and that `bugdhor.openSecurityDashboard` opens the dashboard tab. The VSIX smoke suite performs this against the installed artifact.                                                                                                                         |
| 7   | Python and JavaScript scanning                    | PASS on macOS                                                   | The existing suite scans Python files and the vulnerable Python fixture. A new final-step JavaScript scan opens `javascript scan — café.js`, scans it through the loopback backend, and verifies operation, API version, analysis availability, no fabricated findings, path, and SHA-256.                                                |
| 8   | Unicode paths and filenames                       | PASS on macOS                                                   | The real workspace is `workspace with spaces — ünïcøde 🚀`; scanned files include `café — 日本語.py` and `javascript scan — café.js`. Unit test also inventories `src with spaces — 日本語/café — 日本語.py` from a real temp filesystem.                                                                                                 |
| 9   | Spaces in directory names                         | PASS on macOS                                                   | The same workspace path contains spaces and is passed to VS Code and the backend as a real path, including in the VSIX smoke test.                                                                                                                                                                                                        |
| 10  | Windows path separators                           | Logic verified on macOS; native Windows pending CI              | New unit tests verify backslash normalization in exclude globs, `.gitignore` patterns, and repair patch paths; they also verify that an entry named `..\escape.py` is rejected as `invalid-entry-name` before traversal.                                                                                                                  |
| 11  | Permission errors                                 | PASS as simulated unit case                                     | A fake `readDirectory` throwing `EACCES` produces `RepositoryInventoryError` with `code === 'E_FILESYSTEM'` and the original cause preserved. Native OS permission semantics are not claimed.                                                                                                                                             |
| 12  | Large repositories                                | PASS via bounded unit case                                      | A 2,500-entry in-memory repository with `maxFiles: 50` yields exactly 50 included files, `filesVisited: 51`, and `truncated: true`.                                                                                                                                                                                                       |
| 13  | Extension startup and shutdown                    | PASS on macOS                                                   | Both suites report `Exit code: 0`; backend processes are terminated and temporary workspace/user-data/extensions directories are removed in `finally` blocks.                                                                                                                                                                             |
| 14  | Backend connectivity in the actual Extension Host | PASS on macOS                                                   | The Extension Host tests set `backend.url`, call `api.checkBackendHealth()`, compare direct `api.service.health({})` results, and execute real scan commands. The VSIX smoke suite repeats these checks against the installed extension.                                                                                                  |
| 15  | `extensionKind: ["workspace"]` remote limitations | Verified by manifest inspection; remote environments not tested | The extension runs on the remote side for SSH, WSL, and Codespaces. The loopback backend must therefore be reachable from the remote environment; `127.0.0.1` on the local client is not sufficient. `bugdhor.backend.pythonPath` is reserved and unused, and `bugdhor.backend.autoStart` is false, so a backend must already be running. |

## 5. CI workflow

Created `.github/workflows/extension-tests.yml` with four separate jobs:

| Job                   | Matrix                                                | Command / purpose                                                                        |
| --------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Lint                  | macOS, Windows, Ubuntu                                | `npm --workspace vscode-extension run lint`                                              |
| Unit tests            | macOS, Windows, Ubuntu                                | `npm --workspace vscode-extension test`                                                  |
| Package validation    | macOS, Windows, Ubuntu                                | `package:list`, `package:vsix`, ZIP content assertions, size bound, artifact upload      |
| Extension integration | macOS, Windows, Ubuntu; depends on Package validation | Extension Host integration, then VSIX installation smoke against the downloaded artifact |

Additional CI details:

- Node.js 22.13.0 and Python 3.11 are installed with official GitHub Actions setup steps.
- The Python environment is static-only (`pip install -e ".[dev]"`) so CI does not download ML models.
- `BUGDHOR_PYTHON` points the harness at the per-OS virtual-environment interpreter.
- `@vscode/test-electron` prefers a local VS Code when present and downloads stable VS Code into
  `.vscode-test/` otherwise.
- Ubuntu runs both Extension Host suites under `xvfb-run -a`; only that job installs `xvfb`.
- VSIX artifacts are named `vsix-macos`, `vsix-windows`, and `vsix-ubuntu`.
- There is no publish job and no `vsce publish` step.

## 6. Local verification record

All commands below were run from the repository root unless shown otherwise.

| Command                                                      | Result                                                                                                                |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `npm --workspace vscode-extension run lint`                  | Clean; no ESLint output                                                                                               |
| `npm --workspace vscode-extension test`                      | 409 tests, 409 pass, 0 fail                                                                                           |
| `npm --workspace vscode-extension run test:integration`      | Exit 0; `Bug Dhor backend ready (version 0.1.0, API v1).`; `Bug Dhor Extension Host checks passed.`; `Exit code:   0` |
| `npm --workspace vscode-extension run package:list`          | Exit 0; clean staged file tree                                                                                        |
| `npm --workspace vscode-extension run package:vsix`          | 245 files, 478.85 KB reported by `vsce`, 490,339 bytes on disk                                                        |
| `npm --workspace vscode-extension run test:integration:vsix` | Exit 0; VSIX installed; `Bug Dhor VSIX smoke checks passed.`; `Exit code:   0`                                        |
| `python -m zipfile -l` on the VSIX                           | 245 entries, 0 `extension/test/` entries, 0 parent-path entries, `ajv` present                                        |
| YAML parse of workflow                                       | Four jobs found: `lint`, `unit`, `package`, `integration`                                                             |
| Prettier check of newly created files and workflow           | All matched files use Prettier style                                                                                  |
| `git diff --check`                                           | Clean, exit 0                                                                                                         |

VSIX SHA-256 for this local build:

```text
9aab02598bbc2e9cd6d8b577cc2ffe9426edcad1286eaeb072c93dcc317910f7
```

The build still emits `WARNING LICENSE, LICENSE.md, or LICENSE.txt not found`. No `--skip-license`,
`--no-dependencies`, or similar bypass flag is used. `vsce` output is not byte-deterministic, so a
future build may have a different SHA-256 while containing the same sorted entry list.

## 7. Files added or changed for this phase

Added:

- `.github/workflows/extension-tests.yml`
- `reports/PHASE_05_PLATFORM_COMPATIBILITY.md`
- `vscode-extension/test/integration/pythonDiscovery.js`
- `vscode-extension/test/integration/runVsixTest.js`
- `vscode-extension/test/integration/vsixSmoke.js`
- `vscode-extension/test/integration/vsix-host/package.json`
- `vscode-extension/test/integration/vsix-host/extension.js`
- `vscode-extension/test/unit/platformCompatibility.test.js`

Updated:

- `vscode-extension/test/integration/runTest.js` — uses the shared Python resolver and a Unicode/space workspace path
- `vscode-extension/test/integration/index.js` — Unicode-aware workspace folder name and JavaScript scan
- `vscode-extension/package.json` — `test:integration:vsix` script
- `docs/development-setup.md` — accurate packaging description and VSIX smoke command
- `docs/user-guide.md`, `docs/release-checklist.md` — removed stale `--no-dependencies` / `--skip-license` packaging guidance

## 8. Unverified items and release gates

- Windows and Linux runtime behavior is unverified locally and remains pending CI.
- The GitHub Actions matrix has not yet run, so no CI result is claimed.
- SSH, WSL, and Codespaces remote topologies were not executed; only manifest-level limitations were checked.
- Native `EACCES` behavior and native Windows separator behavior are covered by portable unit cases, not by OS-specific integration runs.
- `bugdhor.localEngine.pythonPath` defaults to `python`, which may be absent on macOS/Linux; the integration harness avoids this by resolving `python3` or the repository virtual environment.
- Phase 04 remains **NO-GO** with 2 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW, and 3 INFORMATIONAL findings.
- Missing license, publisher-identity verification, and the Phase 04 CRITICAL/HIGH findings still block publication.
- Python dependency CVE scanning remains incomplete because the required scanners were unavailable in the Phase 04 environment.

No platform other than the explicitly tested macOS configuration is claimed as supported.
