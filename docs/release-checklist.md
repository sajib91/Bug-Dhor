# Bug Dhor VS Code Extension Release Checklist

This checklist covers packaging the Bug Dhor VS Code extension as a VSIX. It
does **not** cover Marketplace publication. The current manifest still uses the
placeholder publisher `your-publisher-id` and has no repository URL or license,
so every build is a development artifact until those fields are resolved.

The extension is a client only. It connects to an already-running Python
backend and never starts one. Python backend installation is documented
separately in [the user guide](user-guide.md#5-installation-instructions) and
[development setup](development-setup.md).

## 1. Versioning policy

`vscode-extension/package.json` is the source of truth for the extension
version. The repository root `package.json` should normally use the same
version.

- **Patch** (`0.1.x`): packaging, documentation, test, or bug-fix changes with
  no new user-facing capability.
- **Minor** (`0.x.0`): new user-facing commands, settings, UI, or backend
  contract support.
- **Major** (`x.0.0`): breaking changes to command IDs, settings, storage, or
  backend compatibility.

When changing the version:

1. Update `version` in `vscode-extension/package.json` (and the root
   `package.json` if the monorepo version should match).
2. Update the literal assertion in
   `vscode-extension/test/unit/manifest.test.js`.
3. Update documentation that states the current version or file counts.
4. Never reuse a version that was already published.
5. Rebuild the VSIX and confirm the filename contains the new version.

## 2. Manifest validation

Run from the repository root:

```bash
npm --workspace vscode-extension test
```

Confirm the manifest suite passes, including:

- `name`, `displayName`, `publisher`, `version`, and `engines.vscode`.
- `main` is `./src/extension.js` and the file exists.
- `icon` is `media/icon.png`, a 128×128 PNG.
- `extensionKind` is `workspace`.
- No TypeScript sources are referenced.
- All contributed commands and activation events match the shared constants.

Manually inspect `vscode-extension/package.json` for the `publisher`,
`repository`, `license`, and `version` fields before any publication attempt.

## 3. Commands and activation

The manifest currently contributes 13 commands and activates on
`onStartupFinished`, the 12 `onCommand:` events, and
`onView:bugdhor.sidebar`. There is no `*` activation event.

Check that:

- Every contributed command has a matching `onCommand:` activation event.
- Every command is registered by `src/commands/index.js`; the manifest test
  compares the manifest against `src/commands/definitions.js`.
- No duplicate command ID exists.
- `bugdhor.openSecurityDashboard` can open or reveal the singleton panel.
- `bugdhor.sidebar` is declared under the `bugdhor` activity-bar container.
- The `view/title` menu entry only references a contributed command.

## 4. Webview resources

The dashboard and sidebar load only files from `vscode-extension/media/` through
`webview.asWebviewUri`, with `localResourceRoots: [mediaRoot]`.

Confirm these files exist and are packaged:

- `media/dashboard.css`
- `media/dashboard.js`
- `media/sidebar.css`
- `media/sidebar.js`
- `media/activitybar.svg`
- `media/icon.png`

Both webviews use a per-render nonce and a restrictive Content Security Policy.
Dynamic dashboard content uses DOM text APIs; embedded state is escaped. Do not
add inline scripts, remote URLs, or network access to the webview shell without
updating the CSP and the webview unit tests.

## 5. `.vscodeignore` and package contents

The ignore file excludes development tests, editor state, lockfiles,
placeholders, secrets, local data, logs, datasets, and model weights, while
keeping `package.json`, `README.md`, `media/**`, and `src/**`.

Build a candidate archive and inspect it:

```bash
cd vscode-extension
npm run package:vsix -- --out /tmp/bugdhor-candidate.vsix
unzip -l /tmp/bugdhor-candidate.vsix
```

Confirm the archive does **not** contain:

- `.env`, `.env.*`, or `*.env`
- `.git/`, `.venv/`, `node_modules/`, `.vscode-test/`, or test files
- `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
- `.gitkeep` placeholders
- `*.vsix`, `*.safetensors`, `*.ckpt`, `*.pt`, `*.pth`, `*.onnx`, or datasets
- local databases, logs, or cache directories

The expected current contents are 45 files (VSIX manifest, content types,
`package.json`, `README.md`, six media assets, and `src/**`). The size is about
102 KB. A candidate VSIX must never include another VSIX.

Run `npm run package:list` if you need a verbose list, but note that `vsce ls`
may display parent-workspace files. The packaged archive is authoritative.

## 6. Backend connection configuration

The extension appends `/api/v1` to `bugdhor.backend.url`, which defaults to
`http://127.0.0.1:8765`. The URL must be an HTTP(S) origin with no credentials,
path, query, or fragment.

### 6.1 Local backend installation and startup

Install dependencies once from the repository root, using CPU-only PyTorch for
a development machine:

```bash
npm run setup -- --cpu
```

The `--with-analyzers` flag is optional and only installs analyzer integrations
that this environment may not have. Model weights are never downloaded by setup
and are not bundled in the VSIX. Docker is not required for installation, basic
scanning, or packaging.

Start the backend from `security-engine/`:

```bash
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765
```

Or, if `bugdhor` is installed on `PATH`:

```bash
bugdhor --host 127.0.0.1 --port 8765
```

Set `BUGDHOR_WORKSPACE_ROOTS` to the folders the backend may inspect. Never
point it at a broader path than intended.

Verify the health endpoint:

```bash
curl -sS http://127.0.0.1:8765/api/v1/health
```

Expected: an HTTP 200 JSON response. If the backend requires a bearer token,
send `Authorization: Bearer <token>` and configure the same token for the
extension host.

### 6.2 Optional bearer token

If `BUGDHOR_API_TOKEN` (or the legacy `BUGDHOR_ENGINE_TOKEN`) is set on the
backend, set the same variable in the environment that launches VS Code. The
token is read from the environment, not from a setting, and is not written to
the VSIX. Restart VS Code after changing it. Without a matching token, API
requests return 401.

### 6.3 Optional remote backend

A remote backend is supported when it exposes the same `/api/v1` HTTP API:

1. Run the backend on the remote host and bind it to an address reachable from
   the VS Code machine.
2. Put it behind HTTPS (a reverse proxy is recommended). The extension does not
   manage TLS certificates.
3. Set `BUGDHOR_WORKSPACE_ROOTS` on the remote host to the paths it may inspect.
4. In VS Code, set `bugdhor.backend.url` to the remote origin, for example
   `https://bugdhor.example.internal:8443`. Do not include a path, query, or
   credentials.
5. Set `BUGDHOR_API_TOKEN` in the environment that launches VS Code.
6. Allow the connection through the firewall or VPN. Configure
   `BUGDHOR_CORS_ORIGINS` only if a browser client also calls the API; the
   extension's own fetch does not require CORS.
7. Remember that file paths are resolved on the backend host. A remote backend
   cannot read local files unless the same paths exist there, so enable source
   sharing (`bugdhor.privacy.sendSourceText`) if the backend should analyze the
   current buffer.

Avoid exposing the backend to the public internet. Prefer a private network, a
token, and TLS together.

## 7. Build the release VSIX

From `vscode-extension/`:

```bash
npm run package:vsix
```

This runs:

```bash
vsce package --no-dependencies --allow-missing-repository --skip-license
```

`--no-dependencies` is required because npm workspaces hoist dependencies to
the repository root. The extension has no runtime npm dependency; `ajv` is used
only by tests. Add bundling before importing a runtime dependency.

The default output is `vscode-extension/bug-dhor-<version>.vsix`. Confirm the
file exists, is non-zero, and contains the expected files from section 5.
Record the SHA-256 checksum for the artifact you intend to distribute:

```bash
shasum -a 256 vscode-extension/bug-dhor-0.1.0.vsix
```

## 8. Clean VS Code installation verification

Use a temporary extensions directory so the test does not affect the user's
normal VS Code profile:

```bash
TMP_EXT_DIR="$(mktemp -d)"
CODE_BIN="$(command -v code || true)"
if [ -z "$CODE_BIN" ] && [ -x "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" ]; then
  CODE_BIN="/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
fi
"$CODE_BIN" --extensions-dir "$TMP_EXT_DIR" --install-extension vscode-extension/bug-dhor-0.1.0.vsix
"$CODE_BIN" --extensions-dir "$TMP_EXT_DIR" --list-extensions --show-versions
```

If the `code` CLI is unavailable, install manually through **Extensions →
Views and More Actions → Install from VSIX…** and verify:

- The extension appears as **Bug Dhor Security Framework**.
- The Bug Dhor shield appears in the Activity Bar.
- `Bug Dhor: Open Security Dashboard` opens the singleton panel.
- The dashboard renders with local styles and no CSP errors.
- `Bug Dhor: Show Status` reports the configured backend state and fails
  gracefully when the backend is unreachable.
- With the backend running and healthy, a scan reaches the backend and can render
  real detector-produced findings with `heuristic_index` risk. `analysisAvailable:
  false` is still possible when a stage produces no result; it is reported as
  unavailable analysis, not as a clean scan.
- No finding is fabricated when analysis is unavailable.

A clean installation was verified in the current macOS environment by installing
`bug-dhor-0.1.0.vsix` into a temporary `--extensions-dir` with a temporary
`--user-data-dir`; the result listed as
`your-publisher-id.bug-dhor@0.1.0`. The temporary profile was removed afterward.
Interactive activation checks still need to be repeated in the target VS Code
version and OS.

Remove the temporary directory after verification. Do not reuse a stale VSIX
from a previous build.

## 9. Known release blockers and limitations

- Placeholder publisher `your-publisher-id`; a real Marketplace publisher is
  required before publishing.
- No `repository` URL and no `LICENSE` file. `--allow-missing-repository` and
  `--skip-license` are used only to produce a development VSIX.
- No runtime dependency bundling step. Keep `--no-dependencies` only while the
  runtime remains dependency-free.
- Docker-backed sandbox execution is optional and not assumed. Without a
  sandbox backend, execution is not attempted and verification reports
  `inconclusive` with explicit limitations.
- Semgrep, Bandit, CodeQL, and Joern may be absent; analyzer stages then report
  an explicit unavailable status.
- Model, SAE, and checkpoint artifacts are not bundled and may be absent. Do not
  describe model-backed features as available without the required artifacts.
- No licensed benchmark datasets or experimental runs are included. Do not
  claim empirical results from packaging.
- Backend test suite is green: 638 passed, 0 failed. See the root
  [`release-checklist.md`](../release-checklist.md) §3.2.
- Research-completeness gaps (trained detector, interaction screening, prevention
  loop, localization attribution, end-to-end model/SAE/sandbox evaluation) remain
  open. See [`final-audit.md`](../final-audit.md) and
  [`research-compliance-report.md`](../research-compliance-report.md).

> This document covers extension packaging. The authoritative release decision
> gates are in the root [`release-checklist.md`](../release-checklist.md).

## 10. Release checklist

| Check | Command or action | Status |
|---|---|---|
| Manifest identity, entry point, icon, engine | `npm --workspace vscode-extension test` | Pass (295 tests) |
| Commands and activation events consistent | Unit suite + manifest inspection | Pass |
| Webview assets present and packaged | Archive listing | Pass |
| `.vscodeignore` excludes dev files, secrets, weights | Archive listing | Pass |
| Version updated consistently | `package.json` + manifest test | Pass (0.1.0) |
| Backend unit/API suite | `cd security-engine && ../.venv/bin/python -m pytest -q` | Pass (638 tests) |
| Backend starts locally | `../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765` | Pass (started) |
| Backend health reachable | `curl http://127.0.0.1:8765/api/v1/health` | Pass (HTTP 200) |
| Optional token behavior | Set `BUGDHOR_API_TOKEN` on both sides | Pass (401 without, 200 with) |
| Optional remote backend | Set `bugdhor.backend.url` + token + TLS | Documented; not tested |
| VSIX builds cleanly | `npm run package:vsix` | Pass (45 files, 101.87 KB) |
| Clean VS Code install | Temporary `--extensions-dir` install | Pass (listed `your-publisher-id.bug-dhor@0.1.0`) |
| Interactive activation/UI checks | Launch the installed extension and run a command | Verify per machine |
| Marketplace fields complete | Publisher, repository, license | **Blocked** |
