# Bug Dhor VS Code Extension Release Checklist

This checklist covers packaging the Bug Dhor VS Code extension as a VSIX. It
does **not** publish to the Marketplace. The manifest uses the approved
publisher `sajib91`, extension ID `bug-dhor`, version `0.1.0`, public GitHub
repository URLs, and the repository MIT license. Every build remains a release
candidate until the Phase 04 security gates, publisher verification, and
owner-side Trusted Publishing setup are resolved.

The extension is a client only. It connects to an already-running Python
backend and never starts one. Python backend installation is documented
separately in [the user guide](user-guide.md#5-installation-instructions),
[development setup](development-setup.md), and the Marketplace-facing
[extension README](../vscode-extension/README.md). Marketplace preparation is
tracked in [Phase 06](../reports/PHASE_06_MARKETPLACE_READINESS.md) and OIDC
publishing setup in [Phase 07](../reports/PHASE_07_PUBLISHING_SETUP.md).

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

The manifest currently contributes 27 commands and activates on
`onStartupFinished`, the corresponding `onCommand:` events, and
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
keeping `package.json`, `README.md`, `CHANGELOG.md`, `media/**`, and `src/**`.
It also copies the repository `LICENSE` (MIT) into the staging copy; no license
is invented or suppressed.

Build a candidate archive and inspect it:

```bash
npm --workspace vscode-extension run package:vsix
python -m zipfile -l vscode-extension/bug-dhor-0.1.0.vsix
```

Confirm the archive does **not** contain:

- `.env`, `.env.*`, or `*.env`
- `.git/`, `.venv/`, `.vscode-test/`, `test/`, or development dependencies such as
  `node_modules/@vscode/`
- `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
- `.gitkeep` or `.DS_Store` placeholders
- `*.vsix`, `*.safetensors`, `*.ckpt`, `*.pt`, `*.pth`, `*.onnx`, or datasets
- local databases, logs, or cache directories

The staged production dependency closure (`ajv` and its runtime dependencies)
**is** expected under `node_modules/`. The current build has 237 entries and
484,799 bytes, including the lowercase `changelog.md` and `readme.md` entries
that `vsce` writes into the archive and the repository MIT license. A candidate
VSIX must never include another VSIX.

Run `npm --workspace vscode-extension run package:list` for a verbose staged
tree. The `packageVsix.js` wrapper stages the copy outside the npm workspace, so
it does not display parent-repository files.

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

This calls `scripts/packageVsix.js`, which copies only extension sources, media,
and the declared production dependency closure into a temporary directory and
runs `vsce` there. Do not run `vsce` directly from `vscode-extension/`: npm
workspace hoisting can make it traverse the repository root. The staged archive
includes `ajv` and its runtime dependencies plus the repository MIT license.
No `--skip-license`, `--no-dependencies`, or equivalent bypass flag is used.

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
`--user-data-dir`; the result listed as `sajib91.bug-dhor@0.1.0`. The temporary
profile was removed afterward. Interactive activation checks still need to be
repeated in the target VS Code version and OS.

Remove the temporary directory after verification. Do not reuse a stale VSIX
from a previous build.

## 9. Known release blockers and limitations

- Phase 04 records a **NO-GO for publication** decision with 2 CRITICAL and 4
  HIGH findings still open. Packaging and documentation work does not clear
  those security gates. See [`PHASE_04_SECURITY_AUDIT.md`](../reports/PHASE_04_SECURITY_AUDIT.md).
- Publisher identity is declared as `sajib91` but has not been verified against
  the Marketplace account intended for publication.
- The MIT `LICENSE` file and manifest `license` field are present. Publication
  is still blocked by the Phase 04 security findings, publisher verification,
  and Trusted Publishing setup.
- Runtime dependencies are staged from the declared production closure rather
  than bundled into a single file. A bundling step is still recommended for
  extension startup performance.
- Docker-backed sandbox execution is optional and not assumed. Without a
  sandbox backend, execution is not attempted and verification reports
  `inconclusive` with explicit limitations.
- Semgrep, Bandit, CodeQL, and Joern may be absent; analyzer stages then report
  an explicit unavailable status.
- Model, SAE, and checkpoint artifacts are not bundled and may be absent. Do not
  describe model-backed features as available without the required artifacts.
- No licensed benchmark datasets or experimental runs are included. Do not
  claim empirical results from packaging.
- A prior backend test run recorded 638 passed and 0 failed; that result was not
  repeated during the Phase 06 documentation and packaging update. See the root
  [`release-checklist.md`](../release-checklist.md) §3.2.
- Research-completeness gaps (trained detector, interaction screening, prevention
  loop, localization attribution, end-to-end model/SAE/sandbox evaluation) remain
  open. See [`final-audit.md`](../final-audit.md) and
  [`research-compliance-report.md`](../research-compliance-report.md).

> This document covers extension packaging. The authoritative release decision
> gates are in the root [`release-checklist.md`](../release-checklist.md).

## 10. Release checklist

| Check                                                | Command or action                                                     | Status                                             |
| ---------------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------- |
| Manifest identity, entry point, icon, engine         | `npm --workspace vscode-extension test`                               | Pass (411 tests, 0 failed)                         |
| Marketplace metadata and HTTPS README images         | Manifest + README unit assertions                                     | Pass                                               |
| Commands and activation events consistent            | Unit suite + manifest inspection                                      | Pass (27 commands)                                 |
| Webview assets present and packaged                  | Archive listing                                                       | Pass                                               |
| `.vscodeignore` excludes dev files, secrets, weights | Archive listing                                                       | Pass                                               |
| Version updated consistently                         | `package.json` + manifest test                                        | Pass (0.1.0)                                       |
| Backend unit/API suite                               | `cd security-engine && ../.venv/bin/python -m pytest -q`              | Prior run: 638 pass; rerun required                |
| Backend starts locally                               | `../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765`         | Pass (started in prior verification)               |
| Backend health reachable                             | `curl http://127.0.0.1:8765/api/v1/health`                            | Pass (HTTP 200 in prior verification)              |
| Optional token behavior                              | Set `BUGDHOR_API_TOKEN` on both sides                                 | Pass (401 without, 200 with in prior verification) |
| Optional remote backend                              | Set `bugdhor.backend.url` + token + TLS                               | Documented; not tested                             |
| Extension Host integration                           | `npm --workspace vscode-extension run test:integration`               | Pass                                               |
| Installed VSIX smoke test                            | `npm --workspace vscode-extension run test:integration:vsix`          | Pass                                               |
| VSIX builds cleanly                                  | `npm --workspace vscode-extension run package:vsix`                   | Pass (237 entries, 484,799 bytes)                  |
| Clean VS Code install                                | Temporary `--extensions-dir` install                                  | Pass (listed `sajib91.bug-dhor@0.1.0`)             |
| Interactive activation/UI checks                     | Launch the installed extension and run a command                      | Verify per machine                                 |
| Marketplace documentation                            | `vscode-extension/README.md` and `CHANGELOG.md`                       | Pass                                               |
| Marketplace license field                            | MIT `LICENSE` + manifest `license`                                    | Pass                                               |
| Publisher identity                                   | Marketplace account ownership                                         | **Blocked**                                        |
| Phase 04 security gates                              | [`PHASE_04_SECURITY_AUDIT.md`](../reports/PHASE_04_SECURITY_AUDIT.md) | **Fail** (NO-GO)                                   |
| Three-OS CI evidence                                 | [`extension-tests.yml`](../.github/workflows/extension-tests.yml)     | **Blocked** (no run yet)                           |
| OIDC Trusted Publishing policy                       | Marketplace publisher settings                                        | **Blocked** (owner setup required)                 |
| Final release decision                               | All gates above                                                       | **NO-GO — do not publish**                         |

## 11. OIDC Trusted Publishing workflow

The release workflow is `.github/workflows/publish-extension.yml`. It runs only
on `workflow_dispatch`; there is no push, pull-request, release, or scheduled
trigger. Its sole input is the required boolean `confirm_publish`, which
defaults to `false`.

### 11.1 Marketplace Trusted Publishing policy

The repository owner must configure the Marketplace policy manually:

| Field            | Exact value             |
| ---------------- | ----------------------- |
| Repository owner | `sajib91`               |
| Repository       | `Bug-Dhor`              |
| Workflow         | `publish-extension.yml` |
| Environment      | empty / not configured  |

Use the publisher ID `sajib91` in the Marketplace publisher management page.
The GitHub Actions OIDC identity must match those exact values. Do not create a
PAT or other long-lived publishing secret, and do not configure a GitHub
Environment unless the Marketplace policy uses the same exact name.

### 11.2 Validation without publishing

1. Open **Actions → Publish extension (OIDC Trusted Publishing) → Run workflow**
   in `sajib91/Bug-Dhor`.
2. Select the branch to validate.
3. Leave `confirm_publish` unchecked (`false`).
4. Start the workflow.

The `validate-release` job still performs dependency installation, lint, unit
tests, clean VSIX packaging, archive inspection, and artifact upload. The
`publish` job is skipped. The validation job has only `contents: read`; it never
receives `id-token: write`.

### 11.3 Authorizing an actual release

Do not do this while the Phase 04 NO-GO decision is in force. When the owner has
cleared the release gates and explicitly authorized publication, dispatch the
same workflow with `confirm_publish` checked (`true`). The publish job then
receives `contents: read` and `id-token: write`, downloads the exact VSIX
validated by the first job, verifies its SHA-256, and runs
`npx @vscode/vsce publish --oidc` with that artifact. No version is incremented
and no bypass flag is used.

### 11.4 Verifying a Marketplace release

After a confirmed run succeeds, verify all of the following:

- The GitHub Actions `publish` job completed with exit code 0.
- The Marketplace listing at
  `https://marketplace.visualstudio.com/items?itemName=sajib91.bug-dhor` shows
  the expected version.
- `npx @vscode/vsce show sajib91.bug-dhor --json` reports version `0.1.0` (or
  the intentionally released version).
- VS Code **Extensions → Install from VSIX…** or the Marketplace install flow
  reports extension ID `sajib91.bug-dhor`.

A green workflow run alone is not proof of publication: the Marketplace listing
must confirm it.

### 11.5 User installation

Install the Marketplace item `sajib91.bug-dhor`, or a locally built
`vscode-extension/bug-dhor-0.1.0.vsix`. Then install and start the Python
backend separately as documented in
[the user guide](user-guide.md#5-installation-instructions) and the
[Marketplace README](../vscode-extension/README.md). The VSIX must not contain
a Python virtual environment, model weights, or backend development files.
