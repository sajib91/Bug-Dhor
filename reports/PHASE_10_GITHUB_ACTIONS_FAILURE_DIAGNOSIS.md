# Phase 10 — GitHub Actions Failure Diagnosis

Date: 2026-11-19

Repository: `sajib91/Bug-Dhor`

Commit under diagnosis: `0fc465b580a86e9c3fd238761090a50f74dfb43b`

Failing workflow run: [44554389176](https://github.com/sajib91/Bug-Dhor/actions/runs/44554389176)

Failing jobs:

- `Unit tests (windows-latest)` — job `135666395460`
- `Extension integration (windows-latest)` — job `135666917230`

No commit, push, publication, credential, PAT, or remote change was made during this phase.

## 1. Evidence available

The failing jobs expose only these public annotations:

- `Process completed with exit code 1.`
- A Node.js 20 deprecation warning.

The detailed step logs could not be retrieved:

- `https://api.github.com/repos/sajib91/Bug-Dhor/actions/jobs/135666395460/logs` returned HTTP 403 with `"Must have admin rights to Repository."`
- `https://api.github.com/repos/sajib91/Bug-Dhor/actions/runs/44554389176/logs` returned the same 403.
- Public `.../checks/<job-id>/logs/<step>` URLs returned HTTP 404.
- `gh auth status` reported no authenticated GitHub host.

Therefore the exact CI assertion text is not available and is not invented below. The root causes were derived from deterministic Windows path semantics and reproduced with local path simulations.

All other jobs in run `44554389176` passed: Lint, Unit tests on macOS/Ubuntu, Package validation on macOS/Ubuntu, and Extension integration on macOS/Ubuntu.

## 2. Failing check 1 — Windows unit tests

### 2.1 Test `invoke builds an explicit JSON-only CLI command with a bounded timeout`

File: `vscode-extension/test/unit/phase6LocalEngine.test.js`

Original test expectations used POSIX literals:

```js
const SESSION = '/workspace/.bugdhor/phase6-session.json';
...
assert.ok(call.args.includes(SESSION));
...
assert.ok(call.options.env.PYTHONPATH.split(path.delimiter).includes('/workspace/src'));
```

Production code in `vscode-extension/src/phase6/localEngine.js` builds those values with native `path.join`:

```js
const sessionPath = path.isAbsolute(configuredSession)
  ? configuredSession
  : path.join(root, configuredSession);
...
const pythonPath = [path.join(root, 'src'), process.env.PYTHONPATH]...
```

On Windows, `path.join('/workspace', '.bugdhor/phase6-session.json')` produces `\workspace\.bugdhor\phase6-session.json`, not the POSIX literal expected by the test. The same mismatch applies to the expected `PYTHONPATH` entry.

Reproduced with a `path.win32` simulation of the original test file:

- Original file: 9 pass, 1 fail.
- Failure: `assert.ok(call.args.includes(SESSION))` — actual `false`, expected `true`.
- Fixed file: 10 pass, 0 fail.

Fix applied:

```js
const SESSION = path.join('/workspace', '.bugdhor', 'phase6-session.json');
const WORKSPACE_SRC = path.join('/workspace', 'src');
...
assert.ok(call.options.env.PYTHONPATH.split(path.delimiter).includes(WORKSPACE_SRC));
```

This keeps POSIX behavior unchanged on macOS/Linux and makes the expectation follow the same native path rules as production on Windows.

### 2.2 Test `every engine-backed command invokes its declared service method`

File: `vscode-extension/test/unit/commands.test.js`

The fake diagnostics returned a hard-coded POSIX URI:

```js
getPublishedUris() {
  return ['file:///workspace/src/app.js'];
}
```

The repository inventory builds file URIs from the fake VS Code `Uri.joinPath`, which uses native `path.join`. On Windows the published URI key therefore became `file://\workspace\src\app.js`. `scanIncremental` could not match the published URI to an eligible inventory file and threw `E_NO_INCREMENTAL_TARGETS`, so its `scanWorkspace` service method was never invoked.

Reproduced with a controlled `path.win32` simulation that preserves `path.posix` (so production's intentional POSIX patch normalization is not distorted):

- Before the fix: 284 pass, 1 fail — the actual service-method list was missing one `scanWorkspace` entry.
- After the fix: 285 pass, 0 fail.

Fix applied:

```js
getPublishedUris() {
  // Match the URI produced by the inventory's childUri() so the published
  // URI key resolves on every platform, including Windows separators.
  return [`file://${path.join('/workspace', 'src', 'app.js')}`];
}
```

This is test-harness-only. Production URI handling was not changed.

## 3. Failing check 2 — Windows extension integration

Workflow: `.github/workflows/extension-tests.yml`

Step: `VSIX installation smoke test`

Original command:

```bash
VSIX="$(pwd)/vsix/${VSIX_NAME}"
```

On Windows the step runs under Git Bash. `pwd` emits an MSYS path such as `/d/a/Bug-Dhor/Bug-Dhor`, which native Node/VS Code tooling does not resolve to the downloaded artifact. The smoke test then fails before or during VSIX installation.

Fix applied:

```bash
# Git Bash pwd emits an MSYS path (/d/a/...) on Windows. Resolve the
# artifact with native Node path rules so the VS Code CLI receives a
# usable Windows path while POSIX runners keep the same strategy.
VSIX="$(node -p "require('node:path').resolve('vsix', process.argv[1])" "$VSIX_NAME")"
```

The resolved path was checked locally with Bash and Node. This cannot prove Windows behavior from macOS; a Windows CI re-run is still required.

The job's Extension Host step may also have contributed to the failure, but that cannot be confirmed without the inaccessible logs. The VSIX-path defect is deterministic and Windows-specific, so it is fixed regardless.

## 4. Publish workflow audit

File audited: `.github/workflows/publish-extension.yml`

| Check | Result |
| --- | --- |
| Manual-only trigger | Pass — `workflow_dispatch` only |
| Explicit confirmation | Pass — boolean `confirm_publish`, required, default `false` |
| Publish gate | Pass — `publish` job runs only when `confirm_publish == true` |
| Validation/publish separation | Pass — separate jobs; `validate-release` has no OIDC permission |
| OIDC permission scope | Pass — only `publish` has `id-token: write`; both jobs keep `contents: read` |
| GitHub Environment | Not used |
| Node setup and cache | Pass — `actions/setup-node@v4`, cache keyed to root `package-lock.json` |
| npm installation strategy | Pass — both jobs run `npm ci` from `vscode-extension`; npm resolves the root workspace lockfile and installs the authoritative root `node_modules` |
| Extension identity | Pass — `sajib91.bug-dhor` |
| Version consistency | Pass — extension and root manifest are both `0.1.0` |
| License metadata | Pass — manifest `MIT`; root `LICENSE` exists; VSIX contains `extension/LICENSE.txt` |
| Entry point and runtime dependency | Pass — `./src/extension.js` exists; `ajv` is declared |
| Changelog section | Pass — `## [0.1.0]` exists |
| Phase 04 NO-GO guard | Pass — exact string `**Decision:** **NO-GO for publication**` is present in `reports/PHASE_04_SECURITY_AUDIT.md` |
| Duplicate version guards | Pass — local tag, remote tag, and Marketplace version checks are present |
| Marketplace metadata handling | Pass — `vsce show --json` treats a missing listing as no published versions |
| VSIX required entries | Pass — checked against the built artifact |
| VSIX forbidden entries | Pass — no tests, parent paths, dev dependencies, or model/secret files |
| VSIX size limit | Pass — workflow bound is 100,000–20,000,000 bytes; artifact is 484,799 bytes |
| Artifact upload/download paths | Pass — upload uses repo-relative path; download lands in `vscode-extension/release-vsix`; publish step uses `release-vsix/...` relative to the job working directory |
| Checksum continuity | Pass — validation emits SHA-256; publish recomputes and refuses on mismatch |
| Tool version determinism | Fixed — `npx` could fetch an unvalidated `@vscode/vsce` if the local binary were missing; both calls now use `npx --no-install` |

Change applied to the publish workflow:

```diff
-          if ! npx @vscode/vsce show "$EXTENSION_ID" --json > "$RUNNER_TEMP/marketplace-show.json"; then
+          if ! npx --no-install @vscode/vsce show "$EXTENSION_ID" --json > "$RUNNER_TEMP/marketplace-show.json"; then
...
-          npx @vscode/vsce publish --oidc --packagePath "$VSIX"
+          npx --no-install @vscode/vsce publish --oidc --packagePath "$VSIX"
```

Local tool verification:

- `npx --no-install @vscode/vsce --version` → `4.1.1`
- `vsce show --help` and `vsce publish --help` both expose the required options, including `--oidc` and `--packagePath`.

## 5. Verification performed

All commands were run from the repository root unless noted.

| Command | Result |
| --- | --- |
| `npm ci` | Exit 0 — 236 packages |
| `cd vscode-extension && npm ci` | Exit 0 — root workspace install; `vscode-extension/node_modules` remains empty |
| `npm --workspace vscode-extension run lint` | Exit 0 |
| `npm --workspace vscode-extension test` | Exit 0 — 411 tests, 411 pass, 0 fail |
| `npm --workspace vscode-extension run test:integration` | Exit 0 — Extension Host checks passed |
| `npm run lint` (root) | Exit 1 — 389 Python Ruff findings, pre-existing; unrelated to the CI ESLint job |
| `npm --workspace vscode-extension run package:list` | Exit 0 |
| `npm --workspace vscode-extension run package:vsix` | Exit 0 — 237 files, 484,799 bytes |
| `unzip -t vscode-extension/bug-dhor-0.1.0.vsix` | Exit 0 — no archive errors |
| VSIX integrity script matching the publish workflow | Exit 0 — 237 entries, 484,799 bytes, identity/version/license/contents valid |
| Windows unit simulation — original phase 6 test | 9 pass, 1 fail at `assert.ok(call.args.includes(SESSION))` |
| Windows unit simulation — fixed phase 6 test | 10 pass, 0 fail |
| Windows unit simulation — non-filesystem unit files, before `commands.test.js` fix | 284 pass, 1 fail |
| Windows unit simulation — non-filesystem unit files, after fix | 285 pass, 0 fail |
| YAML parse of both workflows | Exit 0 |
| `git diff --check` | Exit 0 |
| Prettier check on changed files | Workflows and `commands.test.js` pass; `phase6LocalEngine.test.js` reports a pre-existing multi-line assertion that also fails Prettier at `HEAD` |

Current VSIX artifact:

- Path: `vscode-extension/bug-dhor-0.1.0.vsix`
- Entries: 237
- Size: 484,799 bytes
- SHA-256: `7cde725d4552b2237fc51ec010dbeabd72c8c1e9038c5e0ce8c4af7804f0ff35`

The SHA-256 differs from the Phase 09 artifact because the VSIX was rebuilt; its contents, size bound, identity, and archive integrity all revalidated.

## 6. Files changed in this phase

- `.github/workflows/extension-tests.yml` — resolve the downloaded VSIX with native Node path rules.
- `.github/workflows/publish-extension.yml` — use `npx --no-install` for Marketplace metadata and publication.
- `vscode-extension/test/unit/phase6LocalEngine.test.js` — use native path rules for expected session and `PYTHONPATH` values.
- `vscode-extension/test/unit/commands.test.js` — build the fake published URI with native path rules.

No production extension logic, test coverage, or test success criteria were removed or weakened.

## 7. Remaining verification and blockers

- Windows behavior is not verified locally. The fixes are deterministic from Windows path semantics, but the Windows unit and integration jobs must be re-run in GitHub Actions.
- The exact failing step and assertion text in both Windows jobs remain unavailable without repository admin or authenticated log access.
- Filesystem-dependent Windows unit tests (notably symlink creation) were not simulated and could still reveal platform-specific behavior in CI.
- OIDC Trusted Publishing has not been exercised through the configured GitHub Actions identity. Marketplace publisher ownership and the Trusted Publishing policy also remain unverified.
- Phase 04 remains NO-GO: `SEC-01` through `SEC-06` are unresolved (2 CRITICAL, 4 HIGH). The publish workflow correctly refuses a confirmed publication while that decision is present.
- Root `npm run lint` fails on 389 pre-existing Python Ruff findings. The CI lint job and the publish workflow use the extension ESLint command, which passes; the Python findings are outside this phase's scope.
- No publish, push, tag, PAT, or credential operation was performed.

PARTIALLY FIXED
