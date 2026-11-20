# BUG-DHOR — PHASE 11: PERMANENT CI REPAIR

**Date:** 2026-11-19  
**Repository:** https://github.com/sajib91/Bug-Dhor  
**HEAD under repair:** `1b6d727518529ecd071820cae8a3de5524f87634` (`Publish extension`)  
**Workflows:** `.github/workflows/extension-tests.yml`, `.github/workflows/publish-extension.yml`  
**Final status:** READY FOR GITHUB CI VERIFICATION

> This phase did **not** commit, push, tag, publish, create a PAT, or change any release version.
> Windows and macOS behavior was **not** verified on Windows runners locally; those checks require a
> GitHub Actions re-run. OIDC authentication was **not** verified and is not claimed working.

> **Current status (2026-11-20):** This report is historical. Hosted run
> [`44606156782`](https://github.com/sajib91/Bug-Dhor/actions/runs/44606156782) later verified the
> three-OS fixes, and the Phase 04 CRITICAL/HIGH code findings were remediated and committed at
> `7b312f9b72889a36401400d61c59a30e6afce3ce`. The grep gate quoted below was replaced locally by a
> structured release-gate manifest, but publisher/Marketplace Trusted Publishing and OIDC evidence
> remain unverified, so the decision is still **NO-GO**. Current evidence is in
> `reports/PHASE_04_SECURITY_AUDIT.md` §12 and `reports/PHASE_04_SECURITY_REMEDIATION.md` §9.

---

## 1. Actual evidence collected

`gh auth status` is authenticated as `sajib91`, so the real failed logs were retrieved instead of
inferred from job names.

| Run ID | Workflow | Result | Evidence file |
| --- | --- | --- | --- |
| `44554389176` | Final Polish | failure | `reports/ci-debug/failed-run.log` |
| `44572382477` | Extension compatibility tests | failure | `reports/ci-debug/run-44572382477-failed.log` |
| `44571964989` | Publish extension (OIDC Trusted Publishing) | failure | `reports/ci-debug/run-44571964989-failed.log` |
| `44571928443` | Publish extension (OIDC Trusted Publishing) | failure | `reports/ci-debug/run-44571928443-failed.log` |

The Phase 10 fixes already present at HEAD removed the earlier `phase6LocalEngine.test.js` and
`commands.test.js` Windows failures. Run `44572382477` exposed two **new** Windows failures that
had been masked behind the first aborting assertion.

---

## 2. Original failure logs (exact excerpts)

### 2.1 `Unit tests (windows-latest)` — 2 failures

Run `44572382477`, step `Extension unit tests`:

```text
not ok 16 - local Hugging Face provider reads metadata and does not claim internal access
  location: 'D:\a\Bug-Dhor\Bug-Dhor\vscode-extension\test\unit\assistantIntegration.test.js:106:1'
  failureType: 'testCodeFailure'
  error: 'The local Hugging Face model has no readable config.json.'
  code: 'E_PROVIDER_CONFIGURATION'
  name: 'ProviderConfigurationError'
  stack: |-
    readLocalHuggingFaceMetadata (D:\a\Bug-Dhor\Bug-Dhor\vscode-extension\src\integrations\modelMetadata.js:61:11)
    createLocalHuggingFaceProvider (D:\a\Bug-Dhor\Bug-Dhor\vscode-extension\src\integrations\providers\localHuggingFaceProvider.js:31:20)

not ok 17 - local Hugging Face provider reports D/E/F only for validated real accessors
  location: 'D:\a\Bug-Dhor\Bug-Dhor\vscode-extension\test\unit\assistantIntegration.test.js:126:1'
  error: 'The local Hugging Face model has no readable config.json.'

# tests 411
# pass 409
# fail 2
##[error]Process completed with exit code 1.
```

### 2.2 `Extension integration (windows-latest)` — 1 failure

Run `44572382477`, step `Extension Host integration tests`:

```text
Bug Dhor integration failure: AssertionError [ERR_ASSERTION]: the backend must report the resolved path of the scanned file
+ actual - expected

+ 'C:\\Users\\runneradmin\\AppData\\Local\\Temp\\bugdhor-e2e-7m86Wr\\workspace with spaces — ünïcøde 🚀\\café — 日本語.py'
- 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\bugdhor-e2e-7m86Wr\\workspace with spaces — ünïcøde 🚀\\café — 日本語.py'

    at run (d:\a\Bug-Dhor\Bug-Dhor\vscode-extension\test\integration\index.js:156:10)
Exit code:   1
##[error]Process completed with exit code 1.
```

### 2.3 `Publish extension (OIDC Trusted Publishing)` — intentional gate

Run `44571964989`, step `Validate extension / Release authorization and duplicate guards`:

```text
Phase 04 still records a NO-GO publication decision.
##[error]Process completed with exit code 1.
```

The step script was inspected in the log: it is the deliberate
`grep -Fq '**Decision:** **NO-GO for publication**' ../reports/PHASE_04_SECURITY_AUDIT.md` guard.
This is correct behavior, not a workflow configuration defect.

---

## 3. Exact root causes

### 3.1 Unit tests 16 and 17 — Windows fake-filesystem key mismatch

`vscode-extension/test/unit/assistantIntegration.test.js` declared its fixture as the POSIX string
`/models/tiny/config.json`. Production code in
`vscode-extension/src/integrations/modelMetadata.js:54-59` does:

```js
const modelPath = path.resolve(options.modelPath);
const configPath = path.join(modelPath, 'config.json');
fileSystem.readFileSync(configPath, 'utf8');
```

On Windows, `path.resolve('/models/tiny')` becomes `<current drive>:\models\tiny`, so the lookup key
is `D:\models\tiny\config.json`. The fake filesystem compared raw strings, never found that key,
threw `ENOENT`, and `readLocalHuggingFaceMetadata` rewrapped it as
`ProviderConfigurationError: The local Hugging Face model has no readable config.json.`

**Why Phase 10 did not fix it:** Phase 10 repaired path *expectations* in
`phase6LocalEngine.test.js` and `commands.test.js`. It did not touch the local-Hugging-Face fake
filesystem, so these two tests were still latent and only surfaced once the earlier failures were
removed.

### 3.2 Extension integration — Windows 8.3 short name vs resolved long path

`vscode-extension/test/integration/runTest.js` created its workspace with
`fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), ...)))`. On `windows-latest`,
`os.tmpdir()`/`TEMP` is `C:\Users\RUNNER~1\AppData\Local\Temp`. Node's **non-native** `realpathSync`
does not expand 8.3 short names, so every path handed to VS Code and the backend kept `RUNNER~1`.
The Python backend uses `Path.resolve()`/`os.path.realpath()`, which returns the long form
`C:\Users\runneradmin\...`. The assertion at `test/integration/index.js:156` compared the backend
path against the non-native Node realpath, producing the `actual`/`expected` diff above.

**Why Phase 10 did not fix it:** Phase 10 fixed the Windows VSIX path in `extension-tests.yml` by
resolving it with Node `path.resolve` instead of Git Bash `pwd`. That addresses the CLI argument,
but not the temp-root canonicalization or the path assertions inside the Extension Host.

### 3.3 Publish workflow — no configuration defect

The publish workflow is correctly failing on the Phase 04 release gate. `reports/PHASE_04_SECURITY_AUDIT.md`
still records `**Decision:** **NO-GO for publication**` with 2 CRITICAL (SEC-01, SEC-02) and 4 HIGH
(SEC-03–SEC-06) findings. Phase 10 already changed both `npx @vscode/vsce` calls to
`npx --no-install @vscode/vsce`. This phase re-audited the workflow and found no remaining
configuration defect (details in §5.3).

---

## 4. Source files modified

| File | Change |
| --- | --- |
| `vscode-extension/test/unit/assistantIntegration.test.js` | `fakeFileSystem` now resolves keys and lookups with `node:path`; added a regression test. |
| `vscode-extension/test/integration/pathUtils.js` | **New** shared `canonicalPath()` helper using native realpath with fallback and prefix normalization. |
| `vscode-extension/test/unit/pathUtils.test.js` | **New** 4 regression tests for the resolver behavior. |
| `vscode-extension/test/integration/runTest.js` | Canonicalizes the temp root and temp directory before creating the workspace. |
| `vscode-extension/test/integration/runVsixTest.js` | Same canonical temp-root handling for the VSIX smoke harness. |
| `vscode-extension/test/integration/index.js` | Path assertions use `canonicalPath()` instead of `fs.realpathSync()`. |
| `vscode-extension/test/integration/vsixSmoke.js` | Same canonical comparison for the installed-VSIX scan. |
| `reports/PHASE_11_PERMANENT_CI_REPAIR.md` | **New** this report. |

No production extension/backend code, workflow, version, changelog, or license was changed.

---

## 5. Permanent fix details

### 5.1 Windows unit tests

`fakeFileSystem` now stores `path.resolve(filePath)` as each key and resolves the incoming lookup
with the same function. A POSIX-declared fixture and a Windows drive-qualified production lookup
therefore produce the same key on every host. The two failing tests were not weakened: they still
assert capabilities, metadata, limitations, and rejection of internal-activation access.

### 5.2 Extension integration

`canonicalPath()` prefers `fs.realpathSync.native()` (OS API: expands `RUNNER~1` to `runneradmin`),
falls back to `fs.realpathSync()` if native resolution is unavailable, and strips the Windows
`\\?\` / `\\?\UNC\` extended-length prefixes if a platform returns them. It is shared by both Node
harnesses and both Extension Host test entry points:

- `runTest.js` / `runVsixTest.js`: `mkdtempSync(path.join(canonicalPath(os.tmpdir()), ...))`
- `index.js` / `vsixSmoke.js`: `assert.equal(scan.file.path, canonicalPath(sourcePath))`

This keeps the macOS `/var` → `/private/var` symlink behavior while adding Windows short-name
canonicalization. The real backend is still used; no mocks were introduced and no backend-dependent
test was skipped.

### 5.3 Publish workflow audit result (no change required)

Verified against the real repository:

- `package-lock.json` is at repository root only; no `vscode-extension/package-lock.json` exists.
- `npm ci` succeeds both at root and from `vscode-extension`; `npx --no-install @vscode/vsce`
  resolves `4.1.1` from the extension directory.
- Identity `sajib91.bug-dhor`, version `0.1.0` in both manifests, `license: MIT` + root `LICENSE`,
  `## [0.1.0]` in `CHANGELOG.md`, runtime dependency `ajv` all present.
- `@vscode/vsce 4.1.1` help exposes `--oidc` and `--packagePath`; `show --json` returns a `versions`
  array of objects with `.version` (verified against `ms-python.python`).
- `vsce show sajib91.bug-dhor --json` exits 0 and prints `undefined`; the guard explicitly handles
  that value as "no published versions", so a **first** publish is not blocked.
- Artifact upload/download paths, SHA-256 continuity, VSIX contents/size checks, manual
  `workflow_dispatch` + `confirm_publish`, `contents: read` on validation, and `id-token: write` only
  on `publish` are all correct. No PAT or long-lived secret exists in the workflow.

---

## 6. New regression tests

| Test | Purpose |
| --- | --- |
| `assistantIntegration.test.js` → `fake filesystem resolves fixture keys with host path rules` | Guards the POSIX-key/native-key normalization that fixed unit tests 16/17. |
| `pathUtils.test.js` → `canonicalPath uses the native resolver so Windows short names expand` | Simulates `RUNNER~1` vs `runneradmin` and asserts the native resolver is used. |
| `pathUtils.test.js` → `canonicalPath falls back when the native resolver is unavailable` | Guards the non-native fallback. |
| `pathUtils.test.js` → `canonicalPath strips the Windows extended-length prefix` | Guards `\\?\C:\...` normalization. |
| `pathUtils.test.js` → `canonicalPath restores UNC paths from the extended-length prefix` | Guards `\\?\UNC\server\share` normalization. |

The full Extension Host integration suite remains the end-to-end regression test for the resolved
path assertion.

---

## 7. Actual local test results (macOS, Node 22.13.0)

| Command | Result |
| --- | --- |
| `npm ci` (root) | PASS |
| `(cd vscode-extension && npm ci)` | PASS |
| `npm --workspace vscode-extension run lint` | PASS (ESLint) |
| `npm --workspace vscode-extension test` | PASS — **416/416** (was 411 before 5 new tests) |
| `npm test` (root) | PASS — 416/416, exit 0 |
| `npm --workspace vscode-extension run test:integration` | PASS — `Bug Dhor Extension Host checks passed.`, exit 0 |
| `npm --workspace vscode-extension run package:list` | PASS |
| `npm --workspace vscode-extension run package:vsix` | PASS — 237 files, 484,799 bytes |
| `unzip -t vscode-extension/bug-dhor-0.1.0.vsix` | PASS |
| Workflow VSIX integrity script (Python `zipfile`) | PASS — 237 entries, 484,799 bytes |
| `BUGDHOR_VSIX_PATH=... npm --workspace vscode-extension run test:integration:vsix` | PASS — `Bug Dhor VSIX smoke checks passed.`, exit 0 |
| YAML parse of both workflows (Ruby `YAML.load_file`) | PASS |
| `git diff --check` | PASS |
| `npx --no-install @vscode/vsce --version` | `4.1.1` |
| `npx --no-install @vscode/vsce publish --help` | `--oidc` and `--packagePath` present |
| `npm run lint` (root) | **FAIL** — 389 pre-existing Python Ruff errors; not invoked by either CI workflow |

Rebuilt artifact SHA-256:
`b18f7f8ca66ddf4a99139db11d20252432d95e8dcb816cb0403048c8990edc40`.

Pre-existing Prettier findings remain in `test/integration/index.js` and
`assistantIntegration.test.js`; the new lines are Prettier-clean and the CI lint job uses ESLint.

---

## 8. CI tests requiring remote verification

1. Re-run `.github/workflows/extension-tests.yml` on `main`:
   - `Unit tests (windows-latest)` — expect 416/416.
   - `Extension integration (windows-latest)` — expect the resolved-path assertion to pass.
   - `VSIX installation smoke test (windows-latest)` — verifies the Windows CLI install path and
     canonical comparison.
   - macOS/Ubuntu lint, unit, package, integration, and VSIX smoke jobs should remain green.
2. Run `.github/workflows/publish-extension.yml` with `confirm_publish: false` to confirm every
   validation step passes without OIDC permission.
3. `confirm_publish: true` cannot be verified until Phase 04 clears and Marketplace Trusted
   Publishing is configured. OIDC success must not be claimed before that run.

---

## 9. Remaining blockers

- **Phase 04 NO-GO** — SEC-01–SEC-06 (2 CRITICAL, 4 HIGH) are still open; the publish guard is
  intentionally failing and must not be weakened.
- **Marketplace setup** — publisher ownership for `sajib91` and the Trusted Publishing policy are
  unverified.
- **Windows/macOS** — cannot be executed locally; GitHub Actions verification is required.
- **Root lint** — 389 pre-existing Python Ruff findings (not a CI gate for the failing checks).
- No commit, push, tag, or publication was performed.

---

## 10. Exact commands for the next CI run

Local preflight (from repository root):

```bash
git diff --check
npm ci
npm --workspace vscode-extension run lint
npm --workspace vscode-extension test
npm --workspace vscode-extension run test:integration
npm --workspace vscode-extension run package:list
npm --workspace vscode-extension run package:vsix
unzip -t vscode-extension/bug-dhor-0.1.0.vsix
BUGDHOR_VSIX_PATH="$PWD/vscode-extension/bug-dhor-0.1.0.vsix" \
  npm --workspace vscode-extension run test:integration:vsix
```

GitHub Actions:

```bash
gh run rerun 44572382477 --repo sajib91/Bug-Dhor
# or trigger a fresh Extension compatibility tests run on main after the changes are committed/pushed
gh workflow run "Extension compatibility tests" --repo sajib91/Bug-Dhor --ref main

# Validation-only publish run (no OIDC token issued to validation):
gh workflow run "Publish extension (OIDC Trusted Publishing)" \
  --repo sajib91/Bug-Dhor --ref main -f confirm_publish=false

# Do NOT run with confirm_publish=true until Phase 04 is GO and the Marketplace
# Trusted Publishing policy is configured by the publisher owner.
```

---

## 11. Final status evidence

**READY FOR GITHUB CI VERIFICATION**

- Both originally failing checks are root-caused and permanently fixed in test code, with the exact
  CI error text reproduced and matched to source lines.
- All locally executable checks pass: 416/416 unit tests, Extension Host integration, VSIX smoke,
  packaging, VSIX integrity, YAML parse, ESLint, and both `npm ci` strategies.
- The only remaining publish failure is the deliberate Phase 04 release gate, which was verified in
  the actual workflow log and left intact as required.
- Windows runners and OIDC authentication were not executed locally, so the final confirmation must
  come from the GitHub Actions re-run commands in §10.
