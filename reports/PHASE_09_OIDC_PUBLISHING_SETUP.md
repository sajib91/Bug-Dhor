# BUG-DHOR — PHASE 09: OIDC PUBLISHING SETUP

**Date:** 2026-11-19  
**Repository:** https://github.com/sajib91/Bug-Dhor.git  
**Current HEAD:** `dc9d1a6ac2210e9f20ed6513d1e5ebf63ea79ed2`  
**Publisher:** `sajib91`  
**Extension:** `sajib91.bug-dhor`  
**Version:** `0.1.0`  
**Workflow:** `.github/workflows/publish-extension.yml`  
**Outcome:** Repository-side OIDC publishing setup is complete; publication remains **BLOCKED** and **NOT PUBLISHED**.

> This phase did not publish, commit, push, create a PAT, configure GitHub or Marketplace settings,
> or run a GitHub Actions workflow. OIDC token exchange was not verified locally; it can only be
> verified from a correctly configured GitHub Actions run.

---

## 1. Files inspected

- `package.json` — root npm workspace, version `0.1.0`, Node engine range, scripts.
- `vscode-extension/package.json` — publisher `sajib91`, name `bug-dhor`, version `0.1.0`,
  `main: ./src/extension.js`, repository/homepage/bugs URLs, runtime dependency `ajv`, dev tooling,
  and Marketplace metadata.
- `package-lock.json` — authoritative root lockfile; no `vscode-extension/package-lock.json` exists.
  Locked `@vscode/vsce` is `4.1.1`.
- `vscode-extension/.vscodeignore` — parent-directory exclusion, production dependency allowlist,
  tests, caches, virtual environments, weights, secrets, and development files.
- `vscode-extension/scripts/packageVsix.js` and `vscode-extension/scripts/stageRuntimeDeps.js` —
  clean staging build and production dependency closure.
- `.github/workflows/publish-extension.yml` — previous `YES`/`NO` and environment-based workflow.
- `.github/workflows/extension-tests.yml` — separate non-publishing three-OS lint, unit, package,
  integration, and VSIX smoke workflow.
- `vscode-extension/test/unit/*.test.js`, especially `manifest.test.js` — identity, metadata,
  packaging-script assertions, and OIDC-capable `vsce` version assertions.
- `README.md`, `CHANGELOG.md`, `vscode-extension/README.md`, `vscode-extension/CHANGELOG.md`,
  `docs/user-guide.md`, `docs/release-checklist.md`, `docs/development-setup.md`, and
  `release-checklist.md`.
- `LICENSE` — committed MIT license, `Copyright (c) 2026 Md. Khayrul Islam Sajib`.
- Existing reports: `PHASE_01_PACKAGING_AUDIT.md`, `PHASE_04_SECURITY_AUDIT.md`,
  `PHASE_05_PLATFORM_COMPATIBILITY.md`, `PHASE_06_MARKETPLACE_READINESS.md`,
  `PHASE_07_PUBLISHING_SETUP.md`, `PHASE_3_FINAL_REPORT.md`, `PHASE_4_*`, `PHASE_6_*`,
  `MARKETPLACE_READINESS_REPORT.md`, and `FINAL_RELEASE_GATE.md`.

Report PASS states were not trusted blindly. The Phase 04 CRITICAL/HIGH findings and the current
license state were independently rechecked in source.

### Re-audit result

- Extension identity, entry point, repository URL, and version are consistent.
- `ajv ^8.20.0` remains the only declared runtime dependency.
- MIT `LICENSE` exists at the repository root; the earlier “no license” reports are stale.
- Phase 04 still records **NO-GO for publication**. SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, and
  SEC-06 remain present in source at current HEAD. These are 2 CRITICAL and 4 HIGH findings.
- Marketplace publisher ownership remains unverified: `vsce show sajib91.bug-dhor --json` returned
  `undefined` in the prior gate and the public item URL returned HTTP 404.
- No Marketplace Trusted Publishing policy exists yet; it must be created by the owner.

---

## 2. Files created or modified

### Created

- `reports/PHASE_09_OIDC_PUBLISHING_SETUP.md`

### Modified

- `.github/workflows/publish-extension.yml` — rewritten for boolean confirmation, no environment,
  separated validation/publish permissions, artifact handoff, and checksum verification.
- `vscode-extension/package.json` — added `"license": "MIT"` to match the committed license.
- `vscode-extension/test/unit/manifest.test.js` — asserts MIT license metadata and enforces
  `@vscode/vsce >= 4.0.2`.
- `vscode-extension/README.md` — corrected release-status, known-limitation, and license text.
- `vscode-extension/CHANGELOG.md` — corrected stale license and publication wording.
- `README.md` — corrected stale root license statement.
- `CHANGELOG.md` — corrected stale root release statement.
- `docs/release-checklist.md` — corrected license/current-artifact facts and added OIDC Trusted
  Publishing setup, trigger, verification, installation, and backend instructions.
- `docs/development-setup.md` — corrected packaging/license and publishing references.
- `release-checklist.md` — added a current Phase 09 identity note over the historical checklist.
- Historical reports `PHASE_01_PACKAGING_AUDIT.md`, `PHASE_04_SECURITY_AUDIT.md`,
  `PHASE_05_PLATFORM_COMPATIBILITY.md`, `PHASE_06_MARKETPLACE_READINESS.md`,
  `PHASE_07_PUBLISHING_SETUP.md`, `MARKETPLACE_READINESS_REPORT.md`, and `FINAL_RELEASE_GATE.md` —
  added concise supersession notes; historical evidence and failures were not deleted.

`package-lock.json` was not modified: it already declared `@vscode/vsce` `4.1.1`, and `npm ci`
completed successfully from `vscode-extension/`.

---

## 3. Installed `@vscode/vsce` version

| Check                                                           | Value                                          |
| --------------------------------------------------------------- | ---------------------------------------------- |
| Declared dev dependency                                         | `@vscode/vsce: ^4.1.1`                         |
| Root lockfile version                                           | `4.1.1`                                        |
| Installed version from `node_modules/@vscode/vsce/package.json` | **`4.1.1`**                                    |
| Required minimum                                                | `4.0.2`                                        |
| OIDC support                                                    | PASS — `publish --oidc` is present in CLI help |
| Node requirement                                                | Node 22+; workflow pins `22.13.0`              |

No dependency downgrade or lockfile rewrite was needed.

---

## 4. Packaging changes and explanation

The packaging scripts were preserved. They already solve the historical failure where direct `vsce`
execution followed `node_modules/bug-dhor -> ../vscode-extension` and included roughly 76,774
parent-directory files totaling about 2.4 GB.

Current safeguards:

- `scripts/stageRuntimeDeps.js` resolves only declared production dependencies and their production
  transitive closure.
- `scripts/packageVsix.js` copies the extension manifest, README, changelog, `.vscodeignore`,
  `src/`, `media/`, the production dependency closure, and the root `LICENSE` into a temporary
  directory outside the npm workspace before running `vsce`.
- `.vscodeignore` starts with `../**`, preventing parent-directory traversal, and excludes tests,
  development dependencies, caches, virtual environments, model weights, environment files, and
  unrelated repository content.
- `ajv` and its runtime dependencies remain included.
- The extension manifest now declares `"license": "MIT"`, and packaging produces the repository
  license entry in the VSIX.

No bypass flags are used: no `--no-dependencies`, `--allow-missing-repository`, `--skip-license`,
`--skip-duplicate`, or equivalent.

---

## 5. Workflow design and security permissions

| Control                 | Implementation                                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Trigger                 | `workflow_dispatch` only; no push, pull_request, release, or schedule trigger                                                             |
| Input                   | Required boolean `confirm_publish`, default `false`                                                                                       |
| Validation when `false` | `validate-release` always runs; `publish` is skipped                                                                                      |
| Publishing when `true`  | `publish` needs `validate-release` and uses `if: ${{ inputs.confirm_publish == true }}`                                                   |
| Validation permissions  | `contents: read` only; **no** `id-token: write`                                                                                           |
| Publish permissions     | `contents: read` and `id-token: write` only                                                                                               |
| Environment             | None; no `environment:` key                                                                                                               |
| Node                    | `22.13.0` via `actions/setup-node@v4`, npm cache from `package-lock.json`                                                                 |
| Dependencies            | `npm ci` from `vscode-extension/` in both jobs                                                                                            |
| Quality gates           | ESLint and the 411-test extension unit suite                                                                                              |
| Package checks          | Clean staged list, VSIX build, required entries, forbidden-entry checks, identity/version/license checks, `unzip -t`, size bound, SHA-256 |
| Artifact handoff        | Validation uploads the VSIX; publish downloads it and verifies the same SHA-256 before publishing                                         |
| Publish command         | `npx @vscode/vsce publish --oidc --packagePath "$VSIX"` inside the gated publish job                                                      |
| Concurrency             | `cancel-in-progress: false` release lock per workflow/ref                                                                                 |
| Credentials             | No PAT, no `secrets.*`, no `VSCE_PAT`, no `vsce login`, no token output                                                                   |
| Version policy          | No auto-increment, no tag creation, no version rewriting                                                                                  |

The workflow was parsed successfully and inspected programmatically:

- triggers: `workflow_dispatch`
- `confirm_publish`: boolean, required, default `false`
- `validate-release`: permissions `{"contents":"read"}`, no environment
- `publish`: permissions `{"contents":"read","id-token":"write"}`, condition
  `${{ inputs.confirm_publish == true }}`, no environment

### Integration-test decision

Integration tests were intentionally excluded from the publish workflow. They require a real Python
backend, a downloaded VS Code/Extension Host, and a graphical or virtual display; duplicating that
setup in the release gate would make publication validation slower and more fragile. The separate
`.github/workflows/extension-tests.yml` already provides non-publishing lint, unit, package,
Extension Host, and VSIX smoke jobs with a static Python environment and `xvfb-run` on Linux. No
CI run evidence exists yet, so inclusion here would not be justified. No security or privacy
setting was weakened to avoid the integration setup.

---

## 6. Test commands and actual results

All Task 4 commands were run from `vscode-extension/`.

| Command                        | Actual result                                                         |
| ------------------------------ | --------------------------------------------------------------------- |
| `npm ci`                       | PASS — 236 packages installed, 238 audited                            |
| `npm run lint`                 | PASS — ESLint clean, exit 0                                           |
| `npm test`                     | PASS — 411 tests, 411 pass, 0 fail, 0 skipped                         |
| `npm run package:vsix`         | PASS — 237 files, 473.44 KB reported by `vsce`, 484,799 bytes on disk |
| `npx @vscode/vsce ls --tree`   | PASS — exit 0, 283 output lines, 0 parent/dev/test entries            |
| `unzip -t bug-dhor-0.1.0.vsix` | PASS — `No errors detected in compressed data`                        |

Additional checks:

| Check                                                                 | Actual result                                       |
| --------------------------------------------------------------------- | --------------------------------------------------- |
| Workflow YAML parse                                                   | PASS                                                |
| Prettier check on changed files                                       | PASS                                                |
| `git diff --check`                                                    | PASS                                                |
| Simulated workflow VSIX integrity check against the produced artifact | PASS                                                |
| `npm audit --omit=dev`                                                | PASS — 0 vulnerabilities                            |
| `npm audit`                                                           | PASS with advisory — 2 moderate dev-only advisories |

No command in the Task 4 sequence failed.

---

## 7. VSIX artifact

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| Filename          | `vscode-extension/bug-dhor-0.1.0.vsix`                             |
| Size              | **484,799 bytes**                                                  |
| Entries           | **237**                                                            |
| SHA-256           | `65dae897afc7d2f915b632300b258e2b99a5b6c7302eff48c8a19034e3c5c679` |
| Packaged identity | `sajib91.bug-dhor`                                                 |
| Packaged version  | `0.1.0`                                                            |
| Packaged license  | `MIT`                                                              |

Verified archive contents:

- `extension/package.json`: 1
- `extension/readme.md`: 1
- `extension/changelog.md`: 1
- `extension/src/extension.js`: 1
- `extension/media/icon.png`: 1
- `extension/node_modules/ajv/package.json`: 1
- Repository license: `extension/LICENSE.txt`
- Parent entries: 0
- Test entries: 0
- Development `@vscode` package entries: 0
- `.env`, Python, model-weight, and virtual-environment entries: 0

The checksum applies only to this artifact. Rebuilding changes ZIP timestamps and requires a new
checksum and integrity check.

---

## 8. Warnings, failures, and blocked tests

- `vsce` emitted only its standard startup-performance advisory (189 JavaScript files). The
  missing-license warning is gone because the MIT license is now staged.
- `npm ci` reports 2 moderate advisories in development tooling (`@vscode/vsce` / `minimatch`);
  production audit is clean and those packages are not shipped in the VSIX.
- Extension Host and installed-VSIX smoke tests were not rerun in Phase 09; they are excluded from
  this publishing workflow for the reasons in §5 and remain covered by `extension-tests.yml`.
- Phase 04 remains **NO-GO**: 2 CRITICAL and 4 HIGH findings are unresolved. This is a release
  blocker, not a packaging failure.
- Windows and Linux CI has no run evidence; macOS is the only locally verified platform.
- Python dependency CVE scanning remains incomplete because the required scanners were unavailable
  in the earlier audit environment.
- Marketplace publisher ownership is unverified; the public listing query returned `undefined` /
  HTTP 404.
- Marketplace Trusted Publishing policy is not configured.
- No Marketplace screenshots are present; none were fabricated.
- OIDC authentication was not verified locally and must not be claimed verified.

---

## 9. Manual Marketplace Trusted Publishing configuration still required

The repository owner must complete these steps in the Marketplace UI:

1. Sign in at https://marketplace.visualstudio.com/manage.
2. Confirm or create the publisher ID exactly `sajib91`.
3. Open **Trusted Publishing** and create a policy.
4. Enter these exact values:

   | Field            | Value                   |
   | ---------------- | ----------------------- |
   | Repository owner | `sajib91`               |
   | Repository       | `Bug-Dhor`              |
   | Workflow         | `publish-extension.yml` |
   | Environment      | empty / not configured  |

5. Do not configure a GitHub Environment for this workflow. The workflow intentionally has no
   `environment:` key.
6. Do not create a PAT or any long-lived Marketplace publishing secret.
7. Review the policy and save it.

Reference:
https://code.visualstudio.com/api/working-with-extensions/publishing-extension#publish-with-github-actions-and-trusted-publishing

---

## 10. Exact next commands and manual steps for the repository owner

### 10.1 Clear the release blockers first

1. Resolve Phase 04 SEC-01 through SEC-06 and have the security audit re-run. Do not publish while
   `reports/PHASE_04_SECURITY_AUDIT.md` records NO-GO.
2. Confirm control of the `sajib91` Marketplace publisher.
3. Configure the Marketplace Trusted Publishing policy with the exact values in §9.
4. Obtain Windows and Linux CI evidence or formally accept the gap.
5. Complete Python dependency CVE scanning or formally accept the gap.
6. Give explicit authorization for the specific `0.1.0` release.

### 10.2 Review and publish the repository changes

Nothing was committed or pushed during Phase 09. After reviewing the diff:

```bash
git status --short
git diff --check
git add -A
git commit -m "Configure manual OIDC extension publishing"
git push origin HEAD
```

### 10.3 Run validation without publishing

In `sajib91/Bug-Dhor`, open **Actions → Publish extension (OIDC Trusted Publishing) → Run
workflow**. Select the intended branch/ref and leave `confirm_publish` unchecked (`false`). Confirm:

- `validate-release` succeeds.
- `publish` is skipped.
- The uploaded artifact is `release-vsix-0.1.0`.

### 10.4 Authorize an actual release

Only after all blockers are cleared and explicit owner authorization is given:

1. Run the same workflow again with `confirm_publish` checked (`true`).
2. Wait for `validate-release` to succeed.
3. Confirm the `publish` job receives only `contents: read` and `id-token: write`.
4. Confirm the log reports the exact validated SHA-256 before the OIDC publish command runs.
5. Do not paste a PAT or create a long-lived credential into the workflow or repository settings.

### 10.5 Verify the Marketplace release

```bash
npx @vscode/vsce show sajib91.bug-dhor --json
```

Then open:

https://marketplace.visualstudio.com/items?itemName=sajib91.bug-dhor

Confirm the listing shows version `0.1.0`, the publisher is `sajib91`, and installation is available.
A green workflow run alone is not proof of publication.

### 10.6 Install the extension and the separate backend

Install the Marketplace item or the local artifact:

```bash
code --install-extension vscode-extension/bug-dhor-0.1.0.vsix
```

Install the Python backend separately:

```bash
git clone https://github.com/sajib91/Bug-Dhor.git
cd Bug-Dhor
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e "./security-engine[dev]"
cd security-engine
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765
```

Verify connectivity from another terminal:

```bash
curl -sS http://127.0.0.1:8765/api/v1/health
```

The extension must not start or bundle the backend, virtual environment, model weights, or backend
development files.

---

## 11. Final status

READY FOR MANUAL OIDC CONFIGURATION

BLOCKED — unresolved Phase 04 CRITICAL/HIGH findings; Marketplace publisher ownership unverified; remote Trusted Publishing policy not configured; Windows/Linux CI run evidence and Python CVE scanning incomplete.

NOT PUBLISHED
