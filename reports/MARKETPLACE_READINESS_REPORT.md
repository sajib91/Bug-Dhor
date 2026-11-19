# Marketplace Readiness Report

> **Historical Phase 01 report.** The investigation and root-cause analysis below remain valid, but
> the artifact hash, file count, README text, and publish command reflect an earlier build. The
> current release workflow and validation evidence in
> [`PHASE_09_OIDC_PUBLISHING_SETUP.md`](PHASE_09_OIDC_PUBLISHING_SETUP.md) are authoritative. The
> missing-license statements below are stale: a root MIT `LICENSE` now exists.

**Audit date:** 2026-11-19  
**Target:** `vscode-extension/` (Bug Dhor VS Code extension)  
**Final artifact:** `vscode-extension/bug-dhor-0.1.0.vsix`  
**SHA-256:** `1808341f0ee9612bba3ebace380d0ce730c0a94272cbeb20f1e6d1214adb49df`

## 1. Executive summary

The extension is technically packaged and locally installable, but it is **not cleared for Marketplace release** because the repository has no selected license and the Marketplace publisher identity still requires owner verification. No publish, commit, push, credential use, or architecture rewrite was performed.

The oversized VSIX was reproduced and traced to npm workspace dependency traversal: the root workspace symlink `node_modules/bug-dhor -> ../vscode-extension` caused `vsce` to walk the parent repository. The broken scan listed **76,389 paths totaling 2,515,860,774 bytes** (about 2.34 GiB / 2.52 GB), including parent-directory source, environments, tests, caches, lockfiles, and local environment files.

Packaging now occurs in a clean temporary copy outside the workspace. The final VSIX contains **245 files and 490,330 bytes** (about 478.8 KiB), has zero parent-directory entries, includes the production AJV dependency closure, passes archive integrity checks, and installs successfully as `sajib91.bug-dhor@0.1.0` in local VS Code 1.146.0.

## 2. Audit scope and method

The audit covered:

- Full `package.json` JSON parse, identity fields, commands, activation events, contributions, configuration, engines, scripts, and dependencies.
- `.vscodeignore` exclusions and dependency allowlisting.
- npm workspace layout, lockfile entries, symlinks, and the exact cause of parent-directory inclusion.
- Import analysis for production source and tests.
- Marketplace-facing README claims: description, features, installation, backend setup, configuration, usage, languages, privacy, limitations, icon, and screenshots.
- Repository license discovery.
- Lint, unit, and Extension Host integration suites.
- VSIX packaging, file-list inspection, archive integrity, packaged dependency load test, and local install/activation metadata.

All existing commands, activation events, contributions, configuration keys, declared dependencies, and features were preserved. No credentials or API keys were exposed.

## 3. Changes made

- **Manifest identity and metadata**
  - Name: `bug-dhor`
  - Publisher: `sajib91`
  - Display name: `Bug-Dhor: AI Code Security Analyzer`
  - Added `repository`, `homepage`, and `bugs` metadata pointing to `https://github.com/sajib91/Bug-Dhor`.
  - Corrected the JSON formatting of the inserted blocks.
  - Added packaging scripts without removing existing scripts or contributions.

- **Packaging pipeline**
  - Added `scripts/stageRuntimeDeps.js` to resolve and stage only declared production dependencies and their production transitive closure.
  - Added `scripts/packageVsix.js` to build from a clean temporary copy, avoiding both workspace parent traversal and duplicate case-insensitive paths.
  - Set `package:vsix` and `package:list` to use the new wrapper.
  - Did **not** use `--no-dependencies`; `vsce` detects the staged local closure normally.
  - Did **not** use `--skip-license`; the missing-license warning remains visible. No license was invented.

- **Packaging exclusions**
  - Rewrote `.vscodeignore` to block `../**`, Git metadata, editor/OS files, tests, caches, coverage, logs, temporary/local state, secrets, model artifacts, lockfiles, old VSIX files, docs/build artifacts, development packages, and dependency source maps/TypeScript/test folders.
  - Added an explicit allowlist for the five required runtime packages.

- **README corrections**
  - Added the extension icon.
  - Added Marketplace installation instructions using `sajib91.bug-dhor`.
  - Documented backend setup, privacy/data handling, supported languages, accurate packaging behavior, and known limitations.
  - Corrected the stale publisher, test-count, dependency, and VSIX-size claims.
  - Stated that no screenshots or license are currently bundled.

- **Tests**
  - Updated `test/unit/manifest.test.js` for the approved identity, repository metadata, and new packaging scripts.

## 4. Oversized VSIX root cause and fix

The repository root declares `vscode-extension` as an npm workspace. Its lockfile contains:

- `node_modules/bug-dhor -> ./vscode-extension`
- `node_modules/ajv@8.20.0` and its transitive dependencies at the repository root

When `vsce` ran from `vscode-extension/`, npm dependency detection followed the workspace graph through the root symlink and back into the extension. Reproduced results before the fix:

| Metric                     |                                                         Broken packaging scan |
| -------------------------- | ----------------------------------------------------------------------------: |
| Listed paths               |                                                                        76,389 |
| Total bytes                |                                                                 2,515,860,774 |
| Approximate size           |                                                        2,399.31 MiB / 2.52 GB |
| Parent `../` paths         |                                                                           Yes |
| Parent repository contents | `.env`, `.venv/`, tests, research reports, lockfiles, caches, and other files |

Simply staging dependencies into `vscode-extension/node_modules` was not sufficient: `vsce` then discovered the same packages both through the workspace root and locally, producing duplicate case-insensitive paths that the VSIX format rejects.

The final fix stages the production closure and invokes `vsce` from a temporary directory outside the workspace. The staging copy contains only:

- `package.json`
- `README.md`
- `.vscodeignore`
- `src/`
- `media/`
- the five staged production packages

The generated VSIX is copied back to `vscode-extension/` after packaging. This avoids modifying or deleting the root workspace symlink and leaves root state untouched.

## 5. Files changed

| File                                           | Status            | Purpose                                                                                        |
| ---------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------- |
| `vscode-extension/package.json`                | Modified          | Correct identity, repository metadata, and packaging scripts.                                  |
| `vscode-extension/.vscodeignore`               | Modified          | Parent-path guard, exclusions, and runtime dependency allowlist.                               |
| `vscode-extension/README.md`                   | Modified          | Accurate Marketplace-facing installation, privacy, language, packaging, and limitation claims. |
| `vscode-extension/scripts/stageRuntimeDeps.js` | New               | Production dependency closure discovery/staging.                                               |
| `vscode-extension/scripts/packageVsix.js`      | New               | Clean-copy VSIX builder/inspector.                                                             |
| `vscode-extension/test/unit/manifest.test.js`  | Modified          | Identity, metadata, and packaging-script assertions.                                           |
| `vscode-extension/bug-dhor-0.1.0.vsix`         | Generated         | Final optimized artifact; ignored by Git.                                                      |
| `~/.vscode/extensions/sajib91.bug-dhor-0.1.0`  | Installed locally | Verification copy produced by VS Code CLI.                                                     |
| `reports/MARKETPLACE_READINESS_REPORT.md`      | New               | This report.                                                                                   |

Unrelated uncommitted Phase 3–6 work, including root `package-lock.json`, documentation, Python sources/tests, and user-owned extension behavior changes, was preserved and not overwritten.

## 6. Size and file-count comparison

| Artifact / scan               | Files or paths |         Bytes | Notes                                                             |
| ----------------------------- | -------------: | ------------: | ----------------------------------------------------------------- |
| Broken `vsce` dependency scan |         76,389 | 2,515,860,774 | Included parent repository and local files; not a valid artifact. |
| Pre-existing development VSIX |             49 |       119,844 | Did not include the production dependency closure.                |
| **Final VSIX**                |        **245** |   **490,330** | Clean, dependency-complete artifact.                              |

The final artifact reduces the broken scan by **99.679% in paths** and **99.9805% in bytes**, approximately 5,131× smaller. It is larger than the old 49-file VSIX by 196 files and 370,462 bytes because AJV and its required runtime closure are now present.

Final archive details:

- Compressed size: **490,330 bytes**
- Uncompressed payload: **1,452,743 bytes**
- VS Code extension payload: 81 `src/` files, 11 `media/` files, 149 `node_modules/` files, manifest, and README
- Parent `../` entries: **0**
- Development dependencies/tests/lockfiles/environment files: **0**
- Archive integrity: `No errors detected in compressed data`

## 7. Dependency and license audit

Declared runtime dependency:

- `ajv@^8.20.0`

Staged production closure:

| Package                | Version |
| ---------------------- | ------- |
| `ajv`                  | 8.20.0  |
| `fast-deep-equal`      | 3.1.3   |
| `fast-uri`             | 3.1.9   |
| `json-schema-traverse` | 1.0.0   |
| `require-from-string`  | 2.0.2   |

No production file under `src/` imports AJV; `ajv/dist/2020` is used by the unit contract tests. The dependency remains declared and packaged as required. After extracting the final VSIX, `ajv/dist/2020.js` loaded successfully and exposed `validateSchema`.

Excluded development dependencies are `@vscode/test-electron`, `@vscode/vsce`, `eslint`, `eslint-config-prettier`, `globals`, and `prettier`. Dependency `.map`, `.ts`, test, benchmark, and GitHub metadata files are excluded; package licenses and READMEs are retained.

No repository license file was found in the working tree or Git index. The root README states:

> No license has been selected yet. Do not redistribute this repository until a license is added.

Therefore, no license was invented or added, and packaging intentionally leaves the `vsce` missing-license warning visible. This is a release blocker, not a packaging failure.

## 8. Validation results

| Check                                          | Result                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------- |
| Manifest JSON parse                            | Pass                                                                      |
| Approved identity/metadata                     | Pass                                                                      |
| Existing contributions preserved               | 27 commands and 29 activation events reported by the installed manifest   |
| `npm run lint`                                 | Pass, no findings                                                         |
| `npm test`                                     | 403 tests, 403 pass, 0 fail                                               |
| `npm run test:integration`                     | Exit 0; `Bug Dhor Extension Host checks passed.`                          |
| `npm run package:vsix`                         | Pass; 245 files, 490,330 bytes                                            |
| `unzip -t bug-dhor-0.1.0.vsix`                 | Pass; no errors                                                           |
| Parent traversal / dev files / secrets in VSIX | None found                                                                |
| Packaged AJV load after extraction             | Pass                                                                      |
| VS Code CLI version                            | 1.146.0                                                                   |
| Local install                                  | `Extension 'bug-dhor-0.1.0.vsix' was successfully installed.`             |
| Installed extension listing                    | `sajib91.bug-dhor@0.1.0`                                                  |
| Installed manifest verification                | Correct identity, 27 commands, 29 activation events, AJV and icon present |
| `git diff --check`                             | Clean                                                                     |

README claims were aligned with the verified implementation: the backend is separate and must be started manually; unavailable analysis stages are reported honestly; monitoring and source sharing are opt-in; Phase 6 repairs are proposals with static reanalysis only; Python, JavaScript, and Java support is explicitly scoped; and SAE/counterfactual/steering features are not claimed as operational.

## 9. Warnings, release gates, and publication commands

### Warnings and release gates

1. **License — blocking.** Select and add the intended repository license, rebuild if the packaging script is updated to include it, and resolve redistribution rights before publication.
2. **Publisher identity — verify.** Confirm that the `sajib91` Marketplace account is owned/controlled by the publisher before release.
3. **Marketplace screenshots — quality warning.** No screenshots are currently bundled. An icon is present.
4. **`vsce` bundling advisory — non-blocking.** VS Code reports: “This extension consists of 245 files, out of which 189 are JavaScript files. For performance reasons, you should bundle your extension.” No architecture change was made to address this advisory.
5. **Backend separation — documented limitation.** The Python backend is not bundled; the extension reports unavailable states when it is not configured.
6. **No publication performed.** The VSIX was built and installed locally only.

### Verification and publish sequence

Run from `vscode-extension/`:

```bash
npm run lint
npm test
npm run test:integration
npm run package:vsix
```

The publish command, for reference only, is:

```bash
npx vsce publish --packagePath bug-dhor-0.1.0.vsix
```

Do **not** run that command until the license and publisher-identity gates above are resolved. Packaging uses no bypass flags; the missing-license warning is visible in `npm run package:vsix` output.

Local reinstall command already used for verification:

```bash
/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code \
  --install-extension bug-dhor-0.1.0.vsix --force
```
