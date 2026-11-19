# BUG-DHOR — Phase 01 Production Packaging Audit

**Date:** 2026-11-19  
**Repository:** https://github.com/sajib91/Bug-Dhor.git  
**Working directory:** `vscode-extension/`  
**Generated artifact:** `vscode-extension/bug-dhor-0.1.0.vsix`  
**Final SHA-256:** `1808341f0ee9612bba3ebace380d0ce730c0a94272cbeb20f1e6d1214adb49df`

> **Post-Phase-09 note:** This report is historical. The packaging root cause and clean-staging
> fix remain valid, but a root MIT `LICENSE` now exists and is staged into the VSIX. Artifact
> hashes, file counts, and license warnings below describe the earlier build. Current evidence is
> in [`PHASE_09_OIDC_PUBLISHING_SETUP.md`](PHASE_09_OIDC_PUBLISHING_SETUP.md).

## 1. Executive summary

A lightweight, production-shaped VSIX was produced without changing the extension architecture. The previous ~2.4 GB packaging failure was reproduced and traced to npm workspace dependency traversal through `node_modules/bug-dhor -> ../vscode-extension`, combined with an under-scoped `.vscodeignore`. The final archive contains the extension entry point, all 81 `src/` modules, 11 required media assets, the manifest, README, and the five-package AJV production closure.

The final VSIX is **490,330 bytes / 245 files**, down from a reproduced broken scan of **2,515,546,005 bytes / 76,435 paths** (about 2.34 GiB / 2.52 GB), a **99.9805% byte reduction**. It passes `unzip -t`, has zero parent-directory entries, and installs locally as `sajib91.bug-dhor@0.1.0`.

No source files were deleted, no license was invented, no bypass flags were used in the final package command, and nothing was published, committed, or pushed. The `vsce` missing-license warning is intentionally left visible.

## 2. Repository structure and large-directory inspection

Top-level directories observed:

```text
.bugdhor-data  .git  .pytest_cache  .ruff_cache  .venv  .vscode
benchmarks  docs  examples  htmlcov  mathematical-regression-tests
node_modules  outputs  reports  research  scripts  security-engine
shared  src  tests  vscode-extension
```

Measured large directories:

```text
1.4G    .venv
160M    node_modules
 12M    .git
3.2M    vscode-extension/node_modules
 36K    outputs
204K    reports
```

Git tracking:

```text
663 total tracked files
138 tracked files under vscode-extension/
348 tracked files under src/, tests/, security-engine/, shared/schemas/
```

The separately distributed Python backend remains tracked in Git. `.vscodeignore` only affects VSIX contents; it does not remove backend source from the repository. The deleted-tracked-file check was empty:

```text
git diff --name-status --diff-filter=D
(no output)
```

## 3. Root cause of the 76,774-file / 2.4 GB VSIX

The root package declares an npm workspace:

```json
"workspaces": ["vscode-extension"]
```

After install, the root contains:

```text
../vscode-extension
lrwxr-xr-x@ ... ../node_modules/bug-dhor -> ../vscode-extension
```

`vsce` dependency detection runs `npm list --production --parseable --depth=99999`. From `vscode-extension/`, that resolves production dependencies through the root workspace and the self-referential symlink. With the original `.vscodeignore`, `vsce ls` walked into the parent repository.

To reproduce without modifying repository files, the committed baseline ignore file was applied via `--ignoreFile`:

```bash
git show 710ff24:vscode-extension/.vscodeignore > /tmp/phase1-original.vscodeignore
npx --no-install vsce ls --ignoreFile /tmp/phase1-original.vscodeignore
```

Captured result:

```text
exit=0
   76435 /tmp/.../phase1-vsce-ls-original-ignore.txt
parent_prefix=76349
env_paths=2
venv_paths=41991
test_paths=56
git_paths=2183
{"listed":76435,"bytes":2515546005,"gb":"2.516","gib":"2.343"}
```

First listed paths included:

```text
../research-implementation-status.md
../research-compliance-report.md
../requirements-ast.txt
../release-checklist.md
../package.json
../package-lock.json
../model-compatibility-report.md
../mathematical_validation_report.md
../mathematical-consistency-report.md
../final-system-architecture.md
../final-audit.md
../feature-capability-matrix.md
```

The measured 76,435 paths are close to the reported 76,774; the small difference is consistent with local cache/runtime drift. The failure mode and magnitude match the reported ~2.4 GB VSIX.

A second failure mode appeared when production dependencies were staged locally but `vsce` was still run from the workspace: it discovered the same packages twice, once via the root workspace and once locally, and rejected duplicate case-insensitive VSIX paths. The final wrapper avoids both problems by packaging from a clean temporary copy outside the workspace.

## 4. Manifest, lockfile, and Git-tracking findings

Manifest JSON parsed successfully. Corrected identity and metadata:

```text
name:        bug-dhor
publisher:   sajib91
displayName: Bug-Dhor: AI Code Security Analyzer
version:     0.1.0
repository:  https://github.com/sajib91/Bug-Dhor.git
homepage:    https://github.com/sajib91/Bug-Dhor#readme
bugs:        https://github.com/sajib91/Bug-Dhor/issues
main:        ./src/extension.js
engines:     ^1.90.0
```

Preserved contributions:

```text
activation events: 29
commands:          27
configuration keys: 54
```

`package-lock.json` initially did not match the workspace manifest, so `npm ci` failed with:

```text
npm error code EUSAGE
npm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.
npm error Missing: bug-dhor@0.1.0 from lock file
```

The lockfile was synchronized with `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`. The relevant correction was:

```diff
+    "node_modules/bug-dhor": {
+      "resolved": "vscode-extension",
+      "link": true
+    },
...
-    "node_modules/vscode-extension": {
-      "resolved": "vscode-extension",
-      "link": true
-    },
...
     "vscode-extension": {
+      "name": "bug-dhor",
       "version": "0.1.0",
```

No source files were removed or rewritten.

## 5. Exact runtime files required

Extension entry point:

```text
src/extension.js
```

Runtime source modules:

```text
81 files under src/
```

Runtime media assets packaged:

```text
media/.gitkeep
media/activitybar.svg
media/dashboard.css
media/dashboard.js
media/gutter-critical.svg
media/gutter-high.svg
media/gutter-low.svg
media/gutter-medium.svg
media/icon.png
media/sidebar.css
media/sidebar.js
```

`media/.DS_Store` exists locally but is excluded from the VSIX.

Required package files:

```text
package.json
README.md (package path: extension/readme.md)
.vscodeignore (build input only; not shipped)
```

External production imports found under `src/`:

```text
15 node:path
 7 node:crypto
 6 vscode
 2 node:fs
 2 node:child_process
 1 node:util
 1 node:url
```

No production `src/**` file imports AJV. AJV is used by the unit contract tests and remains declared and packaged as required:

```text
test/unit/sharedContracts.test.js:7:const Ajv2020 = require('ajv/dist/2020');
```

All 81 `src/` files are preserved rather than pruned, avoiding any architecture or lazy-loading change. The Python backend is not required for extension activation and remains separately distributed in the repository.

## 6. Packaging fix and `.vscodeignore` scope

`vscode-extension/package.json` now uses:

```json
"package:prepare": "node scripts/stageRuntimeDeps.js",
"package:vsix": "node scripts/packageVsix.js package",
"package:list": "node scripts/packageVsix.js list"
```

`scripts/stageRuntimeDeps.js` resolves only declared production dependencies and their production transitive closure. `scripts/packageVsix.js` copies only `package.json`, `README.md`, `.vscodeignore`, `src/`, `media/`, and the staged closure into a temporary directory outside the workspace, then runs `vsce` there.

No bypass flags are used:

- No `--no-dependencies`
- No `--skip-license`
- No `--allow-missing-repository`

`.vscodeignore` excludes:

- `../**` and all parent-repository paths
- `.git/**`, editor/OS files, `.vscode/**`, `.vscode-test/**`
- Python environments: `.venv/**`, `venv/**`, `env/**`, `ENV/**`
- Python caches: `**/__pycache__/**`, `**/*.py[cod]`, `.pytest_cache/**`, `.mypy_cache/**`, `.ruff_cache/**`
- Tests and coverage: `test/**`, `**/*.test.js`, `coverage/**`, `htmlcov/**`, `.nyc_output/**`, `**/test-results/**`
- Build artifacts: `dist/**`, `build/**`, `*.egg-info/**`, `scripts/**`, `eslint.config.js`
- Logs/temp/local state: `**/*.log`, `**/*.tmp`, `tmp/**`, `temp/**`, `.cache/**`, `.bugdhor-data/**`, `.bugdhor/**`, `artifacts/**`, `logs/**`, `*.sqlite*`, `*.db`
- Secrets: `.env`, `.env.*`, `*.env`
- Models/datasets: `models/**`, `checkpoints/**`, `datasets/**`, `*.safetensors`, `*.ckpt`, `*.pt`, `*.pth`, `*.onnx`, `*.h5`, `*.bin`
- Lockfiles/package artifacts: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `*.vsix`
- Development docs/output: `docs/**`, `site/**`, `.github/**`, `reports/**`, `outputs/**`, `benchmarks/results/**`
- Development packages via `node_modules/**`, with an explicit allowlist for exactly these runtime packages:
  - `ajv@8.20.0`
  - `fast-deep-equal@3.1.3`
  - `fast-uri@3.1.9`
  - `json-schema-traverse@1.0.0`
  - `require-from-string@2.0.2`

Dependency `.map`, `.ts`, test, benchmark, and `.github` files are excluded; package licenses and READMEs are retained.

## 7. Test and command output

### 7.1 `npm ci`

Initial run from `vscode-extension/` and the repository root failed because the lockfile lacked the workspace link. After the lockfile synchronization described above:

```bash
npm ci
```

```text
added 408 packages, and audited 410 packages in 5s

124 packages are looking for funding
  run `npm fund` for details

3 moderate severity vulnerabilities

To address all issues (including breaking changes), run:
  npm audit fix --force

Run `npm audit` for details.
```

The same successful result was obtained from `vscode-extension/`. The three moderate advisories are reported by npm audit; no audit bypass flag was used.

### 7.2 `npm test`

```bash
npm test
```

```text
ℹ tests 403
ℹ suites 0
ℹ pass 403
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 3049.218916
```

### 7.3 `npm run lint`

```bash
npm run lint
```

```text
> bug-dhor@0.1.0 lint
> eslint .

(no findings; exit 0)
```

### 7.4 `npx vsce ls --tree`

`npm run package:list` invokes `vsce ls --tree` in the clean staging directory. Captured output:

```text
> bug-dhor@0.1.0 package:list
> node scripts/packageVsix.js list

bug-dhor-0.1.0.vsix
├─ README.md [37.77 KB]
├─ package.json [28.47 KB]
├─ media/
│  ├─ .gitkeep
│  ├─ activitybar.svg [162.36 KB]
│  ├─ dashboard.css [36 KB]
│  ├─ dashboard.js [124.46 KB]
│  ├─ gutter-critical.svg [0.69 KB]
│  ├─ gutter-high.svg [0.7 KB]
│  ├─ gutter-low.svg [0.7 KB]
│  ├─ gutter-medium.svg [0.69 KB]
│  ├─ icon.png [42.68 KB]
│  ├─ sidebar.css [3.43 KB]
│  └─ sidebar.js [0.46 KB]
├─ node_modules/
│  ├─ ajv/
│  │  ├─ LICENSE [1.06 KB]
│  │  ├─ README.md [13.46 KB]
│  │  ├─ package.json [4.3 KB]
...
```

```text
exit=0
298 output lines (including npm/script headers)
parent paths: 0
```

The final listing contains 245 packaged files. A direct `npx vsce ls` from the workspace after the fix lists only 94 local paths and omits root-hoisted runtime dependencies; clean staging is what makes the dependency closure both visible and correctly scoped.

### 7.5 `npx vsce package`

`npm run package:vsix` invokes `vsce package` in the clean staging directory. Captured output:

```text
> bug-dhor@0.1.0 package:vsix
> node scripts/packageVsix.js package

 INFO  Files included in the VSIX:
bug-dhor-0.1.0.vsix
├─ [Content_Types].xml
├─ extension.vsixmanifest
└─ extension/
   ├─ package.json [28.47 KB]
   ├─ readme.md [37.79 KB]
   ├─ media/ (11 files) [372.18 KB]
   ├─ node_modules/ (149 files) [427.15 KB]
   └─ src/ (81 files) [550.02 KB]

=> Run vsce ls --tree to see all included files.

 DONE  Packaged: /private/var/folders/.../extension/bug-dhor-0.1.0.vsix (245 files, 478.84 KB)
 WARNING  LICENSE, LICENSE.md, or LICENSE.txt not found
 WARNING  This extension consists of 245 files, out of which 189 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension. You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore.

Wrote .../vscode-extension/bug-dhor-0.1.0.vsix (490330 bytes)
```

Both warnings are preserved. No license was invented and no warning was suppressed.

### 7.6 `unzip -t generated.vsix`

```bash
unzip -t bug-dhor-0.1.0.vsix
```

```text
    testing: extension/node_modules/require-from-string/index.js   OK
No errors detected in compressed data of bug-dhor-0.1.0.vsix.
```

### 7.7 Packaged dependency load check

After extraction:

```text
packaged ajv loads: true
packaged identity: bug-dhor sajib91 Bug-Dhor: AI Code Security Analyzer
commands: 27 activationEvents: 29 configKeys: 54
```

## 8. Size and archive comparison

| Artifact / scan                                  | Files or paths |         Bytes | Notes                                                         |
| ------------------------------------------------ | -------------: | ------------: | ------------------------------------------------------------- |
| User-reported broken VSIX                        |        ~76,774 |       ~2.4 GB | Reported problem.                                             |
| Reproduced broken `vsce ls` with baseline ignore |         76,435 | 2,515,546,005 | 76,349 parent paths; includes `.venv`, `.git`, tests, `.env`. |
| Pre-existing development VSIX                    |             49 |       119,844 | No runtime dependency closure.                                |
| **Final VSIX**                                   |        **245** |   **490,330** | Clean, dependency-complete artifact.                          |

Improvement versus reproduced broken scan:

```text
path reduction:  99.679%
byte reduction:  99.9805%
size ratio:      5130.3x smaller
```

The final artifact is larger than the old 49-file VSIX by 196 files / 370,486 bytes because the five production packages are now correctly included.

Final archive details:

```text
entries:              245
compressed:           490,330 bytes
uncompressed:         1,452,762 bytes
parent '../' entries: 0
node_modules files:   149
src files:            81
media files:          11
other files:          4  ([Content_Types].xml, extension.vsixmanifest, package.json, readme.md)
dev dependency paths: 0
test paths:           0
lockfile paths:       0
.env paths:           0
```

Required packaged files verified:

```text
extension/package.json
extension/readme.md
extension/src/extension.js
extension/media/icon.png
extension/node_modules/ajv/dist/2020.js
```

## 9. Final status and gates

Completed:

- Repository structure, manifest, lockfile, ignore rules, Git tracking, and large directories audited.
- Exact parent-traversal root cause reproduced with command output.
- Runtime files and dependency closure identified and preserved.
- Repository/homepage/bugs metadata added and display name corrected.
- Carefully scoped `.vscodeignore` applied.
- Python backend remains in Git and is excluded only from the VSIX.
- VSIX rebuilt, listed, packaged, integrity-checked, inspected, and locally installed.
- No source files deleted; no publish/commit/push performed.

Remaining non-code gates:

1. **License:** No repository license exists. The final `vsce package` warning is deliberately visible. Publication must wait for the intended license.
2. **Publisher identity:** Confirm ownership of the `sajib91` Marketplace account before release.
3. **Quality warning:** VS Code recommends bundling because 189 of 245 files are JavaScript. This was not addressed because the objective explicitly preserves the existing architecture.
4. **npm audit:** Three moderate advisories are reported by `npm ci`; no automatic fix was applied.

Local install verification:

```text
Extension 'bug-dhor-0.1.0.vsix' was successfully installed.
sajib91.bug-dhor@0.1.0
```

Final command output and archive checks support the conclusion that packaging is complete and lightweight, while publication remains blocked by the license decision.
