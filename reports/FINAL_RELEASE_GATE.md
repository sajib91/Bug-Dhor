# BUG-DHOR — PHASE 08: FINAL RELEASE GATE

**Date:** 2026-11-19  
**Target:** Bug-Dhor VS Code extension `0.1.0` and its separately installed Python backend  
**Repository:** https://github.com/sajib91/Bug-Dhor.git  
**Extension ID:** `sajib91.bug-dhor`  
**Decision:** **NO-GO — publication is NOT authorized**

> This is an internal final gate, not a Marketplace publication record. No publish, commit, push,
> PAT, credential, workflow run, or Marketplace/GitHub configuration was performed. No publication
> success is claimed. The public Marketplace item query returned no listing metadata (HTTP 404 via
> the web UI and `undefined` from `vsce show`).

> **Post-Phase-09 note:** This gate records commit `e15e67a4a7370d26d5135dc1ffc6e2112d39a9c8`. At
> current HEAD `dc9d1a6ac2210e9f20ed6513d1e5ebf63ea79ed2` a root MIT `LICENSE` exists, the
> extension manifest declares `"license": "MIT"`, and the publishing workflow uses
> `confirm_publish: boolean` with no GitHub Environment. The NO-GO security decision and the
> artifact evidence below remain historical; current evidence is in
> [`PHASE_09_OIDC_PUBLISHING_SETUP.md`](PHASE_09_OIDC_PUBLISHING_SETUP.md).

## Final gate summary

| Field                            | Value                                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Release version                  | `0.1.0`                                                                                                                  |
| Git commit SHA                   | `e15e67a4a7370d26d5135dc1ffc6e2112d39a9c8`                                                                               |
| Working tree state               | Uncommitted release-preparation changes; this report and the workflow are not on a remote branch                         |
| Package filename                 | `vscode-extension/bug-dhor-0.1.0.vsix`                                                                                   |
| Package size                     | 483,685 bytes (472.35 KB reported by `vsce`)                                                                             |
| File count                       | 236 archive entries                                                                                                      |
| Package SHA-256                  | `3cbc3a9753aa3021f73f71b4f1c6425a5f8f446660f646617323a943ae53fb99`                                                       |
| Archive integrity                | PASS — `unzip -t` clean; 0 parent, test, `.gitkeep`, `.DS_Store`, `.env`, or Python entries                              |
| Test summary                     | 1,090 repository pytest + 726 engine pytest + 411 extension unit + Extension Host + installed VSIX smoke: all PASS       |
| Security audit summary           | **FAIL** — 2 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW, 3 INFORMATIONAL; all 6 CRITICAL/HIGH findings still present              |
| Backend compatibility            | PASS for separate, already-running loopback backend; extension does not start it; install guide matches project metadata |
| Platform compatibility           | macOS tested configuration PASS; Windows and Linux BLOCKED pending real CI run evidence                                  |
| Publication authorization status | **NOT AUTHORIZED / NO-GO**                                                                                               |

The VSIX SHA-256 above applies only to the final on-disk artifact built during this gate. `vsce` is
not byte-deterministic, so any rebuild requires re-hashing and re-running the installed-VSIX smoke
test.

---

## 1. Phase 01–07 report verification

| Phase report                                                         | Verification result  | Notes                                                                                                                                 |
| -------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `PHASE_01_PACKAGING_AUDIT.md`                                        | PRESENT / VALID      | Root cause and clean-staging fix confirmed. Its SHA-256 and 245-file count describe an earlier build and are superseded by this gate. |
| `MARKETPLACE_READINESS_REPORT.md` (historical)                       | PRESENT / SUPERSEDED | Clearly marked historical; points to Phase 06/07.                                                                                     |
| Phase 02 report                                                      | NOT FOUND            | No `PHASE_02_*` file or Phase 02 reference exists in the repository. This is a documentation completeness gap.                        |
| `PHASE_3_FINAL_REPORT.md`, `PHASE_4_*`, `PHASE_6_*` research reports | PRESENT / HISTORICAL | Research/implementation reports, not Marketplace release gates. No conflict with this gate's claims was found.                        |
| `PHASE_04_SECURITY_AUDIT.md`                                         | PRESENT / CONFIRMED  | Decision is NO-GO at the current HEAD. All six CRITICAL/HIGH findings were independently rechecked in source.                         |
| `PHASE_05_PLATFORM_COMPATIBILITY.md`                                 | PRESENT / CONFIRMED  | Only the tested macOS configuration is verified; Windows/Linux CI has no run result.                                                  |
| `PHASE_06_MARKETPLACE_READINESS.md`                                  | PRESENT / CONFIRMED  | Documentation/packaging PASS; publication FAIL/BLOCKED. Current artifact hash is superseded by this rebuild.                          |
| `PHASE_07_PUBLISHING_SETUP.md`                                       | PRESENT / CONFIRMED  | Repository-side OIDC workflow PASS; remote Trusted Publishing policy and GitHub environment remain owner setup.                       |

No report was edited to hide a failure. The missing Phase 02 artifact is recorded rather than
invented.

---

## 2. Requirement-by-requirement gate

| #   | Requirement                                      | Status      | Evidence                                                                                                    |
| --- | ------------------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------- |
| 1   | Verify all Phase 01–07 reports                   | **BLOCKED** | All existing reports verified; Phase 02 artifact not found.                                                 |
| 2   | No CRITICAL/HIGH unresolved security issues      | **FAIL**    | SEC-01–SEC-06 remain present in the working tree.                                                           |
| 3   | All required functional tests pass               | **PASS**    | 1,090 pytest + 411 unit + Extension Host + installed VSIX smoke; details in §4.                             |
| 4   | Verify backend installation guide                | **PASS**    | Guide commands match `pyproject.toml`, CLI entry point, health URL, and current extras.                     |
| 5   | Extension works without backend startup          | **PASS**    | No backend process is spawned by the extension; unreachable backend is reported unavailable.                |
| 6   | Scanning works with separately running backend   | **PASS**    | Integration and smoke harnesses start the backend externally, wait for health, then scan Python/JavaScript. |
| 7   | Package size and archive integrity               | **PASS**    | 236 entries, 483,685 bytes, `unzip -t` clean, no forbidden entries.                                         |
| 8   | `package.json` metadata                          | **PASS**    | Identity, version, publisher, engine, icon, categories, keywords, and repository URLs verified.             |
| 9   | License authorization and documentation          | **BLOCKED** | No `LICENSE*`, no manifest `license` field, no owner authorization; warning deliberately visible.           |
| 10  | Marketplace publisher identity                   | **BLOCKED** | Manifest says `sajib91`; owner control of the Marketplace publisher cannot be verified from the repo.       |
| 11  | Trusted Publishing configuration                 | **BLOCKED** | Local workflow is correct; remote policy, GitHub environment, and reviewers require owner setup.            |
| 12  | Release version is `0.1.0`                       | **PASS**    | Root manifest, extension manifest, packaged manifest, and both changelogs agree.                            |
| 13  | `CHANGELOG.md`                                   | **PASS**    | Root and extension `## [0.1.0] - 2026-11-19` sections present; extension changelog shipped in VSIX.         |
| 14  | Build final VSIX                                 | **PASS**    | Rebuilt from clean staging immediately before smoke testing.                                                |
| 15  | Install/test exact VSIX in clean VS Code profile | **PASS**    | Isolated extensions/user-data dirs; hash unchanged before and after smoke test.                             |

Because requirements 1, 2, 9, 10, and 11 do not pass, the objective "when all checks pass" is not
satisfied. No publication command is supplied by this gate.

---

## 3. Security audit summary

**Status: FAIL — NO-GO.**

Phase 04 recorded 2 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW, and 3 INFORMATIONAL findings at commit
`e15e67a4a7370d26d5135dc1ffc6e2112d39a9c8`. Independent source inspection during Phase 08 confirmed
that the release-blocking findings remain unresolved in the working tree:

| ID     | Severity | Phase 08 verification                                                                                                 |
| ------ | -------- | --------------------------------------------------------------------------------------------------------------------- |
| SEC-01 | CRITICAL | `FunctionalVerifier._write_target()` still uses `root / file_path` and writes before consent is checked.              |
| SEC-02 | CRITICAL | `RecommendationEngine._apply_and_validate()` and repair paths still write before containment validation.              |
| SEC-03 | HIGH     | No `vscode.workspace.isTrusted` guard; high-risk settings remain workspace-overridable.                               |
| SEC-04 | HIGH     | Backend auth is still optional and non-loopback bind is not blocked by TLS/token requirements.                        |
| SEC-05 | HIGH     | Full result payloads are still persisted to disk with default permissions.                                            |
| SEC-06 | HIGH     | Workspace snapshots still use `shutil.copytree()` without symlink rejection, allowing dereferencing outside the root. |

Additional security caveats:

- Python dependency CVE scanning remains incomplete; `pip-audit`, `safety`, `osv-scanner`, and
  `trivy` were unavailable in the Phase 04 environment.
- `npm audit --omit=dev` reports 0 production vulnerabilities.
- `npm audit` reports 2 moderate advisories in development tooling (`@vscode/vsce` / `minimatch`);
  they are not shipped in the VSIX.
- This is an internal source review, not a third-party penetration test, certification,
  compliance attestation, or CVE-free guarantee.

---

## 4. Functional test summary

All commands were run from the repository root unless noted.

| Check                         | Command                                                            | Result                                          |
| ----------------------------- | ------------------------------------------------------------------ | ----------------------------------------------- |
| Clean dependency install      | `npm ci`                                                           | PASS — 236 packages installed                   |
| ESLint                        | `npm --workspace vscode-extension run lint`                        | PASS — clean                                    |
| Repository-wide Python suite  | `PYTHONPATH=src:security-engine/src .venv/bin/python -m pytest -q` | PASS — 1,090 passed in 11.06s                   |
| Engine-local Python suite     | `BUGDHOR_PYTHON=.venv/bin/python npm test`                         | PASS — 726 pytest + 411 extension tests         |
| Extension unit tests          | `npm --workspace vscode-extension test`                            | PASS — 411 pass, 0 fail                         |
| Extension Host integration    | `npm --workspace vscode-extension run test:integration`            | PASS — `Bug Dhor Extension Host checks passed.` |
| Clean package staging         | `npm --workspace vscode-extension run package:list`                | PASS — clean staged tree                        |
| Final VSIX build              | `npm --workspace vscode-extension run package:vsix`                | PASS — 236 files, 483,685 bytes                 |
| Installed VSIX smoke          | `npm --workspace vscode-extension run test:integration:vsix`       | PASS — exact final artifact, hash unchanged     |
| Production npm audit          | `npm audit --omit=dev --json`                                      | PASS — 0 vulnerabilities                        |
| Full npm audit                | `npm audit --json`                                                 | PASS with advisory — 2 moderate, dev-only       |
| Python dependency consistency | `.venv/bin/python -m pip check`                                    | PASS — no broken requirements                   |
| Whitespace check              | `git diff --check`                                                 | PASS — clean                                    |

### No-backend startup verification

- `vscode-extension/src/extension.js` does not spawn a Python backend. The only `execFile` uses are
  Git changed-file discovery and the explicitly opt-in local Phase 6 CLI.
- `bugdhor.backend.autoStart` is reserved and logs that the extension does not start a backend.
- The Extension Host test sets `backend.url` to `http://127.0.0.1:1` and asserts health is
  `undefined`; unavailable analysis is never reported as a clean scan.
- Integration and VSIX smoke harnesses start the backend themselves with
  `python -m bugdhor --host 127.0.0.1 --port <free-port>`, then pass the URL to the extension.

### Separate-backend scanning verification

The integration suite verified:

- backend version `0.1.0`, API `v1`, and `/api/v1/health`;
- unsaved-buffer hash is sent instead of the saved disk copy when source sharing is enabled;
- saved-file fallback when `privacy.sendSourceText` is disabled;
- workspace metadata-only scanning;
- selection/detection requests;
- benign Python and JavaScript scans produce no fabricated findings;
- real detector findings, explanation, repair proposal, and verification flows;
- unreachable backend reported as unavailable.

The installed-VSIX smoke suite repeated install, health, activation, dashboard, and scan checks
against the packed artifact in an isolated VS Code profile.

---

## 5. Backend installation guide verification

**Status: PASS with environment caveat.**

Verified sources:

- `docs/user-guide.md` §5.1–5.3: prerequisites, repository setup, and manual virtual environment.
- `docs/user-guide.md` §6.1–6.3: startup from `security-engine/`, host/port overrides, environment
  settings, and `GET /api/v1/health`.
- `vscode-extension/README.md` §Separate Python backend installation and §Backend startup.
- `security-engine/pyproject.toml`: Python `>=3.11,<3.15`, CLI script `bugdhor = bugdhor.main:main`,
  and `dev`, `ml`, `analyzers` extras referenced by the guide.
- `security-engine/src/bugdhor/main.py`: `--host` and `--port` arguments documented correctly.
- `pip check`: no broken requirements.
- `PYTHONPATH=src .venv/bin/python -m bugdhor --help`: correct CLI help.

Caveat: the existing local `.venv` has a stale editable-install path from an earlier directory name,
so repository-wide tests were run with `PYTHONPATH=src:security-engine/src`. The documented commands
are correct for a fresh checkout; no guide change was needed.

---

## 6. Package metadata and archive integrity

### Manifest metadata

| Field         | Value                                        | Status                              |
| ------------- | -------------------------------------------- | ----------------------------------- |
| `name`        | `bug-dhor`                                   | PASS                                |
| `publisher`   | `sajib91`                                    | PASS in manifest; ownership BLOCKED |
| `version`     | `0.1.0`                                      | PASS                                |
| `displayName` | `Bug-Dhor: AI Code Security Analyzer`        | PASS                                |
| `engine`      | `^1.90.0`                                    | PASS                                |
| `main`        | `./src/extension.js`                         | PASS                                |
| `icon`        | `media/icon.png` (128×128 PNG)               | PASS                                |
| `license`     | absent / `null`                              | BLOCKED                             |
| `categories`  | `Linters`, `Other`                           | PASS                                |
| `repository`  | `https://github.com/sajib91/Bug-Dhor.git`    | PASS                                |
| `homepage`    | `https://github.com/sajib91/Bug-Dhor#readme` | PASS                                |
| `bugs`        | `https://github.com/sajib91/Bug-Dhor/issues` | PASS                                |

### Archive evidence

| Check                                                              | Result                                                             |
| ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Entries                                                            | 236                                                                |
| Size                                                               | 483,685 bytes                                                      |
| SHA-256                                                            | `3cbc3a9753aa3021f73f71b4f1c6425a5f8f446660f646617323a943ae53fb99` |
| `unzip -t`                                                         | No errors detected                                                 |
| `extension/package.json`                                           | 1                                                                  |
| `extension/readme.md`                                              | 1                                                                  |
| `extension/changelog.md`                                           | 1                                                                  |
| `extension/media/icon.png`                                         | 1                                                                  |
| Runtime `ajv` closure                                              | Present                                                            |
| Test / parent / `.gitkeep` / `.DS_Store` / `.env` / Python entries | 0 / 0 / 0 / 0 / 0 / 0                                              |
| Development `@vscode` packages                                     | 0                                                                  |
| Repository license                                                 | 0                                                                  |
| Third-party dependency LICENSE files                               | 5, from AJV and its runtime transitive dependencies only           |

`vsce` also emitted its standard bundling advisory (189 JavaScript files). No architecture rewrite
was attempted, and no `--no-dependencies`, `--skip-license`, or `--skip-duplicate` bypass was used.

---

## 7. License authorization and documentation

**Status: BLOCKED.**

- No `LICENSE`, `LICENSE.md`, or `LICENSE.txt` exists in the repository or extension directory.
- Neither `package.json` declares a `license` field.
- The README and changelog disclose the absence; no license was invented.
- The VSIX staging script would copy a root or extension license if the owner later adds one.
- The publish workflow explicitly fails when no license file exists.
- No owner authorization for any specific license has been provided.

The missing-license warning remains visible in the final build output.

---

## 8. Marketplace identity and Trusted Publishing

### Publisher identity

- Manifest publisher/name: `sajib91` / `bug-dhor`.
- Git remote owner: `sajib91`.
- `npx @vscode/vsce show sajib91.bug-dhor --json`: `undefined`.
- Public Marketplace item URL: HTTP 404.
- Conclusion: no public listing exists, and publisher account ownership cannot be proven from the
  repository. Owner verification at the Marketplace publisher management page remains required.

### Trusted Publishing

Repository-side configuration is present:

- `.github/workflows/publish-extension.yml` is manual-only (`workflow_dispatch`).
- Required inputs: `expected_version` and `confirm_publish=YES`.
- Permissions: `contents: read`; publish job adds `id-token: write`.
- Node: `22.13.0`; `npm ci`; lint; unit tests; clean VSIX packaging; packaged-identity check.
- Publishes the exact VSIX using `vsce` OIDC authentication and an explicit `--packagePath` input;
  the command itself is intentionally not restated in this NO-GO gate.
- No `secrets.*` reference, PAT, `vsce login`, or token output.
- Duplicate guards include manifest/root version, changelog, local/remote tags, and Marketplace
  metadata with fail-closed query behavior.
- Current guards would reject publication because the license is absent and Phase 04 says NO-GO.

Remote configuration cannot be verified here:

- Marketplace Trusted Publishing policy has not been created.
- GitHub environment `marketplace-release` and required reviewers have not been created.
- The workflow is uncommitted, so no GitHub Actions run or deployment approval exists.

---

## 9. Platform compatibility

| Platform                   | Status   | Evidence                                                                                          |
| -------------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| macOS tested configuration | PASS     | Extension Host and installed VSIX suites passed on the local macOS/VS Code configuration.         |
| Windows                    | BLOCKED  | Three-OS workflow exists, but no Windows run result is available.                                 |
| Linux                      | BLOCKED  | Three-OS workflow with `xvfb-run` exists, but no Linux run result is available.                   |
| SSH / WSL / Codespaces     | UNTESTED | Only manifest-level limitation checked: backend must be reachable from the remote extension host. |

The compatibility workflow is evidence of planned coverage, not evidence that Windows or Linux
pass.

---

## 10. Remaining known limitations and release blockers

1. Phase 04 security NO-GO: 2 CRITICAL and 4 HIGH findings remain open.
2. No repository license and no owner license authorization.
3. Marketplace publisher ownership of `sajib91` unverified.
4. Marketplace Trusted Publishing policy not configured.
5. GitHub environment `marketplace-release` and reviewers not configured.
6. Publication workflow and all release-preparation changes remain uncommitted and unpushed.
7. No Phase 02 report artifact exists.
8. Windows and Linux runtime behavior unverified; CI has not run.
9. Python dependency CVE scanning incomplete.
10. No Marketplace screenshots exist; none were fabricated.
11. SAE feature extraction, counterfactual effects, and activation steering remain unavailable in the
    default integrated path.
12. The Python backend is distributed separately and must already be running; the local Phase 6
    commands require the repository checkout's `src/bugdhor_ast`, which is not bundled in the VSIX.
13. `vsce` output is not byte-deterministic; rebuilds require a new checksum and smoke test.
14. The installed-VSIX harness emitted duplicate `--user-data-dir` / `--extensions-dir` CLI notices,
    but install, activation, and smoke assertions passed.
15. Two moderate development-only npm advisories remain under upstream investigation.

---

## 11. Publication authorization status

**NOT AUTHORIZED. DO NOT PUBLISH.**

This gate does not pass. The exact publication command and manual approval instructions are
intentionally withheld because explicit repository-owner authorization and the release gates are
missing. The prepared workflow and owner setup steps remain documented in
[`PHASE_07_PUBLISHING_SETUP.md`](PHASE_07_PUBLISHING_SETUP.md) for later use only after:

1. SEC-01 through SEC-06 are fixed and independently re-audited.
2. The owner selects and adds a license.
3. The owner verifies the `sajib91` Marketplace publisher.
4. The owner configures Marketplace Trusted Publishing and the GitHub release environment.
5. Windows and Linux CI passes or the owner formally accepts the gap.
6. Python dependency CVE scanning is completed or the gap is formally accepted.
7. Changes are committed and pushed, then the VSIX is rebuilt and the installed-VSIX smoke test is
   repeated against the new artifact.
8. The repository owner gives explicit authorization for publication.

No Marketplace confirmation of any publication exists, and this report must not be read as a claim
that publication succeeded.
