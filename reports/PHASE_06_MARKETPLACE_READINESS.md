# BUG-DHOR — PHASE 06: MARKETPLACE READINESS

**Date:** 2026-11-19  
**Target:** `vscode-extension/` Marketplace presentation and documentation  
**Extension ID:** `sajib91.bug-dhor`  
**Version:** `0.1.0`  
**Current VSIX:** `vscode-extension/bug-dhor-0.1.0.vsix`  
**VSIX SHA-256:** `76e5ea47efbda6c29081cb11e07518525cfe8682ee7c7f106e7cba97834b1ceb`  
**Decision:** **PASS for documentation and packaging readiness; FAIL/BLOCKED for publication**

> The checksum identifies the on-disk artifact produced during this phase. Rebuilding the VSIX
> changes ZIP timestamps, so any new artifact must be re-hashed. No publish, commit, push, PAT,
> credential, or Marketplace policy configuration was performed.

---

## 1. Objective and outcome

Review and update the Marketplace-facing extension materials so that they are accurate,
evidence-scoped, and technically publishable without claiming capabilities, languages, statistics,
licenses, or security guarantees that do not exist.

**Outcome:** The Marketplace documentation, metadata, icon reference, changelog, and packaging
pipeline pass local verification. Publication remains **NO-GO** because the Phase 04 security gates
are open, no license exists, publisher ownership is unverified, screenshots are absent, and
cross-OS CI evidence is pending.

## 2. Audit scope

The review covered:

- `vscode-extension/README.md`, `vscode-extension/CHANGELOG.md`, root `CHANGELOG.md`
- `vscode-extension/package.json`, `package.json`, `package-lock.json`
- LICENSE discovery, `.vscodeignore`, `media/icon.png`, `media/activitybar.svg`
- `docs/release-checklist.md`, `docs/development-setup.md`, `docs/user-guide.md`
- `reports/MARKETPLACE_READINESS_REPORT.md` and earlier phase reports
- Unit, Extension Host, installed-VSIX smoke, and packaging verification
- `@vscode/vsce` version, CLI flags, and OIDC Trusted Publishing prerequisites

No existing command, activation event, setting, runtime behavior, or dependency declaration was
removed or rewritten to make the documentation look cleaner.

## 3. Marketplace metadata verification

| Field            | Verified value                                                                                                       | Status                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `name`           | `bug-dhor`                                                                                                           | PASS                                                 |
| `publisher`      | `sajib91`                                                                                                            | PASS in manifest; account ownership BLOCKED          |
| Extension ID     | `sajib91.bug-dhor`                                                                                                   | PASS                                                 |
| `displayName`    | `Bug-Dhor: AI Code Security Analyzer`                                                                                | PASS                                                 |
| `version`        | `0.1.0`                                                                                                              | PASS; matches root `package.json`                    |
| `description`    | Local-first diagnostics, evidence-grounded explanations, and proposal-only repair backed by a separate Python engine | PASS                                                 |
| `engines.vscode` | `^1.90.0`                                                                                                            | PASS                                                 |
| `categories`     | `Linters`, `Other`                                                                                                   | PASS                                                 |
| `keywords`       | `security`, `vulnerability`, `static-analysis`, `ast`, `diagnostics`, `repair`                                       | PASS                                                 |
| `repository`     | `https://github.com/sajib91/Bug-Dhor.git`                                                                            | PASS                                                 |
| `homepage`       | `https://github.com/sajib91/Bug-Dhor#readme`                                                                         | PASS                                                 |
| `bugs`           | `https://github.com/sajib91/Bug-Dhor/issues`                                                                         | PASS                                                 |
| `extensionKind`  | `["workspace"]`                                                                                                      | PASS; backend reachability on remote side documented |
| `icon`           | `media/icon.png`                                                                                                     | PASS; 128×128 PNG                                    |
| `license`        | absent                                                                                                               | BLOCKED                                              |
| Screenshots      | none available                                                                                                       | BLOCKED                                              |

The categories were narrowed from `Machine Learning` to capabilities that are actually wired in the
default extension path. The description and keywords no longer advertise SAE, counterfactual, or
steering as generally available features.

## 4. README and documentation review

The Marketplace README now contains every requested section:

| Requested section         | Location in `vscode-extension/README.md`  | Status                              |
| ------------------------- | ----------------------------------------- | ----------------------------------- |
| Introduction              | Opening paragraphs                        | PASS                                |
| Project overview          | `## Project overview`                     | PASS                                |
| Features                  | `## Key features`                         | PASS                                |
| Architecture              | `## Architecture`                         | PASS                                |
| Languages                 | `## Supported languages`                  | PASS; capability-scoped             |
| Requirements              | `## Requirements`                         | PASS                                |
| Marketplace installation  | `## Installation from Marketplace`        | PASS                                |
| Backend installation      | `## Separate Python backend installation` | PASS                                |
| Backend startup           | `## Backend startup`                      | PASS                                |
| VS Code configuration     | `## VS Code configuration`                | PASS                                |
| Scanning                  | `## Scanning workflow`                    | PASS                                |
| Security analysis         | `## Security analysis workflow`           | PASS                                |
| Counterfactual analysis   | `## Counterfactual analysis`              | PASS with availability gate         |
| Repair and verification   | `## Repair and verification`              | PASS with proposal-only wording     |
| AI provider configuration | `## AI provider configuration`            | PASS                                |
| Privacy                   | `## Privacy controls`                     | PASS                                |
| Troubleshooting           | `## Troubleshooting`                      | PASS                                |
| Limitations               | `## Known limitations`                    | PASS                                |
| Screenshots               | `## Screenshots`                          | PASS as section; no assets BLOCKED  |
| License                   | `## License`                              | PASS as disclosure; license BLOCKED |
| GitHub                    | `## GitHub repository`                    | PASS                                |

Accuracy controls applied:

- Python and JavaScript are identified as exercised; TypeScript as parsing support only in the
  engine; Java as detected with opt-in local repair only, not default backend parsing.
- SAE feature extraction, counterfactual effects, and activation steering are explicitly described
  as unavailable in the default integrated path without compatible artifacts and model access.
- The backend is separate and must already be running; reserved `autoStart` and `pythonPath`
  settings are identified as having no effect.
- Repairs are proposals. Apply/revert is opt-in and gated; static reanalysis is not called a
  security guarantee.
- No statistics, ratings, benchmarks, CVE-free claim, security certification, or universal SAE
  availability was added.

Supporting docs were synchronized:

- `docs/release-checklist.md`: current identity, counts, artifact size, and final gate statuses.
- `docs/development-setup.md`: approved publisher, current VSIX contents, `vsce` 4.1.1, and audit
  results.
- `reports/MARKETPLACE_READINESS_REPORT.md`: marked as a historical Phase 01 report with pointers
  to the current phase reports.
- Root and extension `CHANGELOG.md`: created with `0.1.0` release-candidate notes.

## 5. Images and icons

| Check                        | Evidence                                                                                  | Status  |
| ---------------------------- | ----------------------------------------------------------------------------------------- | ------- |
| Marketplace icon path        | `media/icon.png`                                                                          | PASS    |
| Icon format                  | `file`: PNG image data, 128×128 RGBA                                                      | PASS    |
| Icon dimensions              | `sips`: pixelWidth 128, pixelHeight 128                                                   | PASS    |
| README icon link             | `https://raw.githubusercontent.com/sajib91/Bug-Dhor/main/vscode-extension/media/icon.png` | PASS    |
| HTTPS URL resolution         | HTTP/2 200, `content-type: image/png`, `content-length: 43701`                            | PASS    |
| SVG icon misuse              | `media/activitybar.svg` remains a local Activity Bar asset, not the Marketplace icon      | PASS    |
| All README image links HTTPS | Enforced by `manifest.test.js`                                                            | PASS    |
| Screenshots                  | None present in repository                                                                | BLOCKED |

No synthetic or illustrative screenshots were created. The README states the absence directly.

## 6. Packaging and artifact evidence

Build command:

```bash
npm --workspace vscode-extension run package:vsix
```

Current artifact evidence:

| Check                                     | Result                                                             | Status             |
| ----------------------------------------- | ------------------------------------------------------------------ | ------------------ |
| `vsce` reported files                     | 236                                                                | PASS               |
| Archive entries                           | 236                                                                | PASS               |
| On-disk size                              | 483,685 bytes                                                      | PASS               |
| SHA-256                                   | `76e5ea47efbda6c29081cb11e07518525cfe8682ee7c7f106e7cba97834b1ceb` | PASS               |
| `unzip -t`                                | No errors detected                                                 | PASS               |
| `extension/package.json`                  | 1 entry                                                            | PASS               |
| `extension/readme.md`                     | 1 entry                                                            | PASS               |
| `extension/changelog.md`                  | 1 entry                                                            | PASS               |
| `extension/media/icon.png`                | 1 entry                                                            | PASS               |
| `extension/node_modules/ajv/package.json` | 1 entry                                                            | PASS               |
| `extension/test/` entries                 | 0                                                                  | PASS               |
| Parent `../` entries                      | 0                                                                  | PASS               |
| `.gitkeep` / `.DS_Store` entries          | 0 / 0                                                              | PASS               |
| Development `@vscode/` packages in VSIX   | 0                                                                  | PASS               |
| License warning                           | Visible and unsuppressed                                           | PASS / BLOCKED     |
| Bundling advisory                         | Visible; no architecture rewrite attempted                         | PASS with advisory |

`vsce` 4 writes `readme.md` and `changelog.md` in lowercase inside the archive. The CI archive
assertion was updated accordingly.

The staging script now also copies an existing `LICENSE`, `LICENSE.md`, or `LICENSE.txt` from the
extension or repository root when one is added later. No license file exists now, so nothing was
staged and the warning remains visible.

## 7. Local verification results

| Check                       | Command                                                      | Result                                   | Status             |
| --------------------------- | ------------------------------------------------------------ | ---------------------------------------- | ------------------ |
| ESLint                      | `npm --workspace vscode-extension run lint`                  | Clean                                    | PASS               |
| Unit tests                  | `npm --workspace vscode-extension test`                      | 411 pass, 0 fail                         | PASS               |
| Extension Host integration  | `npm --workspace vscode-extension run test:integration`      | `Bug Dhor Extension Host checks passed.` | PASS               |
| Installed VSIX smoke        | `npm --workspace vscode-extension run test:integration:vsix` | `Bug Dhor VSIX smoke checks passed.`     | PASS               |
| Package listing             | `npm --workspace vscode-extension run package:list`          | Clean staged tree                        | PASS               |
| VSIX build                  | `npm --workspace vscode-extension run package:vsix`          | 236 entries, 483,685 bytes               | PASS               |
| Clean install from Phase 01 | Temporary VS Code CLI profile                                | `sajib91.bug-dhor@0.1.0`                 | PASS               |
| Production audit            | `npm audit --omit=dev --json`                                | 0 vulnerabilities                        | PASS               |
| Full dev audit              | `npm audit --json`                                           | 2 moderate, dev-only                     | PASS with advisory |
| Lockfile install            | `npm ci`                                                     | Succeeded                                | PASS               |
| YAML parse                  | PyYAML `BaseLoader` on both workflow files                   | Parsed                                   | PASS               |
| Workflow formatting         | `npx prettier --check .github/workflows/*.yml`               | Clean                                    | PASS               |

The two moderate advisories are from the `@vscode/vsce` development dependency's `minimatch`
transitive dependency. They are not shipped in the VSIX, which stages only the declared production
dependency closure.

## 8. Privacy and security documentation

The README discloses:

- no built-in telemetry, analytics, crash reporting, or advertising SDK;
- health checks send no source;
- explicit file/selection source sharing is controlled by `bugdhor.privacy.sendSourceText`;
- background monitoring is off and requires two independent consents;
- workspace scans send folder metadata and the backend reads allowlisted files;
- API and provider credentials are environment-only;
- the local Phase 6 session stays local and defaults to `.bugdhor/phase6-session.json`.

Those statements are documentation-only. The implementation still has open Phase 04 findings, so
the privacy section must not be read as a security attestation.

## 9. Final release checklist

|   # | Check                                         | Status      | Evidence / action required                                  |
| --: | --------------------------------------------- | ----------- | ----------------------------------------------------------- |
|   1 | Manifest identity and metadata                | **PASS**    | `sajib91.bug-dhor`, `0.1.0`, public repository URLs         |
|   2 | Marketplace description, categories, keywords | **PASS**    | Capability-scoped metadata; no ML/SAE overclaim             |
|   3 | README requested sections                     | **PASS**    | All 21 requested sections present                           |
|   4 | HTTPS image links                             | **PASS**    | Single icon link is HTTPS and resolves as PNG               |
|   5 | Marketplace icon format/size                  | **PASS**    | 128×128 PNG, not SVG                                        |
|   6 | Local Activity Bar SVG usage                  | **PASS**    | `activitybar.svg` is not used as Marketplace icon           |
|   7 | CHANGELOG shipped                             | **PASS**    | `extension/changelog.md` in archive                         |
|   8 | Backend install/startup documentation         | **PASS**    | Separate install, startup, health, token, remote notes      |
|   9 | VS Code configuration documentation           | **PASS**    | Key settings and remote-side requirement documented         |
|  10 | Scanning/security/repair documentation        | **PASS**    | Proposal-only and `unavailable` states preserved            |
|  11 | Counterfactual/steering availability honesty  | **PASS**    | Explicitly unavailable by default                           |
|  12 | Language-support honesty                      | **PASS**    | Python/JavaScript exercised; Java locally scoped            |
|  13 | Privacy documentation                         | **PASS**    | Data flows and opt-in controls disclosed                    |
|  14 | Screenshots                                   | **BLOCKED** | No verified screenshots available; none fabricated          |
|  15 | Repository license                            | **BLOCKED** | No `LICENSE*` file; warning visible                         |
|  16 | Publisher ownership                           | **BLOCKED** | Owner must verify `sajib91` on Marketplace                  |
|  17 | Phase 04 security gates                       | **FAIL**    | NO-GO: 2 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW, 3 INFORMATIONAL |
|  18 | Windows/Linux runtime verification            | **BLOCKED** | Three-OS CI workflow exists but has no run evidence         |
|  19 | Python dependency CVE scanning                | **BLOCKED** | Incomplete from Phase 04                                    |
|  20 | VSIX packaging hygiene                        | **PASS**    | 236 entries, 483,685 bytes, no dev/test/parent files        |
|  21 | Local lint/unit/integration/Vsix tests        | **PASS**    | 411 unit tests; integration and VSIX smoke passed           |
|  22 | Publishing workflow configuration             | **PASS**    | Manual-only OIDC workflow present and parsed/prettier-clean |
|  23 | Marketplace Trusted Publishing policy         | **BLOCKED** | Owner must create it manually                               |
|  24 | GitHub environment reviewers                  | **BLOCKED** | Owner must create/configure `marketplace-release`           |
|  25 | Final publication decision                    | **NO-GO**   | Do not publish until items 14–19 and 22–24 are resolved     |

## 10. Release decision

Documentation and packaging are ready for review, but the extension is **not cleared for Marketplace
publication**. The authoritative blockers remain in
[`PHASE_04_SECURITY_AUDIT.md`](PHASE_04_SECURITY_AUDIT.md) and
[`PHASE_05_PLATFORM_COMPATIBILITY.md`](PHASE_05_PLATFORM_COMPATIBILITY.md).

No commit, push, publish, credential creation, or Marketplace configuration was performed in this
phase.
