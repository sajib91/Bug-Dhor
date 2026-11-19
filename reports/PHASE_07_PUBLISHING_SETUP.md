# BUG-DHOR — PHASE 07: OIDC TRUSTED PUBLISHING PREPARATION

**Date:** 2026-11-19  
**Repository:** `https://github.com/sajib91/Bug-Dhor.git`  
**Publisher:** `sajib91`  
**Extension:** `sajib91.bug-dhor`  
**Version prepared:** `0.1.0`  
**Workflow:** `.github/workflows/publish-extension.yml`  
**Decision:** **Configuration PASS; publication NOT PERFORMED**

> This phase prepared manual, OIDC-based release tooling only. No publisher was created, no Trusted
> Publishing policy was configured, no GitHub environment was created, no workflow run was started,
> no Personal Access Token (PAT) was created or stored, and nothing was committed, pushed, or
> published.

---

## 1. Objective and outcome

Prepare a secure release path for `sajib91.bug-dhor` using Visual Studio Marketplace Trusted
Publishing with GitHub Actions OIDC, without introducing long-lived publishing credentials.

**Outcome:** The repository now contains a manual-only publishing workflow, a compatible `@vscode/vsce`
version, a verified lockfile, duplicate-version guards, and owner-facing setup instructions. Actual
publication remains blocked by Phase 04 security gates, the missing license, publisher ownership
verification, Marketplace policy setup, and GitHub environment approval configuration.

## 2. Publisher identity verification

| Check                          | Evidence                                                            | Status                               |
| ------------------------------ | ------------------------------------------------------------------- | ------------------------------------ |
| Manifest publisher             | `vscode-extension/package.json` has `"publisher": "sajib91"`        | PASS                                 |
| Manifest name                  | `bug-dhor`                                                          | PASS                                 |
| Full extension ID              | `sajib91.bug-dhor`                                                  | PASS                                 |
| Repository owner in remote URL | `sajib91`                                                           | PASS                                 |
| Marketplace account ownership  | Cannot be determined from the repository                            | BLOCKED                              |
| Existing listing query         | `npx @vscode/vsce show sajib91.bug-dhor --json` printed `undefined` | Not published / ownership not proven |

The exact string `sajib91` was preserved. No fallback, alias, or placeholder publisher was left in
the manifest, README, workflow, or report. The Marketplace output `undefined` means no public listing
metadata was returned; it is **not** evidence that the publisher account exists or is controlled by
the repository owner.

Owner action remains required: sign in at the
[Visual Studio Marketplace publisher management page](https://marketplace.visualstudio.com/manage)
and confirm that the publisher ID is exactly `sajib91`.

## 3. Toolchain verification

| Check                   | Command / evidence                                                         | Result                                                  | Status             |
| ----------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------ |
| Latest stable `vsce`    | `npm view @vscode/vsce dist-tags --json`                                   | `latest: 4.1.1`; `next: 4.1.2-0`                        | PASS               |
| Stable 4.x releases     | `npm view @vscode/vsce@4 version --json`                                   | `4.0.0`, `4.1.0`, `4.1.1`                               | PASS               |
| Declared dev dependency | `vscode-extension/package.json`                                            | `@vscode/vsce: ^4.1.1`                                  | PASS               |
| Installed version       | `node_modules/@vscode/vsce/package.json`                                   | `4.1.1`                                                 | PASS               |
| Node requirement        | Installed package `engines.node`                                           | `>= 22`                                                 | PASS               |
| OIDC flag               | `publish --help`                                                           | `--oidc` present                                        | PASS               |
| Exact VSIX publish      | `publish --help`                                                           | `--packagePath <paths...>` present                      | PASS               |
| Duplicate flag          | `publish --help`                                                           | `--skip-duplicate` exists but is intentionally not used | PASS               |
| Lockfile update         | `npm install` then `npm ci`                                                | Completed successfully                                  | PASS               |
| Production audit        | `npm audit --omit=dev --json`                                              | 0 vulnerabilities                                       | PASS               |
| Dev audit               | `npm audit --json`                                                         | 2 moderate advisories in `@vscode/vsce`/`minimatch`     | PASS with advisory |
| Packaging resolver      | `require.resolve('@vscode/vsce/package.json', { paths: [extensionRoot] })` | Resolves to root-hoisted package                        | PASS               |

`@vscode/vsce` 3.9.1 was replaced with stable 4.1.1 because it supports `publish --oidc` and requires
Node 22 or newer. The workflow pins Node `22.13.0`.

## 4. Publishing workflow

Created `.github/workflows/publish-extension.yml`.

| Control                  | Implementation                                                                       | Status                                       |
| ------------------------ | ------------------------------------------------------------------------------------ | -------------------------------------------- |
| Trigger                  | `workflow_dispatch` only; no `push`, `pull_request`, `release`, or scheduled trigger | PASS                                         |
| Intentional confirmation | Required `confirm_publish` choice defaulting to `NO`; value must be `YES`            | PASS                                         |
| Exact version input      | Required `expected_version` string must equal manifest and root versions             | PASS                                         |
| Permissions              | Top level `contents: read`; publish job adds `id-token: write`                       | PASS                                         |
| Environment              | `marketplace-release` with owner-configured required reviewers                       | PASS in YAML; BLOCKED until owner configures |
| Node                     | `actions/setup-node@v4` with `22.13.0` and `package-lock.json` cache                 | PASS                                         |
| Dependencies             | `npm ci`                                                                             | PASS                                         |
| Quality gates            | ESLint and full extension unit suite                                                 | PASS                                         |
| Packaging                | `npm --workspace vscode-extension run package:vsix`                                  | PASS                                         |
| Artifact verification    | VSIX exists, packaged `package.json` identity/version checked                        | PASS                                         |
| Publish command          | `npx @vscode/vsce publish --oidc --packagePath "$VSIX"`                              | PASS                                         |
| PAT / secrets            | No `secrets.*` reference, no `VSCE_PAT` value, no `vsce login`, no token echo        | PASS                                         |
| Concurrency              | `cancel-in-progress: false` for release group                                        | PASS                                         |

The publish job packages the extension and then publishes the exact VSIX file it just built. This
avoids `vsce` traversing the npm workspace root, which was the cause of the oversized VSIX analyzed
in Phase 01. No `--no-dependencies`, `--skip-license`, or `--skip-duplicate` bypass is used.

The compatibility workflow `.github/workflows/extension-tests.yml` was also updated to assert the
lowercase `extension/readme.md` and `extension/changelog.md` archive entries produced by `vsce` 4.

## 5. Version and duplicate-version policy

The workflow fails before packaging when any of these conditions is true:

1. `confirm_publish` is not exactly `YES`.
2. A root `LICENSE`, `LICENSE.md`, or `LICENSE.txt` is absent.
3. `reports/PHASE_04_SECURITY_AUDIT.md` still records `**Decision:** **NO-GO for publication**`.
4. `expected_version` does not match `vscode-extension/package.json`.
5. The extension and root package versions differ.
6. The version is not strict `major.minor.patch`.
7. The publisher/name is not exactly `sajib91` / `bug-dhor`.
8. `vscode-extension/CHANGELOG.md` has no `## [<version>]` section.
9. A local `v<version>` tag exists.
10. A remote `v<version>` tag exists on `origin`.
11. Marketplace metadata contains the same version.

The Marketplace query now fails closed: if `vsce show` exits non-zero, the workflow refuses to
publish instead of treating a network or authentication failure as "not published". The CLI returns
`undefined` with exit code 0 for an unknown extension, which the guard treats as no existing
listing.

Marketplace versions cannot be reused after deletion, and the workflow does not auto-increment
versions or create Git tags. To release again, update the extension version, root version, changelog,
and any version-specific documentation, then rebuild and revalidate.

## 6. Exact manual setup — Marketplace

These steps must be completed by the repository owner. They were **not** performed here.

1. Sign in to the [Visual Studio Marketplace publisher management page](https://marketplace.visualstudio.com/manage).
2. Open the publisher that owns the extension and confirm its ID is exactly `sajib91`.
   - If it does not exist, create a publisher with that exact ID. A publisher ID cannot be changed
     later.
   - Do not create or use a different publisher just to make the workflow pass.
3. Select **Trusted Publishing**.
4. Expand **Create** and enter these exact values:
   - **Policy name:** `Bug-Dhor release workflow` (or another descriptive name)
   - **Repository owner:** `sajib91`
   - **Repository:** `Bug-Dhor`
   - **Workflow:** `publish-extension.yml`
   - **Environment:** `marketplace-release`
5. Select **Create**.
6. If the repository is made private, run the configured workflow within 48 hours after creating
   the policy. The first successful token exchange permanently activates it.
7. Do not create a PAT. As of the current publishing documentation, global Azure DevOps PATs are
   retired on 2026-12-01, and Trusted Publishing is the recommended GitHub Actions path.

Reference: [Publishing Extensions — Trusted Publishing](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#publish-with-github-actions-and-trusted-publishing).

## 7. Exact manual setup — GitHub

1. In `sajib91/Bug-Dhor`, open **Settings → Environments → New environment**.
2. Name it exactly `marketplace-release`.
3. Add **Required reviewers** chosen by the owner. At least one reviewer must approve each publish
   job.
4. Optionally restrict deployment branches to `main` only.
5. Merge or otherwise place `.github/workflows/publish-extension.yml` on the branch from which the
   release will be dispatched.
6. Open **Actions → Publish extension (OIDC Trusted Publishing) → Run workflow**.
7. Select the intended branch/ref.
8. Enter:
   - `expected_version`: exact manifest version, currently `0.1.0`
   - `confirm_publish`: `YES`
9. Wait for the `validate-release` job to pass, then approve the `marketplace-release` environment
   when GitHub requests it.
10. Review the job logs. No credential value should appear; only validation, packaging, and
    publish status messages should be printed.

The workflow never runs automatically after a push, pull request, merge, or GitHub release.

## 8. Verified commands

Repository-root commands used or verified in this phase:

```bash
npm view @vscode/vsce dist-tags --json
npm view @vscode/vsce@4 version --json
npm ci
npm --workspace vscode-extension run lint
npm --workspace vscode-extension test
npm --workspace vscode-extension run package:list
npm --workspace vscode-extension run package:vsix
node node_modules/@vscode/vsce/vsce publish --help
node node_modules/@vscode/vsce/vsce show sajib91.bug-dhor --json
```

The publish command used only inside the manually dispatched workflow, after all gates pass, is:

```bash
npx @vscode/vsce publish --oidc --packagePath "vscode-extension/bug-dhor-${VERSION}.vsix"
```

For reference only, not run here. Marketplace credentials issued through Trusted Publishing expire
after 15 minutes and each GitHub OIDC token can be exchanged once.

## 9. Validation evidence

| Check                                          | Result                     |
| ---------------------------------------------- | -------------------------- |
| `publish-extension.yml` YAML parse             | PASS (PyYAML `BaseLoader`) |
| `extension-tests.yml` YAML parse               | PASS (PyYAML `BaseLoader`) |
| Prettier check on both workflow files          | PASS                       |
| `npm ci` after lockfile update                 | PASS                       |
| Extension ESLint after `npm ci`                | PASS                       |
| Extension unit tests after `npm ci`            | 411 pass, 0 fail           |
| VSIX built before final documentation edits    | 236 entries, 483,685 bytes |
| Workflow contains `secrets.` references        | 0                          |
| Workflow contains PAT creation or `vsce login` | 0                          |
| Automatic publish triggers                     | 0                          |

## 10. Phase 07 checklist

|   # | Check                                                   | Status                              | Notes                                               |
| --: | ------------------------------------------------------- | ----------------------------------- | --------------------------------------------------- |
|   1 | Publisher is exactly `sajib91` in manifest and workflow | **PASS**                            | No placeholder remains                              |
|   2 | Marketplace account ownership                           | **BLOCKED**                         | Owner must verify on Marketplace manage page        |
|   3 | `@vscode/vsce` stable >= 4.0.2                          | **PASS**                            | 4.1.1 installed and declared                        |
|   4 | `package-lock.json` updated via npm                     | **PASS**                            | `npm install` then `npm ci` succeeded               |
|   5 | Packaging/publishing commands verified                  | **PASS**                            | `--oidc`, `--packagePath`, `show`, `publish --help` |
|   6 | Manual-only workflow                                    | **PASS**                            | `workflow_dispatch` with typed confirmation         |
|   7 | Environment approval                                    | **PASS in YAML; BLOCKED in GitHub** | Owner must create reviewers                         |
|   8 | Node 22 LTS                                             | **PASS**                            | Workflow pins 22.13.0                               |
|   9 | Required permissions                                    | **PASS**                            | `contents: read`, publish job `id-token: write`     |
|  10 | Lint/tests/package gates                                | **PASS**                            | Verified locally and wired into workflow            |
|  11 | Version/duplicate guards                                | **PASS**                            | Manifest, root, changelog, tags, Marketplace        |
|  12 | No PAT or stored secrets                                | **PASS**                            | No secret references and no token values            |
|  13 | Marketplace Trusted Publishing policy                   | **BLOCKED**                         | Owner must create it manually                       |
|  14 | Phase 04 security gates                                 | **FAIL**                            | NO-GO still recorded                                |
|  15 | Repository license                                      | **BLOCKED**                         | No license selected                                 |
|  16 | Actual publication                                      | **NOT PERFORMED**                   | Intentionally not run                               |

## 11. Final status

OIDC publishing preparation is complete at the repository level. The release is **not authorized**:
the owner must complete the Marketplace and GitHub manual setup, select a license, and clear the
Phase 04 release gates before a manual workflow run is appropriate.

No commit, push, publish, credential, or policy configuration was performed in this phase.
