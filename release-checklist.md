# Bug Dhor — Release Checklist

**Version:** 0.1.0  
**Date:** 2026-11-16  
**Scope:** Root-level release gate for the Bug Dhor monorepo (VS Code extension + Python security engine + research artifacts).  
**Detailed companion:** [`docs/release-checklist.md`](docs/release-checklist.md) — packaging, versioning, webview, and clean-install procedures. This file is the release **decision** record; where the two overlap, this file's gates take precedence and the companion provides the step-by-step detail.

> **Current decision: DO NOT RELEASE as a finished research system.** A private/preview VSIX may be distributed for evaluation, but the project is not research-complete. See §6.

---

## 1. Release identity

| Item | Value | Status |
|---|---|---|
| Product | Bug Dhor Security Framework | — |
| Extension name | `bug-dhor` | ✅ |
| Version | `0.1.0` | ✅ |
| Publisher | `your-publisher-id` | ❌ placeholder |
| Repository URL | absent from `package.json` | ❌ missing |
| License | absent from `package.json` | ❌ missing |
| VS Code engine | `^1.90.0` | ✅ |
| Backend | FastAPI `/api/v1`, `0.1.0` | ✅ |
| Python | 3.11–3.14 (3.11.14 verified) | ✅ |
| Node | 22.13+/24 (Node 25.9.0 used locally) | ✅ |

---

## 2. Build artifacts

| Artifact | Path | Status |
|---|---|---|
| VSIX | `vscode-extension/bug-dhor-0.1.0.vsix` | ✅ built |
| VSIX size | 104,319 bytes, 45 files | ✅ |
| VSIX SHA-256 | `6ee5a897fe886634a56f8d34aa9af6a26ff8d974f1956b657abf34d4e40875d3` | ✅ recorded |
| Backend package | `security-engine/` (editable install) | ✅ |
| Datasets / weights | none committed | ✅ (by design) |

Rebuild:

```bash
cd vscode-extension
npm run package:vsix
npm run package:list
shasum -a 256 bug-dhor-0.1.0.vsix
```

Expected package contents: `package.json`, `README.md`, six `media/*` assets, `src/**`. Must **not** contain tests, `.env`/secrets, lockfiles, caches, datasets, model weights, or nested VSIX files.

- [ ] Archive contents re-verified after any rebuild
- [ ] SHA-256 recorded and matching

---

## 3. Automated test gates

### 3.1 Extension
```bash
cd vscode-extension
npm test
npm run format:check
```
- [x] Unit tests: **295 passed, 0 failed**
- [ ] `format:check` — **FAILS** on a pre-existing repository-wide baseline (57 files would be reformatted); no unrelated reformatting was applied in this integration pass
- [ ] Failures fixed or formatter config reconciled

### 3.2 Backend
```bash
cd security-engine
../.venv/bin/python -m pytest -q
```
- [x] Suite green — **638 passed, 0 failed**

### 3.3 Not covered by automated tests
- [ ] `experiments/` — **no tests**
- [ ] `evaluation/` — **no tests**
- [ ] Real LLM / SAE checkpoint run — **not performed**
- [ ] Semgrep / Bandit / CodeQL / Joern — **not installed**
- [ ] Docker sandbox execution — **not validated**
- [ ] Dataset-driven evaluation — **not performed**

---

## 4. Backend operational verification

```bash
cd security-engine
../.venv/bin/python -m bugdhor
```

- [x] `GET /api/v1/health` → HTTP 200
- [x] Optional bearer token: 401 without/wrong token, 200 with correct token
- [x] Capability discovery returns explicit booleans:
  - `features_extract:false`, `counterfactual_analyze:false`, `prevention_steer:false`
  - `repair_generate:true`, `verification_run:true`
  - `scan_file:true`, `scan_workspace:true`, `detection_analyze:true`, `explanation_analyze:true`
- [x] Unavailable stages return `unavailable`/`partial` with reason codes (no fabricated results)
- [ ] Semgrep/Bandit installed and static stage `ok` in the target environment
- [ ] Docker sandbox exercised end-to-end
- [ ] Backend stopped after testing (no orphan process)

**Known runtime gaps (must be documented in release notes):**
- `features/extract`, `counterfactual/analyze`, `prevention/steer` return empty/`plan=None` results.
- `repair/generate` returns `patch=null` / `INCONCLUSIVE` without a configured LLM.
- Detection probe on four injected vulnerability classes reported only CWE-502.
- Health advertises `sandboxBackend: "docker"` without validated Docker execution.

---

## 5. Extension installation verification

- [x] VSIX built with local `@vscode/vsce` 3.9.1 (`--no-dependencies --allow-missing-repository --skip-license`)
- [x] Clean install into temporary extensions/user-data dirs
- [x] Extension listed as `your-publisher-id.bug-dhor@0.1.0`
- [x] Temp dirs removed after verification
- [x] Archive contains `package.json`, `README.md`, `media/*`, `src/**`
- [ ] Interactive VS Code session: activation, command palette, dashboard webview, diagnostics, Quick Fix
- [x] Extension connects to a running backend and renders real scan results (Extension Host e2e)
- [x] Unsaved-editor-text path verified in a live Extension Host
- [ ] Extension uninstall leaves no residual state

> The extension does **not** start the backend. Release notes must state that a separately running engine at `http://127.0.0.1:8765` is required, with optional token via `BUGDHOR_API_TOKEN` (legacy `BUGDHOR_ENGINE_TOKEN`).

---

## 6. Research release gates (blocking a research claim)

Per `final-audit.md` and `research-compliance-report.md`:

- [ ] Trained multi-view detector with `θ_d`, `τ_d`, and calibrated probabilities (Algorithm 2)
- [ ] Pearson co-activation screening + control interventions + corrected statistics (Algorithm 4)
- [ ] Paper-defined prevention loop (Algorithm 7) — currently **NOT IMPLEMENTED**
- [ ] Localization/attribution scoring `L(r_i)=αa_i+βs_i+γt_i+δn_i` (Algorithm 5)
- [ ] SAE features wired into detection/explanation
- [ ] Counterfactual/steering wired into the API/orchestrator
- [ ] Licensed benchmark datasets + real model/SAE artifacts
- [ ] E0–E8 experiments executed with recorded manifests, seeds, statistics
- [ ] Experiment/evaluation packages have automated tests
- [ ] Documentation drift corrected (see §7)

**Consequence:** No performance, effectiveness, prevention, or reproducibility claim may appear in release notes, README, or marketing until every box above is checked.

---

## 7. Documentation integrity gate

- [x] `README.md` status no longer says detection/SAE/counterfactual/steering/repair/verification are unimplemented
- [x] `README.md` no longer claims `features/` performs SAE feature extraction (it is a scaffold)
- [x] `docs/architecture.md` status reflects the current pipeline and explicit unavailable stages
- [x] `docs/research-alignment.md` no longer claims the paper text was not supplied
- [x] `docs/research-alignment.md` focus-area table cites existing modules and flags missing capabilities
- [ ] Prune or individually mark planned entries in the `docs/architecture.md` target tree
- [x] `docs/release-checklist.md` and this file agree on version/artifact/status
- [ ] No fabricated citations, datasets, metrics, or results anywhere (re-verify before release)
- [ ] Limitations and unavailable capabilities disclosed in README and release notes

---

## 8. Metadata and distribution gate

- [ ] Replace `your-publisher-id` with the real Marketplace publisher
- [ ] Add `repository` URL
- [ ] Add `license` (and `LICENSE` file) consistent with distribution intent
- [ ] Decide distribution channel: private VSIX / Open VSX / Marketplace
- [ ] Add `CHANGELOG` entry for `0.1.0`
- [ ] Confirm no secrets in repo, archive, logs, or committed config
- [ ] Confirm `.vscodeignore` still excludes tests/secrets/weights/datasets

---

## 9. Sign-off

| Role | Name | Decision | Date |
|---|---|---|---|
| Engineering | — | ☐ approved ☐ rejected | — |
| Security | — | ☐ approved ☐ rejected | — |
| Research | — | ☐ approved ☐ rejected | — |
| Release owner | — | ☐ approved ☐ rejected | — |

**Release channels:**

- **Preview / internal evaluation:** permitted only with §3.2 failures and §6 gaps disclosed.
- **Public Marketplace release:** **blocked** by §3.2, §7, §8, and placeholder metadata.
- **Research/publication release:** **blocked** by §6 in full.

---

## 10. Post-release verification

- [ ] Install the published artifact from the actual channel on a clean machine
- [ ] Verify version, publisher, commands, and activation
- [ ] Verify backend connectivity and capability reporting
- [ ] Verify no fabricated results are rendered
- [ ] Record artifact hash in the release notes
- [ ] Open follow-up issues for every unchecked box above
