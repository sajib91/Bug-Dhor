# Bug Dhor — Final Strict Audit

**Audit date:** 2026-11-16  
**Audited against:** *An Explainable Multi-Feature Security Framework for Vulnerability Detection, Prevention, and Automated Repair in Large Language Models* (`Research.txt`, 6,232 lines)  
**Repository:** `/Users/md.khayrulislamsajib/Downloads/CRAFT-Sec`  
**Auditor method:** Full source/doc inspection, test execution, OpenAPI/route inspection, live FastAPI `TestClient` probes, VSIX archive inspection, and clean VS Code installation.

---

## 0. Status rules used in this audit

Only the five mandated statuses are used:

| Status | Definition applied here |
|---|---|
| **IMPLEMENTED AND VERIFIED** | Code exists, is wired into the operational path, has automated tests, and was executed end-to-end in this environment with real inputs/artifacts. |
| **IMPLEMENTED BUT NOT FULLY VALIDATED** | Code exists and is tested at unit/component level, but is unwired, conditional on unavailable artifacts, or not exercised end-to-end with real data/models. |
| **PARTIALLY IMPLEMENTED** | Only part of the required behavior exists, or the implemented behavior materially differs from the paper's specification. |
| **NOT IMPLEMENTED** | No implementation of the specified requirement exists. |
| **NOT APPLICABLE** | The requirement does not apply to this artifact. |

**No area is marked IMPLEMENTED AND VERIFIED merely because a class or file exists.** Passing unit tests that use synthetic `TinyAdapter`/`FakeAdapter` fixtures do **not** count as validation with real LLM/SAE artifacts.

---

## 1. Summary table

| # | Requirement area | Status |
|---|---|---|
| 1 | Architecture | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 2 | Code quality | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 3 | Research contribution implementation | PARTIALLY IMPLEMENTED |
| 4 | SAE authenticity | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 5 | Counterfactual validity | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 6 | Pairwise interactions | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 7 | Higher-order interactions | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 8 | Activation steering | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 9 | Detection reliability | PARTIALLY IMPLEMENTED |
| 10 | Explainability | PARTIALLY IMPLEMENTED |
| 11 | Repair reliability | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 12 | Independent verification | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 13 | Experimental reproducibility | PARTIALLY IMPLEMENTED |
| 14 | Security / privacy | IMPLEMENTED BUT NOT FULLY VALIDATED |
| 15 | Testing coverage | PARTIALLY IMPLEMENTED |
| 16 | Documentation | PARTIALLY IMPLEMENTED |
| 17 | Extension installation | IMPLEMENTED AND VERIFIED |
| 18 | Performance | IMPLEMENTED BUT NOT FULLY VALIDATED |

**Overall: NOT COMPLETE.** Three mandatory research contributions (trained multi-view detection, Pearson interaction screening with control interventions, paper-defined prevention loop, and localization attribution) remain unimplemented or unvalidated. The backend test suite is also red (6 failures). The project must not be described as research-complete or submission-ready.

---

## 2. Per-requirement findings

### 2.1 Architecture — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- Layered monorepo: `vscode-extension/` (JS client) and `security-engine/` (Python/FastAPI).
- Package boundaries: `api/`, `core/`, `detection/`, `sae/`, `counterfactual/`, `steering/`, `repair/`, `verification/`, `sandbox/`, `program_analysis/`, `static/`, `models/`, `experiments/`, `evaluation/`, `explain/`, `parsing/`.
- `core/orchestrator.py` (938 lines) wires a real multi-stage pipeline; `core/pipeline.py` defines explicit `StageStatus`.
- API composition in `api/app.py` and `api/routes/__init__.py` includes health, scan, detection, explanation, features, counterfactual, prevention, repair, verification, and jobs routers.

**Evidence**
- Runtime capability probe: `{features_extract:false, counterfactual_analyze:false, prevention_steer:false, repair_generate:true, verification_run:true, scan_file:true, scan_workspace:true, detection_analyze:true, explanation_analyze:true}`.
- Stage reports explicitly return `unavailable` with reason codes (`E_MODEL_UNAVAILABLE`, `E_SAE_UNAVAILABLE`, `E_COUNTERFACTUAL_UNAVAILABLE`, `E_STEERING_UNAVAILABLE`, `E_TOOL_MISSING`) instead of fabricating results.
- `security-engine/tests/unit/test_pipeline.py` and `tests/api/*` exercise orchestration.

**Gaps / findings**
- Four packages are empty scaffolds: `features/` (`__init__.py` says "package scaffold only. No runtime behavior is implemented yet."), `artifacts/`, `contracts/`, `ingestion/`.
- Core research stages (model capture, SAE features, feature aggregation, counterfactual, steering) are registered as `UnavailableStage` in the orchestrator (`core/orchestrator.py`).
- Architecture documentation is stale and contradicts the operational code (see §16).
- `docs/research-alignment.md` references modules that do not exist (see §16), so the documented architecture is not the implemented architecture.

---

### 2.2 Code quality — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- Typed Python (`from __future__ import annotations`, dataclasses, protocols), explicit error/status models, pydantic schemas with `extra="forbid"`.
- Deterministic hashing/canonical JSON in `experiments/config.py`, `sae/model.py`, `repair/workflow.py`.
- Prompt-injection hardening in `repair/engine.py` (untrusted repository/finding content delimited).

**Evidence**
- Backend: `6 failed, 448 passed in 7.87s` (`../.venv/bin/python -m pytest -q`).
- Failing tests:
  - `tests/api/test_openapi.py::test_openapi_exposes_exactly_the_versioned_operations`
  - `tests/api/test_openapi.py::test_every_operation_documents_success_and_problem_details`
  - `tests/api/test_scan.py::test_scan_file_reports_real_metadata_and_explicit_unavailable_stages`
  - `tests/api/test_scan.py::test_scan_file_hashes_supplied_source_text_instead_of_the_disk_copy`
  - `tests/api/test_scan.py::test_scan_workspace_discovers_sources_and_ignores_generated_directories`
  - `tests/unit/test_pipeline.py::test_orchestrator_capabilities_require_every_operation_stage`
- `npm run format:check` has pre-existing failures in `media/dashboard.js`, `src/repair/patchApplication.js`, `src/webviews/dashboardPanel.js`, `test/unit/dashboardPanel.test.js`.
- Extension unit tests: **230 passed, 0 failed**.

**Gaps / findings**
- The six backend failures are **contract drift**, not missing features: production now exposes `/api/v1/jobs/*` and reports `analysisAvailable: true` / `explanation_analyze: true` where tests encode the older contract (`analysisAvailable: false`; explanation requiring its own stage). Either the tests or capability semantics must be reconciled.
- A red backend suite blocks a "verified" quality claim.

---

### 2.3 Research contribution implementation — PARTIALLY IMPLEMENTED

Paper-contribution coverage (detail in `research-compliance-report.md`):

| Paper contribution | Status |
|---|---|
| Integrated explainable security framework (Algorithm 1) | PARTIALLY IMPLEMENTED — pipeline exists; several stages are `UnavailableStage`. |
| Multi-feature vulnerability detection (Algorithm 2, §5.5) | PARTIALLY IMPLEMENTED — deterministic evidence fusion exists; **no trained multi-view classifier**, no `θ_d`, no calibrated `p`. |
| SAE-based security interpretability (Algorithm 3, §5.6) | IMPLEMENTED BUT NOT FULLY VALIDATED — genuine SAE code; no real checkpoint/end-to-end capture. |
| Feature interaction analysis (Algorithm 4, §5.7) | PARTIALLY IMPLEMENTED — factorial contrasts exist; **no Pearson co-activation screening, no control interventions**. |
| Hybrid program-level validation (AST/CFG/DFG/taint/static) | IMPLEMENTED BUT NOT FULLY VALIDATED — Semgrep/Bandit unavailable in this environment. |
| Explainable localization (Algorithm 5, §5.8) | PARTIALLY IMPLEMENTED — evidence-grounded text only; **no localization score/attribution**. |
| Security-aware prevention (Algorithm 7, §5.12) | **NOT IMPLEMENTED as specified** — no iterative generate→analyze→feedback loop; API `prevention/steer` returns `plan=None`. |
| Automated repair (Algorithm 8, §5.13) | IMPLEMENTED BUT NOT FULLY VALIDATED — proposal-only workflow; default run returns `patch=null` without a model. |
| Patch validation (Algorithm 9, §5.14) | IMPLEMENTED BUT NOT FULLY VALIDATED — static verification integrated; Docker execution unverified. |
| Comprehensive evaluation (Algorithms/metrics/ablations) | PARTIALLY IMPLEMENTED — helpers exist; **no datasets, no runs, no results**. |

**Gaps / findings (mandatory)**
- No trained detection model, calibrator, or probability output.
- No Pearson screening / intervention controls for interaction validity.
- No paper-defined prevention loop.
- No localization attribution formula (`L(r_i)=αa_i+βs_i+γt_i+δn_i`).
- No empirical evaluation and therefore no research claims can be supported.

---

### 2.4 SAE authenticity — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `sae/model.py` (77 lines): genuine PyTorch `SparseAutoencoder` with ReLU encoder, decoder, L1 sparsity.
- `sae/training.py` (197 lines): training loop, reconstruction + sparsity loss, checkpointing.
- `sae/checkpoint.py`, `sae/metrics.py`, `sae/association.py` (347 lines), `sae/interpretation.py` (352 lines), `sae/config.py`.
- `models/adapter.py`, `models/activations.py`, `models/huggingface.py`, `models/manager.py`, `models/inference.py` provide white-box activation capture contracts.
- Tests with genuine `torch` tensors and a `TinyAdapter` (`tests/unit/test_models_runtime.py`, SAE tests).

**Evidence**
- No stubbed/fake SAE math found: encoder/decoder are real modules; no random scores returned in production paths.
- `features/` API stage is `unavailable` (`E_SAE_UNAVAILABLE` / `E_MODEL_UNAVAILABLE`) rather than returning fabricated features.

**Gaps / findings**
- No licensed/available SAE checkpoint and no real LLM was executed; activation capture is not validated against a real HuggingFace model.
- `features/` package (feature aggregation/feature cards) is a scaffold only.
- SAE features are not wired into detection, explanation, or the API path.
- Association/interpretation outputs are association-only; no causal validation.

**Verdict:** The SAE implementation is authentic (not a fake), but authenticity of the *research pipeline* is unvalidated.

---

### 2.5 Counterfactual validity — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `counterfactual/engine.py` (359 lines): single-feature `ablate`/`modify` interventions over SAE decoder directions, activation hooks, output comparisons, deterministic seeds, effects/budget.
- `counterfactual/pairwise.py` (325 lines): factorial 2×2 contrasts and non-additivity estimates.
- `counterfactual/higher_order.py` (424 lines): order-3 intervention sets and higher-order effects.
- Tests: `test_counterfactual_engine.py`, `test_pairwise_counterfactual.py`, `test_higher_order_counterfactual.py` use `TinyAdapter` and synthetic effects.

**Evidence**
- Runtime: `counterfactual_analyze: false`; API returns `partial` with `effects: []` and `counterfactual` stage `unavailable`.
- Orchestrator maps `counterfactual_analyze → ("counterfactual",)`, and no real stage is registered.

**Gaps / findings**
- Not integrated into the orchestrator/HTTP path; no real model/SAE run.
- Paper Algorithm 4's **Pearson co-activation screening**, **control interventions**, and screening thresholds are not implemented.
- Effects are model-internal output comparisons, not real-world causal effects — correctly labeled, but not validated.
- `docs/research-alignment.md`'s gate ("causal claims only after intervention") is respected; no causal claims are made.

---

### 2.6 Pairwise interactions — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `counterfactual/pairwise.py`: 2×2 factorial contrast (`00`, `10`, `01`, `11`), interaction effect, duplicate/collision handling, budget.
- Test `test_pairwise_counterfactual.py::test_pairwise_contrast_detects_non_additive_synthetic_effect` verifies detection of a synthetic non-additive effect.

**Gaps / findings**
- Only factorial contrast is implemented; paper §5.5/Algorithm 4 Pearson co-activation screening is absent.
- No statistical significance/CI over repeats in the pairwise engine.
- Not wired into API; no real-model validation.

---

### 2.7 Higher-order interactions — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `counterfactual/higher_order.py`: order-3+ subsets, inclusion-exclusion-style higher-order effects, combinatorial budget controls.
- Test `test_higher_order_counterfactual.py` (synthetic order-3 effect).

**Gaps / findings**
- Same integration and validity gaps as pairwise.
- No sampling strategy for large feature sets validated at paper scale; no real features.

---

### 2.8 Activation steering — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `steering/engine.py` (430 lines): genuine additive decoder-direction steering with hooks.
- `steering/risk_controller.py` (428 lines): risk/guardrail policy.
- `steering/adaptive.py` (422 lines): adaptive/iterative strength policy.
- `steering/functional.py` (243 lines): functional constraint evaluation.
- Tests: `test_steering_engine.py`, `test_adaptive_steering.py`, `test_functional_steering.py` (test doubles).

**Evidence**
- Runtime: `prevention_steer: false`; `prevention/steer` returns `plan=None`, steering stages `unavailable`.

**Gaps / findings**
- Not integrated into orchestrator/API; no real model/SAE.
- Materially differs from paper Algorithm 7 (iterative security-aware generation/feedback with `V_known`, `S_req`, `C_sec`, retry budget `B`, functional suite `Q`, acceptance `τ_sec`). This audit separates the two: steering code is real, Algorithm 7 is not implemented.

---

### 2.9 Detection reliability — PARTIALLY IMPLEMENTED

**What exists**
- `detection/engine.py` (267 lines), `fusion.py` (676 lines), `classification.py` (659 lines), `evidence.py` (511 lines), `ast_analysis.py` (678 lines), `context.py`, `llm.py`, `config.py`, `models.py`.
- Deterministic evidence grouping, family weighting, redundancy damping, noisy-OR fusion, CFG-reachability and sanitizer refutation.
- Integrated into `scan_file`/`scan_workspace`/`detection_analyze`.

**Evidence — this is the strongest negative finding**
- A controlled probe on a file containing SQL string concatenation, `subprocess.run(..., shell=True)`, `open(request.args.get("f"))`, and `pickle.loads(data)` produced **only CWE-502 unsafe deserialization**. SQL injection, command injection, and path traversal were **not reported**.
- Static stage `unavailable` (`E_TOOL_MISSING`): Semgrep and Bandit are not installed. No CodeQL/Joern either.
- `detection/fusion.py` explicitly documents: "The result is a heuristic prioritization score. It is not a probability."
- No trained classifier, no `θ_d`, no `τ_d`, no calibration dataset, no held-out evaluation.

**Gaps / findings**
- Paper Algorithm 2's multi-view representation `[x_lex; x_syn; x_sem; x_str; x_sec]` and trained `p = DETECTION_MODEL(X_all, θ_d)` are absent.
- Recall is demonstrably incomplete even for textbook patterns; this is a rule-coverage gap, not merely a calibration gap.
- Four API/unit tests around `analysisAvailable` fail, so capability semantics are inconsistent with the test contract.

**Status rationale:** Detection runs and produces real findings, but reliability relative to the paper is not established.

---

### 2.10 Explainability — PARTIALLY IMPLEMENTED

**What exists**
- `explain/engine.py` (evidence-grounded explanations; preserves epistemic types: observation/inference/hypothesis/association/output-comparison).
- `SAEFeatureReference` explicitly refuses semantic claims.
- Integrated into `explanation_analyze` (capability `true`).

**Gaps / findings**
- No localization score/attribution `L(r_i)=αa_i+βs_i+γt_i+δn_i` and no per-region `a_i, s_i, t_i, n_i` terms.
- No SAE-feature attribution (features are unwired) and no counterfactual evidence in explanations.
- No explanation-quality evaluation (comprehensibility, faithfulness, localization metrics are unimplemented as measured outputs).
- `docs/research-alignment.md` references `explain/graph.py`, which does not exist.

---

### 2.11 Repair reliability — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `repair/engine.py` (473 lines): LLM repair prompting with prompt-injection hardening, patch normalization, constraints.
- `repair/context.py` (346 lines): repository context building.
- `repair/ranking.py` (214 lines): candidate ranking.
- `repair/workflow.py` (446 lines): 12-step proposal-only workflow, states `PENDING → SECURITY_PASSED → FUNCTIONAL_PASSED → FULLY_VERIFIED / FAILED / INCONCLUSIVE`, independent verification.
- Integrated: `repair_generate: true`.

**Evidence**
- Live probe: `repair` returns `partial` / `INCONCLUSIVE`, `patch=null` because no LLM is configured.
- Extension applies patches only after diff preview and explicit approval (`src/repair/patchApplication.js`); engine never writes user source.

**Gaps / findings**
- No real LLM patch generation executed; no repair benchmark, no functional test suite per repo, no regression results.
- Proposal-only: no auto-apply, no multi-candidate search in the HTTP path, no patch correctness statistics.
- Reliability (repair rate, security preservation, regression rate) is unmeasured.

---

### 2.12 Independent verification — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- `verification/engine.py` (958 lines): independent static security verification, patch application to a temp copy, verifier verdicts (`verified_security_improvement`, `partial_improvement`, failure, inconclusive).
- `verification/functional.py` (537 lines): functional verification.
- `sandbox/executor.py`: consent-gated execution (`allow_network`, `allow_privileged`, `allow_destructive`).
- Integrated: `verification_run: true`; repair workflow invokes it independently of the generator.

**Evidence**
- Live probe: verification returned `partial` / `inconclusive_verification` when the supplied patch did not apply cleanly.
- Health reports `sandboxBackend: "docker"`, but Docker execution was **not functionally validated** (no image/container run in this environment).

**Gaps / findings**
- Dynamic/execution verification path is unvalidated; "safe when sandbox unavailable" behavior is implemented but not proven under adversarial code.
- Independent analyzer verification depends on Semgrep/Bandit/CodeQL/Joern, all unavailable here.
- `docs/research-alignment.md` references `verification/verifier.py`, which does not exist.

---

### 2.13 Experimental reproducibility — PARTIALLY IMPLEMENTED

**What exists**
- `experiments/config.py`: canonical JSON, SHA-256, environment/run manifests.
- `experiments/datasets.py` (595 lines): dataset cards/manifests.
- `experiments/splits.py` (318 lines): repository-level, temporal, CWE-based, cross-language splits.
- `experiments/evaluation.py`: runner, prerequisites, observations.
- `experiments/groups.py`: E0–E8 experiment groups.
- `experiments/export.py`.
- `evaluation/metrics.py`: detection, localization, repair, explainability, performance metrics (incl. PR-AUC).
- `evaluation/statistics.py` (645 lines): bootstrap CI, permutation, Wilcoxon, Mann–Whitney, t-test, Cohen's d, Cliff's delta, Holm–Bonferroni, BH.
- `evaluation/ablation.py`, `comparisons.py`, `reporting.py`.

**Evidence**
- `grep -rln "bugdhor.experiments\|bugdhor.evaluation" security-engine/tests` → only `tests/integration/INTEGRATION_TEST_REPORT.md`; **no automated tests** for these packages.
- No datasets, checkpoints, run manifests, or results are present.

**Gaps / findings**
- The infrastructure is real, but unexecuted and untested. Reproducibility cannot be claimed without a runnable experiment and recorded outputs.
- Paper §7 dataset selection (CodeXGLUE, Big-Vul, Devign, Juliet, DiverseVul, PrimeVul) is not satisfied; no licensed data is committed.
- No seeds/trials/results recorded.

**Status rationale:** Infrastructure only; no reproducibility demonstrated.

---

### 2.14 Security / privacy — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- Bearer-token middleware (optional), request-size limits, request-context/request-ID, RFC 9457 problem details, CORS configuration (`api/middleware.py`, `api/app.py`).
- Workspace-root allowlisting and file-path inspection (`core/orchestrator.py`, `api/routes/scan.py`).
- Consent-gated sandbox execution; no network/privileged/destructive actions without flags.
- Prompt-injection hardening for LLM repair prompts.
- VSIX excludes tests, secrets, lockfiles, caches, datasets, weights (`vscode-extension/.vscodeignore`).
- Local backend token probe: 401 without/wrong token, 200 with correct token.

**Gaps / findings**
- Token is optional by default; local unauthenticated mode is the default.
- No third-party security review or fuzzing; Docker sandbox escape resistance unverified.
- Execution-based verification and model/LLM paths not adversarially tested.
- `docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md` explicitly disclaims proof of security; that disclaimer is appropriate.

---

### 2.15 Testing coverage — PARTIALLY IMPLEMENTED

**What exists**
- 36 backend test files, **454 tests** (448 pass, 6 fail).
- 230 extension tests pass (`npm test`).
- Unit coverage of detection, SAE, counterfactual, steering, repair, verification, parsing, static adapters, API.
- API tests for health, scan, analysis, errors, OpenAPI, security.

**Gaps / findings**
- No tests for `experiments/` or `evaluation/`.
- No end-to-end tests with a real LLM, real SAE checkpoint, real Semgrep/Bandit/CodeQL/Joern, or Docker.
- Counterfactual/steering tests use synthetic doubles; they prove mechanics, not research validity.
- No performance/load tests, no sandbox escape tests, no dataset-driven evaluation.
- Six failing tests mean the suite is not green.
- No coverage measurement reported.

---

### 2.16 Documentation — PARTIALLY IMPLEMENTED

**What exists**
- Extensive docs: `README.md`, `docs/architecture.md` (1,217 lines), `docs/research-alignment.md` (549 lines), `docs/research-methodology.md`, `docs/implementation-mapping.md`, `docs/api.md`, `docs/user-guide.md`, `docs/release-checklist.md`, module docs.
- `docs/implementation-mapping.md` is generally honest about partial/unavailable capabilities.

**Documentation defects found and their remediation (2026-11-16)**

1. **`README.md` Status** previously said the project does **not** implement detection, SAE extraction, counterfactuals, steering, repair, or verification. **Corrected:** status now distinguishes wired detection/explanation/repair/verification from unwired SAE/counterfactual/steering and the `features/` scaffold.
2. **`README.md` core-module bullet** previously said `sae/` and `features/` provide "genuine SAE feature extraction." **Corrected:** `features/` is labeled a scaffold.
3. **`docs/architecture.md`** previously said no detection/SAE/counterfactual/steering/repair/verification capability is implemented. **Corrected:** status now reflects the partial pipeline, and the layout/responsibility tables are explicitly labeled target vs. implemented.
4. **`docs/research-alignment.md`** previously said the paper text/equations/section numbers "were not supplied." **Corrected:** it now points to `research-compliance-report.md` for traceability against `Research.txt`.
5. **`docs/research-alignment.md`** previously referenced nonexistent modules (`models/runtime.py`, `features/extractor.py`, `steering/planner.py`, `steering/steerer.py`, `steering/evaluate.py`, `explain/graph.py`, `verification/verifier.py`). **Corrected:** the focus-area table now cites existing modules and reports the missing capabilities.
6. **No fabricated metrics or citations were found.** Performance numbers in `docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md` are local micro-benchmarks and must not be presented as research results.

**Remaining documentation work**
- `docs/architecture.md` still contains a target-layout tree with planned files; the added note prevents misreading, but a future pass should prune or mark each entry.
- `docs/implementation-mapping.md` uses "Implemented (conditional)" for SAE/counterfactual/steering libraries; this is accurate for libraries but must be read together with the integration status in this audit.
- Release notes must disclose every unavailable stage and the absence of empirical validation.

---

### 2.17 Extension installation — IMPLEMENTED AND VERIFIED

**What exists**
- VSIX: `vscode-extension/bug-dhor-0.1.0.vsix`, **45 files, 104,319 bytes**.
- SHA-256: `6ee5a897fe886634a56f8d34aa9af6a26ff8d974f1956b657abf34d4e40875d3`.
- Manifest: `name: bug-dhor`, `version: 0.1.0`, 13 commands, `engines.vscode: ^1.90.0`, no runtime npm dependencies.

**Evidence**
- Archive inspected: required `package.json`, `README.md`, six `media/*` assets, `src/**`; no secrets/tests/weights/datasets/nested VSIX.
- Clean install into temporary VS Code extensions/user-data dirs succeeded; extension listed as `your-publisher-id.bug-dhor@0.1.0`; temp dirs removed.
- Extension unit tests: 230 passed.

**Gaps / findings**
- Interactive activation/dashboard/webview behavior was **not** exercised in a real VS Code UI session; only CLI install + listing.
- **Not marketplace-ready:** publisher is the placeholder `your-publisher-id`, `repository` is absent, `license` is absent.
- The extension does not start the backend; users must run it separately.

---

### 2.18 Performance — IMPLEMENTED BUT NOT FULLY VALIDATED

**What exists**
- Local measurements in `docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md`.
- Backend suite completes in ~7–8 s; extension suite passes.
- Bounded resource controls: request-size limits, analysis budgets in counterfactual, timeouts.

**Gaps / findings**
- No full-scale performance evaluation of model inference, SAE training, activation capture, static analyzers, or sandbox execution.
- No memory/latency benchmarks on real repositories or models; no concurrency/load testing.
- Paper §6.13 computational considerations are not validated.
- Existing micro-benchmark numbers are environment-specific and must not be generalized.

---

## 3. Fake, simulated, or placeholder implementations

**Conclusion: no production code fabricates research results.** Unavailable stages return explicit `unavailable`/`partial` statuses, and heuristic scores are labeled non-probabilistic. The following are nonetheless placeholders/scaffolds and must not be described as implemented:

| Item | Finding |
|---|---|
| `security-engine/src/bugdhor/features/__init__.py` | Scaffold only; no feature extraction/aggregation/cards. |
| `artifacts/`, `contracts/`, `ingestion/` | Empty scaffolds (`__init__.py` only). |
| `core/orchestrator.py` | `model_capture`, `sae_features`, `feature_aggregation`, `counterfactual`, `steering_plan`, `steering_evaluation` are default `UnavailableStage`. |
| `prevention/steer` | Returns `plan=None`; no paper prevention loop. |
| `features/extract`, `counterfactual/analyze` | Return `partial` with empty results. |
| Test doubles (`TinyAdapter`, `FakeAdapter`) | Test-only; correctly not used as production evidence. |
| `docs/research-alignment.md` referenced modules | Do not exist. |

No hard-coded fake metrics, invented citations, or simulated benchmark outputs were found.

---

## 4. Mandatory unresolved gaps (release blockers)

1. **Trained multi-view detection + calibration** (Algorithm 2, §5.5) — not implemented.
2. **Pearson co-activation screening and control interventions** (Algorithm 4, §5.7) — not implemented.
3. **Paper-defined prevention loop** (Algorithm 7, §5.12) — not implemented; steering is an unwired substitute.
4. **Localization/attribution scoring** (Algorithm 5, §5.8) — not implemented.
5. **End-to-end validation** with a real LLM, SAE checkpoint, analyzers, and Docker sandbox — not performed.
6. **Experimental evaluation** on licensed benchmarks with seeds/trials/statistics — not performed; evaluation code is untested.
7. **Backend test suite green** — 6 failures must be resolved.
8. **Documentation integrity** — core drift (README status, architecture status, research-alignment paper-text/module references) was corrected in this audit; remaining work is to prune the target-layout tree and audit release notes for unavailable-stage disclosure.
9. **Marketplace metadata** — publisher/repository/license placeholders must be resolved before any public release.

---

## 5. Audit conclusion

Bug Dhor is a substantial, largely honest engineering scaffold with genuine implementations of SAE math, program analysis, evidence fusion, repair workflow, independent verification, and evaluation helpers. It is **not** a complete or validated implementation of the paper:

- The paper's central learned detection model, interaction-screening methodology, prevention loop, and localization attribution are missing.
- The operational pipeline deliberately reports unimplemented research stages as `unavailable`; this is correct behavior, not completion.
- Detection recall on a simple adversarial probe was poor, and the test suite is red.
- No empirical results exist, so no performance/effectiveness claim in the paper can be attributed to this repository.

**Do not mark the project complete, submission-ready, or research-validated.** Resolve the blockers in §4 first.
