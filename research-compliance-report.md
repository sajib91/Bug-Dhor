# CRAFT-Sec — Research Compliance Report

**Date:** 2026-11-16  
**Paper source:** `Research.txt` (*An Explainable Multi-Feature Security Framework for Vulnerability Detection, Prevention, and Automated Repair in Large Language Models*)  
**Companion:** `final-audit.md`  
**Rule:** A component is compliant only when the paper-specified behavior exists, is wired into an operational path, and is validated with real artifacts. Presence of a file is not compliance.

> **Paper status:** `Research.txt` is a proposal/methodology. It contains no empirical results, tables of measured outcomes, or reported metrics. This report therefore maps **specified mechanisms** to code; it does not validate any effect size.

---

## 1. Compliance summary

| Layer | Compliant items | Partial items | Missing items |
|---|---|---|---|
| Architecture components (§4.3, 16) | 3 | 10 | 3 |
| Mathematical formulations (§5.1–5.14) | 3 | 8 | 3 |
| Algorithms (1–9) | 0 | 6 | 3 |
| Evaluation metrics (§7.2–7.6) | 0 | 5 | 0* |
| Ablations / statistics / reproducibility (§7.10–7.15) | 0 | 4 | 0* |

\* Metric/statistics **functions** exist, but none are validated or used in a run. They are marked partial below.

**Overall research compliance: NOT COMPLIANT.** Core contributions (learned multi-view detection, interaction screening, prevention loop, localization attribution) are absent or materially different, and no experiment has been executed.

---

## 2. §4.3 — Architecture components (1–16)

| # | Paper component | Status | Implementation evidence | Gap |
|---|---|---|---|---|
| 1 | LLM-generated code input | IMPLEMENTED BUT NOT FULLY VALIDATED | `api/routes/scan.py`, `api/schemas/scan.py`, caller-supplied editor text, `core/orchestrator._inspect` | No LLM generation/ingestion; input is existing source only. |
| 2 | Code preprocessing | IMPLEMENTED AND VERIFIED | `parsing/parser.py`, `parsing/languages.py`, `parsing/models.py`; `preprocessing` stage `ok` in live probe | Language/tool coverage limited to supported parsers. |
| 3 | Multi-feature vulnerability detection | PARTIALLY IMPLEMENTED | `detection/engine.py`, `fusion.py`, `classification.py`, `evidence.py`, `ast_analysis.py` | No lexical/semantic embeddings, no trained classifier, no calibrated probability. |
| 4 | SAE-based feature extraction | IMPLEMENTED BUT NOT FULLY VALIDATED | `sae/model.py`, `training.py`, `checkpoint.py`, `association.py`, `interpretation.py`; `models/activations.py` | No real checkpoint/model run; `features/` aggregation is a scaffold; not wired. |
| 5 | Feature interaction analysis | PARTIALLY IMPLEMENTED | `counterfactual/engine.py`, `pairwise.py`, `higher_order.py` | No Pearson screening/control interventions; not wired; synthetic tests only. |
| 6 | Explainable vulnerability localization | PARTIALLY IMPLEMENTED | `explain/engine.py` (evidence-grounded explanations) | No localization score, region attribution, or faithfulness evaluation. |
| 7 | AST analysis | IMPLEMENTED AND VERIFIED | `program_analysis/analysis.py`, `parsing/` AST; `detection/ast_analysis.py`; `tests/unit/test_parsing_*` | Tree-sitter/ast coverage varies by language. |
| 8 | Control flow graph analysis | IMPLEMENTED AND VERIFIED | `program_analysis/cfg.py`, `analysis.py`; reachability used in fusion/refutation | No path-sensitivity/soundness validation. |
| 9 | Data flow graph analysis | IMPLEMENTED BUT NOT FULLY VALIDATED | `program_analysis/dfg.py`, `variables.py`; used by taint | Intra-procedural limits. |
| 10 | Taint analysis | IMPLEMENTED BUT NOT FULLY VALIDATED | `program_analysis/taint.py`; `verification/engine.py` uses taint | Detection probe missed path traversal/SQLi despite taint machinery. |
| 11 | Multi-feature evidence fusion | IMPLEMENTED BUT NOT FULLY VALIDATED | `detection/fusion.py` (grouping, family weighting, noisy-OR, refutation) | Heuristic score, not the paper's probabilistic fusion; no calibrated posterior. |
| 12 | Security risk assessment | PARTIALLY IMPLEMENTED | Severity/priority in `detection/models.py`, `fusion.py` | No paper risk formula, no calibrated probability, no validated thresholds. |
| 13 | Vulnerability prevention | NOT IMPLEMENTED | Adjacent: `steering/*` (unwired); `prevention/steer` returns `plan=None` | Paper iterative generate/analyze/feedback loop absent. |
| 14 | Automated program repair | IMPLEMENTED BUT NOT FULLY VALIDATED | `repair/engine.py`, `context.py`, `ranking.py`, `workflow.py`; `repair_generate: true` | No real LLM run; live probe returns `patch=null`; proposal-only. |
| 15 | Patch validation | IMPLEMENTED BUT NOT FULLY VALIDATED | `verification/engine.py`, `verification/functional.py`, `repair/workflow.py`; `verification_run: true` | Docker/execution path unvalidated; analyzers unavailable. |
| 16 | Explainable security report generation | IMPLEMENTED BUT NOT FULLY VALIDATED | `explain/engine.py`, API responses, extension dashboard | No report export, no localization/attribution section, no evaluation. |

---

## 3. §5 — Mathematical formulations (5.1–5.14)

| Formula area | Paper requirement | Status | Code / gap |
|---|---|---|---|
| 5.1 Source code representation | Multi-view vector / structural views | PARTIALLY IMPLEMENTED | AST/CFG/DFG/taint products exist; no concatenated `[x_lex; x_syn; x_sem; x_str; x_sec]` vector. |
| 5.2 Vulnerability classification | Learned classifier over representation | NOT IMPLEMENTED | Rule/evidence classification in `detection/classification.py`; no trained model. |
| 5.3 SAE encoding | `z = ReLU(W_e h + b_e)` | IMPLEMENTED BUT NOT FULLY VALIDATED | `sae/model.py` encoder is genuine. |
| 5.4 Latent feature activation | Sparse latent features per layer/position | IMPLEMENTED BUT NOT FULLY VALIDATED | `sae/association.py`, `models/activations.py`; no real-model capture. |
| 5.5 Feature interaction strength | Pearson co-activation + intervention contrast | PARTIALLY IMPLEMENTED | Factorial contrast in `counterfactual/pairwise.py`; **no Pearson screening**. |
| 5.6 Feature attribution | `L(r_i)=αa_i+βs_i+γt_i+δn_i` | NOT IMPLEMENTED | No attribution terms/score anywhere in `explain/` or `detection/`. |
| 5.7 AST and CFG representation | Structural graph encoding | IMPLEMENTED AND VERIFIED | `program_analysis/cfg.py`, `detection/ast_analysis.py`. |
| 5.8 Data flow and taint propagation | DFG + taint | IMPLEMENTED BUT NOT FULLY VALIDATED | `program_analysis/dfg.py`, `taint.py`; no whole-program validation. |
| 5.9 Multi-feature evidence fusion | Fuse complementary evidence | IMPLEMENTED BUT NOT FULLY VALIDATED | `detection/fusion.py` implements transparent heuristic fusion, explicitly not a probability. |
| 5.10 Security risk scoring | Calibrated risk/probability | PARTIALLY IMPLEMENTED | Heuristic prioritization only; calibrator hook exists but no fitted calibrator. |
| 5.11 Repair candidate generation | Generate patch candidates | PARTIALLY IMPLEMENTED | `repair/engine.py` + ranking; requires LLM; default yields no patch. |
| 5.12 Patch correctness | Functional correctness | IMPLEMENTED BUT NOT FULLY VALIDATED | `verification/functional.py`; no real test-suite execution validated. |
| 5.13 Security preservation | Re-analysis shows improvement | IMPLEMENTED BUT NOT FULLY VALIDATED | `verification/engine.py` verdicts; analyzers absent; probe inconclusive. |
| 5.14 Unified mathematical model | End-to-end integrated model | NOT IMPLEMENTED | No unified scoring/optimization object linking all terms. |

---

## 4. §6 — Algorithms 1–9

### Algorithm 1 — Overall CRAFT-Sec Security Framework
**Status: PARTIALLY IMPLEMENTED**

- `core/orchestrator.py` implements an end-to-end pipeline with real file inspection, preprocessing, program analysis, evidence fusion, explanation, repair, and verification.
- Stages 4/5/7 (`model_capture`, `sae_features`, `feature_aggregation`, `counterfactual`, `steering_plan`, `steering_evaluation`) are `UnavailableStage`.
- No single algorithm object executes the paper's full information flow; the pipeline is a service composition.

### Algorithm 2 — Vulnerability Detection
**Status: PARTIALLY IMPLEMENTED**

- Implemented: multi-source evidence collection (`detection/evidence.py`), AST rules (`ast_analysis.py`), classification (`classification.py`), fusion/refutation (`fusion.py`), orchestrator integration.
- Missing: trained parameters `θ_d`, multi-view vector `X_all`, model `DETECTION_MODEL`, threshold `τ_d`, calibrated probabilities.
- Live evidence: probe detected only CWE-502 from four injected vulnerability classes; static analyzers unavailable.

### Algorithm 3 — SAE-Based Security Feature Extraction
**Status: IMPLEMENTED BUT NOT FULLY VALIDATED**

- Implemented: real SAE encoder/decoder/training/checkpointing, activation contracts, association and interpretation.
- Missing: end-to-end activation capture from a real model, feature aggregation (`features/` scaffold), API wiring (`features/extract` returns `partial`), real artifact validation.

### Algorithm 4 — Feature Interaction Analysis
**Status: PARTIALLY IMPLEMENTED**

- Implemented: single-feature interventions, 2×2 factorial contrast, higher-order contrasts, budget control.
- Missing: Pearson co-activation screening, control interventions, screening thresholds, statistical significance over repeated interventions, API/orchestrator integration, real-feature validation.

### Algorithm 5 — Explainable Vulnerability Localization
**Status: PARTIALLY IMPLEMENTED**

- Implemented: evidence-grounded explanations preserving claim type, CWE/category, locations, evidence sources.
- Missing: localization objective and attribution terms (`a_i, s_i, t_i, n_i`), region ranking, SAE/counterfactual evidence, faithfulness/localization metrics.

### Algorithm 6 — Multi-Feature Evidence Fusion
**Status: IMPLEMENTED BUT NOT FULLY VALIDATED**

- Implemented: evidence grouping, duplicate resolution, category/CWE classification, family-wise scoring with redundancy decay, noisy-OR across families, CFG/sanitizer refutation.
- Gaps: no validated fusion weights, no calibration, no comparison against baselines, no dataset evaluation.

### Algorithm 7 — Security-Aware Vulnerability Prevention
**Status: NOT IMPLEMENTED**

- Paper requires iterative generation with known vulnerability constraints `V_known`, requirements `S_req`, policy `C_sec`, attempt budget `B`, functional suite `Q`, and security acceptance `τ_sec`.
- Repository contains isolated activation-steering code (`steering/engine.py`, `risk_controller.py`, `adaptive.py`, `functional.py`) and a prevention API, but:
  - steering is not wired into the orchestrator (`prevention_steer: false`);
  - `prevention/steer` returns `plan=None`;
  - there is no generation/feedback loop or `B`-attempt procedure.
- **Do not describe activation steering as an implementation of Algorithm 7.**

### Algorithm 8 — Automated Vulnerability Repair
**Status: IMPLEMENTED BUT NOT FULLY VALIDATED**

- Implemented: repository context, prompt hardening, candidate generation/ranking, proposal-only workflow, explicit approval before application.
- Gaps: no configured LLM, live probe `patch=null`, no repair-rate measurement, no multi-candidate empirical comparison.

### Algorithm 9 — Patch Validation and Security Verification
**Status: IMPLEMENTED BUT NOT FULLY VALIDATED**

- Implemented: independent security verification, patch application to isolated temp state, functional verification hooks, verdict taxonomy, workflow integration.
- Gaps: Semgrep/Bandit/CodeQL/Joern unavailable; Docker sandbox not executed; no adversarial/regression validation.

---

## 5. §7 — Evaluation protocol compliance

### 5.1 Dataset selection and preprocessing (§7.2–7.4)
**Status: NOT IMPLEMENTED (no data).**

- Paper names CodeXGLUE, Big-Vul, Devign, Juliet, DiverseVul, PrimeVul.
- `experiments/datasets.py` provides manifest/card infrastructure, but no dataset is present or licensed in the repo.
- No preprocessing run, no splits materialized.

### 5.2 LLM selection and generation (§7.5)
**Status: NOT IMPLEMENTED (no model run).**

- `models/huggingface.py` and adapter contracts exist; no model checkpoint or generation run.
- No LLM-generated code corpus.

### 5.3 Baselines (§7.6)
**Status: PARTIALLY IMPLEMENTED (infrastructure only).**

- `evaluation/comparisons.py` has cross-model/cross-dataset comparison helpers.
- No baseline was run; no results.

### 5.4 Hardware/software environment (§7.7)
**Status: IMPLEMENTED BUT NOT FULLY VALIDATED.**

- `experiments/config.py` records platform, Python version, environment/run manifest and hashes.
- Environment was recorded only in code, not in an executed experiment.

### 5.5 Training/testing configuration and hyperparameters (§7.8–7.9)
**Status: PARTIALLY IMPLEMENTED.**

- Config structures exist (`experiments/config.py`, `sae/config.py`, `detection/config.py`).
- No training run, no hyperparameter sweep, no recorded configuration for a real experiment.

### 5.6 Repeated trials and seeds (§7.10–7.11)
**Status: PARTIALLY IMPLEMENTED.**

- Deterministic seeds are used in counterfactual and experiments code; `evaluation/statistics.py` supports repeated-measure tests.
- No repeated trials were executed; no seed registry/output exists.

### 5.7 Cross-dataset / CWE-level evaluation (§7.12–7.13)
**Status: PARTIALLY IMPLEMENTED.**

- Split helpers exist: `experiments/splits.py` (repository-level, temporal, CWE-based, cross-language).
- No cross-dataset or CWE-level results.

### 5.8 Ablation experiments (§7.14)
**Status: PARTIALLY IMPLEMENTED.**

- `evaluation/ablation.py` implements `run_ablation` and multiple-comparison summarization; `experiments/groups.py` defines E0–E8.
- **No automated tests, no executed ablation, no output.**

### 5.9 Evaluation metrics (§7.2–7.6)
**Status: PARTIALLY IMPLEMENTED (functions only).**

| Metric family | Implemented | Validated / used |
|---|---|---|
| Detection: precision, recall, F1, ROC-AUC, PR-AUC | `evaluation/metrics.py` | No |
| Explainability metrics | `evaluation/metrics.py` | No |
| Localization metrics | `evaluation/metrics.py` | No |
| Repair metrics | `evaluation/metrics.py` | No |
| Prevention metrics | Not found as a dedicated metric implementation | No |
| Performance metrics | `evaluation/metrics.py` | Micro-benchmarks only |
| Statistical tests/CIs/effect sizes/multiple comparisons | `evaluation/statistics.py` | No |

### 5.10 Consolidated reporting / metric selection (§7.7–7.8)
**Status: PARTIALLY IMPLEMENTED.**

- `evaluation/reporting.py` and `experiments/export.py` exist.
- No report has been generated; no results, tables, or figures exist.

---

## 6. §5.15 / §6.14 — Established vs. proposed and reliability

- The paper distinguishes established formulations from proposed ones and requires causal caution for feature co-activation.
- The repository correctly avoids causal claims: `counterfactual/__init__.py`, `explain/engine.py`, and `docs/research-alignment.md` label effects/associations appropriately.
- However, the paper's proposed interaction validity procedure (Pearson screening + controlled interventions) is not implemented, so the methodological distinction is preserved only by **not** making claims, not by executing the required controls.

---

## 7. Reproducibility assessment (§5.16)

| Requirement | Status | Notes |
|---|---|---|
| Versioned configuration | IMPLEMENTED BUT NOT FULLY VALIDATED | `ExperimentConfig`, canonical JSON, config hashing. |
| Environment capture | IMPLEMENTED BUT NOT FULLY VALIDATED | Platform/version constants. |
| Deterministic splits | IMPLEMENTED BUT NOT FULLY VALIDATED | Stable hashing/round-robin; no materialized split. |
| Seed management | PARTIALLY IMPLEMENTED | Seeds accepted; no registry of executed seeds. |
| Run manifests/artifacts | IMPLEMENTED BUT NOT FULLY VALIDATED | Manifest code exists; no artifact store (`artifacts/` empty). |
| Recorded results | NOT IMPLEMENTED | No runs/results. |
| Re-execution instructions | IMPLEMENTED BUT NOT FULLY VALIDATED | Docs describe setup, but no end-to-end experiment command was verified. |
| Automated tests for experiment/evaluation code | NOT IMPLEMENTED | No tests reference `craftsec.experiments` or `craftsec.evaluation`. |

**Reproducibility claim: unsupported.** The infrastructure is a credible foundation, but reproducibility requires at least one fully recorded, re-runnable experiment.

---

## 8. Claims that must not be made

Until the blockers are resolved, the repository must not claim:

- that the paper's detection method is implemented (it is a heuristic fusion, not the trained multi-view model);
- that SAE features improve detection or explain findings (features are not wired);
- that pairwise/higher-order interactions were validated (only synthetic mechanics tests);
- that the prevention algorithm is implemented (steering ≠ Algorithm 7);
- that vulnerabilities are localized with attribution (no `L(r_i)`);
- any precision/recall/AUC/repair-rate/prevention-rate result;
- that the system is reproducible, benchmarked, or empirically validated;
- that the project is research-complete or publication-ready.

---

## 9. Minimum work to reach research compliance

1. Implement `features/` extraction/aggregation and wire model capture + SAE into the orchestrator.
2. Implement the trained multi-view detector, threshold `τ_d`, and a fitted calibrator with held-out data.
3. Implement Pearson co-activation screening, control interventions, and multiple-comparison-corrected interaction statistics; wire counterfactuals into the API.
4. Implement the Algorithm 7 prevention loop (generation + security feedback + retry budget + functional acceptance) or explicitly re-scope the contribution.
5. Implement localization/attribution scoring and per-region terms.
6. Establish at least one licensed benchmark, real model/SAE artifacts, analyzer toolchain, and Docker sandbox; run E0–E8 with recorded manifests/results.
7. Add tests for `experiments/` and `evaluation/`; make the backend suite green.
8. Correct documentation drift and add a traceability addendum keyed to `Research.txt` sections/equations/algorithms.

---

## 10. Conclusion

The repository implements a meaningful subset of the paper's **engineering mechanics** — parsing, AST/CFG/DFG/taint, evidence fusion, SAE math, intervention machinery, repair workflow, verification, and evaluation helpers — with commendable honesty about unavailable stages. It does **not** implement the paper's central learned detection, interaction-screening methodology, prevention loop, or localization attribution, and it has **no empirical results**. Research compliance is therefore **not achieved**.
