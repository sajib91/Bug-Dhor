# Bug Dhor — Mathematical Implementation Mapping

**Purpose.** Map every numbered equation, the unnumbered localization score, Algorithms 1–9, and the §7 metrics to the code that implements them — or to the explicit gap when no implementation exists.

**Audit date:** 2026-11-16  
**Codebase:** `security-engine/src/bugdhor/`  
**Constraint:** documentation only; no algorithm or source file was modified.

**Companion documents:**

- [`research/mathematical-framework-audit.md`](mathematical-framework-audit.md) — verdicts and issue register.
- [`research/mathematical-formulations.md`](mathematical-formulations.md) — variables, assumptions, corrected forms.

---

## 0. Evidence levels

| Level | Meaning |
|---|---|
| **E0** | Paper only; no code. |
| **E1** | Library code exists and is unit-tested with synthetic fixtures; not on the HTTP/orchestrator path, or no real artifact. |
| **E2** | Wired into the orchestrator/API, but the required model/checkpoint/analyzer is absent, so a real end-to-end result cannot be produced. |
| **E3** | Executed end-to-end with a real model/checkpoint/analyzer and real input. |
| **E4** | E3 plus a completed experiment with reported metrics and uncertainty. |

**No formulation in this repository reaches E4.** No detector was trained, no SAE checkpoint is registered, no benchmark experiment was executed, and the backend suite is currently red (6 failures, 448 passes at last run). Line numbers are approximate as of the audit date and may shift after edits.

> **Status update (2026-11-17).** The counterfactual-validation slice has since been
> executed end-to-end on two real Qwen checkpoints with trained SAEs, a declared
> outcome probe, bootstrap intervals, and a saved artifact. By the definitions
> above that slice is **E3/E4 at artifact level**, but it is *not* a vulnerability
> benchmark: the corpus is synthetic and the labels are generator labels. The rest
> of this document describes the 2026-11-16 state and remains a snapshot of the
> code-gap audit. See `mathematical_validation_report.md` and
> `mathematical-consistency-report.md` for the executed experiment and the
> implementation-consistency verdicts.

---

## 1. Module inventory

| Module | Role | Own evidence level |
|---|---|---|
| `parsing/` | Tokenization, AST parsing, normalization, function/line locations | E2 (used by scan/detection/explain) |
| `program_analysis/analysis.py` | Builds AST/CFG/DFG views per module/function | E2 |
| `program_analysis/cfg.py` | Control-flow graph construction | E2 |
| `program_analysis/dfg.py` | Def-use graph construction | E2 |
| `program_analysis/taint.py` | Source/sanitizer/sink taint paths | E2 (intraprocedural limits) |
| `models/activations.py` | Layer discovery and activation capture | E1 (requires a model runtime) |
| `models/inference.py` | Generation wrapper | E1 |
| `sae/model.py` | ReLU encoder / linear decoder / L1 loss | E1 |
| `sae/training.py` | Training, validation, feature extraction | E1 |
| `sae/metrics.py` | Reconstruction, L0, active-feature stats | E1 |
| `sae/association.py` | Means, activation frequency, selectivity, cross-dataset stability | E1 |
| `sae/interpretation.py` | Feature annotation/report assembly | E1 |
| `counterfactual/engine.py` | Feature intervention runner, activation hooks | E1 |
| `counterfactual/pairwise.py` | Four-cell interaction contrast + descriptive CI | E1 |
| `counterfactual/higher_order.py` | Alternating-sign higher-order contrast | E1 |
| `steering/engine.py` | Decoder-direction steering for compatible local models | E1 |
| `steering/adaptive.py` | Importance scores, interaction-aware strength allocation | E1 |
| `steering/risk_controller.py` | CWE policy, priority, banding, optional calibration | E1 |
| `steering/functional.py` | Functional constraints for steering candidates | E1 |
| `detection/engine.py` | Evidence collection and finding assembly | E2 |
| `detection/fusion.py` | Family-wise noisy-OR heuristic score | E2 |
| `detection/classification.py` | Category/CWE/severity mapping | E2 |
| `explain/engine.py` | Evidence-grounded explanation assembly | E2 |
| `repair/engine.py` | Approval-gated repair proposal generation | E1 |
| `repair/ranking.py` | Hard constraints + weighted candidate ranking | E1 |
| `repair/workflow.py` | Generate → verify → report workflow, never auto-applies | E2 |
| `verification/engine.py` | Before/after static, taint, CWE, regression checks | E2 |
| `verification/functional.py` | Sandboxed test discovery/execution | E1 (Docker unavailable) |
| `evaluation/metrics.py` | Detection/localization/repair/explainability/performance metrics | E1, no tests |
| `evaluation/statistics.py` | Bootstrap, permutation, Wilcoxon, MWU, t-test, effect sizes, Holm/BH | E1, no tests |
| `evaluation/ablation.py` | Ablation runner + multiplicity summary | E1, no tests |
| `experiments/` | Dataset loading, splits, evaluation harness | E1, no executed experiment |
| `core/orchestrator.py` | Operation composition and stage availability | E2 |
| `risk/models.py`, `risk/normalization.py` | Evidence/claim/reliability contracts, explicit exclusion reasons | E1 |
| `risk/engine.py`, `risk/config.py` | Eq. (28)–(29) index, dependency groups, noisy-OR, interactions, uncertainty | E1 |
| `risk/calibration.py`, `risk/evaluation.py` | Group-disjoint Platt calibration, acceptance gates, evaluation CLI | E1, no labelled dataset |
| `decision/rules.py`, `decision/adaptive.py`, `decision/engine.py` | Transparent baseline, gated utility ranking, advisory trace | E1 |

---

## 2. Equation-to-code map

Legend: **Impl.** = implementation status; `✔` full, `◐` partial, `✘` none; **Ev.** = evidence level.

### 2.1 §5.1–5.2 — Representation and classification

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (1) | Five-view `x(c)` | `program_analysis/analysis.py::analyze_parsed`; `parsing/parser.py`; `program_analysis/taint.py` | Builds AST, CFG, DFG, taint per file/function; no concatenated vector, no `Φ` | ◐ | E2 (views), E0 (Eq. 1) | No view encoders, no dimensions, no normalization, no concatenation, no feature vector artifact |
| (2) | `P(y=1|c)=σ(f_θ(x))` | None | No trained classifier or `θ_det` | ✘ | E0 | Entire detector model |
| (3) | `ŷ=I[P≥η]` | None | No threshold selection | ✘ | E0 | `η` protocol |
| (4) | Weighted BCE | None | No training loop for a detector | ✘ | E0 | Loss, optimizer, splits, calibration |

**Note.** `detection/engine.py` and `detection/fusion.py` produce findings and a heuristic score. They do **not** implement Eq. (2)–(4), and the code explicitly labels the fusion score as not a probability (`LIM-DET-01`).

### 2.2 §5.3–5.4 — SAE and latent association

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (5) | `z=ReLU(W_e h+b_e)` | `sae/model.py::SparseAutoencoder.encode` | `torch.relu(self.encoder(activations))` | ✔ | E1 | No `h` normalization/preprocessing; no real checkpoint |
| (6) | `ĥ=W_d z+b_d` | `sae/model.py::SparseAutoencoder.decode` | `self.decoder(latents)` | ✔ | E1 | — |
| (7) | `L_SAE = MSE + λ‖z‖₁` | `sae/model.py::loss` | MSE reconstruction + `config.sparsity_coefficient * latents.abs().mean()` | ✔ | E1 | `λ` selection protocol; dead-feature handling; decoder normalization |
| (8) | `z_ij=ReLU(w_j^T h_i+b_j)` | `sae/model.py::encode`, `feature_activations` | Row of encoder applied with ReLU | ✔ | E1 | Paper's `w_j` column/row notation mismatch |
| (9) | `Δμ_j=E[z_j|y=1]−E[z_j|y=0]` | `sae/association.py::_association` | `vulnerable_mean − secure_mean` across samples | ✔ | E1 | No CI; no multiplicity control |
| (10) | `d_j=Δμ_j/s_{j,pool}` | None | Not computed; `_selectivity` and activation frequency are used instead | ✘ | E0 | Pooled SD, Hedges' g, CI, variance guard |

**Selectivity.** `association.py::_selectivity` is a project-specific score, not Eq. (10). It must not be reported as Cohen's *d*.

### 2.3 §5.5 — Interactions

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (11) | Pearson `ρ_ij` | None | `select_association_pairs` and `preselect_features` rank by `abs(selectivity)`, not Pearson | ✘ | E0 | Correlation screening; binary/zero-inflation handling |
| (12) | `I_ij=g(1,1)−g(1,0)−g(0,1)+g(0,0)` | `counterfactual/pairwise.py::estimate_interaction` | `joint.mean − feature_a.mean − feature_b.mean + baseline.mean` | ✔ | E1 | No control interventions; no outcome-scale declaration; CI descriptive only |
| (13) | Continuous `I_ij(a,b)` | `counterfactual/higher_order.py::estimate_higher_order`; `pairwise.py` | Alternating sign over powerset; pairwise is the 2-feature case | ◐ | E1 | No dose-response API; no validated intervention operator; no permutation null |

**CI detail (`pairwise.py`).** The standard error uses independent-cell sample variances:

```
se = sqrt(var(joint)/n_joint + var(a)/n_a + var(b)/n_b + var(base)/n_base)
CI = contrast ± 1.96·se
```

The module docstring and comments describe this as descriptive, not a significance test. That is the correct interpretation.

**Higher-order detail (`higher_order.py`).** `estimate_higher_order` requires all `2^k` cells and computes `Σ_T (−1)^{k−|T|} mean(T)`. It reports complexity (`complexity_report`) and preselection by selectivity. It does not implement a variance estimator matched to the alternating contrast.

### 2.4 §5.6 — Attribution

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (14) | `A_j=|∂f/∂x_j|` | None | No gradient path | ✘ | E0 | Differentiable detector, gradient capture |
| (15) | Integrated Gradients | None | — | ✘ | E0 | Baseline, interpolation steps, completeness check |
| (16) | `A_j^SAE=|∂f/∂z_j|` | None | — | ✘ | E0 | Chain rule through decoder; latent attribution |

**Explain module.** `explain/engine.py` accepts `SAEFeatureReference`, `FeatureInteractionReference`, and `CounterfactualReference` and assembles them into an explanation. It does not compute any attribution value. It is an evidence assembler, not Eq. (14)–(16).

### 2.5 §5.7–5.8 — AST, CFG, DFG, taint

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (17) | `G_AST=(V,E)` | `parsing/parser.py`; tree-sitter AST | Parsed AST nodes/spans | ✔ | E2 | No graph object exposed as `G_AST`; no GNN |
| (18) | `G_CFG=(V,E)` | `program_analysis/cfg.py::ControlFlowGraph` | Basic blocks + typed edges; `successors`/`predecessors` | ✔ | E2 | Interprocedural/exception limits documented in `LIMITATIONS.md` |
| (19) | `A_uv` | `program_analysis/cfg.py` | NetworkX `DiGraph` edges; no explicit adjacency matrix | ◐ | E2 | Matrix form not materialized; not needed by current code |
| (20) | GNN message passing | None | No graph neural network | ✘ | E0 | Node features, `h^(0)`, `A` use, readout, training |
| (21) | `G_DFG=(V,E)` | `program_analysis/dfg.py::DataFlowGraph` | Def-use/closure/return/call edges | ✔ | E2 | Intraprocedural; unresolved uses reported |
| (22) | `Reachable_DFG(s,k)=1` | `program_analysis/taint.py::analyze_taint` | Source→sink reachability with sanitizer/propagator rules | ◐ | E2 | May-analysis; no runtime validation; interprocedural limits |
| (23) | `P_unsafe={p:q(p)=0}` | `taint.py::TaintFinding`, `unsanitized_findings` | Reports potential paths; sanitizer adequacy is rule-based | ◐ | E2 | Binary sanitizer treatment; unknown paths not separated |

### 2.6 §5.9 — Evidence fusion

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (24) | Evidence vector `e_i` | `detection/evidence.py`; `detection/engine.py` | Evidence items with family, type, polarity, support, locations | ◐ | E2 | No concatenated vector; no per-modality embedding |
| (25) | `h_fusion=F_φ(e,m)` | None | No learned fusion function | ✘ | E0 | Architecture, training, missing-modality handling |
| (26) | Weighted baseline `S_i` | None | No weighted mean; code uses noisy-OR | ✘ | E0 | Weights, `q_ij` normalization, denominator guard |
| (27) | `P_fusion=σ(w_f^T h+b_f)` | `detection/fusion.py::with_calibration` (optional only) | Optional caller-supplied calibrator; no learned head | ✘ | E0 | Training, calibration fit, probability claim |

**What the code actually does (`detection/fusion.py::_heuristic_risk`):**

```
family_score = 1 − Π_{items in family} (1 − decayed_support)
combined     = 1 − Π_{families} (1 − family_score)       # with family caps
refutation   = 1 − Π_{refuting items} (1 − effective_support)
penalty      = min(0.95, refutation_scale × refutation)
value        = clamp(combined × (1 − penalty), 0, 1)
band         = thresholds.band(value)
```

This is a documented heuristic prioritization score. It is **not** Eq. (25)–(27). `_family_scores` applies caps per family (`detection/config.py`), and `_noisy_or` is the standard independent-or formula.

### 2.7 §5.10 — Risk

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (28) | `R=αP+βS+γE+δI` | `risk/engine.py::UnifiedRiskEngine._risk_index`; `steering/risk_controller.py` | Unified engine: normalized weighted sum with renormalization; steering controller: different additive policy with clamp | ◐ | E1 | Unified engine implements the arithmetic literally, but its `p_hat` is heuristic without a validated artifact; no calibrated `P(v)` ships |
| (29) | Threshold bands | `risk/models.py::RiskThresholds.band`; `risk_controller.py::_band`; `detection/config.py::Thresholds.band` | Highest band whose threshold is ≤ value | ✔ | E1/E2 | Unified engine uses lowercase bands including `unknown`; other modules use different labels; thresholds are configuration |

**Exact risk-controller semantics (`risk_controller.py::assess`):**

```
feature_score     = mean/aggregate of feature activations or contrasts
interaction_score = mean absolute interaction contrast (mapped from `estimate.contrast`)
static_score      = mean of static evidence scores meeting `static_evidence_threshold`
heuristic_score   = caller-supplied heuristic risk
priority = clamp((offset + w_f·feature + w_i·interaction + w_s·static + heuristic) × context_multiplier,
                 max_priority)
band = highest configured band with threshold ≤ priority
strength = 0 if no feature evidence or priority < steering_threshold
           else min(max_steering_strength,
                    max(0, (base + priority·scale) × context_multiplier))
calibrated_probability = optional model-specific calibrator result, else None
```

The optional calibrator is the only path to a probability. When absent, `calibrated_probability` is `None` and the decision records fallback reasons. That is the correct behavior.

### 2.8 §5.11–5.14 — Repair, correctness, preservation, unified model

| Eq. | Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|---|
| (30) | `P'=G_ψ(P,L,Q,π_r)` | `repair/engine.py::RepairEngine.propose`; `repair/workflow.py::RepairWorkflow.run` | Prompt builder + adapter generation (or proposal-only) | ◐ | E1 | No `π_r` contract; no guarantee of non-empty candidate; approval-gated |
| (31) | `P*=argmin J` | `repair/ranking.py::PatchRanker.rank` | Selects max score among candidates satisfying hard constraints | ◐ | E1 | Different objective; no `J_repair` |
| (32) | `J_repair=λ_sL_s+λ_fL_f+λ_rL_r+λ_dL_d` | `repair/ranking.py::_weighted_score` | Weighted normalized score over 8 terms: security 4, functional 3, regression 3, syntax 2, CWE 3, repo consistency 2, complexity 1, unnecessary changes 2 | ✘ (as written) | E1 | No operational loss definitions; weights differ; no `L_diff` |
| (33) | `P'⊨Q_func ∧ P'⊨Q_security` | `repair/ranking.py::MandatoryConstraints`; `repair/workflow.py` | Hard constraints: syntax, CWE compliance, independent verification; optional functional/regression requirements | ◐ | E2 | `⊨` is operationalized as test/tool checks; inconclusive handling |
| (34) | `Pass_func=ΣI[P'(t)=o_t]/|T|` | `verification/functional.py::_aggregate_pass_rate` | Pass counts from test harness output | ◐ | E1 | Harness pass rate, not exact output equality |
| (35) | `V_func=I[Pass=1]` | `verification/functional.py::_overall_status`; `repair/workflow.py::_derive_state` | Pass/fail/inconclusive | ◐ | E1 | Docker unavailable; no executed functional verification |
| (36) | `{P}P'{Q}` | None | No Hoare logic or formal verifier | ✘ | E0 | Specifications, invariants, verifier |
| (37) | `V_target(P')∩V_target(P)=∅` | `verification/engine.py::_compare_static_findings`, `_compare_taint`, `_cwe_specific_check` | Before/after finding comparison by CWE/location/taint | ◐ | E2 | Correspondence heuristic; detector-relative |
| (38) | `V(P')\V(P)=∅` | `verification/engine.py::_compare_static_findings` | New findings after patch are flagged | ◐ | E2 | Detector-relative; external tools optional |
| (39) | `Accept=V_syntax∧V_func∧V_reg∧V_security` | `verification/engine.py::_classify`; `repair/workflow.py::_derive_state` | Conjunction with three-valued checks; `FULLY_VERIFIED` only if all pass | ◐ | E2 | Inconclusive policy; no formal `V_reg`/`V_security` definition |
| (40) | `x=Φ(c)` | `program_analysis/analysis.py` | Per-file views, no `Φ` | ◐ | E2 | Same as Eq. (1) |
| (41) | `z=SAE(h_m(c))` | `models/activations.py`; `sae/model.py` | Activation capture + SAE encode are separate; not wired together in an operation | ◐ | E1 | No end-to-end activation→SAE→feature result |
| (42) | `e=Ψ(·)` | `detection/engine.py`; `program_analysis/` | Evidence assembled from heuristic and program analysis | ◐ | E2 | No interaction/SAE evidence in the live path |
| (43) | `h_u=F_φ(e,m)` | None | No learned fusion | ✘ | E0 | — |
| (44) | `p̂=σ(f_θ(h_u))` | None | No trained fused head | ✘ | E0 | — |
| (45) | `A=Attribution(p̂,x,z)` | None | — | ✘ | E0 | — |
| (46) | `R=R_fn(p̂,S,E,I)` | `steering/risk_controller.py` | Different policy formula | ◐ | E1 | No `p̂`; no `S/E/I` decomposition |
| (47) | `c_secure=G_prevent(...)` | `core/orchestrator.py::prevention_steer` | Returns `PreventionResult(plan=None, ...)`; stages declared unavailable | ✘ | E2 (endpoint), E0 (algorithm) | No generation loop, no steering plan |
| (48) | `P'=G_repair(P,A,Q_security)` | `repair/engine.py`, `repair/workflow.py` | Proposal generation; no attribution input | ◐ | E1 | No `A`; no iterative loop |
| (49) | `P*=P' if Accept else P` | `repair/workflow.py` | Never auto-applies; requires explicit user approval | ◐ | E2 | Acceptance is workflow state, not automatic replacement |

**Unified-engine note (audit addition, 2026-11-18).** `risk/engine.py` realizes
parts of (42), (45), and (46) as an E1 library: dependency-group evidence
aggregation produces a heuristic `p_hat`, `contributions`/`explanation` provide
attribution-shaped output, and Eq. (28)–(29) produce the index and bands. It
does **not** implement (43)–(44): there is no learned `F_φ` or fused head.
Stages (47)–(49) remain in the separate repair/recommendation/verification
workflow and require human approval. `decision/*` consumes `RiskResult` but is
not an equation in Eq. (40)–(49). See `docs/unified-risk-engine.md` and
`docs/adaptive-decision-policy.md`.

---

## 3. Unnumbered localization formula

| Construct | Code location | Code semantics | Impl. | Ev. | Gap |
|---|---|---|---|---|---|
| `L(r_i)=αa_i+βs_i+γt_i+δn_i` and Alg. 5 normalized form | `explain/engine.py::ExplainableVulnerabilityEngine.explain` | Assembles claims, evidence, taint paths, and limitations; no score, no ranking, no threshold | ✘ | E1/E2 | `a_i` (attribution), normalization, mask, `τ_l`, ranking, metrics |

`explain/engine.py` produces a `VulnerabilityExplanation` with claims, evidence, source/sink paths, and limitations. That is a valuable **evidence report**, but it is not a localization score. The paper's §5.8 formula is not implemented anywhere.

---

## 4. Algorithm-to-code map

### Algorithm 1 — Overall Bug Dhor Security Framework

| Paper stage | Implementation | Status | Evidence |
|---|---|---|---|
| Input validation / snapshot | `core/orchestrator.py`, `api/` | ✔ | E2 |
| Preprocessing | `parsing/`, `program_analysis/` | ✔ | E2 |
| Multi-feature detection | `detection/engine.py` (heuristic) | ◐ | E2 |
| SAE features | `features_extract` stage | ✘ (unavailable) | E2 (reports unavailable) |
| Counterfactual analysis | `counterfactual_analyze` | ✘ (empty effects) | E2 |
| Evidence fusion | `detection/fusion.py` | ◐ (different formula) | E2 |
| Risk assessment | `steering/risk_controller.py` | ◐ (policy, not Eq. 28) | E1 |
| Prevention | `prevention_steer` | ✘ (`plan=None`) | E2 |
| Repair | `repair_generate` | ◐ (proposal + verification workflow) | E2 |
| Verification | `verification_run` | ◐ (static/taint; no Docker) | E2 |
| Report | API models | ✔ | E2 |

**Verdict: PARTIALLY IMPLEMENTED.** The orchestrator is honest about unavailable stages; that is not the same as implementing Algorithm 1.

### Algorithm 2 — Vulnerability Detection

| Paper step | Implementation | Status |
|---|---|---|
| Build `x(c)` | Program-analysis views only | ◐ |
| Classify with `f_θ` | None | ✘ |
| Threshold `η` | None | ✘ |
| CWE assignment | `detection/classification.py` (category → default CWE) | ◐ |
| Return probability + evidence | Heuristic score + evidence | ◐ |

**Verdict: PARTIALLY IMPLEMENTED.** The live probe reported only CWE-502 for SQLi/command-injection/path-traversal/deserialization samples, which is evidence that the heuristic classifier is not the paper's multi-view detector.

### Algorithm 3 — SAE-Based Security Feature Extraction

| Paper step | Implementation | Status |
|---|---|---|
| Capture activations | `models/activations.py` | ◐ (needs runtime) |
| Train SAE | `sae/training.py::SAETrainer.fit` | ✔ (E1) |
| Encode latents | `sae/model.py::encode` | ✔ (E1) |
| Aggregate feature activations | `sae/training.py::extract_features`; `sae/association.py` | ✔ (E1) |
| Associate with labels | `sae/association.py::analyze_features` | ◐ (no Eq. 10) |
| Return feature dictionary | `FeatureDictionary.save` | ✔ (E1) |

**Verdict: PARTIALLY IMPLEMENTED.** The SAE math is real and tested; the operation is not wired to a live model, and no checkpoint/artifact exists.

### Algorithm 4 — Feature Interaction Analysis

| Paper step | Implementation | Status |
|---|---|---|
| Compute association screening (Eq. 11) | None (selectivity used instead) | ✘ |
| Select pairs with `τ_corr` | `select_association_pairs` (selectivity ranking) | ◐ |
| Run four-cell interventions (Eq. 12) | `pairwise.py` | ✔ (E1) |
| Estimate interaction with `τ_int` | `estimate_interaction` (no threshold semantics) | ◐ |
| Higher-order subsets | `higher_order.py` | ✔ (E1) |
| Return interaction evidence | `PairwiseInteractionResult`, `HigherOrderResult` | ✔ (E1) |

**Verdict: PARTIALLY IMPLEMENTED.** The factorial contrast is real. Pearson screening, control interventions, threshold semantics, and API wiring are missing.

### Algorithm 5 — Explainable Vulnerability Localization

| Paper step | Implementation | Status |
|---|---|---|
| Extract candidate units | `parsing/functions.py`, `parsing/locations.py` | ◐ |
| Attribution score `s_neural` | None | ✘ |
| AST relevance | AST span matching in `explain/engine.py` | ◐ |
| CFG/DFG relevance | Taint path evidence | ◐ |
| Security evidence `s_sec` | `explain/engine.py` evidence | ✔ |
| Localization score `s_loc` | None | ✘ |
| Threshold `τ_l` | None | ✘ |
| Rank and return | Sort not implemented | ✘ |
| Explanation | `VulnerabilityExplanation.to_human` | ✔ |

**Verdict: PARTIALLY IMPLEMENTED.** Explanation exists; localization scoring/ranking does not.

### Algorithm 6 — Multi-Feature Evidence Fusion

| Paper step | Implementation | Status |
|---|---|---|
| Normalize modality evidence | `detection/evidence.py` (support values) | ◐ |
| Apply availability mask | Not a vector | ✘ |
| Learn/weight fusion | Heuristic noisy-OR | ◐ |
| Fuse to probability | No probability claim | ✘ |
| Attach evidence provenance | `FusionResult`, `_explain` | ✔ |

**Verdict: PARTIALLY IMPLEMENTED, DIFFERENT FORMULA.** The code's noisy-OR is a defensible engineering baseline; it is not Eq. (25)–(27).

### Algorithm 7 — Security-Aware Vulnerability Prevention

| Paper step | Implementation | Status |
|---|---|---|
| Build security constraints | `steering/` policies, `RepairPromptBuilder` | ◐ |
| Generate code | Model adapter | ◐ (needs model) |
| Analyze generated code | `detection/engine.py` | ✔ (heuristic) |
| Iterative feedback loop | None | ✘ |
| Apply steering | `steering/engine.py`, `adaptive.py` (unwired) | ◐ |
| Acceptance `τ_sec` | `steering/functional.py` | ◐ |
| Return `c_safe` | `prevention_steer` returns `plan=None` | ✘ |

**Verdict: NOT IMPLEMENTED as an algorithm.** Steering components exist at E1; the loop and endpoint do not.

### Algorithm 8 — Automated Vulnerability Repair

| Paper step | Implementation | Status |
|---|---|---|
| Build repair context | `repair/context.py` | ✔ |
| Localize repair target | Input to prompt | ◐ |
| Generate candidates | `repair/engine.py::propose` | ✔ (E1) |
| Apply in isolation | `repair/engine.py::_apply_patch` | ✔ (E1) |
| Rank candidates | `repair/ranking.py` | ✔ (E1) |
| Iterate until acceptable | Not implemented | ✘ |
| Return accepted patch | `repair/workflow.py` (requires approval) | ◐ |

**Verdict: IMPLEMENTED BUT NOT FULLY VALIDATED.** Proposal + ranking + workflow exist; no iterative loop, no full Eq. (32), no real execution.

### Algorithm 9 — Patch Validation and Security Verification

| Paper step | Implementation | Status |
|---|---|---|
| Syntax validity | `verification/engine.py::_syntax_valid`; `repair/workflow.py::_validate_syntax` | ✔ |
| Functional tests | `verification/functional.py` | ◐ (Docker unavailable) |
| Regression comparison | `verification/functional.py::_compare`; `_regression_risk` | ✔ |
| Security re-analysis | `verification/engine.py::_run_static_scans` | ◐ (tools optional) |
| Taint comparison | `_compare_taint` | ✔ |
| New-vulnerability detection | `_compare_static_findings` | ◐ (detector-relative) |
| Accept/reject | `_classify`; `_derive_state` | ✔ (three-valued) |
| Hoare verification | None | ✘ |

**Verdict: IMPLEMENTED BUT NOT FULLY VALIDATED.** The honest three-valued classification is a strength. Docker-backed execution and formal verification are absent.

---

## 5. Metric-to-code map

### 5.1 Detection

| Paper metric | Code | Status |
|---|---|---|
| Accuracy | `aggregate_detection_metrics` | ✘ (not a field) |
| Precision | ✔ | ✔ |
| Recall | ✔ | ✔ |
| F1 | ✔ | ✔ |
| MCC | ✔ | ✔ |
| ROC-AUC | — | ✘ |
| PR-AUC | `_pr_auc` | ◐ (custom estimator, not average precision) |
| Brier score | — | ✘ |
| ECE | — | ✘ |
| Multi-class/CWE metrics | — | ✘ |

### 5.2 Explainability

| Paper metric | Code | Status |
|---|---|---|
| Comprehensiveness | — | ✘ |
| Sufficiency | — | ✘ |
| Attribution faithfulness | — | ✘ |
| Attribution stability | — | ✘ |
| SAE feature stability | `sae/association.py::_stability`, `_cross_dataset_metrics` | ◐ |
| Explanation consistency | `compute_explainability_metrics` (averages supplied values) | ◐ |

### 5.3 Localization

| Paper metric | Code | Status |
|---|---|---|
| Line precision | `compute_localization_metrics` | ✔ |
| Line recall | ✔ | ✔ |
| Line F1 | — | ✘ |
| Line accuracy | — | ✘ |
| Exact-set match | `localization_accuracy` | ✔ (misleading name) |
| IoU | — | ✘ |
| Hit@k | — | ✘ |
| MRR | — | ✘ |

### 5.4 Repair

| Paper metric | Code | Status |
|---|---|---|
| PGR | `repair_success_rate` | ◐ (name/semantics differ) |
| CSR | — | ✘ |
| TPR | `functional_pass_rate` (mean) | ◐ |
| FC | — | ✘ |
| PSR | `verified_repair_success` | ◐ |
| SRR | `security_regression_rate` | ◐ |
| SFR | — | ✘ |
| ART | — | ✘ |
| ANC | — | ✘ |

### 5.5 Prevention

| Paper metric | Code | Status |
|---|---|---|
| VR | — | ✘ |
| VRR | — | ✘ |
| ΔVR | — | ✘ |
| FPass | — | ✘ |
| FPR_preserve | — | ✘ |
| SCR | — | ✘ |

### 5.6 Statistical inference

| Capability | Code | Tests |
|---|---|---|
| Bootstrap CI | `bootstrap_ci` | No automated tests |
| Paired permutation | `paired_permutation_test` | No automated tests |
| Wilcoxon signed-rank | `wilcoxon_signed_rank` | No automated tests |
| Mann–Whitney U | `mann_whitney_u` | No automated tests |
| Paired t-test | `paired_t_test` | No automated tests |
| Cohen's d (paired) | `cohens_d_paired` | No automated tests |
| Cliff's delta | `cliffs_delta` | No automated tests |
| Holm–Bonferroni | `holm_bonferroni` | No automated tests |
| Benjamini–Hochberg | `benjamini_hochberg` | No automated tests |
| Ablation + multiplicity | `evaluation/ablation.py` | No automated tests |

**Note.** `evaluation/metrics.py` and `evaluation/statistics.py` have no dedicated test files in `security-engine/tests/`. This is a concrete gap: the formulas may be correct, but they are unverified.

---

## 6. Wiring and stage availability

`core/orchestrator.py` declares these stages unavailable:

| Stage | Reason code | Effect |
|---|---|---|
| `model_capture` | `E_MODEL_UNAVAILABLE` | No activations |
| `sae_features` | `E_SAE_UNAVAILABLE` | No SAE latents |
| `feature_aggregation` | `E_FEATURE_UNAVAILABLE` | No feature vectors |
| `counterfactual` | `E_COUNTERFACTUAL_UNAVAILABLE` | Empty effects |
| `steering_plan` | `E_STEERING_UNAVAILABLE` | No plan |
| `steering_evaluation` | `E_STEERING_UNAVAILABLE` | No evaluation |
| `repair` | `E_REPAIR_UNAVAILABLE` | Repair stage unavailable by default |
| `verification` | `E_VERIFICATION_UNAVAILABLE` | Verification unavailable unless configured |

Operation-level behavior:

| Operation | Live behavior |
|---|---|
| `features_extract` | Returns `analysis_available` from stage status; `features=[]` |
| `counterfactual_analyze` | Returns `effects=[]` |
| `prevention_steer` | Returns `plan=None`, empty guardrails/evaluation/limitations |
| `repair_generate` | Runs the repair/verification workflow; approval-gated |
| `verification_run` | Runs independent verification if configured |
| `scan` / `detection` / `explanation` | Real heuristic/program-analysis results |

This is the correct honesty posture: the API does not fabricate SAE, counterfactual, steering, or prevention outputs. It also means the mathematical components behind those endpoints cannot be experimentally evaluated from the running system today.

---

## 7. Gap summary

### 7.1 Mathematical components with no implementation

1. Five-view representation `Φ` (Eq. 1, 40) — no concatenated feature vector.
2. Trained detector `f_θ`, threshold `η`, weighted/calibrated BCE (Eq. 2–4, 44).
3. Pooled standardized effect `d_j` (Eq. 10).
4. Pearson screening `ρ_ij` (Eq. 11).
5. Gradient/IG/SAE attribution (Eq. 14–16, 45).
6. GNN message passing (Eq. 20).
7. Learned fusion `F_φ` and logistic head (Eq. 25, 27, 43, 44).
8. Risk decomposition `αP+βS+γE+δI` (Eq. 28).
9. Repair objective `J_repair` (Eq. 31–32) as written.
10. Hoare correctness (Eq. 36).
11. Localization score `L(r_i)` and ranking (§5.8, Alg. 5).
12. Prevention loop `G_prevent` (Eq. 47, Alg. 7).
13. Prevention metrics (VR/VRR/FPass/SCR).
14. Several §7 metrics (accuracy, ROC-AUC, Brier/ECE, localization F1/IoU/Hit@k/MRR, repair CSR/SFR/ART/ANC).

### 7.2 Components implemented but not validated with real artifacts

1. SAE encoder/decoder/loss (Eq. 5–7) — synthetic tests only.
2. Latent association (Eq. 9) — synthetic labels/features.
3. Pairwise interaction contrast (Eq. 12–13) — synthetic outcomes.
4. Higher-order contrast — synthetic outcomes.
5. Decoder-direction steering — synthetic/tiny adapter tests.
6. Adaptive steering and risk controller — synthetic policy tests.
7. Detection fusion heuristic — unit tests; live probe produced a single CWE classification on a multi-CWE sample.
8. Repair proposal/ranking — synthetic candidates.
9. Independent verification — static/taint paths tested; no Docker execution.
10. Evaluation metrics/statistics — code exists, no dedicated tests, no experiment.

### 7.3 Components implemented differently from the paper

| Paper | Code | Risk |
|---|---|---|
| Eq. (25)–(27) fusion | Family-wise noisy-OR | Must not be reported as Eq. (27) |
| Eq. (28) risk | CWE-policy additive priority (steering controller) | Must not be reported as Eq. (28) |
| Eq. (28) arithmetic | Unified `risk/engine.py` weighted sum | Arithmetic matches Eq. (28), but `p_hat` is heuristic unless a validated artifact supplies a probability |
| Eq. (32) repair objective | 8-term weighted ranking | Must not be reported as Eq. (32) |
| Eq. (34) exact output equality | Test-harness pass rate | Paper should adopt the operational form |
| Eq. (36) Hoare | Static/taint checks | Must not claim formal correctness |
| Eq. (11) Pearson | Selectivity ranking | Must not claim Pearson screening |

---

## 8. Supported vs unsupported claims

### 8.1 Supported by code and tests (E1–E2)

- The SAE is a real PyTorch ReLU/linear SAE with an L1 loss (Eq. 5–7).
- The pairwise and higher-order interaction contrasts are real arithmetic over measured cells (Eq. 12–13 generalization).
- AST/CFG/DFG/taint analysis is real and wired into scan/detection/explanation.
- Decoder-direction steering and adaptive strength allocation are real code paths, though unwired.
- The CWE risk policy, banding, and optional calibration are real code paths.
- The unified risk engine's group aggregation, Eq. (28)–(29) arithmetic, and
  calibration acceptance gates are real, unit-tested library code (E1), with no
  labelled dataset or validated artifact shipped.
- The advisory decision baseline and gated deterministic utility ranking are
  real, unit-tested library code (E1), not an optimal or learned policy.
- Repair proposal generation, ranking, hard constraints, and approval gating are real.
- Independent verification performs real before/after static and taint comparisons.
- The code is explicit that fusion is not a probability and that repairs are never auto-applied.

### 8.2 Not supported (E0)

- Any claim that Eq. (2)–(4) is implemented or evaluated.
- Any claim that Eq. (10), (11), (14)–(16), (20), (25)–(27), (31)–(32), or (36) is implemented as written. Eq. (28)'s arithmetic is implemented by `risk/engine.py`, but Eq. (28) as written requires a calibrated `P(v)`, and none is shipped.
- Any claim of detection, localization, repair, prevention, or explanation performance.
- Any claim of calibrated probabilities.
- Any claim that the five-view representation or unified model is operational.
- Any claim that the framework is research-complete or submission-ready.

---

## 9. Cross-reference to prior audits

This mapping is consistent with:

- `final-audit.md` — research contribution **PARTIALLY IMPLEMENTED**; SAE/counterfactual/steering/repair/verification **IMPLEMENTED BUT NOT FULLY VALIDATED**; detection/explainability/reproducibility **PARTIALLY IMPLEMENTED**; overall **NOT COMPLETE**.
- `research-compliance-report.md` — §5 formulations partially implemented, Algorithms 2/4/5/7 incomplete, no empirical results.

No status in those reports is upgraded by this mapping. The additional detail here is the equation-level evidence level and the explicit list of formulations that are implemented differently from the paper.
