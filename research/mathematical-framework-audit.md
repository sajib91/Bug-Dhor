# CRAFT-Sec — Mathematical Framework Audit

**Audit date:** 2026-11-16  
**Audited source text:** `Research.txt` — *An Explainable Multi-Feature Security Framework for Vulnerability Detection, Prevention, and Automated Repair in Large Language Models*  
**Audited codebase:** `security-engine/` (Python package `craftsec`), `vscode-extension/`  
**Companion documents:**

- [`research/mathematical-formulations.md`](mathematical-formulations.md) — equation-by-equation definitions, variables, assumptions, and corrected alternatives.
- [`research/mathematical-implementation-mapping.md`](mathematical-implementation-mapping.md) — equation/algorithm-to-code map with evidence levels.

**Constraint observed:** no algorithm, model, or source file was modified for this audit. This is a documentation-only review.

---

## 0. What this audit does and does not establish

This audit checks three different things and keeps them separate:

1. **Mathematical validity** — is the equation well-formed, are its symbols defined, are its assumptions stated, and is the stated conclusion supported by the equation?
2. **Implementability** — can the equation be computed from data/artifacts that the project can realistically obtain, with a defined estimator and a defined failure mode?
3. **Implementation evidence** — is there code, is it wired into an operational path, and has it been executed with real (not synthetic) artifacts?

A formulation can be mathematically correct but unimplemented. It can also be implemented in code but be a **different formula** from the one in the paper. Both cases are reported explicitly.

### 0.1 Evidence levels used below

| Level | Meaning |
|---|---|
| **E0 — Paper only** | The formulation exists only in `Research.txt`. No code. |
| **E1 — Library code, synthetic tests** | Code exists and is unit-tested, but only with fixtures/`TinyAdapter`/`FakeAdapter`, and is not on the HTTP/orchestrator path. |
| **E2 — Wired, no real artifacts** | Code is reachable from the orchestrator/API, but the model/SAE/analyzer artifact required to produce a real result is absent. |
| **E3 — Executed with real artifacts** | Code was run end-to-end with a real model/checkpoint/analyzer and real input. |
| **E4 — Empirically validated** | E3 plus a completed experiment with reported metrics and uncertainty. |

No equation in this project reaches **E4**. Several reach **E1–E2**. None of the neural formulations reaches **E3**, because there is no trained detector, no SAE checkpoint, and no licensed benchmark run in this environment. This is consistent with `final-audit.md`, which marks the research contribution **PARTIALLY IMPLEMENTED** and the overall project **NOT COMPLETE**.

### 0.2 Status vocabulary

`final-audit.md` uses five statuses. This audit reuses them for the implementation column and adds mathematical statuses that are orthogonal to them:

| Mathematical status | Meaning |
|---|---|
| **Correct** | Well-formed and internally consistent under the stated assumptions. |
| **Correct (conditional)** | Correct only if an additional condition is met (stated in the finding). |
| **Under-specified** | Symbols, domains, normalization, or estimators are missing, so the equation is not yet testable as written. |
| **Notation defect** | The equation is mathematically fine but the notation is inconsistent or overloaded. |
| **Detector-relative** | The equation is well-formed but its truth value is defined only relative to an imperfect detector; absence of a finding is not evidence of absence. |

---

## 1. Executive verdict

`Research.txt` contains **49 numbered equations (1)–(49)**, one unnumbered localization score in §5.8, nine algorithms (1–9), and the metric definitions in §7.2–7.6. The mathematical core is conventional and mostly correctly transcribed: logistic classification, a ReLU/L1 sparse autoencoder, factorial interaction contrasts, graph reachability, weighted aggregation, indicator-based test metrics, and a conjunction of acceptance conditions.

The **substantive mathematical problems are not the algebra**; they are specification and inference problems:

1. **Several "models" are named but never defined.** `Φ`, `F_φ`, `G_ψ`, `G_repair`, `Ψ`, `Attribution`, `q(p)`, `L_security`, `L_function`, `L_regression`, `L_diff`, `s_{j,pool}`, and the availability mask are used as if defined. Some are defined in words elsewhere; several are not defined at all.
2. **Causal language is used for non-causal estimands.** SAE feature means, Pearson correlation, gradient attribution, and taint reachability are associational or may-analysis constructs. The paper repeatedly says so — which is good — but the component descriptions and algorithm names sometimes drift back into causal language ("contribute", "cause", "prevention").
3. **Probability claims outrun the evidence.** Eq. (2), (27), (28), and (44) are written as probabilities; no calibration procedure, calibration metric, or calibrated artifact exists. The code correctly refuses to call its fusion score a probability (`fusion.py` limitation `LIM-DET-01`), which is *more* honest than the paper.
4. **The unified model (§5.14) is a restatement, not a derivation.** It does not add constraints, a theorem, or an identification argument. It should be presented as a pipeline schematic, not as a mathematical model with independent content.
5. **Acceptance and verification equations are detector-relative.** Eq. (37)–(39) define "secure" as "the current tools found nothing". That is a valid engineering acceptance rule, but not the set-theoretic guarantee the notation suggests.
6. **The repair objective (Eq. 31–33) is not optimized anywhere.** The paper concedes this ("A language model does not necessarily optimize Equation (32) directly"). The code ranks candidates with a different weighted score and hard constraints. The equation should be relabelled as a *selection criterion*, not an optimization problem.

### 1.1 Equation status summary

| § | Equations | Mathematical status | Implementation status |
|---|---|---|---|
| 5.1 Representation | (1) | Under-specified | Partial (AST/CFG/DFG/taint exist; no five-view vector) |
| 5.2 Classification | (2)–(4) | Correct | **Not implemented** (no trained detector, no `θ`, no `η`) |
| 5.3 SAE | (5)–(7) | Correct (conditional on preprocessing) | Implemented at E1 (library + synthetic tests) |
| 5.4 Latent activation | (8)–(10) | (8) notation defect; (9) correct; (10) under-specified | (8)–(9) implemented; (10) **not implemented** |
| 5.5 Interactions | (11)–(13) | (11) conditional; (12)–(13) conditional on intervention validity | (12)–(13) implemented at E1; (11) **not implemented** |
| 5.6 Attribution | (14)–(16) | (14) correct as sensitivity; (15) conditional; (16) notation defect | **Not implemented** |
| 5.7 AST/CFG | (17)–(20) | (17)–(19) correct; (20) incomplete | (17)–(19) implemented; (20) **not implemented** |
| 5.8 DFG/taint | (21)–(23) | (21)–(22) correct as may-analysis; (23) under-specified | Implemented at E2 with intraprocedural limits |
| 5.9 Fusion | (24)–(27) | (24) under-specified (mask equation missing); (25)–(27) under-specified | **Different formulation** (heuristic noisy-OR) |
| 5.10 Risk | (28)–(29) | Correct as a linear index; calibration/normalization under-specified | Partial (CWE policy, not Eq. 28) |
| 5.11 Repair | (30)–(33) | Under-specified | Partial (proposal + ranking; no Eq. 32 optimizer) |
| 5.12 Correctness | (34)–(36) | (34) too strict; (35) correct; (36) correct but not computable as stated | Partial; no Hoare verification |
| 5.13 Preservation | (37)–(39) | Detector-relative | Partial; three-valued verification exists |
| 5.14 Unified | (40)–(49) | Restatement with notation collisions | Partial pipeline composition |
| §5.8 Localization | unnumbered | Under-specified | **Not implemented** (explanations exist, no localization score) |
| §7 Metrics | §7.2–7.6 | Mostly correct; some definitions too strict | Partial (see §6) |

### 1.2 Overall classification

| Dimension | Verdict |
|---|---|
| Equation inventory completeness | **Complete** — all numbered equations located and audited. |
| Algebra correctness | **Mostly correct** — no fatal algebraic errors. |
| Symbol/definition completeness | **Inadequate** — multiple undefined functions and parameters. |
| Causal identification | **Inadequate** — no identification assumptions or controls specified for causal claims. |
| Statistical inference | **Partial** — effect sizes and tests exist in code, but the paper does not specify estimators, CIs, or multiplicity control for equations (9)–(13). |
| Implementability | **Partial** — the deterministic program-analysis parts are implementable and implemented; the neural parts are not executable without artifacts. |
| Empirical testability | **Partial** — every component has a plausible experiment, but several claims (feature semantics, "prevention") are not falsifiable with the stated design. |
| Research-integrity risk | **High if results are claimed** — no results exist; the paper's "will be evaluated" framing is correct and must be preserved. |

---

## 2. Per-component findings

Each block uses the same fields required by the task: equation, variables, assumptions, correctness, implementability, code, missing components, evaluation. Full variable definitions and corrected forms are in `mathematical-formulations.md`; exact code locations are in `mathematical-implementation-mapping.md`.

### 2.1 SAE-based vulnerability-associated feature extraction — Eq. (5)–(10), Alg. 3

- **Equations:** (5) encoder, (6) decoder, (7) SAE loss, (8) latent activation, (9) mean difference, (10) standardized mean difference.
- **Variables:** `h ∈ R^d` activation; `W_e ∈ R^{d_s×d}`, `b_e ∈ R^{d_s}`; `z ∈ R^{d_s}`; `W_d ∈ R^{d×d_s}`, `b_d ∈ R^d`; `λ ≥ 0`; `N_h` activation count; `μ_{j,1}`, `μ_{j,0}`; `s_{j,pool}`.
- **Assumptions:** activation vectors are drawn from the same layer/position distribution as the analyzed code; L1 produces useful sparsity; vulnerable/secure groups are exchangeable except for the label; pooled SD is defined and non-zero; samples are independent.
- **Correctness:** (5)–(7) are the standard ReLU SAE with an L1 penalty. (9) is a raw mean difference and is scale-dependent. (10) is Cohen's *d* but `s_{j,pool}` is never defined; the standard pooled SD is `sqrt(((n_1−1)s_1² + (n_0−1)s_0²)/(n_1+n_0−2))`. For ReLU latents, which are zero-inflated, `s_{j,pool}` can be zero or unstable, so `d_j` can be undefined or explode.
- **Implementability:** (5)–(9) are directly computable. (10) is computable after defining the pooled SD, but needs a variance guard and a CI.
- **Code:** `sae/model.py` implements (5)–(7) faithfully. `sae/training.py` trains and validates. `sae/association.py` computes means, activation frequency, and selectivity but **not** the pooled standardized effect (10). There is no `H_norm` preprocessing step and no real checkpoint in the repository.
- **Missing:** pooled SD definition, Hedges' *g* correction, bootstrap CI, multiplicity control over features, dead-feature reporting, reconstruction/`R²` reporting, and a real SAE artifact.
- **Evaluation:** reconstruction MSE and variance explained; L0/L1 and dead-feature rate; per-feature `Δμ_j`, Hedges' *g*, bootstrap 95% CI, BH-adjusted *q*-values; stability of selected features across seeds and datasets. These are descriptive, not causal.

### 2.2 Sparse latent feature representations — Eq. (5)–(8)

- **Equations:** (5), (7), (8).
- **Variables:** as above; `z_{ij}` is the activation of feature `j` for sample `i`; `w_j` is the encoder row for feature `j`; `b_j` its bias.
- **Assumptions:** the L1 penalty induces a sparse code; the latent basis is identifiable enough to interpret; features are not polysemantic.
- **Correctness:** the equations are correct. The **claim** that the code is sparse is an objective, not a theorem: ReLU + L1 yields shrinkage and can still produce dense small activations. Sparsity must be measured (`L0`, Hoyer sparsity, activation frequency), not asserted.
- **Implementability:** Yes, fully.
- **Code:** `sae/model.py` (`encode`, `decode`, `loss`), `sae/metrics.py` (reconstruction/L0/sparsity if present), `sae/training.py`.
- **Missing:** formal sparsity target, dead-feature resampling, decoder-column normalization, and a documented `λ` selection protocol.
- **Evaluation:** Pareto curve of reconstruction loss vs L0/L1; dead-feature fraction; downstream stability of feature associations; ablation of `λ`.

### 2.3 Single-feature intervention — Eq. (8)–(13), counterfactual engine

- **Equations:** (8) activation; (12)/(13) factorial contrast specialized to one feature.
- **Variables:** `g(·)` is the declared outcome function (probability, logit, or detector score); intervention state `1`/`0` or magnitude `a`; baseline state.
- **Assumptions:** the intervention is well-defined, applied to the same input, and only changes the target feature; the outcome is measured on a comparable scale; no confounding by other features or by input distribution shift.
- **Correctness:** the one-feature contrast is well-formed, but the paper never defines the intervention operator (ablation, clamping, resampling, or decoder-direction steering). "0" is ambiguous between "feature off" and "reference condition". A raw probability-scale contrast is bounded and non-collapsible; a logit-scale contrast is additive. The two answer different questions.
- **Implementability:** Yes, if a model and SAE exist. Without them, only the contrast arithmetic is testable.
- **Code:** `counterfactual/pairwise.py` builds four cells and computes the contrast; `counterfactual/engine.py` defines the runner interface. Cells are supplied by the caller; the engine does not itself implement ablation or clamping.
- **Missing:** a canonical intervention operator, a control intervention matched for activation magnitude, a distribution-shift diagnostic, a dose-response curve, and a significance/equivalence criterion.
- **Evaluation:** report `I` on probability and logit scales; permutation null over feature/state labels; negative controls (random features matched on activation); test–retest reliability across seeds; check that the intervention does not change unrelated activations beyond a tolerance.

### 2.4 Pairwise feature interactions — Eq. (11)–(13), Alg. 4

- **Equations:** (11) Pearson correlation; (12) binary factorial interaction; (13) continuous factorial interaction.
- **Variables:** `ρ_ij`; `I_ij`; `g(1,1)`, `g(1,0)`, `g(0,1)`, `g(0,0)`; magnitudes `a`, `b`.
- **Assumptions:** the four cells are measured on the same inputs with only the two features changed; the outcome is on an additive scale where "interaction" is meaningful; correlation is computed on non-degenerate features.
- **Correctness:** (12)–(13) are the standard 2×2 difference-in-differences. They are **correct as a contrast**, not as a causal effect unless the intervention is valid. (11) is attenuated by zero inflation and undefined when either feature has zero variance. The paper correctly notes that correlation is not interaction.
- **Implementability:** Yes, at E1.
- **Code:** `counterfactual/pairwise.py::estimate_interaction` computes `joint − a − b + baseline`; `higher_order.py` generalizes to alternating signs over the powerset. The 95% CI uses independent-cell sample variances and is described as descriptive only. `select_association_pairs` ranks by **selectivity**, not Pearson correlation; the paper's screening step (11) is not implemented.
- **Missing:** Pearson screening, `τ_corr`/`τ_int` semantics, multiplicity control over pairs, control interventions, and API wiring.
- **Evaluation:** interaction estimates with bootstrap CIs; permutation null; sign/synergy classification; agreement between correlation screening and interaction ranking; sensitivity to the outcome scale and intervention dose.

### 2.5 Higher-order interactions — Eq. (12)–(13) generalized, Alg. 4

- **Equations:** the alternating-sum generalization of (12) over a subset `S`; the code uses `Σ_{T⊆S} (−1)^{|S|−|T|} g(T)`.
- **Variables:** subset `S`, order `k = |S|`, cell outcomes `g(T)` for every `T ⊆ S`.
- **Assumptions:** all `2^k` cells are measured; the same intervention operator is used at every level; the outcome scale is additive.
- **Correctness:** the Möbius/alternating contrast is the correct higher-order interaction functional. The **cost is exponential** and the variance grows with `2^k`; the paper does not state a budget or a sampling estimator.
- **Implementability:** Yes for small `k` (code defaults to `max_order = 3`), not for large `k`.
- **Code:** `counterfactual/higher_order.py` implements the alternating contrast and requires all cells; it preselected features by selectivity.
- **Missing:** variance estimator for the `2^k` contrast, sparsity/sampling strategy with unbiased weights, and a clear statement that a non-zero higher-order contrast is not evidence of a "mechanism".
- **Evaluation:** estimate stability vs `k` and sample size; null calibration via permutation; compare exhaustive vs sampled subsets; report cost.

### 2.6 Counterfactual risk analysis — Eq. (12)–(13), Alg. 4 and risk controller

- **Equations:** interaction contrasts feed the risk controller; the controller's own formula is **not** Eq. (28) (see 2.8).
- **Variables:** per-feature contrast, interaction contrast, static score, heuristic risk, context multiplier, priority weights, `max_priority`.
- **Assumptions:** the contrasts are on a scale that can be linearly combined with static and heuristic scores; the context multiplier is valid; the clamp does not hide saturation.
- **Correctness:** the arithmetic is internally consistent. The **interpretation** as "risk" is a policy choice, not a probability. The controller's `priority` is explicitly bounded and banded; that is defensible.
- **Implementability:** Yes, but only with model artifacts; the current API returns empty effects.
- **Code:** `counterfactual/engine.py`, `steering/risk_controller.py` (`_bounded`, `_band`, `_steering_strength`, `_calibrate`).
- **Missing:** a specified counterfactual risk estimand, a link from contrasts to `P(v)`, and calibration.
- **Evaluation:** rank correlation between counterfactual priority and expert severity; calibration of the optional calibrator; ablation of each term; sensitivity to `max_priority` and context multipliers.

### 2.7 Interaction-aware adaptive activation steering — decoder-direction steering, Alg. 7 (steering part)

- **Equations:** no numbered equation. The code uses `Δ = Σ_j s_j · d_j`, where `d_j` is the decoder direction (column of `W_d`), clipped to `‖Δ‖ ≤ max_delta_norm`; adaptive strength is `base_strength × weight × score × direction`, with interaction contributions divided by order and a context multiplier.
- **Variables:** `s_j` strength; `d_j` decoder column; `score` importance (selectivity or association); `direction` sign; `order` interaction order; `context_multiplier`.
- **Assumptions:** decoder columns are meaningful directions; adding them steers the model monotonically toward/away from the feature; the clip preserves the intended effect; the importance score is a valid proxy for steering utility.
- **Correctness:** the construction is a legitimate linear intervention in activation space. It is **not** derived from Eq. (12)–(13)**; the "interaction-aware" part is a heuristic allocation rule, not an interaction effect. Dividing by order is a variance-control heuristic, not a theorem.
- **Implementability:** Yes, with a compatible local transformer and SAE. The code is not wired into the prevention endpoint (`plan=None`).
- **Code:** `steering/engine.py` (decoder directions, clip), `steering/adaptive.py` (importance, interaction contributions, context multiplier), `steering/risk_controller.py` (CWE policy, threshold-gated strength).
- **Missing:** a stated steering estimand, monotonicity check, off-target activation audit, and the iterative generation loop of Alg. 7.
- **Evaluation:** target-feature activation change; off-target activation change; security outcome (VR/VRR) vs strength; functional pass rate; dose-response; negative controls (random decoder directions).

### 2.8 CWE-specific risk assessment — Eq. (28)–(29)

- **Equations:** (28) `R(v)=αP(v)+βS(v)+γE(v)+δI(v)`; (29) threshold bands.
- **Variables:** `P` calibrated probability; `S` normalized severity; `E` exposure/exploitability; `I` impact; `α,β,γ,δ ≥ 0`; `τ_1<τ_2<τ_3`.
- **Assumptions:** each input is normalized to a compatible range; the weights are on a common scale; the linear additive form is an acceptable policy; `P` is actually calibrated.
- **Correctness:** (28) is a valid **linear prioritization index**, not a probability. It is unbounded unless inputs and weights are normalized, and the paper does not require `α+β+γ+δ=1`. (29) is correct given ordered thresholds. The claim that `P(v)` is "calibrated" is unsupported: no calibration method or metric is specified.
- **Implementability:** Yes as a policy. Calibration requires labeled data and a calibration fit.
- **Code:** `steering/risk_controller.py` computes `clamp((offset + w_f·feature + w_i·interaction + w_s·static + heuristic) × context_multiplier, max_priority)` and bands it. This is **not** Eq. (28): there is no `P(v)`, `S`, `E`, `I` decomposition; severity is a CWE default; exposure/impact are not separate terms.
- **Missing:** normalization mapping, weight calibration protocol, calibration metric (Brier/ECE), and a documented decision on whether the score is a probability or an index.
- **Evaluation:** calibration (reliability diagram, Brier, ECE) only if a probability is claimed; otherwise decision-utility analysis (precision@k, cost-weighted ranking); sensitivity to weights; agreement with expert triage.

### 2.9 Multi-source evidence fusion — Eq. (24)–(27), Alg. 6

- **Equations:** (24) evidence vector; (25) learned fusion; (26) weighted baseline; (27) logistic head.
- **Variables:** `e_i` concatenated modality evidence; `m_i` availability mask; `F_φ`; `w_j` reliability weights; `q_{ij}` normalized evidence; `w_f`, `b_f`.
- **Assumptions:** modalities are comparable after normalization; availability is independent of the evidence value (MAR); learned fusion has enough labeled data; weights are calibrated.
- **Correctness:** (26) is correct and explicitly conditional on a positive denominator. (25) and (27) are under-specified: the output dimension of `F_φ` is not defined, the training objective is not given, and `m_i` is described but the displayed mask equation is **missing** from the text. (27) applies a sigmoid to `w_f^T h_fusion`, but if `F_φ` already outputs a score, the composition is ambiguous.
- **Implementability:** (26) is directly implementable; (25)/(27) require a labeled training set and a missing-modality strategy.
- **Code:** `detection/fusion.py` implements a **different** model: within-family noisy-OR with redundancy decay, family caps, cross-family noisy-OR, and a refutation penalty. It explicitly states that the score is **not a probability** (`LIM-DET-01`). `detection/config.py` documents the weights. This is a defensible engineering alternative, but it is not Eq. (25)–(27), and the paper must not claim it is.
- **Missing:** the mask equation, a learned fusion baseline, a calibrated weighted baseline, and a comparison between the heuristic and Eq. (26).
- **Evaluation:** ablation over modality subsets; compare heuristic noisy-OR, Eq. (26), and a logistic stacker on the same splits; AUROC/AUPRC/MCC with bootstrap CIs; calibration (Brier/ECE) for any probability claim; missing-modality stress tests.

### 2.10 Explainable vulnerability localization — unnumbered §5.8 formula, Alg. 5

- **Equation:** `L(r_i)=αa_i+βs_i+γt_i+δn_i`.
- **Variables:** region `r_i`; attribution `a_i`; static evidence `s_i`; taint/data-flow evidence `t_i`; neural-feature evidence `n_i`; non-negative `α,β,γ,δ`.
- **Assumptions:** each evidence source is normalized to a comparable scale; unavailable modalities are not zero; the linear combination is an acceptable ranking policy; attribution is meaningful.
- **Correctness:** this is a valid **ranking score**, not a probability. The text says unavailable modalities must be represented explicitly, but the formula has **no mask**, unlike Alg. 5's normalized form. `a_i`, `s_i`, `t_i`, `n_i` are not defined operationally, and no threshold `τ_l` appears in the formula (Alg. 5 has one).
- **Implementability:** Yes, if attribution and static/taint evidence exist. The attribution part is missing.
- **Code:** `explain/engine.py` assembles evidence-grounded explanations but does **not** compute `L(r_i)`, does not rank regions, and does not compute attribution. `evaluation/metrics.py` has line precision/recall/accuracy only.
- **Missing:** attribution, normalization, the mask, `τ_l`, ranking, and the evaluation metrics F1/IoU/Hit@k/MRR.
- **Evaluation:** line/statement/function precision, recall, F1, IoU, Hit@k, MRR; comprehensiveness/sufficiency; stability under paraphrase/seed; expert rating; ablations of `α,β,γ,δ`.

### 2.11 Repository-aware automated repair — Eq. (30)–(33), Alg. 8

- **Equations:** (30) generation `P'=G_ψ(P,L,Q,π_r)`; (31) argmin over `C(P)`; (32) weighted objective; (33) constraints.
- **Variables:** `P` program; `L` localization; `Q` tests/constraints; `π_r` generation settings; `C(P)` candidate set; `λ_s,λ_f,λ_r,λ_d`; `L_*` loss terms.
- **Assumptions:** the candidate set contains a valid patch; the loss terms are measurable; the weights reflect a defensible trade-off; the constraints are decidable.
- **Correctness:** (30) is a schematic, not a mathematical function (no domain/codomain). (31) is only meaningful over the finite generated set `C(P)`; it is **selection**, not optimization. (32) is under-specified: none of the four losses is defined. (33) uses `⊨` for test suites and security constraints that are not formal specifications.
- **Implementability:** Partial. Candidate generation and ranking are implementable; a true optimizer over program space is not.
- **Code:** `repair/workflow.py`, `repair/engine.py` (proposal generation, approval-gated), `repair/ranking.py` (hard constraints + weighted normalized score with weights 4/3/3/2/3/2/1/2). There is no Eq. (32) optimizer and no iterative repair loop.
- **Missing:** operational definitions of `L_security`, `L_function`, `L_regression`, `L_diff`; a `π_r` specification; a candidate-set construction guarantee; and a decision rule for infeasible constraints.
- **Evaluation:** Patch Generation Rate (PGR), Compilation Success Rate (CSR), Test Pass Rate (TPR), Patch Success Rate (PSR), Security Regression Rate (SRR), Security Fix Rate (SFR), ART, ANC; ablations of individual loss terms.

### 2.12 Security and functional preservation — Eq. (34)–(39)

- **Equations:** (34) pass ratio; (35) functional indicator; (36) Hoare triple; (37) targeted removal; (38) no new vulnerabilities; (39) acceptance conjunction.
- **Variables:** test set `T`; expected output `o_t`; `V_target`; `V(P)`; predicates `V_syntax`, `V_func`, `V_reg`, `V_security`.
- **Assumptions:** tests are representative and deterministic; outputs are exactly comparable; vulnerability identity/correspondence is defined; the detector has no false negatives; `V_reg` and `V_security` are decidable.
- **Correctness:** (34) is too strict: exact output equality fails on floating-point, timing, nondeterminism, and output formatting. A test harness pass/fail is the correct operationalization. (35) is correct but inherits the test suite's coverage limits. (36) is a proof obligation, not an algorithm; Alg. 9 does not implement Hoare logic, so the paper must say "where a formal specification and verifier exist". (37) is only as good as the correspondence between findings; `V_target(P') ∩ V_target(P) = ∅` can be satisfied by a detector that simply stops reporting. (38) is explicitly detector-relative and should not be written as a set-theoretic guarantee. (39) is a correct conjunction, but `V_reg` and `V_security` are not formally defined.
- **Implementability:** (34)–(35), (37)–(39) are implementable as three-valued checks. (36) is not implementable without a verifier and specifications.
- **Code:** `verification/engine.py` runs before/after static scans, taint comparison, CWE-specific checks, regression checks, syntax checks, and optional functional tests; it classifies outcomes as pass/fail/inconclusive. `repair/workflow.py` requires syntax, security, and functional checks for `FULLY_VERIFIED`. This is the honest operationalization of (39), but it is **not** a proof of (36)–(38).
- **Missing:** tolerance-based output comparison, explicit `V_reg`/`V_security` definitions, a documented inconclusive policy, and a Hoare/formal-verification path (or an explicit statement that it is out of scope).
- **Evaluation:** TPR, PSR, SRR, SFR, false-acceptance rate on adversarial patches; inter-tool agreement; inconclusive rate; regression rate; test-suite coverage.

### 2.13 Independent verification — Eq. (36)–(39), Alg. 9

- **Equations:** as above.
- **Variables:** as above, plus the verification profile and sandbox backend.
- **Assumptions:** the verifier is independent of the generator; the analyzers are available; the sandbox faithfully executes tests; the patch applies cleanly.
- **Correctness:** the conjunction is correct. The independence claim is **architectural**, not mathematical: the verifier uses different tools but the same codebase and possibly the same detectors. "Independent" should be qualified.
- **Implementability:** Yes for static/taint checks; functional execution depends on Docker and the test framework.
- **Code:** `verification/engine.py`, `verification/functional.py`, `sandbox/executor.py`. Static scans use Semgrep/Bandit/CodeQL/Joern adapters when available. Docker-backed execution is unavailable in this environment.
- **Missing:** a formal independence argument, a verifier-version pin, a false-negative audit, and execution evidence.
- **Evaluation:** agreement between verifier and human labels; false-acceptance rate; inconclusive rate; reproducibility across runs; comparison against a single-tool baseline.

### 2.14 Unified mathematical model — Eq. (40)–(49)

- **Equations:** (40) `x=Φ(c)`; (41) `z=SAE(h_m(c))`; (42) `e=Ψ(·)`; (43) `h_u=F_φ(e,m)`; (44) `p̂=σ(f_θ(h_u))`; (45) `A=Attribution(p̂,x,z)`; (46) `R=R(p̂,S,E,I)`; (47) `c_secure=G(m,p,Q_security)`; (48) `P'=G_repair(P,A,Q_security)`; (49) accept/reject.
- **Variables:** as above; `θ` is overloaded between the detector and the head; `R` is overloaded between the risk score and the risk function; `G` is overloaded between generation and repair.
- **Assumptions:** all earlier components are defined and available; the pipeline is acyclic; the evidence is conditionally independent given the label (implicitly assumed by noisy-OR, not stated).
- **Correctness:** the model is a **restatement**, not a derivation. It adds no identification result, no consistency theorem, and no error propagation analysis. Eq. (41) conflates the SAE with its encoder. Eq. (42) omits `e_interaction` from Eq. (24). Eq. (44) reuses `θ` from Eq. (2). Eq. (46) omits the weights `α,β,γ,δ` from Eq. (28). Eq. (47) omits the inputs listed in Alg. 7. Eq. (48) omits `L` and `π_r` from Eq. (30).
- **Implementability:** as a pipeline, partially; as a single differentiable model, no.
- **Code:** `core/orchestrator.py` composes scan/detection/explanation/repair/verification; `features_extract`, `counterfactual_analyze`, and `prevention_steer` return unavailable/empty results.
- **Missing:** a notation table, distinct symbols per model, and an explicit error-propagation or calibration analysis.
- **Evaluation:** end-to-end pipeline test on real code; stage-wise availability/coverage reporting; ablation of each stage; latency and failure-mode analysis.

---

## 3. Issue register

Severity: **S1** blocks a defensible empirical claim; **S2** blocks reproducibility or correct interpretation; **S3** clarity/notation.

| ID | Sev. | Affected | Problem | Defensible alternative |
|---|---|---|---|---|
| M-01 | S1 | (1), (40) | `x_lex, x_syn, x_sem, x_str, x_sec` are heterogeneous (tokens, graphs, sets) and of undefined dimension; semicolon concatenation is not defined. | Define `Φ` explicitly: each view is pooled/projected to a fixed dimension `d_v`, then concatenated; or replace concatenation with per-view encoders and a fusion layer. Report each view's dimension and normalization. |
| M-02 | S1 | (2)–(4), (44) | No trained detector, no `θ`, no `η`, no calibration; the paper's central classifier does not exist. | Implement a baseline (e.g., logistic regression / gradient-boosted trees on program features, then a code model) with a fixed train/val/test split; select `η` on validation by a stated criterion (e.g., max F1 or target FPR); report calibration. Do not claim Eq. (2) results until this exists. |
| M-03 | S2 | (2)–(4) | Class-weighted BCE changes the probability scale; `p_i` is then not the unweighted posterior. | State the weighting in the loss and recalibrate (Platt/isotonic) on validation, or report the weighted score as a ranking score, not a probability. |
| M-04 | S2 | (5)–(7) | `h` preprocessing/normalization is unspecified; no tied weights; no dead-feature handling; L1 does not guarantee sparsity. | Document `h` extraction (layer, hook, token pooling, normalization); report reconstruction `R²`, L0, dead-feature fraction; add dead-feature resampling if needed. |
| M-05 | S3 | (8) | `w_j` is written as a column (`w_j^T h`) but `W_e` is `d_s×d`, so feature `j` is a **row**. | Define `w_j = W_e[j,:]^T` explicitly, or write `z_j = ReLU(W_e[j,:] h + b_j)`. |
| M-06 | S2 | (9)–(10) | `Δμ_j` is scale-dependent; `s_{j,pool}` is undefined; ReLU zero-inflation makes `d_j` unstable; no multiplicity control. | Define pooled SD; use Hedges' *g* with bootstrap CI; report activation frequency separately; apply BH across features; add a variance guard. |
| M-07 | S1 | (11)–(13) | Pearson correlation is not interaction; the intervention operator and the outcome scale are undefined; no controls for distribution shift. | Define the intervention (ablation/clamp/steer), the outcome (probability vs logit), the reference state, and matched controls; use (12)–(13) for interaction and (11) only as a screening statistic with a CI. |
| M-08 | S2 | (12)–(13) | The contrast is on the probability scale, where interaction is not invariant to baseline risk; the sign has no mechanistic meaning. | Report the contrast on both probability and logit scales; state the scale; use a permutation null; do not call a non-zero contrast a "mechanism". |
| M-09 | S3 | (16) | `f_θ(z)` is not the same function as `f_θ(x)`; the chain rule through the decoder (`∂f/∂z = ∂f/∂h · W_d`) is omitted. | Define `f̃(z) = f(W_d z + b_d)` and state the chain rule; or attribute to `h` and project. |
| M-10 | S2 | (17)–(20) | Eq. (20) does not use `A_uv`; `h_v^(0)`, the readout/pooling, and edge features are undefined. | Write `h_v^(l+1)=φ(W_0 h_v^(l)+Σ_u A_uv W_1 h_u^(l))`; define initialization and graph-level readout. |
| M-11 | S2 | (22)–(23) | `Reachable_DFG=1` is may-reachability; `q(p)` (sanitizer adequacy) is undefined; a wrong sanitizer can be treated as safe. | Use a three-valued path status (sanitized / unsanitized / unknown); define sanitizer rules per CWE; keep "unknown" as inconclusive, not safe. |
| M-12 | S1 | (24)–(27) | The availability-mask equation is missing; `F_φ`, `q_{ij}`, and the output dimension of `h_fusion` are undefined; no training objective. | Display the mask definition; define `q_{ij}∈[0,1]` and its normalization; specify `F_φ` (e.g., per-modality encoders + masked mean) and train (27) with BCE; treat (26) as a transparent baseline. |
| M-13 | S1 | (25)–(27) vs code | The code's fusion is a heuristic noisy-OR, not Eq. (25)–(27); calling it Eq. (27) would be a false claim. | Either implement (26)/(27) or explicitly present the noisy-OR as a separate, uncalibrated prioritization score; compare both empirically. |
| M-14 | S1 | (28)–(29) | `P(v)` is claimed calibrated but no calibration procedure exists; `S,E,I` normalization is undefined; the score is unbounded unless normalized; `Σ weights` is unconstrained. | Declare (28) a prioritization index; define normalization to `[0,1]`; constrain weights (e.g., sum to 1); calibrate or drop the word "probability"; report Brier/ECE only if calibrated. |
| M-15 | S2 | (30)–(33) | `G_ψ` is a schematic with no domain/codomain; (31) is selection over a generated finite set, not optimization; the four losses are undefined. | Define `C(P)` as the finite candidate set; define each loss operationally; state that (31) is `argmin` over candidates (selection), not a program-space optimizer. |
| M-16 | S2 | (32) vs code | The code ranks with a different weighted score (8 terms) and hard constraints; it does not optimize Eq. (32). | Present the code's ranking as the operational surrogate; define the mapping between Eq. (32) terms and the code's terms, or align them. |
| M-17 | S2 | (34) | Exact output equality `P'(t)=o_t` is too strict for real programs (float, nondeterminism, formatting). | Use the test harness pass/fail (exit code + assertions) as `Pass_func`; if comparing outputs, use a stated tolerance or an equivalence oracle. |
| M-18 | S2 | (36) | Hoare correctness is stated but not implemented and no specifications exist. | Say "where a formal specification and verifier are available"; otherwise report test-based correctness only and do not claim (36). |
| M-19 | S1 | (37)–(39) | "No new vulnerabilities" and "targeted removal" are detector-relative; a false-negative detector makes them vacuously true; `V_reg`/`V_security` are undefined. | Define acceptance as three-valued checks with explicit inconclusive; require independent tools; report false-acceptance risk; never state (38) as a theorem. |
| M-20 | S2 | (40)–(49) | Notation collisions (`θ`, `R`, `G`), omissions (interaction evidence, weights, `L`, `π_r`), and no added theorem. | Add a notation table; use `θ_det`, `θ_fuse`, `ψ_repair`, `R_index`; present (40)–(49) as a pipeline schematic, not a model with independent content. |
| M-21 | S1 | §5.8 localization | `L(r_i)` has no mask, no normalization, no threshold, and undefined `a_i,s_i,t_i,n_i`; the text's own "explicit absence" requirement is violated by the formula. | Use `L(r_i)=Σ m_r α_r e_r / Σ m_r α_r` (Alg. 5's normalized form) with `τ_l` and an insufficient-evidence status; define each `e_r` in `[0,1]`. |
| M-22 | S1 | Privacy/utility boundary | Risk, steering, and repair are described as if they operate on the same code representation, but the LLM activation path and the program-analysis path are never joined mathematically. | Define the join explicitly: activations come from `h_m(c)` for the same `c`; program features come from `c`; state the alignment (same function/file) and the failure mode when they are not aligned. |
| M-23 | S2 | Metrics | No accuracy, ROC-AUC, Brier/ECE, localization F1/IoU/Hit@k/MRR, or prevention metrics in code; PR-AUC is a custom step estimator. | Add the missing metrics; document the PR-AUC estimator (or use average precision); validate against a reference implementation on synthetic cases. |
| M-24 | S2 | Statistics | The paper does not specify estimators, CIs, or multiplicity control for (9)–(13); the code has tests but no automated tests for them. | Pre-register the estimator (Hedges' *g*, bootstrap CI, permutation test) and correction (BH/Holm) per family; unit-test the statistics against known cases. |
| M-25 | S3 | Alg. 4 | `τ_corr` and `τ_int` are inputs but their semantics (raw, absolute, standardized) are unspecified; `I_assoc` is not defined. | Define thresholds on the chosen scale (e.g., |ρ| ≥ τ_corr, |I| ≥ τ_int with CI excluding 0); state the multiplicity correction. |
| M-26 | S3 | Alg. 7 | The prevention loop is described as iterative but the endpoint returns `plan=None`; no stopping rule or budget semantics. | Define `B` and `τ_sec` operationally; implement or explicitly mark as unavailable; do not claim prevention results. |
| M-27 | S2 | Alg. 9 | "Independent" verification shares the same codebase/detectors; the independence claim is architectural, not established. | State the independence boundary; use at least one external analyzer; report agreement and false-acceptance. |
| M-28 | S3 | §5.15 / §6.14 | The paper's own status labels ("established", "proposed") are correct but inconsistent with some result-oriented wording elsewhere. | Keep the status labels; audit the prose for "detects", "prevents", "repairs" claims that imply completed results. |
| M-29 | S3 | §7.6.3 | `FPR` is used for **functional pass rate**, which collides with the standard false positive rate. | Use `FPass` (or `FuPR`) for functional pass rate and reserve `FPR` for false positives. |
| M-30 | S3 | §7.4.4 vs code | `localization_accuracy` in the code is exact-set match, while §7.4.4 defines line-level accuracy. | Report exact-set match as `EM`; implement line-level `Acc_line` separately. |

---

## 4. Claims that the mathematics does not support

The following claims must not be made on the basis of the current equations or code:

1. **"CRAFT-Sec detects vulnerabilities with [metric]."** No trained detector exists (`θ`, `η`, Eq. 2–4 unimplemented).
2. **"SAE feature `j` is a vulnerability feature."** Eq. (9)–(10) are group mean differences; they do not establish semantics or causality.
3. **"Feature interactions cause vulnerability-related behavior."** Eq. (12)–(13) are factorial contrasts under an intervention; without a valid intervention and controls, they are descriptive non-additivity.
4. **"The framework produces a calibrated vulnerability probability."** No calibrator exists; the fusion module explicitly says its score is not a probability.
5. **"The risk score is a probability/severity measure."** Eq. (28) is a linear index; it is not calibrated and may be unbounded.
6. **"The patch is verified correct."** Eq. (36) is not implemented; Eq. (37)–(39) are detector-relative and can be inconclusive.
7. **"The repair optimizes Eq. (32)."** The code ranks candidates with a different score; no optimizer exists.
8. **"Prevention reduces vulnerabilities."** The prevention endpoint returns no plan; no prevention experiment has been run.
9. **"Localization identifies the vulnerable line."** `L(r_i)` is not implemented and no localization metrics beyond line P/R/accuracy exist.
10. **"The unified model is validated."** Eq. (40)–(49) is a schematic; no end-to-end run exists.

---

## 5. Evaluation readiness by component

| Component | Primary metric | Code support | Ready to run? |
|---|---|---|---|
| Detection | Accuracy, precision, recall, F1, MCC, ROC-AUC, PR-AUC, Brier/ECE | Precision, recall, F1, MCC, PR-AUC; **no accuracy/ROC-AUC/Brier/ECE** | No (no model/data) |
| SAE association | Reconstruction, L0, dead features, Hedges' *g*, CI, BH | Reconstruction/L0 partial; **no pooled effect/CI/BH** | No (no checkpoint/data) |
| Pairwise interaction | Contrast + CI + permutation null | Contrast + descriptive CI | Partially (synthetic only) |
| Higher-order | Contrast + CI + cost | Contrast | Partially (synthetic only) |
| Attribution | Comprehensiveness, sufficiency, stability | **None** | No |
| Localization | Line/function P/R/F1, IoU, Hit@k, MRR | Line P/R/accuracy only | No |
| Fusion | AUROC/AUPRC/MCC, calibration, ablation | Heuristic score; no calibration | No (no model/data) |
| Risk | Calibration or decision utility | Policy + optional calibrator | No (no labels) |
| Repair | PGR, CSR, TPR, PSR, SRR, SFR, ART, ANC | PSR-like, functional pass, regression rate | No (no execution) |
| Prevention | VR, VRR, FPR, SCR | **None** (endpoint empty) | No |
| Verification | False-acceptance, inconclusive rate, agreement | Before/after checks | Partially (no Docker) |

---

## 6. Metric audit (§7.2–7.6)

The paper's metrics are mostly standard. The issues are definitional and implementation coverage.

### 6.1 Detection (§7.2)

- Accuracy, precision, recall, F1, MCC, ROC-AUC, PR-AUC are standard and correctly stated.
- **Code:** `evaluation/metrics.py::aggregate_detection_metrics` computes TP/FP/TN/FN, precision, recall, F1, MCC, PR-AUC. It does **not** compute accuracy or ROC-AUC. `_pr_auc` is a custom step/trapezoid estimator seeded with `prev_precision = 1.0`; it is not guaranteed to equal average precision. This must be documented and validated, or replaced.
- **No Brier score or ECE** despite the paper mentioning calibration in §7.
- **Multi-class/CWE metrics** are described in §7.2.8 but not implemented.

### 6.2 Explainability (§7.3)

- Faithfulness, attribution faithfulness, attribution stability, SAE feature stability are described. The code's `compute_explainability_metrics` only averages caller-supplied fields (`feature_faithfulness`, `explanation_consistency`, `counterfactual_validity`). It does not compute comprehensiveness, sufficiency, or stability.
- **Recommendation:** implement deletion/insertion curves and seed/paraphrase stability before claiming explainability metrics.

### 6.3 Localization (§7.4)

- Precision, recall, F1, accuracy, IoU, Hit@k, MRR are stated. The code computes only line precision, line recall, and exact-set accuracy. It does not compute F1, IoU, Hit@k, or MRR.
- The code's "localization accuracy" is exact-set match, not the usual top-1/top-k accuracy; the name is misleading and must be documented.

### 6.4 Repair (§7.5)

- PGR, CSR, TPR, PSR, SRR, SFR, ART, ANC are stated. The code's `compute_repair_metrics` computes a proposed-patch rate, a verified-repair rate, a mean functional pass rate, and a security-regression rate. It does not compute CSR, ART, or ANC. Field names do not match the paper's metric names, which risks inconsistent reporting.

### 6.5 Prevention (§7.6)

- VR, VRR, FPR, SCR, and the functional-security trade-off are stated. **No prevention metrics are implemented**, and the prevention endpoint returns no plan. This is consistent with `final-audit.md` marking prevention **NOT IMPLEMENTED**.

---

## 7. Algorithm audit (1–9)

| Algorithm | Paper purpose | Mathematical status | Implementation | Evidence |
|---|---|---|---|---|
| 1 — Overall framework | Compose all stages | Pipeline schematic | Orchestrator composes stages; model/SAE/counterfactual/steering stages unavailable | E2 |
| 2 — Vulnerability detection | Multi-view classifier | Eq. (2)–(4) | No trained classifier; heuristic detection only | E2 (heuristic), E0 (Eq. 2) |
| 3 — SAE feature extraction | Train SAE, extract features | Eq. (5)–(10) | SAE library + training + association; not wired to a live model; no checkpoint | E1 |
| 4 — Interaction analysis | Screen + factorial contrasts | Eq. (11)–(13) | Contrasts implemented; Pearson screening and thresholds missing | E1 |
| 5 — Localization | Score and rank regions | §5.8 formula | Explanation engine only; no `L(r_i)`, attribution, or ranking | E1 |
| 6 — Evidence fusion | Learn/weight evidence | Eq. (24)–(27) | Heuristic noisy-OR, explicitly not Eq. (25)–(27) | E1 |
| 7 — Prevention | Iterative secure generation | Eq. (47), steering | Steering code exists, unwired; endpoint returns `plan=None` | E0/E1 |
| 8 — Repair | Generate/rank patches | Eq. (30)–(33) | Proposal + ranking + approval gate; no Eq. (32) optimizer | E1 |
| 9 — Verification | Independent acceptance | Eq. (34)–(39) | Static/taint/regression checks; Docker execution unavailable; no Hoare | E2 |

---

## 8. Ordered path to an executable framework

This is the minimum sequence that makes the mathematics testable **without changing any algorithm yet**. It is ordered by dependency, not by paper section.

1. **Freeze the evaluation contract.** Datasets, splits, labels, and the exact metric definitions (including the PR-AUC estimator) must be fixed before any modeling. Add the missing metrics (accuracy, ROC-AUC, Brier/ECE, localization F1/IoU/Hit@k/MRR, prevention metrics) with unit tests against reference values.
2. **Implement Eq. (1)–(4) as a baseline detector.** Start with a deterministic feature baseline (lexical + program-analysis features) and a logistic/GBM classifier; then add a code model. Define `η` selection and calibration. This unlocks detection, fusion, risk, and localization evaluation.
3. **Produce a real SAE artifact.** Pin a model, layer, hook, token pooling, and normalization; train with Eq. (5)–(7); report reconstruction, L0, dead features, and stability. Then compute Eq. (9) with Hedges' *g*, bootstrap CI, and BH.
4. **Define and implement the intervention operator.** Choose ablation/clamping/steering, define the outcome scale (probability and logit), and add matched controls. Then run Eq. (12)–(13) with a permutation null.
5. **Implement Eq. (26) as the transparent fusion baseline.** Compare it with the existing noisy-OR and a logistic stacker (Eq. 25/27) on identical splits; report calibration.
6. **Replace Eq. (28)'s probability claim with an explicit policy.** Either calibrate `P(v)` and report Brier/ECE, or relabel `R` as an index and report decision utility.
7. **Implement the localization score in the normalized, masked form** and the attribution baseline (gradient/IG or perturbation). Add line/region ranking and the §7.4 metrics.
8. **Define the repair objective operationally** and map it to the existing ranking terms; then run Alg. 8/9 with a real test suite in a sandbox.
9. **Implement or explicitly disable prevention.** If the iterative loop is out of scope, remove prevention claims and mark the endpoint unavailable, as it already does.
10. **Add statistical inference.** Pre-register estimators, CIs, multiplicity correction, and repeated seeds for every comparative claim.

Until steps 1–3 are complete, no detection, fusion, risk, or attribution result can be reported. Until step 8, no repair result can be reported. Until step 9, no prevention result can be reported.

---

## 9. Integrity statement

- No equation in this audit was invented to increase apparent sophistication. Where the paper's formulation was under-specified, the audit says so and proposes a conventional, defensible alternative.
- No result, metric, citation, or empirical claim was fabricated. The repository contains **no empirical results**, and `Research.txt` is written in a proposal/future-work register.
- The code's own limitation strings (for example `LIM-DET-01` in `detection/fusion.py`) are treated as authoritative statements about what the code does **not** claim.
- This audit does not modify algorithms. All recommendations are documentation-level and must be implemented and tested separately.
