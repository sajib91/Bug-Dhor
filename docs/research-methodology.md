# Bug Dhor Research Methodology (Technical)

**Status:** Technical research documentation grounded in repository implementation and design contracts.  
**Scope:** Distinguishes **implemented** modules/methods, **implemented-but-conditional** capabilities (require models/artifacts/tools/data/config), and **planned/target** methods described in research alignment but not fully realized in a default environment.  
**Integrity:** No fabricated citations, experimental results, mathematical properties, novelty claims, or unavailable component outcomes. The full paper text, equations, and section-level claims were not supplied with this repository; this document maps the stated research focus areas to implemented modules and design contracts, not to unverified paper specifics. When paper text is available, add a traceability addendum rather than retrofitting claims to code.

---

## 1. Research problem and objectives

### 1.1 Problem

Automated vulnerability detection and repair for source code remain challenging because practical systems must balance precision, coverage, explainability, functional preservation, and operational safety. Purely heuristic or opaque signals can be difficult to audit; generated repairs may introduce regressions or security issues; and model-internal mechanisms (e.g. learned features) are often interpreted without sufficient evidence controls.

### 1.2 Objectives

Bug Dhor targets a local-first, evidence-aware research framework with the following objectives (as reflected in implemented modules and research contracts):

1. **Evidence-grounded vulnerability analysis:** integrate parsing/program analysis, taint, and available static evidence into explainable detection outputs with explicit provenance and limitations.
2. **SAE-based representation analysis:** train/analyze sparse autoencoder features over model activations and study associations with labeled security-relevant data under explicit non-causal interpretation unless separately validated.
3. **Counterfactual intervention analysis:** perform controlled single-feature and multi-feature (pairwise/higher-order) interventions on declared outcome scales with reproducibility metadata and uncertainty reporting where supported.
4. **Interaction-aware steering research:** explore adaptive/constraint-aware activation steering policies informed by measured evidence, without claiming guaranteed security improvement.
5. **Repository-aware repair:** generate/evaluate repair proposals using bounded repository context and verification-aware ranking, without automatic patch application.
6. **Independent verification:** assess security/functional impact independently of generator rationale, using explicit consent and isolated execution for untrusted tests.
7. **Reproducible evaluation:** support honest experimental design, metrics, statistical analysis, ablations, comparisons, and reporting only from actual available data/runs.

## 2. System architecture

### 2.1 Architectural overview

Bug Dhor is organized as a monorepo with a **VS Code extension client** and a **Python/FastAPI security engine**:

- **Client/UI layer:** command registration, workspace validation, backend transport, response validation, dashboard rendering, diagnostics/hover/code actions, and privacy-aware request shaping.
- **API/orchestration layer:** FastAPI routes/schemas, middleware (auth/CORS/limits/errors/request context), orchestrator, job/progress/cancellation tracking, and result persistence.
- **Analysis layer:** source preprocessing/parsing, AST/CFG/DFG construction, taint analysis, static analyzer adapters/runner, detection/fusion, and explanation generation.
- **Model/research layer (conditional):** local Hugging Face adapter/runtime, activation capture, SAE training/checkpointing, feature association/interpretation, counterfactual engines, and steering/policy controllers.
- **Repair/verification layer:** repository context building, repair prompting/candidate normalization/ranking, integrated repair workflow, sandbox execution with consent, and independent security/functional verification.
- **Evaluation layer:** dataset handling/splits, experiment groups/config/tracking, metrics, statistical procedures, ablation/comparison utilities, and export/reporting.

### 2.2 Execution and trust boundaries

- The extension connects to an already-running backend; it does not supervise backend startup in current implementation.
- Backend analysis operates within configured workspace roots/path containment and request/file limits.
- Untrusted code/tests are not executed on the host as a verification path; isolated execution requires explicit consent and available sandbox backend.
- Repair outputs are proposals; user approval and client-side/application safeguards are required.

### 2.3 Honest state model

Operations and stages report explicit statuses (e.g. `ok`, `partial`, `unavailable`, `failed`, `not_run`) with reasons/warnings/provenance where available. Missing prerequisites (models, SAE artifacts, analyzers, datasets, sandbox) must be surfaced, not hidden.

## 3. SAE methodology

### 3.1 Implemented components

- **SAE model/training (`bugdhor.sae.model`, `training`, `metrics`, `checkpoint`, `config`)**: ReLU-encoder/linear-decoder sparse autoencoder over activation tensors with configurable dimensions/hyperparameters, reconstruction and sparsity-related metrics (e.g. reconstruction error, relative error, L0/activity/utilization, dead features), training history, and checkpoint save/load with configuration hashing/validation.
- **Activation extraction support (`bugdhor.models.activations`, adapter/runtime modules)**: infrastructure to collect model activations from compatible local Transformer models when configured/loaded.
- **Association analysis (`bugdhor.sae.association`)**: computes feature-association statistics from explicitly labeled secure/vulnerable samples and actual SAE activations (e.g. activation frequency, mean differences, precision/recall-like active-feature statistics, CWE-specific/selectivity/stability/cross-dataset validation metrics as implemented), with provenance fields (model/layer/checkpoint/datasets/thresholds).
- **Interpretation/reporting (`bugdhor.sae.interpretation`)**: evidence-backed interpretation hypotheses from association evidence and examples, with annotations, limitations, export (JSON/CSV flattening rules), and explicit non-semantic/non-causal disclaimers.

### 3.2 Methodological constraints

- SAE features are **mathematical latent directions**; activation/utilization/reconstruction statistics alone do not establish semantic labels (e.g. "SQL injection feature") or causal roles.
- Causal claims require separately designed, controlled intervention studies with independent evaluation.
- End-to-end feature extraction in deployed API flows is **conditional** on compatible model runtime and SAE artifacts.

## 4. Feature identification methodology

### 4.1 Implemented identification/selection mechanisms

- **Association-driven identification:** features can be ranked/filtered using measured association metrics (e.g. selectivity, mean difference, stability) and optional CWE/dataset constraints through analysis APIs/dictionaries.
- **Evidence packaging:** feature dictionaries/reports retain provenance (model ID/version, layer, SAE checkpoint, dataset/experiment identifiers, thresholds) and explicitly mark association-only interpretations.
- **Policy-driven selection for steering (conditional):** adaptive steering/risk control components select features using configured, measured importance metrics and thresholds (not opaque learned weights), with auditable decision records.

### 4.2 Planned/conditional extensions

- Fully automated, validated semantic labeling of features is not assumed; auto-interpretation outputs, when used, must be treated as hypotheses with provenance and uncertainty.
- Robust cross-model/cross-layer feature identity mapping is limited by artifact compatibility and is not generally guaranteed.

## 5. Counterfactual intervention methodology

### 5.1 Single-feature interventions (implemented library)

`bugdhor.counterfactual.engine` supports reproducible SAE-based interventions against compatible local Transformers models, including:

- baseline activation measurement at selected layers/positions;
- intervention modes (e.g. ablation/target-value modification as supported);
- generation/comparison of baseline vs intervened outputs under identical generation settings;
- recording of activation/output/risk-score differences (when provided), prompt hash, seed, model/tokenizer/layer/SAE provenance, and token positions.

Ground-truth vulnerability status is treated as externally supplied and not inferred from generated outputs.

### 5.2 Pairwise interventions (implemented library)

`bugdhor.counterfactual.pairwise` evaluates factorial-style four-cell contrasts on an explicitly declared outcome scale:

`Interaction(A,B) = Outcome(A,B) - Outcome(A,0) - Outcome(0,B) + Outcome(0,0)`

- Requires defined baseline, feature A, feature B, and joint intervention cells.
- Supports replicate-based descriptive uncertainty (e.g. standard error/normal-approximation interval) when independent replicates are provided; no p-values/significance labels are produced by this mechanism.
- Results depend on intervention design, controls, target values, and outcome scale (not invariant to nonlinear transforms).

### 5.3 Higher-order interventions (implemented library)

`bugdhor.counterfactual.higher_order` computes factorial contrasts over feature subsets `S` of order `k`:

`sum(T subset S) (-1)^(k - |T|) Outcome(T)`

- Requires all `2^k` cells for evaluated subsets.
- Addresses combinatorial growth via preselection, order bounds, subset sampling/exhaustive modes, evaluation budgets, and cell caching.
- Reports observed/theoretical complexity and descriptive uncertainty when repeated independent outcomes are available; no statistical significance claims are made.

### 5.4 Causal interpretation boundary

Counterfactual modules provide **controlled intervention comparisons** within specified experimental settings. They do **not** automatically establish real-world causal vulnerability mechanisms or guaranteed remediation effects.

## 6. Pairwise interaction formulation

- **Unit of analysis:** feature pair `(A,B)` under a fixed intervention protocol and outcome scale.
- **Contrast:** difference-in-differences over the four intervention cells.
- **Inputs:** selected feature indices/values, positions/layer/context, baseline/intervened outcomes, seed/generation/intervention config, optional replicate outcomes.
- **Outputs:** interaction estimate, per-cell outcomes, provenance, replicate/uncertainty descriptors (when available), and limitations/assumptions.
- **Validity conditions:** meaningful only relative to declared scale/design; sensitive to confounding in experimental setup, off-distribution interventions, and measurement noise.

## 7. Higher-order interaction formulation

- **Unit of analysis:** feature subset `S`, `|S|=k >= 2` (and configurable maximum order).
- **Contrast:** signed inclusion-exclusion (factorial) over all subset intervention cells.
- **Selection/pruning:** measured feature preselection (e.g. selectivity), order limits, sampling strategy, and budget constraints to manage exponential growth.
- **Outputs:** subset interaction estimates, evaluated cell records/caching stats, complexity/budget reports, descriptive uncertainty (if supported by replicates), and provenance.
- **Interpretation caution:** magnitude/sign depend on outcome scale and design; terms like "synergistic/antagonistic" must be qualified by scale and evidence.

## 8. Adaptive activation steering

### 8.1 Implemented mechanisms (conditional)

- **Steering engine (`bugdhor.steering.engine`)**: white-box activation intervention for compatible HF Transformer models; disabled by default and requires explicit enablement/specification. Applies additive decoder-direction interventions at configured layers/positions with norm bounds, finiteness/shape checks, hook cleanup, and baseline-vs-steered output comparison under recorded provenance.
- **Adaptive policy (`bugdhor.steering.adaptive`)**: integrates measured feature dictionaries and pairwise/higher-order results to rank/select features and schedule strengths/positions based on configured, auditable rules (no opaque feature weighting). Records individual/pairwise/higher-order contributions and intervention history.
- **CWE-specific risk control (`bugdhor.steering.risk_controller`)**: combines evidence components under explicit policies/thresholds/multipliers; exposes bounded heuristic priority (not calibrated probability unless a versioned calibrator is provided). Can gate steering when evidence/threshold conditions are not met.
- **Functional-preservation constraints (`bugdhor.steering.functional`)**: evaluates candidates against measured evidence (syntax/compile/tests/behavior/security/overhead) via supplied evaluators; rejects or retains rejected candidates for audit rather than accepting unsupported claims.

### 8.2 Methodological limits

- Steering effects are model-internal behavioral interventions and may degrade capability/fluency or fail to generalize.
- Any security benefit must be demonstrated by independent, reproducible evaluation; steering alone does not prove true vulnerability remediation.

## 9. CWE-specific risk control

### 9.1 Implemented approach

- Evidence aggregation is performed under explicit per-CWE/per-policy configurations (weights, thresholds, activation/interaction criteria, context multipliers, steering gates).
- Decisions record component contributions (features, interactions, static evidence, optional heuristics), evidence availability, fallback reasons, and calibration metadata when present.
- Priority values are **bounded policy evidence** unless a validated, model/version-specific calibrator is supplied.

### 9.2 Non-claims

- No implicit probability calibration, no universal CWE coverage guarantees, and no assumption that policy priority equals exploitability or confirmed vulnerability.

## 10. Evidence fusion

### 10.1 Implemented detection/explanation fusion

- **Detection (`bugdhor.detection.*`)** fuses available evidence from program analysis/taint and static-analysis coverage/adapters where configured, producing findings with confidence/coverage/evidence-source metadata and explicit gaps.
- **Static integration (`bugdhor.static.*`)** normalizes tool outputs into shared findings with provenance, conservative mappings, deduplication rules, and explicit unavailable/failed/timed-out statuses.
- **Explanation (`bugdhor.explain.*`)** preserves evidence boundaries and labels hypotheses/inferences separately; SAE and counterfactual information, when supplied, are included only as evidenced records with provenance and limitations.

### 10.2 Principles

- Evidence is additive and provenance-tracked; missing analyzers/stages reduce coverage and are reported.
- Analyzer findings and model/SAE signals are not, by themselves, proof of confirmed vulnerabilities.

## 11. Repository-aware repair

### 11.1 Implemented components

- **Context building (`bugdhor.repair.context`)**: opt-in, bounded repository context from target file and related imports/tests/config/security utilities within workspace containment rules; includes metadata/summaries (paths, hashes, symbols, dependencies, AST/CFG/DFG summaries where supported) without including raw source text in context objects as specified.
- **Prompting/candidate generation (`bugdhor.repair.engine`)**: CWE/evidence-aware prompting for validated local model adapters (when configured), multi-candidate unified-diff handling, normalization/application in temporary directories for validation, syntax checks, and ranking inputs. Prompting treats source/findings/evidence/repo context as untrusted data.
- **Ranking (`bugdhor.repair.ranking`)**: separates mandatory constraints (e.g. syntax, required evidence/tests/compliance/touched-file limits when configured) from weighted preferences; unavailable evidence is recorded, not fabricated.
- **Workflow (`bugdhor.repair.workflow`)**: integrated 12-step proposal/verification-oriented process with traceable stages, approval requirement, and verification-dependent status (e.g. verified states only when mandatory checks/evidence support them). The steps are: (1) record original source state; (2) generate/provide a repair candidate; (3) validate patch format; (4) validate syntax in an isolated copy; (5) run independent security checks; (6) run functional tests (consent/sandbox dependent); (7) run regression comparisons; (8) compare before/after findings; (9) generate a final verification report/state; (10) request explicit user approval; (11) apply only where a client/user flow permits (the engine never modifies user source; step is blocked otherwise); (12) record final patch metadata. `FULLY_VERIFIED` requires valid syntax, passing independent security verification, and passing functional/regression checks in isolated execution; otherwise the workflow records partial/inconclusive/failed states.

### 11.2 Safety constraints

- No automatic patch application to user workspace by backend/workflow.
- No claim of security or functional preservation without independent evidence/verification.
- Generated patches and repository content are untrusted inputs.

## 12. Independent verification

### 12.1 Implemented components

- **Security verification (`bugdhor.verification.engine`)**: independent comparison of static/taint evidence before/after candidate patches in isolated temporary contexts; produces verdicts/classifications with evidence and limitations.
- **Functional verification (`bugdhor.verification.functional`)**: consent-gated, sandbox-dependent execution model; refuses host execution of untrusted project tests and reports unavailable/not-run/inconclusive outcomes when prerequisites are unmet.
- **Sandbox execution (`bugdhor.sandbox.executor`)**: explicit consent model, denial of destructive/privileged requests, isolated backend execution (e.g. Docker-based when configured/available), resource/time/network restrictions as implemented.

### 12.2 Independence and verdict semantics

- Verifier consumes patch/base/evidence/profile inputs independently of generator rationale.
- Verdict taxonomy distinguishes verified/partially verified/failed/inconclusive/not-run (or equivalent workflow states) and must include scope/profile/limitations.
- "Verified" is bounded to performed checks and environment, never a general security guarantee.

## 13. Experimental design

### 13.1 Implemented framework

- **Experiment groups (E0–E8):** defined in `bugdhor.experiments.groups` with descriptions and prerequisite flags (SAE/static/repair dependencies vary by group).
- **Datasets and preprocessing:** loaders/registry and validation utilities for supported datasets subject to local availability and explicit license acknowledgment; normalization, duplicate detection/deduplication, and leakage checks as implemented.
- **Splitting strategies:** repository-level, temporal (when metadata permits), CWE-based, and cross-language splits with explicit unsupported/partial handling and reproducibility metadata (e.g. hashes).
- **Run configuration/tracking:** deterministic config hashing, manifests, environment/tool metadata capture, seed/config recording, and raw output persistence.
- **Execution pipeline:** model/evaluator interfaces and runners that execute only satisfied prerequisites and record reasons for skipped/unavailable components; unmeasured metrics remain null.

### 13.2 Design requirements

- No fabricated datasets, baselines, or outcomes.
- Every run must be traceable to configuration, data provenance, code/tool versions, and recorded limitations.

## 14. Baselines

### 14.1 Baseline concepts represented

- **E0 (Original LLM):** no security-specific intervention (conceptual baseline; requires runnable model/eval setup).
- **E1 (Security prompting):** prompting-based baseline (conditional).
- **E2 (Static-analysis baseline):** tool/evidence-based baseline (conditional on analyzers/config).

### 14.2 Status

Baseline experiment definitions and prerequisite checks are implemented in the evaluation framework; actual baseline results are **not** reported in this repository documentation because they require executed runs on available, licensed data and configured tooling/models.

## 15. Ablation studies

### 15.1 Implemented ablation support

`bugdhor.evaluation.ablation` and experiment group structures support analyses corresponding to ablations such as **A1–A8** (e.g. removing SAE features, counterfactual analysis, pairwise interactions, higher-order interactions, steering, static-analysis fusion, repository context, or independent verification), subject to available implementations and data.

### 15.2 Reporting requirements

- Ablations must compare like-for-like configurations on actual observations.
- Missing components or infeasible ablations must be reported as unavailable/not run, not substituted with estimates.

## 16. Evaluation metrics

### 16.1 Implemented metric families (from provided observations)

- **Detection:** precision, recall, F1, MCC, PR-AUC (when computable from inputs).
- **Localization:** line-level precision/recall and localization accuracy (as defined/implemented).
- **Repair:** repair success rate, verified repair success, functional pass rate, security regression rate.
- **Explainability:** feature faithfulness, explanation consistency, counterfactual validity (as operationalized in code; require valid inputs/definitions).
- **Performance:** inference overhead, analysis latency, memory usage.

### 16.2 Constraints

- Metrics are computed only from supplied observations; absent inputs yield null/unavailable values.
- Calibration metrics (e.g. Brier/ECE) are out of scope unless genuine calibrated models/data are available.

## 17. Statistical analysis

### 17.1 Implemented procedures (`bugdhor.evaluation.statistics`)

- **Data/assumption reporting:** sample sizes, missing data, independence/normality/sample-size checks and caveats where applicable.
- **Confidence intervals:** bootstrap methods (including cluster bootstrap when cluster IDs provided).
- **Hypothesis tests (conditional):** paired t-test where assumptions/data permit, Wilcoxon signed-rank, paired permutation tests; nonparametric alternatives as implemented.
- **Effect sizes:** e.g. Cohen's d, Cliff's delta (as implemented/applicable).
- **Multiple-comparison correction:** Holm–Bonferroni, Benjamini–Hochberg.

### 17.2 Interpretation rules

- Distinguish **statistical** significance/evidence from **practical** significance.
- Report all relevant assumptions, corrections, and limitations; do not fabricate p-values, intervals, or effect sizes.

## 18. Threats to validity

- **Construct validity:** proxy metrics (e.g. analyzer findings, rule matches, proxy outcome scales) may not fully represent true security or exploitability.
- **Internal validity:** confounding in dataset construction, leakage, prompt/setup differences, non-determinism, and intervention design can bias results.
- **External validity:** results may not generalize across languages, projects, CWEs, models, layers, SAE checkpoints, tools, or environments.
- **Conclusion validity:** small samples, violated assumptions, dependence/repeated measures, and multiple testing can affect inference; unavailable tests/corrections must be disclosed.
- **Tool/runtime validity:** static analyzers have false positives/negatives and version sensitivity; sandbox/model/runtime availability constrains executable evaluations.
- **Ecological validity:** controlled samples/benchmarks may differ from real-world codebases and deployment conditions.

## 19. Limitations

- Many advanced capabilities are **artifact-, tool-, or configuration-dependent** (local models, SAE checkpoints, static analyzers, sandbox backends, licensed datasets) and may be unavailable in a given environment.
- Current analysis support is strongest for implemented parsing/program-analysis paths (primarily Python/JavaScript in documented components) and remains approximate in areas such as interprocedural reasoning, aliasing, path feasibility, and dynamic behavior.
- SAE feature semantics and causal effects are not established by default; counterfactual and steering results are bounded by experimental design and declared outcome scales.
- Repair candidates are untrusted proposals; verification coverage is limited to configured checks/profiles and may be partial/inconclusive/not run.
- No experimental benchmark results are claimed here; reproducible evidence requires completed, exported runs with full provenance.
- Security cannot be concluded from passing tests or static analysis alone.

## References and alignment

- Repository research contracts and limitations: `docs/research-alignment.md`, `docs/architecture.md`
- Component methodology docs: `docs/sae.md`, `docs/sae-feature-analysis.md`, `docs/sae-feature-interpretation.md`, `docs/counterfactual.md`, `docs/pairwise-counterfactual.md`, `docs/higher-order-counterfactual.md`, `docs/steering.md`, `docs/explain.md`, `docs/repair.md`, `docs/program-analysis.md`
- Evaluation framework overview: `research/evaluation/README.md`
- Implementation mapping: `docs/implementation-mapping.md`

(External academic citations are not fabricated in this document; cite specific sources in publications only when verified.)
