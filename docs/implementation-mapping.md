# Bug Dhor Implementation Mapping

**Purpose:** Map Bug Dhor research methodology areas to concrete repository components, interfaces, and current implementation status.  
**Status labels:**
- **Implemented:** code/module exists and is usable in supported contexts (subject to normal bugs/limits).
- **Implemented (conditional):** implemented but requires external prerequisites (model/runtime, SAE artifacts, analyzers, sandbox, datasets, licenses, config, or valid requests) to execute end-to-end.
- **Partial / integrated path:** wired into orchestrated flows for some cases, but coverage, accuracy, or end-to-end availability is limited.
- **Planned / target:** described in architecture/research alignment but not fully implemented or not available as a complete operational capability.
- **Not available in default environment:** cannot be exercised without prerequisites not present by default (reported honestly at runtime).

No fabricated results, citations, or capability claims.

---

## 1. Research problem and objectives

| Methodology element | Repository artifacts | Implementation status | Notes |
|---|---|---|---|
| Problem framing and claim/evidence contract | `docs/research-alignment.md`, `docs/architecture.md`, `README.md` | **Implemented** (documentation/contracts) | Defines claim kinds, honest status reporting, gates, and limitations; binding intent for engineering/research claims. |
| Local-first client/engine architecture | `vscode-extension/`, `security-engine/src/bugdhor/api`, `core`, `main.py` | **Implemented** | Extension connects to running FastAPI backend; versioned `/api/v1` API and orchestration exist. |
| Evidence-grounded analysis objective | `bugdhor/parsing`, `program_analysis`, `static`, `detection`, `explain` | **Partial / integrated path** | Real preprocessing/program/taint/detection/explanation paths integrated in orchestrator; quality/coverage depends on language/tool availability. |
| SAE/counterfactual/steering research objectives | `bugdhor/models`, `sae`, `counterfactual`, `steering`, `features` routes/modules | **Implemented (conditional)** | Core libraries exist; runtime use requires compatible checkpoints/artifacts/config and compute. |
| Repair and independent verification objectives | `bugdhor/repair`, `verification`, `sandbox`, repair/verification routes/workflow | **Implemented (conditional)** | Proposal-only workflow and independent verification implemented; model/sandbox/consent/analyzers affect executability. |
| Unified mathematical risk and advisory decision objective | `bugdhor/risk`, `bugdhor/decision`, `research/configs/risk/*` | **Implemented (programmatic, conditional)** | Correlation-aware Eq. (28)–(29) index and transparent/adaptive advisory policy; no API exposure, no labelled dataset, and no calibrated probability ship. |
| Reproducible evaluation objective | `bugdhor/experiments`, `bugdhor/evaluation`, `research/evaluation/README.md` | **Implemented (conditional)** | Framework implemented; actual experiments require licensed local data and satisfied prerequisites. |

## 2. System architecture

| Component | Key paths | Status | Interfaces / behavior |
|---|---|---|---|
| VS Code extension activation/commands | `vscode-extension/src/extension.js`, `commands/*`, `package.json` | **Implemented** | Registers commands, views, settings; engine-backed commands call service layer with validation/progress/error handling. |
| Backend HTTP client & result validation | `vscode-extension/src/api/apiClient.js`, `securityEngineService.js`, `securityResultService.js`, `configurationService.js` | **Implemented** | Calls `/api/v1` endpoints, handles timeouts/cancellation/problem details/schema validation, preserves unavailable/partial states. |
| Dashboard and webviews | `vscode-extension/src/webviews/*`, `media/*` | **Implemented** | CSP/nonce-restricted webviews, allowlisted command execution, validated messages, honest empty/live state handling with no demo or sample data. |
| Diagnostics, hovers, quick fixes | `vscode-extension/src/diagnostics/*` | **Implemented** | Publishes only validated backend findings; repair quick fixes only when backend marks eligible. |
| FastAPI app and middleware | `security-engine/src/bugdhor/api/app.py`, `middleware/*`, `dependencies.py` | **Implemented** | Request context, auth (optional token), request/body limits, CORS config, error/problem handling, logging integration. |
| API routes/schemas | `security-engine/src/bugdhor/api/routes/*`, `schemas/*` | **Implemented** | Health, scan, detection, explanation, features, counterfactual, prevention, repair, secure recommendations, verification, jobs endpoints with typed payloads/responses. |
| Orchestrator and jobs | `security-engine/src/bugdhor/core/orchestrator.py`, `core/jobs.py`, `core/pipeline.py`, `core/settings.py` | **Implemented / partial integration** | Central pipeline execution, progress/cancellation hooks, persistence, caching/limits; stage availability varies by capability/config. |
| Path safety and settings | `security-engine/src/bugdhor/core/paths.py`, `core/errors.py`, `config.py` | **Implemented** | Workspace containment/symlink-safe resolution, typed errors, env-backed settings and redaction. |

## 3. SAE methodology

| Methodology element | Key paths | Status | Notes |
|---|---|---|---|
| SAE config/model/training/metrics/checkpoints | `security-engine/src/bugdhor/sae/{config.py,model.py,training.py,metrics.py,checkpoint.py,errors.py}` | **Implemented** | Train/evaluate/save/load sparse autoencoders over activation tensors; configuration-hash aware checkpoints. |
| Activation capture support | `security-engine/src/bugdhor/models/{adapter.py,huggingface.py,activations.py,manager.py,inference.py}` | **Implemented (conditional)** | Requires compatible local model/runtime and dependencies. |
| Feature association analysis | `security-engine/src/bugdhor/sae/association.py` | **Implemented (conditional)** | Requires labeled samples and actual activations/SAE encoding; association-only outputs. |
| Feature interpretation and annotation | `security-engine/src/bugdhor/sae/interpretation.py` | **Implemented (conditional)** | Produces hypothesis reports from supplied evidence/examples; no fabricated semantics/causality. |
| API feature extraction | `security-engine/src/bugdhor/api/routes/features.py`, `core/orchestrator.py` | **Partial / integrated path (currently unavailable stages)** | Endpoint exists, but the default orchestrator declares `model_capture`/`sae_features`/`feature_aggregation` unavailable and returns no features. SAE libraries are usable programmatically only when callers supply compatible activations/artifacts. |
| SAE training UI/automation | (not exposed as end-user UI workflow) | **Planned / target** | Training is library-level; no dedicated VS Code workflow documented as available. |

## 4. Feature identification methodology

| Methodology element | Key paths | Status | Notes |
|---|---|---|---|
| Association metrics/selectivity/stability/CWE stats | `security-engine/src/bugdhor/sae/association.py` | **Implemented (conditional)** | Depends on labeled data and computed activations. |
| Feature dictionary/provenance records | `security-engine/src/bugdhor/sae/association.py`, related SAE modules | **Implemented (conditional)** | Records model/layer/checkpoint/dataset/threshold metadata where produced. The `bugdhor/features/` package is currently a scaffold only and is not claimed as an implemented extraction/aggregation runtime. |
| Policy-based feature selection | `security-engine/src/bugdhor/steering/adaptive.py`, `steering/risk_controller.py` | **Implemented (conditional)** | Uses configured measured metrics/thresholds; requires evidence inputs. |
| Automatic semantic naming/ground-truth labeling | n/a (no claimed automatic ground-truth) | **Planned / target** | Interpretation remains hypothesis/evidence-based. |

## 5. Counterfactual intervention methodology

| Methodology element | Key paths | Status | Notes |
|---|---|---|---|
| Single-feature counterfactual engine | `security-engine/src/bugdhor/counterfactual/engine.py` | **Implemented (conditional)** | Requires compatible model/SAE/runtime and valid intervention config. |
| Pairwise interactions | `security-engine/src/bugdhor/counterfactual/pairwise.py` | **Implemented (conditional)** | Four-cell contrast on declared outcome scale; descriptive uncertainty possible with replicates. |
| Higher-order interactions | `security-engine/src/bugdhor/counterfactual/higher_order.py` | **Implemented (conditional)** | Factorial contrasts with budget/sampling/caching; all required cells needed per evaluated subset. |
| API counterfactual analysis | `security-engine/src/bugdhor/api/routes/counterfactual.py`, schemas, orchestrator | **Partial / integrated path (currently unavailable stages)** | Endpoint exists, but the default orchestrator declares the `counterfactual` stage unavailable; it does not invoke the counterfactual libraries. Programmatic library use requires configured model/SAE/runtime and valid intervention data. |
| Validated causal attribution pipeline in production UI | n/a | **Planned / target** | Libraries produce controlled comparisons, not automatic causal proof. |

## 6. Pairwise interaction formulation

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Contrast formula and 4-cell design | `counterfactual/pairwise.py`, `docs/pairwise-counterfactual.md` | **Implemented** | Outcome-scale dependent; design/provenance recorded. |
| Replicate uncertainty (descriptive) | `counterfactual/pairwise.py` | **Implemented (conditional)** | Requires >=2 independent replicates per cell; no significance testing. |
| Feature selection by measured selectivity/CWE | `counterfactual/pairwise.py`, SAE association outputs | **Implemented (conditional)** | Depends on available feature dictionaries/metrics. |

## 7. Higher-order interaction formulation

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Factorial subset contrast | `counterfactual/higher_order.py`, `docs/higher-order-counterfactual.md` | **Implemented** | Requires all `2^k` cells for subset. |
| Budget/sampling/preselection/caching | `counterfactual/higher_order.py` | **Implemented** | Manages combinatorial complexity; records observed/theoretical cost. |
| Descriptive uncertainty reporting | `counterfactual/higher_order.py` | **Implemented (conditional)** | Requires repeated independent outcomes. |

## 8. Adaptive activation steering

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Activation steering engine | `security-engine/src/bugdhor/steering/engine.py` | **Implemented (conditional)** | Explicit opt-in, compatible model/layer/SAE required; hook-based intervention with safety checks/provenance. |
| Adaptive policy and history | `security-engine/src/bugdhor/steering/adaptive.py` | **Implemented (conditional)** | Evidence-informed scheduling/selection; auditable decisions/history. |
| Functional-preservation constraints | `security-engine/src/bugdhor/steering/functional.py` | **Implemented (conditional)** | Depends on supplied evaluators/evidence; unavailable required evidence rejected by default. |
| API prevention/steer operation | `security-engine/src/bugdhor/api/routes/prevention.py`, schemas, orchestrator | **Partial / integrated path (currently unavailable stages)** | Endpoint exists, but the default orchestrator declares `steering_plan`/`steering_evaluation` unavailable. Steering libraries are separate/programmatic and require explicit opt-in, compatible runtime, and SAE/evaluator inputs. |
| Proven generalized security improvement | n/a | **Planned / target** | Requires reproducible evaluation; not claimed. |

## 9. CWE-specific risk control

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Policy-driven CWE risk controller | `security-engine/src/bugdhor/steering/risk_controller.py`, `docs/steering.md` | **Implemented (conditional)** | Configurable thresholds/weights/multipliers; records component evidence and fallbacks. |
| Calibration interface/result handling | `security-engine/src/bugdhor/steering/risk_controller.py` | **Implemented (conditional)** | Calibrated probabilities exposed only with valid calibrator metadata/results. |
| Comprehensive CWE-specific detection/mitigation coverage | detection/static/risk modules across engine | **Partial / integrated path** | Coverage depends on rules, analyzers, evidence, and configuration. |

## 10. Evidence fusion

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Parsing and program analysis (AST/CFG/DFG) | `security-engine/src/bugdhor/parsing/*`, `program_analysis/*` | **Implemented** | Integrated in scan/detection/explanation paths for supported sources. |
| Taint analysis | `security-engine/src/bugdhor/program_analysis/taint.py` | **Implemented** | Rule-based, bounded/same-file propagation characteristics; explicit limitations. |
| Static analyzer adapters/runner | `security-engine/src/bugdhor/static/*` | **Implemented (conditional)** | Semgrep/Bandit and optional CodeQL/Joern adapters; missing tools reported explicitly. |
| Detection fusion engine | `security-engine/src/bugdhor/detection/*` | **Implemented / partial integration** | Produces evidence-backed findings/coverage; false positives/negatives possible. |
| Explanation engine and evidence graph concepts | `security-engine/src/bugdhor/explain/*`, `docs/explain.md` | **Implemented / partial integration** | Structured/human-readable explanations from available evidence; preserves boundaries. |
| Full evidence-graph UI parity for all node types | extension dashboard/webviews + backend payloads | **Partial / integrated path** | UI renders supplied state; not all research evidence types are always available. |

## 11. Repository-aware repair

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Repository context builder | `security-engine/src/bugdhor/repair/context.py` | **Implemented** | Bounded, containment-aware context and summaries; opt-in. |
| Repair engine (prompting/candidates/validation) | `security-engine/src/bugdhor/repair/engine.py` | **Implemented (conditional)** | LLM-backed generation requires compatible local model adapter; prompt hardened for untrusted inputs. |
| Patch ranking/constraints | `security-engine/src/bugdhor/repair/ranking.py` | **Implemented** | Mandatory checks and weighted preferences; missing evidence not fabricated. |
| Integrated repair workflow | `security-engine/src/bugdhor/repair/workflow.py` | **Implemented (conditional)** | 12-step proposal/verification-oriented workflow; no auto-apply. |
| Repair API and VS Code flow | `api/routes/repair.py`, `vscode-extension/src/commands/repairCommands.js`, `repair/patchApplication.js` | **Implemented (conditional)** | Proposal generation/request and client-side preview/apply safeguards; depends on backend response and user approval. |
| Fully automatic verified repair | n/a | **Not implemented / by design** | Explicit approval and independent verification required. |

## 12. Independent verification

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Independent security verifier | `security-engine/src/bugdhor/verification/engine.py` | **Implemented (conditional)** | Before/after static/taint-oriented evidence comparison in isolated temp contexts. |
| Functional verifier | `security-engine/src/bugdhor/verification/functional.py` | **Implemented (conditional)** | Consent-gated; requires isolated sandbox for untrusted project tests. |
| Sandbox executor | `security-engine/src/bugdhor/sandbox/executor.py` | **Implemented (conditional)** | Enforces consent/safety constraints; backend availability (e.g. Docker) required. |
| Verification API and extension command | `api/routes/verification.py`, `vscode-extension/src/commands/repairCommands.js` | **Implemented (conditional)** | `verification_run` is a registered integrated interface; individual responses depend on analyzers/consent/sandbox and must remain inconclusive when evidence is unavailable. The independent verification engine is also invoked inside repair and secure-recommendation workflows with mandatory gates. |
| Universal proof of correctness/security | n/a | **Not available** | Verification is bounded by checks/profile/environment. |

## 12A. Secure code recommendation and feedback loop

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Secure recommendation workflow | `security-engine/src/bugdhor/recommendation/*` | **Implemented** | 12 stages: findings, source context, CWE requirements, repository context, evidence, secure prompt, candidates, syntax, static analysis, functional tests, ranking, display. Mandatory gates reject every unverified candidate. |
| Proposal-only recommendation API | `security-engine/src/bugdhor/api/routes/recommendation.py`, `schemas/recommendation.py`, `core/orchestrator.py` | **Implemented** | `POST /api/v1/recommendations/generate`; `requiresApproval` is always true; backend never applies code; `result.prompt.text` returned only to the source-supplying caller. |
| Steering and provenance guards | `security-engine/src/bugdhor/recommendation/engine.py`, `vscode-extension/src/api/securityEngineService.js` | **Implemented** | HTTP steering pipeline is always `None`; no credential is serialized; D/E/F claims require genuine local pipelines; SAE/counterfactual evidence stays hypothesis-level. |
| Provider-backed VS Code generation | `vscode-extension/src/recommendations/secureCodeGeneration.js`, `src/commands/repairCommands.js` | **Implemented (conditional)** | Requires a validated diagnostic and an available B/C provider; obtains the backend prompt, extracts target-file diffs, and submits them for backend verification. Hosted assistants never claim validated steering. |
| Dashboard recommendation review and approval | `vscode-extension/src/webviews/dashboardPanel.js`, `dashboardModel.js`, `media/dashboard.js` | **Implemented** | Shows original/repaired code, changes, rationale, remaining risks, verification, and provenance; explicit approval with base-hash revalidation is required before any edit. |
| Feedback lifecycle and bounded loop | `vscode-extension/src/feedback/*`, `src/monitoring/realtimeMonitor.js`, `src/diagnostics/diagnosticController.js` | **Implemented** | Hooks never synthesize findings; duplicate scans are deduped; one self-induced scan is suppressed and one bounded rescan scheduled; resolution requires patch + clean rescan + passing verification. |
| Fully automatic or guaranteed-secure repair | n/a | **Not implemented / by design** | Explicit approval is mandatory; passing checks are bounded evidence, not a security proof. |

See [secure recommendations and feedback](secure-recommendation-and-feedback.md) for the workflow contract, gate details, settings, and verification commands.

## 12B. Unified risk engine and advisory decision policy

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Evidence normalization and reliability | `security-engine/src/bugdhor/risk/normalization.py`, `models.py` | **Implemented** | Explicit source/claim/polarity/reliability; failed, unavailable, unvalidated, and partial sources are excluded with reasons; no imputation. |
| Correlation control | `security-engine/src/bugdhor/risk/engine.py`, `config.py` | **Implemented** | Declared dependency groups: AST/CFG/DFG/taint → `program_analysis`, model/SAE/interaction → `model_internal`; reliability-weighted group means, noisy-OR across groups, signed interaction adjustments inside a group. |
| Eq. (28)–(29) risk index | `security-engine/src/bugdhor/risk/engine.py` | **Implemented** | Heuristic index with exact weighted contributions, lowercase bands, `renormalize`/`unavailable` missing policies, and a documented uncertainty heuristic; never a probability. |
| Group-disjoint calibration | `security-engine/src/bugdhor/risk/calibration.py`, `evaluation.py` | **Implemented (conditional)** | Platt scaling with validation-only Brier/ECE/log-loss/AUROC, bootstrap intervals, and acceptance gates. Placeholder config only; no labelled dataset or validated artifact ships. Rejected artifacts remain auditable but cannot emit probabilities. |
| Transparent decision baseline | `security-engine/src/bugdhor/decision/rules.py`, `engine.py` | **Implemented** | Rules R01–R09 with observed conditions; capability/consent gates; all blocked actions recorded in the trace; advisory by default. |
| Adaptive decision ranking | `security-engine/src/bugdhor/decision/adaptive.py`, `config.py` | **Implemented** | Deterministic preference-utility ranking under declared weights; not reinforcement learning and not claimed optimal. Distinct from `steering/adaptive.py`. |
| Reproducible configs and CLI | `research/configs/risk/*`, `research/datasets/risk/README.md`, `bugdhor.risk.evaluation` | **Implemented (conditional)** | Versioned configs with recorded hashes; CLI needs a caller-supplied labelled JSONL dataset. |
| HTTP risk/decision endpoints | n/a | **Not implemented / by design** | Programmatic backend libraries only; no client-supplied calibration artifact can reach the engine over the wire. |

See [unified risk engine](unified-risk-engine.md) and [adaptive decision policy](adaptive-decision-policy.md) for contracts, formulas, claim boundaries, and tests.

## 13. Experimental design

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Experiment groups E0–E8 and prerequisites | `security-engine/src/bugdhor/experiments/groups.py` | **Implemented** | Definitions/check metadata only; execution requires prerequisites. |
| Dataset registry/loaders/validation/dedup/leakage checks | `security-engine/src/bugdhor/experiments/datasets.py` | **Implemented (conditional)** | Local licensed/available datasets only. |
| Split strategies and hashing | `security-engine/src/bugdhor/experiments/splits.py` | **Implemented (conditional)** | Some strategies depend on metadata (e.g. temporal). |
| Config hashing/manifests/tracking/raw output | `security-engine/src/bugdhor/experiments/config.py` | **Implemented** | Supports reproducibility metadata capture. |
| Experiment runner/evaluation pipeline | `security-engine/src/bugdhor/experiments/evaluation.py` | **Implemented (conditional)** | Runs only when capabilities/data available; records unavailable reasons. |

## 14. Baselines

| Baseline | Implementation | Status | Notes |
|---|---|---|---|
| E0 Original LLM | `experiments/groups.py`, experiment pipeline | **Implemented (conditional)** | Requires model/runtime and evaluation setup; no results included. |
| E1 Security prompting | `experiments/groups.py`, experiment pipeline | **Implemented (conditional)** | Requires prompt/configured generation path. |
| E2 Static-analysis baseline | `experiments/groups.py`, static adapters/runner | **Implemented (conditional)** | Requires installed/configured analyzers and datasets. |

## 15. Ablation studies

| Ablation (A1–A8 concept) | Implementation | Status | Notes |
|---|---|---|---|
| Without SAE features / counterfactual / pairwise / higher-order / steering / static fusion / repository context / independent verification | `security-engine/src/bugdhor/evaluation/ablation.py`, experiment config/group support | **Implemented (conditional)** | Executable only when compared components and data are available; no fabricated ablation results. |

## 16. Evaluation metrics

| Metric family | Implementation | Status | Notes |
|---|---|---|---|
| Detection metrics | `security-engine/src/bugdhor/evaluation/metrics.py` | **Implemented** | Computed from observations only. |
| Localization metrics | `security-engine/src/bugdhor/evaluation/metrics.py` | **Implemented** | Depends on ground-truth/line annotations in inputs. |
| Repair metrics | `security-engine/src/bugdhor/evaluation/metrics.py` | **Implemented** | Requires repair/verification outcomes data. |
| Explainability metrics | `security-engine/src/bugdhor/evaluation/metrics.py` | **Implemented (conditional)** | Operational definitions depend on provided evidence/labels/protocols. |
| Performance metrics | `security-engine/src/bugdhor/evaluation/metrics.py` | **Implemented** | Latency/overhead/memory from measured runs. |
| Calibration metrics (Brier/ECE) | n/a (documented out of scope until available) | **Planned / target** | Not implemented without genuine calibrators/data. |

## 17. Statistical analysis

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Assumption checks, sample/missing-data reporting | `security-engine/src/bugdhor/evaluation/statistics.py` | **Implemented** | Reports applicability/limitations. |
| Bootstrap CIs (incl. cluster bootstrap) | `security-engine/src/bugdhor/evaluation/statistics.py` | **Implemented (conditional)** | Requires observations; cluster IDs optional/when relevant. |
| Paired/nonparametric tests, effect sizes | `security-engine/src/bugdhor/evaluation/statistics.py` | **Implemented (conditional)** | Computed only when valid; no fabricated results. |
| Multiple-comparison correction (Holm, BH) | `security-engine/src/bugdhor/evaluation/statistics.py` | **Implemented (conditional)** | Applies to provided test families. |
| Reporting/export with significance notes | `security-engine/src/bugdhor/evaluation/reporting.py`, `experiments/export.py` | **Implemented (conditional)** | Exports from actual data; distinguishes statistical vs practical significance in reporting design. |

## 18. Threats to validity

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Limitations/threat disclosures in docs | `docs/research-alignment.md`, `docs/research-methodology.md`, component docs, audit/integration reports | **Implemented** (documentation) | Explicit limitation IDs/registers and non-claims. |
| Runtime provenance/manifest capture | `experiments/config.py`, manifests/export, stage reports | **Implemented / partial integration** | Completeness depends on executed path and available metadata. |
| Automated validity enforcement across all claims | n/a | **Partial / planned** | Contracts/tests enforce parts; full research-claim enforcement is procedural and evidence-dependent. |

## 19. Limitations

| Limitation area | Implementation evidence | Status | Notes |
|---|---|---|---|
| Environment/prerequisite dependence | settings, capability reporting, unavailable stage reasons, docs | **Implemented** (honest reporting) | Model/SAE/analyzers/sandbox/datasets often required. |
| Analysis precision/scope bounds | `parsing/*`, `program_analysis/*`, `static/*`, limitation docs | **Implemented** | Approximate/intraprocedural/unresolved behaviors documented. |
| No guaranteed semantics/causality/security | SAE/counterfactual/steering/repair/verification docs and APIs | **Implemented** (guardrails/contracts) | Must be reflected in outputs and usage. |
| Unexecuted benchmarks in repo docs | `research/evaluation/README.md`, reports | **Current state** | No fabricated benchmark metrics/results. |

## 20. Compatibility testing and realistic coding benchmark

| Element | Implementation | Status | Notes |
|---|---|---|---|
| Model capability probes | `security-engine/src/bugdhor/models/compatibility.py`, `compatibility_probes.py` | **Implemented** | Ten independent probes for local Transformers checkpoints; declared capabilities are never treated as observed. |
| Compatibility matrix runner and report | `research/configs/models/compatibility-matrix.json`, `research/experiments/model_compatibility/run_compatibility_matrix.py` | **Executed** | Committed JSON/Markdown report contains actual evidence; registered checkpoints and hosted providers are `unavailable`. |
| Assistant integration probes | `run_compatibility_matrix.py` | **Unavailable in CLI** | Requires a VS Code host or configured endpoint/model path/manifest; only declared A-F capabilities are shown. |
| Realistic coding task bundle | `benchmarks/configs/coding-benchmark-v1.json`, `benchmarks/tasks/*.json`, `benchmarks/datasets/coding-tasks-v1.json` | **Defined** | Ten scenarios; prompts are separated from ground truth and verified against forbidden terms. |
| Benchmark harness | `benchmarks/harness/run_coding_benchmark.py` | **Executed as readiness bundle** | Validates contract/hashes and writes `not_run` outcomes; no fabricated model, repair, or verification results. |
| Benchmark execution | n/a | **Not run** | Needs an exact production model revision, pinned rule pack, sandbox, and registered executor. |

---

## Cross-cutting interface map

| Interface | Producer | Consumer | Status |
|---|---|---|---|
| `/api/v1/health`, scan, detection, explanation endpoints | FastAPI routes/orchestrator | VS Code extension, API clients | **Implemented** |
| Feature/counterfactual/steering endpoints | Routes/orchestrator (honest stubs; no D/E/F hooks) | Extension, API clients | **Implemented as honest unavailable stubs** |
| Repair/verification endpoints | Routes/orchestrator/workflow/verifiers | Extension, API clients | **Implemented (conditional)** |
| Secure recommendation proposals | `api/routes/recommendation.py`, `recommendation/*`, provider-backed client workflow | Dashboard, API clients | **Implemented (conditional)** |
| Feedback lifecycle and rescan control | Diagnostics hook, `feedback/*`, realtime monitor | Dashboard, notifications, diagnostics | **Implemented** |
| Risk assessment and decision trace | `bugdhor/risk`, `bugdhor/decision` | Programmatic backend callers (no HTTP route) | **Implemented (conditional)** |
| Jobs/status/progress/result/cancel | `core/jobs.py`, `api/routes/jobs.py` | Clients/tools | **Implemented** |
| Diagnostics/hover/quick-fix data | Validated backend scan results | VS Code diagnostics providers | **Implemented** |
| Experiment manifests/exports/reports | `experiments/*`, `evaluation/*` | Researchers/tools | **Implemented (conditional)** |
| Model compatibility report | `models/compatibility*`, compatibility runner | Researchers/tools | **Executed for local research checkpoints** |
| Coding benchmark readiness bundle | `benchmarks/harness/*`, `benchmarks/tasks/*` | Researchers/tools | Harness **Fully** executed as readiness; execution **not_run** until a real executor and sandbox exist |

## Maintenance note

When implementation status changes (e.g. new end-to-end integrations, added analyzers, UI flows, HTTP exposure of risk/decision, or validated experimental runs), update this mapping together with `docs/research-methodology.md`, `docs/api.md`, `docs/unified-risk-engine.md`, `docs/adaptive-decision-policy.md`, and relevant component docs to prevent documentation drift. In particular, exposing a calibrated probability requires a real group-disjoint dataset, a passing calibration artifact, and a shared-contract/schema version decision.