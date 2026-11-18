# Research implementation status

- Date: 2026-11-18
- Worktree HEAD: `709c92b00d8c17fe4ba32c977f4bdb312d2c8ae5`
- State: integration changes are present in the working tree and are **uncommitted**
- Overall verdict: **the local engineering integration is fully operational within its declared scope; the research program is partial and its empirical claims remain unvalidated**

## 1. Status vocabulary

| Status | Meaning in this report |
|---|---|
| **Fully** | Implemented, wired, and verified in automated tests and, where applicable, the Extension Host e2e run. This is an engineering status, not a security, causal, calibrated, or research-validity claim. |
| **Partial** | Real implementation or executed harness exists, but one or more prerequisites, artifacts, independent checks, or validation gates are missing. A partial status does not authorize a research claim. |
| **Unavailable** | Not wired, not configured, absent, or represented by an honest stub. The system reports the gap and fabricates no result. |
| **Not run** | A harness, protocol, or evaluation path exists but no execution result was produced because required inputs are absent. In machine-readable artifacts this appears as `not_run`, `null`, and `measured: false`. |

## 2. Evidence base

| Evidence | Result |
|---|---|
| Backend suite | 638 passed, 0 failed |
| Extension unit suite | 295 passed, 0 failed |
| ESLint | clean |
| Extension Host e2e against a real local backend | passed, exit code 0 |
| Compatibility harness config hash | `10b8282eac8a9c104fd8bdfb0b936078f3f2021e0868fcdc92c31472e8d1d540` |
| Benchmark readiness config hash | `3432152cc3ad0ea5ed45c456031b38cc6c04705ce3de3dcb0f6b593ac454e09c` |
| Benchmark status | `not_run`; `contractIssues: []`; all metrics `null` and `measured: false` |
| Repository-wide `npm run format:check` | fails on a pre-existing baseline; changed JavaScript files are Prettier-clean |

The tests establish mechanical correctness, contracts, safety gates, and graceful degradation on controlled fixtures. They do not establish detector accuracy, security guarantees, SAE semantic validity, causal effects, steering benefit, repair correctness beyond the checks run, or benchmark performance.

## 3. Integrated engineering path

| Component | Status | What is proven | What is not proven |
|---|---|---|---|
| VS Code monitoring, version tracking, debounce, cancellation | **Fully** | Document events and bounded, consent-gated requests work in unit tests and the Extension Host | No model or author attribution |
| Strict HTTP transport and response validation | **Fully** | Versioned requests, typed errors, cancellation, and rejection of malformed payloads are tested | Backend process supervision; the extension does not start the backend |
| Native diagnostics, hover, Quick Fix, patch approval | **Fully** | Real CWE-89 finding became a native diagnostic; hover used only backend data; source edits require approval | No automatic or guaranteed-secure patch |
| Python/JavaScript preprocessing and AST/CFG/DFG | **Fully** within scope | Real parsing, spans, tokens, functions, chunks, graphs, and AST evidence are tested and observed in scans | Other languages, cross-file/incremental indexing, dynamic language features |
| Static analyzer adapters | **Partial** | Semgrep/Bandit plus optional CodeQL/Joern adapters have bounded subprocesses and normalized output | Tool availability, pinned rule pack, universal analyzer correctness |
| Detection and classification | **Partial** | Real findings, including CWE-89 `ast.dynamic-sql-query`, are produced from AST/DFG evidence | Trained multi-view detector, validated multi-class accuracy, exploitability |
| Unified risk enrichment | **Partial** | `scoreKind: heuristic_index`, `probability: null`, config hash `422b0ac3f07f036154012a9a59aee928ba3c578853d6a83cc129f1994c7415f8` observed end-to-end | Calibrated probability, representative labelled validation |
| Explanation | **Partial** | Matching finding IDs return observation graphs with `why_detected`, `source_to_sink_paths`, and `limitations` | Model-internal attribution, localization score `L(r_i)`, causal explanation |
| Repair workflow | **Partial** | Proposal-only workflow, explicit target requirements, approval gate, and no source writes are tested | Autonomous repair, successful patch, verified secure patch |
| Independent verification | **Partial** | Static/bounded checks run and return `inconclusive` with explicit limitations | Proof of correctness, adequate sandbox execution, pass verdict without evidence |
| Feedback and research separation | **Fully** | Bounded feedback/rescan hooks are covered and do not publish synthetic findings | Research evidence status for ordinary editor activity |
| Compatibility harness | **Fully** as an executed harness | Stable config hash and observed probe outcomes were regenerated | Production model availability |
| Benchmark readiness harness | **Fully** as a readiness validator | Contract validation produced `contractIssues: []` and a `not_run` bundle | Any benchmark execution or empirical result |
| Benchmark execution | **Not run** (`not_run`) | Protocol, tasks, conditions, and metrics are defined | All measured results; every metric remains `null` |

## 4. Research component status

| Research component | Implementation status | Operational/API status | Claim boundary |
|---|---|---|---|
| Incremental A–L analysis taxonomy | **Fully** | A/B/C/D/E/L **Fully**; F/G/J/K **Partial**; H/I **Unavailable** | Stage names describe implemented pipeline steps, not research validation |
| Editor-level monitoring (capability A) | **Fully** in the Extension Host; **Unavailable** in the CLI runner | **Fully** in VS Code | It is an editor event observer, not assistant or model access |
| Assistant generation request/response adapters (B/C) | Adapter contracts **Fully** implemented | Local runtime **Unavailable** without a configured documented provider | No endpoint, key, or official extension manifest is present |
| Real activation access (D) | Contract **Partial** | **Unavailable** in the extension/API path | Local probe harness access is not a production accessor |
| SAE integration (E) | Library/artifact/probe code **Partial** | HTTP route **Unavailable** | Requires D plus a validated production SAE artifact |
| Activation steering (F) | Library and deterministic policy code **Partial** | HTTP route **Unavailable** | Requires D, E, real accessors, and explicit opt-in |
| Mathematical risk fusion | **Partial** | `heuristic_index` only | Not a probability; no calibrated artifact ships |
| Calibrated probability | Calibration code **Partial**; artifact **Unavailable** | **Unavailable** | Needs labelled data, split hash, Brier score, ECE, and acceptance gates |
| SAE feature extraction | Library **Partial**; generic feature layer **Unavailable** | HTTP route **Unavailable** | Local 0.5B layer-4 probes are `LIM-COMPAT-01` research evidence only |
| Counterfactual interaction analysis | Estimators **Partial** | HTTP route **Unavailable** | Artifact/revision/layer-specific model-internal hypothesis, never causal |
| Interaction-aware steering | Steering code **Partial** | HTTP route **Unavailable** | Not RL, not optimal control, not a demonstrated security gain |
| Paper Algorithm 7 prevention loop | **Unavailable** | **Unavailable** | Existing steering library is not a substitute |
| Pearson interaction screening with controls | **Unavailable** | **Unavailable** | Current preference ranking uses declared selectivity, not the paper's screening protocol |
| Secure code generation | Prompt/proposal workflow **Partial** | Live provider **Unavailable** | No hosted endpoint/key or registered generation model |
| Repository-aware repair | Proposal workflow **Partial** | **Partial**, proposal-only | No autonomous code generation or application |
| Independent security/functional verification | Check engines **Partial** | **Partial**, usually `inconclusive` | Bounded by analyzers, consent, and sandbox; no security proof |
| Experiment groups E0–E8 | Definitions **Fully** implemented | All execution **Not run** | The benchmark condition labelled E7 maps to group E8; the published registry keeps E7 as steering plus repair and E8 as full framework |
| Metrics, statistics, ablation, and reporting helpers | **Partial** / conditional | **Not run** as an experiment | They compute from supplied observations only; no results are bundled |
| Limitation register and claim guardrails | **Fully** documented in current reports; historical audits are point-in-time | **Partial** enforcement across all claims | Some older documents retain historical wording and are not authoritative status sources |

## 5. Model and compatibility status

| Target class | Status | Evidence |
|---|---|---|
| Registered production checkpoints (Llama 3.1 8B, Qwen2.5-Coder 7B, DeepSeek-Coder 6.7B) | **Unavailable** | `checkpoint_not_present in local Hugging Face cache`; all ten capability probes unavailable |
| Local `Qwen2.5-Coder-0.5B` base and instruct checkpoints | **Fully** as compatibility probes; most probe outcomes `supported` | Generation, activations, SAE, intervention, steering, token-level, reproducibility, and hardware probes observed; `code_analysis` is `partial` because generated text was not valid JSON |
| Assistant integration targets in the CLI runner | **Unavailable** | No VS Code host, endpoint/key, model path, or extension manifest |
| Capability A in the real Extension Host | **Fully** | Extension Host e2e |
| Capabilities B/C in local operation | **Unavailable** | No configured documented provider |
| Capabilities D/E/F in local operation | **Unavailable** | No validated accessor, production SAE artifact, or real steering contract |

`LIM-COMPAT-01` remains binding: the local 0.5B checkpoints are research probes, not production adapters. Their results do not register a production model, enable D/E/F, calibrate risk, or establish causal or security benefit.

## 6. Why statuses are not upgraded

| Missing prerequisite | Blocked upgrade |
|---|---|
| Registered production model path, exact revision, and cache artifact | Production generation/analysis; benchmark model binding |
| Hosted provider endpoint, key, and documented manifest | Live assistant B/C workflows |
| Validated local `activationAccessor` plus production SAE artifact and mapping | D and E |
| Real steering contract with explicit effect metric wired through D/E | F |
| Labelled, group-disjoint calibration dataset and accepted calibrator artifact | Calibrated probability |
| Trained detector and held-out evaluation | Multi-view detection and classification accuracy |
| Adequate, configured execution sandbox | Functional verification pass and benchmark execution scoring |
| Pinned analyzer rule pack and registered benchmark executor | Benchmark execution |
| Empirical runs under the pinned protocol | E0–E8 results and research conclusions |

## 7. Final determination

- **Fully:** integrated local engineering path, A–L monitoring/analysis scaffolding where explicitly listed, strict validation, diagnostics, approval workflow, compatibility harness execution, and benchmark readiness validation.
- **Partial:** preprocessing/program-analysis scope, taint-based security evidence, static adapters, detection, heuristic risk, explanation, repair, verification, research helper libraries, and experiment tracking.
- **Unavailable:** production checkpoints, live assistant B/C, D/E/F in the operational path, SAE/counterfactual/steering HTTP capabilities, calibrated probability, trained detector, localization score, paper-level interaction screening, Algorithm 7 prevention loop, automatic/guaranteed-secure repair, and universal verification.
- **Not run (`not_run`):** all E0–E8 experiment groups and the realistic coding benchmark.

**The project is not complete as a research system.** It is an operational local engineering integration with honest partial results and explicit blockers. No commit, push, calibrated artifact, benchmark result, source patch application, or research-completeness claim has been produced in this worktree.
