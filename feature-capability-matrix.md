# Feature capability matrix

- Date: 2026-11-18
- Scope: current workspace state at HEAD `709c92b00d8c17fe4ba32c977f4bdb312d2c8ae5` with uncommitted integration changes

## Status definitions

| Status | Definition |
|---|---|
| **Fully** | Implemented, wired, and verified in automated tests and, where applicable, the Extension Host e2e run. Scope-limited implementations remain fully implemented only within their declared scope. |
| **Partial** | Real code exists, but required evidence, artifacts, tools, independent checks, or validation are missing. No security, causal, calibrated, or research-completeness claim follows from this status. |
| **Unavailable** | Honest stub, unwired library, absent configuration, or absent artifact. The system reports this explicitly and fabricates no result. |
| **Not run** | A harness or evaluation path exists but was not executed because prerequisites are missing. |

## 1. Integrated product capabilities

| Capability | Status | Evidence | Boundary |
|---|---|---|---|
| VS Code editor monitoring (change events, versions, diagnostics) | **Fully** | 295 extension unit tests; Extension Host e2e passed | No author or model attribution |
| Debounce, cancellation, concurrent documents | **Fully** | Unit and e2e monitor tests | Editor responsiveness preserved |
| Source-sharing privacy gates | **Fully** | Unit tests and e2e consent checks | Workspace scans send metadata only |
| Strict backend response validation | **Fully** | API/client contract tests; real backend payload exercised | Invalid findings are rejected, never synthesized |
| Native diagnostics from real findings | **Fully** | E2e produced CWE-89 finding and native diagnostic | Only workspace-contained, validated findings |
| Hover explanation and repair Quick Fix | **Fully** | Hover verified in e2e; Quick Fix verified in unit tests | Content comes from backend finding/result only |
| Dashboard rendering and state honesty | **Fully** | Unit tests; e2e opened singleton tab | Demo data is explicitly labelled and never a scan result |
| Versioned HTTP transport and typed errors | **Fully** | Backend API tests; e2e health/unreachable checks | Backend process is not started by the extension |
| Python/JavaScript preprocessing | **Fully** | Backend unit/integration tests; scan stages observed | Other languages unsupported |
| AST analysis | **Fully** | Real `ast.dynamic-sql-query` finding observed | Observation, not exploitability proof |
| CFG/DFG construction | **Fully** | Graph unit tests; scan evidence sources | Intraprocedural and same-file only |
| Taint path construction | **Partial** | Positive/negative flow tests; DFG evidence in e2e | Potential syntactic flow, not attacker control |
| Static analyzer adapters | **Partial** | Adapter tests with mocked/fake tools | Tool availability varies; rule pack unpinned |
| Detection engine | **Partial** | Real CWE-89 finding in e2e and API regression tests | No trained multi-view detector |
| Unified risk enrichment | **Partial** | Observed `scoreKind=heuristic_index`, `probability=null` | No calibrated probability artifact |
| Explanation engine | **Partial** | Matching finding produced `analysisAvailable=true`, `claimKinds=["observation"]` | No model-internal attribution or localization score |
| Secure recommendation prompt/proposal | **Partial** | API/integration tests; e2e covered the repair command/proposal path with no generated patch, not hosted generation | No hosted provider credentials or registered generator model |
| Repository-aware repair workflow | **Partial** | Proposal-only repair and approval-gate tests | No autonomous code generation or application |
| Independent static verification | **Partial** | Real checks and explicit inconclusive classification | Not a pass verdict |
| Functional execution verification | **Partial** | Sandbox contract and checks exist | No adequate sandbox; execution not attempted |
| Feedback recording | **Fully** | E2e and unit coverage | Separate from research evidence |
| Compatibility matrix harness | **Fully** | Rerun produced stable config hash and report | Reports observed local probes, not production availability |
| Benchmark readiness harness | **Fully** as a readiness validator | Harness executed; bundle written with `contractIssues=[]` and `status=not_run` | Contract validation only |
| Benchmark execution | **Not run** (`not_run`) | Every metric `null` and `measured: false` | No model path, sandbox profile, rule pack, or executor |

## 2. Research and model-internal capabilities

| Capability | Status | Evidence | Boundary |
|---|---|---|---|
| SAE library code (encode/decode/training helpers) | **Partial** | Unit and mathematics tests; local probe artifacts | Not a production artifact or HTTP capability |
| SAE feature extraction HTTP route | **Unavailable** | Honest stub: no features, empty result | Requires D plus validated production SAE artifact |
| Counterfactual library code | **Partial** | Unit/mathematics tests for single, pairwise, higher-order effects | Not paper-level screening with controls |
| Counterfactual HTTP route | **Unavailable** | Honest stub: no effects or validity estimate | Model-intervention scope only; no causal claim |
| Steering library code | **Partial** | Unit/mathematics tests for steering and decision policy | Advisory deterministic ranking, not RL or optimal control |
| Activation steering HTTP route | **Unavailable** | Honest stub: no plan or evaluation | Requires D, E, explicit opt-in, and real accessor |
| Direct model activation access in extension path | **Unavailable** | Contract-only adapters | No validated `D` accessor configured |
| Registered production checkpoints | **Unavailable** | Compatibility report: all registered targets unavailable | `LIM-COMPAT-01` |
| Local 0.5B Qwen compatibility probes | **Fully** as probes | Observed generation, activation, SAE, intervention, steering, reproducibility | Research probes only; not production adapters |
| Calibrated probability | **Unavailable** | No calibrator artifact, dataset identity, split hash, Brier score, or ECE | `heuristic_index` cannot be promoted |
| Trained multi-view detector | **Unavailable** | No trained detector or evaluation | Current detector is heuristic evidence fusion |
| Localization score `L(r_i)` | **Unavailable** | Not implemented | Explanation graph is not localization attribution |
| Pearson interaction screening and controls | **Unavailable** | Not implemented | Existing ranking is by selectivity |
| Paper-defined Algorithm 7 prevention loop | **Unavailable** | Not implemented | Steering library is not a substitute |
| Experiment tracking and manifests | **Partial** | Experiment groups and harness contracts exist | No executed experiment results |

## 3. Assistant capability taxonomy A–F

| Capability | Exact status | Evidence and boundary |
|---|---|---|
| A — editor monitoring | **Fully** | Observed in the Extension Host; CLI runner reports unavailable because it has no VS Code host |
| B — generation request access | **Unavailable** locally | Adapter contract **Fully** implemented; no configured documented provider |
| C — generation response access | **Unavailable** locally | Adapter contract **Fully** implemented; no configured documented provider |
| D — real internal activation access | **Unavailable** locally | Adapter contract **Partial**; local research probes are separate |
| E — SAE integration | **Unavailable** locally | Adapter contract **Partial**; requires D plus validated production SAE artifact |
| F — activation steering | **Unavailable** locally | Adapter contract **Partial**; requires D, E, explicit opt-in, and real accessor |

Invariants are enforced: E implies D; F implies D and E; hosted providers may not claim D/E/F.

## 4. Assisted workflow A–L

| Stage | Name | Status | Note |
|---|---|---|---|
| A | change_detection | **Fully** | Document events and version tracking |
| B | region_identification | **Fully** | Bounded function-level ranges |
| C | syntax_analysis | **Fully** | Python/JavaScript only |
| D | ast_analysis | **Fully** | Real AST evidence |
| E | cfg_dfg_analysis | **Fully** | Declared intraprocedural/same-file scope |
| F | taint_analysis | **Partial** | Potential flows, not exploitability |
| G | static_analysis | **Partial** | Optional tools and unpinned rule pack |
| H | sae_features | **Unavailable** | Honest HTTP stub |
| I | counterfactual_analysis | **Unavailable** | Honest HTTP stub |
| J | evidence_fusion | **Partial** | Heuristic, not trained/calibrated |
| K | classification | **Partial** | Real findings, no validated multi-view detector |
| L | diagnostic_export | **Fully** | Native diagnostics with strict validation |

## 5. Experiment groups

| Group | Definition | Status |
|---|---|---|
| E0 | Original model, no intervention | **Not run** |
| E1 | Security prompting baseline | **Not run** |
| E2 | Static-analysis baseline | Implementation **Partial**; execution **Not run** |
| E3 | Single-feature SAE steering | Library **Partial**, HTTP **Unavailable**, execution **Not run** |
| E4 | Multi-feature analysis | Library **Partial**, HTTP **Unavailable**, execution **Not run** |
| E5 | Interaction-aware steering | Library **Partial**, HTTP **Unavailable**, execution **Not run** |
| E6 | Automated repair | Proposal workflow **Partial**, execution **Not run** |
| E7 | Steering plus repair | Mapped to existing group `E8` in benchmark config; **Not run** |
| E8 | Full Bug Dhor framework | **Not run** |

The published E0–E8 registry is unchanged. The benchmark condition labelled E7 maps to experiment group E8; all declared metrics remain `null` and `measured: false`.

## 6. Final determination

The integrated VS Code assistant path is **operational and verified for its implemented scope**. It is not a complete research implementation and must not be described as calibrated, causal, model-internal, autonomously repairing, fully verified, or empirically validated.

All integration changes remain uncommitted and unpushed.
