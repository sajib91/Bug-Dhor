# Final system architecture — integrated Bug Dhor assistant

- Date: 2026-11-18
- Worktree HEAD: `709c92b00d8c17fe4ba32c977f4bdb312d2c8ae5`
- State: integration changes are present in the working tree and are **uncommitted**
- Overall verdict: **the local engineering integration is operational and verified; the research system is not complete**

## 1. What this document describes

This report describes the architecture that now exists in the workspace, not only the original design target. It covers the VS Code extension, the Python/FastAPI engine, the twelve-stage assisted-analysis workflow A–L, assistant capabilities A–F, and the boundaries that prevent unavailable research features from being simulated.

Status vocabulary used throughout this report and the companion reports:

| Status | Meaning |
|---|---|
| **Fully** | Wired, exercised by automated tests, and demonstrated in the implemented local path. A fully implemented component may still have a narrow declared scope and may not support a broader security claim. |
| **Partial** | A real implementation exists, but prerequisites, independent evidence, artifacts, or validation are missing. It must not be described as complete or as producing a guaranteed security outcome. |
| **Unavailable** | Not wired, not configured, or represented only by an honest stub. No output is fabricated. |
| **Not run** | An execution path or evaluation exists but was not executed because required prerequisites are absent. |

A “fully” engineering status never means “proven secure,” “calibrated,” “causal,” or “research-validated.”

## 2. System context

Bug Dhor is a local-first client/server system:

```text
VS Code editor events
        |
        v
RealtimeMonitor + provider adapters
        |
        | consented, bounded requests
        v
SecurityEngineService (versioned HTTP client)
        |
        v
FastAPI /api/v1
        |
        v
Orchestrator -> snapshot -> preprocessing -> AST/CFG/DFG/taint
        |              -> static adapters -> detection -> risk
        |              -> explanation -> repair -> verification
        v
Validated operation envelope
        |
        v
DiagnosticController -> Problems panel / hover / Quick Fix / dashboard
```

The extension **does not start or supervise** the backend process. A separately started backend is required. Health flags describe wired API paths; they do not prove provider availability, model access, sandbox execution, or benchmark results.

## 3. Component layers

### 3.1 VS Code client

| Component | Responsibility | Status |
|---|---|---|
| `RealtimeMonitor` | Document change events, version tracking, debouncing, cancellation, changed-function scoping | **Fully** |
| Assistant/provider adapters | A–F taxonomy, documented provider access, provenance, discovery failures | **Partial** — adapter contracts and validation exist; live hosted/local targets are unavailable in this workspace |
| `SecurityEngineService` | Versioned HTTP transport, bearer token, timeouts, cancellation, strict response validation | **Fully** |
| `DiagnosticController` | Validates findings, workspace containment, native diagnostics, hover, Quick Fix | **Fully** |
| Dashboard/views | Eleven sections, strict CSP, observed workspace and backend state only, no demo data | **Fully** for rendering and state handling |
| Patch approval | Workspace edits only after explicit approval and hash revalidation | **Fully** for the approval workflow; no automatic application |

Editor monitoring is observation of ordinary VS Code document events. It is **not** direct access to an AI assistant or a model. Source text is shared only when both automatic monitoring consent and the general source-sharing setting permit it. Workspace scans send folder metadata only.

### 3.2 Backend engine

| Layer | Responsibility | Status |
|---|---|---|
| API and schemas | `/api/v1` routes, typed envelopes, RFC 9457 errors, limits, optional auth | **Fully** |
| Snapshot/ingestion | Allowlisted roots, symlink-safe paths, hashes, language detection, unsaved text handling | **Fully** |
| Preprocessing | Python/JavaScript parsing, spans, tokens, functions, chunks, syntax diagnostics | **Fully** within supported languages |
| Program analysis | Intraprocedural CFG, DFG, same-file taint paths | CFG/DFG and taint graph construction **Fully** within declared scope; taint-based security classification **Partial** |
| Static adapters | Semgrep/Bandit adapters; optional CodeQL/Joern | **Partial** — tool presence is configuration-dependent and the benchmark rule pack is unpinned |
| Detection | Fuses AST, graph, taint, and static evidence into real findings | **Partial** — no trained multi-view detector or calibrated probability |
| Risk | Unified evidence scoring exposed as `heuristic_index` | **Partial** — real prioritization index, no calibrated probability artifact |
| Explanation | Evidence-grounded `observation` claims for matching backend finding IDs | **Partial** — no model-internal attribution or localization score |
| Repair | Proposal-only workflow with caller-supplied candidates and approval gate | **Partial** — the engine never generates/applies code autonomously |
| Verification | Independent static and bounded checks, explicit inconclusive classification | **Partial** — functional execution requires an adequate sandbox and remains inconclusive |
| SAE/counterfactual/steering HTTP routes | Honest `unavailable` stubs | **Unavailable** |
| Research tracking | Experiment groups, manifests, compatibility harness, benchmark contract validator | Experiment definitions **Fully** implemented; harnesses **Fully** executed; all experiments **Not run** |

### 3.3 Research libraries outside the HTTP path

| Library | Status | Boundary |
|---|---|---|
| SAE encoding/training/artifact handling | **Partial** | Real code and local layer-4 probe artifacts exist; no registered production checkpoint |
| Counterfactual estimation | **Partial** | Single, pairwise, and higher-order code is tested; not wired to HTTP and not paper-level screening/controls |
| Steering/decision policy | **Partial** | Deterministic, advisory preference-utility logic; not RL, not optimal decision-making |
| Mathematical risk engine | **Partial** | Evidence fusion and heuristic ranking are real; no fitted calibrator or group-disjoint validation artifact |
| Benchmark readiness harness | **Fully** as a readiness validator; execution **Not run** | Produces a readiness bundle with `status: not_run` and null metrics |

## 4. Assisted-analysis workflow A–L

These are the twelve stages reported by `IncrementalAssistedAnalyzer`. They are the practical A–L workflow covered by the integration.

| Stage | Name | Status | Evidence and boundary |
|---|---|---|---|
| A | `change_detection` | **Fully** | VS Code document events, version tracking, debouncing, and cancellation are unit- and e2e-tested. |
| B | `region_identification` | **Fully** | Function-level spans and bounded half-open line ranges are computed for supported languages. |
| C | `syntax_analysis` | **Fully** | Tree-sitter-based Python/JavaScript parsing with recoverable syntax diagnostics. |
| D | `ast_analysis` | **Fully** | Real AST rules produce evidence such as dynamic SQL construction. |
| E | `cfg_dfg_analysis` | **Fully** | Intraprocedural CFG/DFG products with exact spans; scope is same-file and language-limited. |
| F | `taint_analysis` | **Partial** | Real source-to-sink dependency paths are produced; they are syntactic flow evidence, not proof of attacker control or exploitability. |
| G | `static_analysis` | **Partial** | Adapters are real and bounded, but tools/rule packs may be absent or unpinned. Missing tools remain explicit unavailable stages. |
| H | `sae_features` | **Unavailable** | HTTP route is an honest stub. Local 0.5B probes are research compatibility evidence only (`LIM-COMPAT-01`). |
| I | `counterfactual_analysis` | **Unavailable** | HTTP route is an honest stub; library code exists but is not wired and produces no causal claim. |
| J | `evidence_fusion` | **Partial** | Heuristic fusion produces a real `heuristic_index`; it is not a trained multi-view detector or calibrated probability. |
| K | `classification` | **Partial** | Real CWE-89 finding was produced end-to-end; no validated multi-class detector or localization score exists. |
| L | `diagnostic_export` | **Fully** | Strict finding validation, workspace containment, and native diagnostics are e2e-verified; hover is e2e-verified and Quick Fix is unit-tested. |

Activation steering is adjacent to, but not one of, these twelve reported stages. Its HTTP route remains **Unavailable**.

## 5. Assistant capability taxonomy A–F

| Capability | Meaning | Local observed state |
|---|---|---|
| A | Documented editor change monitoring | **Fully** in the Extension Host; CLI compatibility runner reports unavailable because it has no VS Code host |
| B | Generation request access via documented API | **Unavailable** locally; adapter contract **Fully** implemented but no configured host/provider |
| C | Generation response access via documented API | **Unavailable** locally; adapter contract **Fully** implemented but no configured host/provider |
| D | Real model-internal activation access | **Unavailable** in the operational extension path; local probe harness has direct access to research checkpoints |
| E | SAE integration requiring D plus a validated artifact | **Unavailable** in the operational extension path; local probe artifacts are not production registration |
| F | Activation steering requiring D and E | **Unavailable** in the operational extension path; library/probe code is not an HTTP capability |

Structural invariants remain enforced: `E` implies `D`, and `F` implies `D` and `E`. Hosted providers can never claim D/E/F.

## 6. External interfaces

| Interface | Contract | Notes |
|---|---|---|
| Extension → backend | `GET /api/v1/health`, `/scan/*`, `/detection/analyze`, `/explanation/analyze`, `/features/extract`, `/counterfactual/analyze`, `/prevention/steer`, `/repair/generate`, `/recommendations/generate`, `/verification/run`, feedback routes | Strict versioned envelopes; unavailable stages preserved |
| HTTP finding model | `id`, `message`, `severity`, `cwe`, `location`, `evidence`, optional `riskAssessment` | No shared schema/version bump; real risk is exposed as optional API enrichment |
| Risk semantics | `scoreKind: heuristic_index`, `probability: null` | UI rejects probability laundering and renders only heuristic index |
| Explanation | Matching finding ID required | Unmatched IDs return `analysisAvailable: false`, `graph: null`, `claimKinds: []` |
| Repair/verification | Explicit target required | No finding ID, repair ID, patch, or source edit is inferred |
| Research artifacts | Compatibility and benchmark bundles | Evidence generators only; not empirical results |

Backend `sourceReferences` may serialize optional fields as `null`. The extension normalizer treats those as absent while still validating any supplied value. This was required for a real backend finding to become a native diagnostic.

## 7. Privacy and responsiveness

- Monitoring requires explicit configuration; source text is not sent by default.
- Background source sharing requires both `bugdhor.monitoring.allowAutomaticSourceSharing` and `bugdhor.privacy.sendSourceText`.
- Workspace scans send folder metadata only.
- Recommendation responses and persisted operation JSON can contain source or prompt text and must be handled accordingly.
- Research tracking is separate from ordinary editor activity; hooks record metadata/hashes and publish no findings.
- Debouncing, version checks, cancellation, and bounded requests keep editor responsiveness intact.
- The backend never writes user source. Extension patch application requires explicit approval and hash revalidation.

## 8. Graceful degradation

| Missing prerequisite | System behavior |
|---|---|
| Backend unreachable | Typed transport error; no diagnostics published; no success message |
| Analyzer CLI absent/failed | Explicit unavailable/failed stage; no synthetic clean scan |
| Production checkpoint absent | Registered model target `unavailable`; no simulated model output |
| Hosted endpoint/key/manifest absent | Provider discovery reports unavailable reason codes |
| No calibrated artifact | `heuristic_index` only; `probability` remains null and is never rendered as calibrated |
| No SAE/counterfactual/steering artifact or hook | HTTP stubs report unavailable; no features, effects, or plans |
| No adequate sandbox | No host execution fallback; verification is inconclusive |
| Benchmark prerequisites absent | Bundle remains `not_run` with null metrics |

## 9. Claim boundaries

1. `analysisAvailable: true` means an analysis stage produced a result; it does not mean the file is secure.
2. Findings are evidence-linked observations, not proof of exploitability.
3. `heuristic_index` is a prioritization index, not a probability.
4. Explanations are observation claims derived from real findings, not model-internal attribution.
5. Counterfactual and steering language is artifact/revision/layer-specific and model-internal, never causal or security-improving without separate evidence.
6. Repair is proposal-only; no patch is marked secure without passing verification.
7. Verification is inconclusive when independent analyzers or sandbox execution are unavailable.
8. The benchmark harness is a contract validator, not a measured evaluation.

## 10. Final architecture status

**Integrated local path:** operational and end-to-end verified from editor event through real backend finding, native diagnostic, explanation, an inconclusive proposal-only repair response with no applied patch, explicit-patch verification, and feedback recording.

**Research system:** not complete. Trained detection, calibrated probability, registered production model/SAE artifacts, live D/E/F hooks, paper-level interaction screening and prevention loop, adequate sandbox execution, and benchmark results remain unavailable or unexecuted.

No commit or source-patch application has been performed in this worktree.
