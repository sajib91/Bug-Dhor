# Bug Dhor Documentation

- [Software architecture](architecture.md) — monorepo design, runtime model, contracts, pipeline, roadmap, risks.
- [HTTP API](api.md) — implemented `/api/v1` endpoints, envelopes, errors, auth, limits, and OpenAPI access.
- [Program analysis](program-analysis.md) — standalone Python/JavaScript CFG, DFG, and taint analysis, NetworkX graphs, exact spans, supported constructs, tests, and limitations.
- [Static bug detection](static-bug-detection.md) — rule-based detection in `bugdhor_ast`: 30 language-specific rules, diagnostic schema, CLI usage, support matrix, limitations, and verification record.
- [Scope and data-flow analysis](scope-data-flow-analysis.md) — symbol tables, lexical scopes, def-use chains, reaching definitions, liveness, CFGs, language-pack taint analysis for Python/JavaScript/Java, interprocedural and conservative object flow, CLI/JSON sections, and verification record.
- [Phase 6 evidence-based repair](../reports/PHASE_6_FINAL_REPORT.md) — opt-in local `bugdhor_ast` engine; evidence-separated explanations, root-cause localization, evidence-based CWE mapping, deterministic Python/JavaScript/Java repairs, exact patch preview/apply/revert with approval, independent static verification, optional untrusted AI candidates, JSON-only CLI actions, seven VS Code local-engine commands/settings, measured tests/coverage/benchmarks, and explicit limitations.
- [AI assistant integration](ai-assistant-integration.md) — model-independent provider adapters, A–F capability taxonomy, compatibility matrix, honest provenance, and the incremental assisted-analysis workflow.
- [Workspace scanning audit](workspace-scanning-audit.md) — evidence audit of the VS Code, FastAPI, privacy, and research boundaries for workspace scanning.
- [Current feature status](current-feature-status.md) — one current status matrix and verification record for implemented, partial, unavailable, and not-run capabilities.
- [Workspace scanning implementation plan](workspace-scanning-implementation-plan.md) — architecture decisions, settings, event map, acceptance criteria, and follow-up work for model-independent monitoring.
- [Model compatibility testing](model-compatibility-testing.md) — evidence-backed probes for ten model capabilities, exact checkpoint metadata, SAE/steering compatibility, and the generated compatibility report.
- [Coding benchmark](../benchmarks/README.md) — ten realistic tasks, E0-E7 conditions, leakage controls, and an honest `not_run` readiness bundle.
- [Shared JSON contracts](../shared/schemas/README.md) — Draft 2020-12 schemas, fixtures, and score/availability rules validated from Python and JavaScript.
- [Development setup](development-setup.md) — macOS and Windows installation, CPU-only development, environment variables, verification record.
- [Research alignment and integrity contract](research-alignment.md) — claim taxonomy, SAE rules, counterfactual semantics, steering protocol, verification, reproducibility, limitations.
- [Sparse autoencoder](sae.md) — PyTorch SAE training, validation metrics, checkpoints, and interpretation limits.
- [SAE feature analysis](sae-feature-analysis.md) — labeled activation associations, CWE analysis, stability, and cross-dataset validation.
- [SAE feature interpretation](sae-feature-interpretation.md) — evidence-backed reports, annotations, interventions, and JSON/CSV export.
- [SAE counterfactual analysis](counterfactual.md) — reproducible ablation/modification experiments and output-risk comparisons.
- [Pairwise SAE interactions](pairwise-counterfactual.md) — four-cell interaction contrasts, rankings, and uncertainty.
- [Higher-order SAE interactions](higher-order-counterfactual.md) — factorial contrasts, bounded subset generation, and complexity reporting.
- [SAE activation steering](steering.md) — disabled-by-default decoder-direction interventions, token targeting, adaptive interaction-aware policy, CWE-specific risk control, validation, and provenance.
- [Explainable vulnerability analysis](explain.md) — evidence-separated JSON and human-readable explanations, source-to-sink paths, SAE associations, and counterfactual limitations.
- [Repository-aware repair](repair.md) — bounded multi-file context with import relationships, AST/CFG/DFG summaries, tests, configuration, and security utility metadata.
- [Secure recommendations and feedback](secure-recommendation-and-feedback.md) — proposal-only generation workflow, mandatory verification gates, provider-backed VS Code generation, dashboard approval, bounded rescanning, and finding lifecycle.
- [Unified security risk engine](unified-risk-engine.md) — correlation-controlled evidence aggregation, Eq. (28)–(29) heuristic index, explicit uncertainty, group-disjoint calibration gates, and reproducible configs.
- [Adaptive security decision policy](adaptive-decision-policy.md) — transparent rule baseline, capability/consent gates, deterministic preference-utility ranking, and traceable advisory actions (distinct from adaptive *steering*).
- [User guide](user-guide.md) — installation, backend and model setup, scanning/explanation/SAE/counterfactual/generation/repair/verification tutorials, experiment configuration, troubleshooting, privacy, and limitations (implemented vs unavailable stated explicitly).
- [Research methodology](research-methodology.md) — technical methodology for problem/objectives, SAE, feature identification, counterfactuals, interactions, steering, risk control, evidence fusion, repair, verification, experimental design, metrics, statistics, validity, and limitations.
- [Implementation mapping](implementation-mapping.md) — maps each methodology area to repository modules and labels implemented, conditional, partial, planned, or unavailable.
- [Extension release checklist](release-checklist.md) — VSIX packaging, versioning policy, manifest/command/activation checks, webview assets, backend installation and startup, optional remote backend, and clean VS Code installation verification.
- [Security audit and performance report](SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md) — audit findings, mitigations, available tool/test/benchmark results, and unresolved risks (does not claim security).
- [Final strict audit](../final-audit.md) — 18-area status audit with code/test/runtime evidence and release blockers.
- [Research compliance report](../research-compliance-report.md) — paper components, formulas, Algorithms 1–9, metrics, ablations, and reproducibility.
- [Root release checklist](../release-checklist.md) — authoritative release gates, test status, artifact hashes, and blockers.
- [Architecture decision records](adr/README.md) — recorded decisions and future ADR conventions.

Documents distinguish implemented HTTP/file-inspection, source-preprocessing,
program-analysis, detection, explainability, repair/verification, SAE,
counterfactual, steering, and evaluation modules from capabilities that are
conditional on models, artifacts, analyzers, sandbox, config, or licensed data
and from stages that still report themselves as `unavailable`. No empirical
results are reported.
