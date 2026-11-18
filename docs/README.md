# Bug Dhor Documentation

- [Software architecture](architecture.md) — monorepo design, runtime model, contracts, pipeline, roadmap, risks.
- [HTTP API](api.md) — implemented `/api/v1` endpoints, envelopes, errors, auth, limits, and OpenAPI access.
- [Program analysis](program-analysis.md) — standalone Python/JavaScript CFG, DFG, and taint analysis, NetworkX graphs, exact spans, supported constructs, tests, and limitations.
- [AI assistant integration](ai-assistant-integration.md) — model-independent provider adapters, A–F capability taxonomy, compatibility matrix, honest provenance, and the incremental assisted-analysis workflow.
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
