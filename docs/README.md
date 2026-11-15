# CRAFT-Sec Documentation

- [Software architecture](architecture.md) — monorepo design, runtime model, contracts, pipeline, roadmap, risks.
- [HTTP API](api.md) — implemented `/api/v1` endpoints, envelopes, errors, auth, limits, and OpenAPI access.
- [Program analysis](program-analysis.md) — standalone Python/JavaScript CFG, DFG, and taint analysis, NetworkX graphs, exact spans, supported constructs, tests, and limitations.
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
- [Architecture decision records](adr/README.md) — recorded decisions and future ADR conventions.

Documents distinguish the implemented HTTP/file-inspection, source-preprocessing,
and program-analysis layers from research capabilities that remain unimplemented
and report themselves as `unavailable`. No empirical results are reported.
