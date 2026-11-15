# CRAFT-Sec Documentation

- [Software architecture](architecture.md) — monorepo design, runtime model, contracts, pipeline, roadmap, risks.
- [HTTP API](api.md) — implemented `/api/v1` endpoints, envelopes, errors, auth, limits, and OpenAPI access.
- [Program analysis](program-analysis.md) — standalone Python/JavaScript CFG, DFG, and taint analysis, NetworkX graphs, exact spans, supported constructs, tests, and limitations.
- [Shared JSON contracts](../shared/schemas/README.md) — Draft 2020-12 schemas, fixtures, and score/availability rules validated from Python and JavaScript.
- [Development setup](development-setup.md) — macOS and Windows installation, CPU-only development, environment variables, verification record.
- [Research alignment and integrity contract](research-alignment.md) — claim taxonomy, SAE rules, counterfactual semantics, steering protocol, verification, reproducibility, limitations.
- [Sparse autoencoder](sae.md) — PyTorch SAE training, validation metrics, checkpoints, and interpretation limits.
- [Architecture decision records](adr/README.md) — recorded decisions and future ADR conventions.

Documents distinguish the implemented HTTP/file-inspection, source-preprocessing,
and program-analysis layers from research capabilities that remain unimplemented
and report themselves as `unavailable`. No empirical results are reported.
