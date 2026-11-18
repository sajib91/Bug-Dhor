# Bug Dhor

**Counterfactual Risk Analysis and Feature-aware Steering for Secure Code Generation.**

Bug Dhor is a local-first research system for explainable vulnerability detection, SAE-based feature analysis, counterfactual multi-feature interaction analysis, interaction-aware activation steering, repository-aware repair, and independent security/functional verification. It is delivered as a JavaScript VS Code extension backed by a Python/FastAPI security engine.

## Status

**Phase 1: scaffold, extension shell, and an operational but partial research engine.** The Python engine exposes a `/api/v1` HTTP API and performs real allowlisted file/workspace inspection (including caller-supplied unsaved editor text), parsing, AST/CFG/DFG/taint analysis, heuristic evidence fusion, evidence-grounded explanation, proposal-only repair, and independent static/functional verification. Detection, explanation, repair, and verification are wired into the API and report explicit `partial`/`unavailable` stage statuses. SAE, counterfactual, and activation-steering code exists but is **not wired** into the operational path; `features/extract`, `counterfactual/analyze`, and `prevention/steer` return empty/`plan=None` results. No trained detector, real model/SAE artifact, licensed benchmark dataset or execution result, Docker-backed execution, or empirical result is present. No fabricated findings, scores, features, effects, patches, verdicts, or metrics are produced. See [`final-audit.md`](final-audit.md) and [`research-compliance-report.md`](research-compliance-report.md).

## Research integrity

- SAE features are only produced from a genuine, compatible SAE artifact and a white-box model with accessible activations. Missing capabilities are reported as unavailable, never simulated.
- Heuristic risk scores are not probabilities. Calibrated scores require a fitted calibrator and a held-out labelled dataset.
- Counterfactual effects describe model-internal interventions, not real-world causal effects.
- Activation steering is limited to compatible models with accessible internal activations.
- Repairs are applied only after explicit user approval; the Python engine never writes user source.
- Execution-based verification requires an isolated sandbox. If no adequate sandbox exists, execution is not attempted and verification reports `inconclusive`, never a pass.
- No fabricated datasets, citations, metrics, or experimental results are permitted.
- Every research component must ship tests and documented limitations before its capability is enabled.

See [docs/research-alignment.md](docs/research-alignment.md) for the binding claim taxonomy and acceptance gates.

## Monorepo map

| Path | Purpose |
|------|---------|
| `vscode-extension/` | JavaScript VS Code extension, webviews, backend HTTP client, patch approval |
| `security-engine/` | Python/FastAPI engine: ingestion, parsing, analyzers, model/SAE, detection, counterfactuals, steering, repair, verification |
| `shared/` | JSON Schemas, generated contract artifacts, and contract fixtures |
| `research/` | Experiment configs, evaluation protocols, dataset cards, and research records |
| `benchmarks/` | Benchmark harness, task definitions, configs, and non-committed results |
| `docs/` | Architecture, research alignment, ADRs |
| `scripts/` | Development and validation tooling |

Core research modules under `security-engine/src/bugdhor/`:

- `sae/` — genuine SAE model/training/association code; not yet wired to model capture or the API.
- `features/` — **scaffold only**; feature extraction/aggregation is not implemented.
- `counterfactual/` — single-feature, pairwise, and higher-order intervention code; not yet wired to the API.
- `steering/` — activation steering, risk control, adaptive policy, and functional constraints; not yet wired to the API.
- `detection/` and `explain/` — evidence fusion and explainable findings.
- `repair/` — repository-aware patch proposals.
- `verification/` — independent security and functional checks.
- `parsing/`, `static/`, and `program_analysis/` — program analysis.
- `evaluation/` — metrics and statistical evaluation helpers.

## Requirements

- Python 3.11–3.14 (3.11.14 verified)
- Node.js 22.13+ or 24+ (24 LTS recommended; Node 23 is unsupported)
- VS Code 1.90+
- Optional: Semgrep, Bandit, Docker/Podman, CodeQL, Joern
- Optional: CUDA/MPS hardware for future model/SAE workflows; CPU-only development is supported

The engine server is runnable. From the repository root after setup:

```bash
cd security-engine
../.venv/bin/python -m bugdhor
```

It binds `127.0.0.1:8765` by default and serves OpenAPI at `/openapi.json` and `/docs`. See [docs/api.md](docs/api.md) for endpoints, limits, auth, and response contracts.

## Development setup

Verified macOS command (see [docs/development-setup.md](docs/development-setup.md) for Windows PowerShell and manual steps):

```bash
npm run setup -- --python python3.11 --cpu --with-analyzers
npm run doctor
npm run check
```

`--python` is optional; setup selects a supported interpreter automatically. `--cpu` installs CPU-only PyTorch. `--with-analyzers` installs optional Semgrep and Bandit. Setup does not download models, datasets, or SAE artifacts.

## Quick validation

```bash
npm run structure:check
```

This verifies that the scaffold matches the approved architecture layout. After setup, `npm run check` runs structure, lint, formatting, and tests. The current tests cover the versioned HTTP API, validation and problem details, auth/CORS/limits, path containment, pipeline semantics, environment settings, command registration and validation, backend URL/timeout/privacy configuration, HTTP transport and response validation, the extension manifest, the dashboard model/HTML/panel/client, the sidebar launcher, and an Extension Host run against a live backend that verifies health, unsaved-buffer scanning, consent-gated source sharing, workspace/selection scans, and the dashboard. Detection, explanation, repair, and verification are functional but partial; SAE, counterfactual, and steering endpoints return explicit `unavailable`/empty results.

## Documentation

- [User guide](docs/user-guide.md) — installation, backend/model configuration, tutorials, troubleshooting, privacy, and limitations
- [Research methodology](docs/research-methodology.md) — technical methodology and evidence boundaries
- [Implementation mapping](docs/implementation-mapping.md) — methodology-to-module mapping and capability status
- [Final audit](final-audit.md) — strict 18-area status audit with evidence and blockers
- [Research compliance report](research-compliance-report.md) — paper component/algorithm/formula traceability
- [Release checklist](release-checklist.md) — root release gates and blockers
- [Extension release checklist](docs/release-checklist.md) — VSIX packaging, versioning, backend setup, remote backend, and clean-install verification
- [Development setup](docs/development-setup.md)
- [HTTP API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Research alignment and integrity contract](docs/research-alignment.md)
- [Security audit and performance report](docs/SECURITY_AUDIT_AND_PERFORMANCE_REPORT.md)
- [Architecture decision records](docs/adr/README.md)

## Data policy

Datasets, model weights, SAE artifacts, experiment outputs, and benchmark results are not committed to this repository. Dataset cards and configuration files may be committed; data and results remain local or externally hosted under their own licenses.

## License

No license has been selected yet. Do not redistribute this repository until a license is added.
