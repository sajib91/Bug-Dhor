# Bug Dhor Security Engine

Local FastAPI research engine for vulnerability evidence, SAE feature extraction, counterfactual analysis, activation steering, repository-aware repair, and independent verification.

## Status

**HTTP API, source preprocessing, program analysis, static adapters, detection,
explanation, proposal-only repair, and bounded verification are implemented;
model-internal research stages remain unwired.** The versioned FastAPI transport,
typed request/response schemas, structured errors, logging, auth, CORS, request
limits, workspace containment, and real file/workspace inspection exist. Tree-sitter
preprocessing, CFG/DFG/taint construction, and Semgrep/Bandit adapters are wired
into scan and detection stages. Explanation returns observation claims for matching
backend findings. Repair remains proposal-only and requires caller-supplied
candidates plus explicit approval; verification is inconclusive without independent
analyzers or an adequate sandbox. Counterfactual and steering libraries exist but
are not wired into the API, and no production model/SAE artifact or adequate
execution sandbox is present. No results are invented.

Implemented and tested:

- `src/bugdhor/api/` — app factory, `/api/v1` routes, Pydantic schemas,
  request-ID/access-log middleware, optional bearer auth, streaming body limits,
  and RFC 9457 problem-detail handlers.
- `src/bugdhor/core/` — settings, typed errors, logging, path containment,
  pipeline primitives, and the operation orchestrator.
- `src/bugdhor/parsing/` — Python/JavaScript detection, BOM and line-ending
  normalization with a lossless source map, exact UTF-8/UTF-16 spans,
  tokenization, function/method/lambda extraction, AST-aware chunking,
  repository metadata, and recoverable syntax-error diagnostics.
- `src/bugdhor/program_analysis/` — module/function CFGs with basic blocks,
  branches, loops, exceptions, returns, and break/continue; reaching-definition
  DFGs with def-use, parameter, call, return, raise, and closure edges; a taint
  graph with explicit source, sanitizer, validator, propagator, and sink rules,
  per-kind gating, direct same-file interprocedural propagation, evidence paths,
  confidence notes, and limitation disclosures; exact spans and NetworkX
  `DiGraph` products.
- `src/bugdhor/static/` — Semgrep and Bandit adapters, plus optional CodeQL and
  Joern adapters, with executable/version detection, argv-only sanitized
  subprocess execution, timeouts, bounded stdout/stderr capture, native-output
  parsing, shared normalized findings, conservative CWE extraction, and
  deduplication. Missing, failed, and timed-out tools are explicit statuses, never
  empty successful scans.
- `src/bugdhor/main.py` — Uvicorn entry point with configurable host and port.
- File scans — allowlisted-root validation, path/symlink containment, UTF-8 and
  size checks, SHA-256 computation, and language detection.
- Workspace scans — symlink-safe source discovery with ignored generated
  directories, a configurable file-count limit, and available scan stages over
  discovered sources.
- 638 tests under `tests/`, covering every endpoint, validation, problem details,
  auth, CORS, request/file/workspace limits, path containment, pipeline status
  semantics, settings, OpenAPI paths, shared contracts, source preprocessing,
  CFG/DFG graph correctness, positive/negative taint flows, subprocess safety and
  timeouts, static-output normalization, detection, explanation, risk semantics,
  repair/verification, and mocked adapter integrations.
- [API documentation](../docs/api.md), [program-analysis documentation](../docs/program-analysis.md),
  and generated OpenAPI at `/openapi.json`, `/docs`, and `/redoc`.

Detection and explanation return `analysisAvailable: true` when they produce real
results; SAE, counterfactual, and steering endpoints remain explicit `unavailable`
stubs. Health flags for detection, explanation, repair, and verification are `true`,
but these flags declare wired paths, not provider availability, model access,
sandbox execution, or benchmark results. Successful scans can contain real
AST/CFG/DFG/taint-backed findings, evidence sources, and a `heuristic_index` risk
assessment; absent analyzers are reported explicitly.

## API

From `security-engine/`:

```bash
../.venv/bin/python -m bugdhor
# or
../.venv/bin/bugdhor
```

Defaults: `127.0.0.1:8765`, 2 MB request body, 1 MB file, 50,000 workspace files,
no CORS origins, and workspace roots set to the process working directory. Set
`BUGDHOR_API_TOKEN` to require `Authorization: Bearer <token>` on `/api/*`
requests. See [../docs/api.md](../docs/api.md) and [../.env.example](../.env.example).

## Layout

```text
src/bugdhor/
  api/                FastAPI app, routes, schemas, middleware
  artifacts/          content-addressed artifact store
  contracts/          generated Pydantic models from shared JSON Schema
  core/               errors, logging, paths, pipelines, orchestrator, settings
  counterfactual/     single, pairwise, higher-order analysis
  db/                 SQLite models and repositories
  detection/          evidence fusion and findings
  evaluation/         metrics and statistical evaluation
  experiments/        run manifests and export
  explain/            evidence graph
  features/           SAE feature extraction and aggregation
  ingestion/          project snapshots
  models/             Lazy local HF runtime, tokenizer, inference, and activations
  observability/      logging, redaction, audit
  parsing/            tree-sitter detection, tokenization, symbols, chunks, metadata
  program_analysis/   intraprocedural CFG/DFG and same-file taint with NetworkX
  repair/             context assembly and patch generation
  sae/                sparse autoencoder training, metrics, and checkpoints
  sandbox/            isolated execution backends
  static/             Semgrep, Bandit, CodeQL, Joern adapters
  steering/           activation steering and evaluation
  verification/       independent security/functional verification
```

## Local setup

From the repository root, the verified path is:

```bash
npm run setup -- --cpu --with-analyzers
npm run doctor
npm test
```

`--cpu` installs CPU-only PyTorch. `--with-analyzers` adds Semgrep and Bandit; omit it for a lighter environment. No model weights are downloaded.

See [../docs/models.md](../docs/models.md) for supported Hugging Face
checkpoints, licensing, local loading behavior, and activation limitations.

For a manual environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
cd security-engine
python -m pip install -e ".[dev,ml,analyzers]"
```

On Windows use `py -3.11 -m venv .venv` and `.\.venv\Scripts\Activate.ps1`. See [../docs/development-setup.md](../docs/development-setup.md) for the full macOS and Windows instructions.

## Tests

```bash
npm test
```

or directly:

```bash
cd security-engine
../.venv/bin/python -m pytest
```

The suite exercises the HTTP API, backend primitives, shared contract schemas,
preprocessing, program analysis, taint flows, static-analyzer adapters, detection,
explanation, risk enrichment, proposal-only repair, and bounded verification.
Static adapter tests use mocked tool output and fake executables; they do not
require Semgrep, Bandit, CodeQL, or Joern to be installed. The suite does not
validate real model/SAE execution, calibrated probabilities, counterfactual or
steering interventions in the HTTP workflow, or Docker-backed functional execution;
those capabilities remain conditional or unwired and are never simulated.

## Build

```bash
npm run build
```

This produces `security-engine/dist/bugdhor_engine-0.1.0-py3-none-any.whl` and a development VSIX. It does not download models.

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md), [../docs/api.md](../docs/api.md), and the
authoritative register in [../docs/research-alignment.md](../docs/research-alignment.md).
