# Security Engine Limitations

The HTTP API, file/workspace inspection, shared contract validation, standalone
Python/JavaScript source preprocessing, intraprocedural CFG/DFG construction,
configuration-driven same-file taint analysis, and standalone Semgrep/Bandit/
CodeQL/Joern adapters are implemented. No detector, model, SAE, counterfactual,
steering, repair, or verification component is implemented as of this phase. This
file tracks component-specific limitations as each module is built.

The authoritative limitation register is maintained in
[docs/research-alignment.md](../docs/research-alignment.md#12-limitations-register).
Every research component must reference the relevant `LIM-*` identifiers here
before its capability is exposed.

## Current status

- File and workspace scans inspect real files and report hashes, sizes, languages,
  and discovered source URIs.
- A standalone preprocessing library detects, normalizes, parses, tokenizes,
  extracts functions from, chunks, and summarizes Python and JavaScript files.
  It is not connected to the API, workspace scans, or the VS Code extension.
- A standalone program-analysis library builds intraprocedural control-flow and
  data-flow graphs for Python and JavaScript, plus a configuration-driven taint
  graph with direct same-file call/return propagation. It is not connected to the
  API, workspace scans, or the VS Code extension.
- Shared JSON Schema contracts and fixtures are validated by both runtimes, but the
  HTTP API still returns interim operation envelopes and does not generate or
  validate runtime responses from those schemas.
- A standalone static-analysis library runs Semgrep and Bandit, plus optional
  CodeQL and Joern, with executable/version detection, validated configuration,
  bounded argv-only subprocesses, normalized findings, conservative CWE mapping,
  and deduplication. It is not connected to the API, workspace scans, detection, or
  the VS Code extension. Missing, failed, and timed-out tools are explicit
  results, never empty successful scans.
- No evidence-fusion detector exists; scan findings are always empty with an
  explicit `analysisAvailable: false`.
- No SAE artifact has been registered or validated.
- No model activations have been captured.
- No counterfactual effect has been computed.
- No steering run has been performed.
- No repair has been proposed, applied, or verified.
- No benchmark or evaluation result exists.
- The VS Code extension connects to this server over the versioned HTTP API and
  performs health checks, file scans, selection detection requests, and workspace
  scans. It does not start or supervise the server. Research analysis stages still
  report explicit `unavailable` results.

## Parsing limitations

- Supported languages are Python (`.py`, `.pyi`, `.pyw`) and JavaScript (`.js`,
  `.jsx`, `.mjs`, `.cjs`). TypeScript, TSX, and other source formats are reported
  as `unsupported_language` by repository metadata and are never content-guessed
  when the extension is known and unsupported.
- Detection prefers an explicit editor language ID, then a supported extension,
  then a shebang, and finally a conservative content heuristic for extensionless
  files. Ambiguous content remains undetected.
- Normalization removes a leading BOM and converts CRLF/CR to LF. Original text is
  retained, and every span maps back to original byte offsets. `column` is a UTF-8
  byte column for tree-sitter; `character` is a UTF-16 column for VS Code/LSP.
- Tree-sitter error recovery is best effort. Invalid files are returned with
  diagnostics instead of raising, but recovered tokens, functions, and chunks may
  be incomplete or misleading. Consumers must inspect `has_syntax_errors` or
  `parse_ok` and must not claim full coverage.
- Function extraction covers declarations, expressions, arrows, methods, lambdas,
  async functions, and generators. Decorators are included in a symbol's span but
  are not exposed as separate metadata. Dynamic assignment, alias resolution, JSX
  component semantics, and type information are not modeled.
- Chunking uses top-level syntax boundaries and a character limit, not dependency
  analysis or model-tokenizer boundaries. Oversized single lines are split at
  character boundaries, so a part can end mid-token.
- Repository metadata uses a fixed ignored-directory set rather than full
  `.gitignore` semantics and skips symlinks. Oversized, binary, invalid-UTF-8,
  unsupported, and unreadable files are reported in `skipped_files` rather than
  silently dropped.
- There is no persisted index, incremental reparse, cross-file symbol table, import
  resolution, or call graph. The parsing API is currently library-only.

## Program-analysis limitations

The CFG and DFG are intraprocedural and syntactic. The taint layer adds direct
same-file argument/parameter and return/call-result propagation. All three
preserve exact spans and produce deterministic NetworkX graphs, but none is sound
or complete.

- `LIM-PA-01` — CFG/DFG calls are syntactic sites, not resolved targets. There is
  no call graph, recursion handling, argument-to-parameter binding, or
  return-to-caller flow in the CFG/DFG products. Taint's limited same-file
  propagation is covered by `LIM-PA-09`.
- `LIM-PA-02` — Exception edges originate at a `try` dispatch, not at every
  potentially raising instruction. Handler type matching is not evaluated, a
  `raise` inside a `try` routes to the first handler, and returns/raises inside
  `try`/`finally` bypass the finalizer.
- `LIM-PA-03` — Closures resolve to the nearest earlier definition in an enclosing
  scope. `global`/`nonlocal`, named JavaScript function expressions, dynamic
  scoping, `eval`, reflection, and monkeypatching are not modeled.
- `LIM-PA-04` — There is no value, type, alias, or mutation tracking.
  Attribute/subscript flow is reduced to base-name uses; mutating a container or
  object does not create a new definition. Points-to, field sensitivity, string
  evaluation, and runtime type information are absent.
- `LIM-PA-05` — Comprehensions do not get loop CFGs. Generators and async functions
  are treated as ordinary functions; `yield` and `await` scheduling are ignored.
  Python `match` has no fallthrough and only a literal `_` pattern is treated as
  exhaustive. JavaScript labels are not modeled as break/continue targets, JSX is
  opaque expression syntax, and TypeScript/TSX are unsupported by the parsing
  layer.
- `LIM-PA-06` — Tree-sitter recovery can produce incomplete or misleading
  instructions, functions, and edges for invalid source. Dead code is represented
  as unreachable blocks. Path feasibility, constant conditions, and implicit or
  exception flows are not evaluated.
- `LIM-PA-07` — Spans are exact for parsed nodes, but synthetic entry/exit blocks
  are zero-width and block text spans exclude synthetic lowering anchors.
  Consumers must retain the original source for slicing.
- `LIM-PA-08` — Graphs are rebuilt from scratch with no incremental or cross-file
  index. Output order is structurally deterministic for a fixed parser/grammar
  version, not semantically stable across grammar upgrades or language changes.
- `LIM-PA-09` — Taint follows direct calls only when the target is a unique
  same-file declaration name, or a `self`/`this` method in the same class
  container. Imports, re-exports, aliases, dynamic dispatch, callbacks,
  higher-order calls, and cross-file summaries are not resolved. Ambiguous or
  unknown targets block value flow.
- `LIM-PA-10` — Taint findings are potential syntactic source-to-sink flows, not
  confirmed vulnerabilities. Path feasibility, runtime values, types,
  authentication, authorization, framework routing, and blocking validation are
  not evaluated. Confidence is analysis confidence, not exploitability.
- `LIM-PA-11` — Sources, sanitizers, validators, propagators, and sinks are
  explicit configuration. Validators are inventoried but do not clear taint
  unless configured as sanitizers. An unconfigured unknown call is assumed to
  block value flow, so missing rules produce false negatives.

## Static-analysis limitations

The static adapters are library-only. They detect executables, validate
configuration, run bounded subprocesses, parse native output, and normalize
findings, but they do not establish that a repository is free of vulnerabilities.
Tool output and coverage remain bounded by each analyzer's own rules and
limitations.

- `LIM-STATIC-01` — The adapters are not wired into the HTTP scan pipeline,
  detection, repair, or verification. Their findings never appear in API scan
  responses or the VS Code extension, and no evidence-fusion or scoring step
  consumes them.
- `LIM-STATIC-02` — CodeQL runs against a caller-supplied, pre-built database and
  requires at least one query suite plus an explicit license acceptance. The
  adapter does not create databases, download query packs, or upgrade schemas, so
  a missing or mismatched database fails explicitly. Joern requires a
  caller-supplied CPG and a query script with the documented output contract, and
  the CLI must meet the configured minimum version.
- `LIM-STATIC-03` — Native output parsers support the formats and versions
  exercised by the tests. Unknown or changed output shapes produce a failed or
  partial result with warnings, not an assumed-clean scan. CWE mapping is
  conservative: it uses Semgrep metadata, SARIF rule tags, Bandit metadata and a
  curated map, and explicit Joern fields; findings without supporting evidence
  keep `cwe: None`. Tool rule IDs are preserved. A normalized finding is analyzer
  output, not a confirmed vulnerability, and never establishes exploitability.
- `LIM-STATIC-04` — Deduplication merges only findings whose source spans overlap
  and that share a rule ID, fingerprint, or at least one CWE. It keeps the primary
  record, the highest severity, the union of CWE evidence, and all original rule
  IDs. Non-overlapping duplicates remain separate, and distinct issues that share
  only a CWE at an overlapping span can be merged into one primary finding.
- `LIM-STATIC-05` — Execution uses an argv-only subprocess with `shell=False`, a
  sanitized environment, closed stdin, a timeout, process-group termination, and
  bounded output capture. This is not an OS sandbox: analyzers run with the
  engine user's filesystem and network access, may execute CodeQL/Joern queries,
  and can consume substantial CPU, memory, or disk. Callers must supply only
  trusted configurations and query or rule packs.

## API limitations

- All analysis endpoints return `200` with `partial` operation status and explicit
  `unavailable` stages. Their result objects contain no findings, scores, features,
  effects, patches, or verdicts.
- Verification returns `verdict: "not_run"` because no verifier or adequate
  sandbox exists.
- Scans return an empty `findings` array. This is not a clean bill of health.
- The API is synchronous. There is no job queue, SSE stream, cancellation
  endpoint, or persisted analysis record.
- Workspace scans discover files but do not invoke the parsing library or analyze
  them. Scan responses contain no tokens, functions, chunks, or parsing
  diagnostics.
- Workspace roots must be inside `BUGDHOR_WORKSPACE_ROOTS`, which defaults to the
  process working directory. Requested roots and files are resolved; escaping
  symlinks are rejected.
- Binary and non-UTF-8 files are rejected. Files over `BUGDHOR_MAX_FILE_BYTES`
  and workspaces over `BUGDHOR_MAX_WORKSPACE_FILES` are rejected rather than
  silently truncated.
- Bearer auth is optional and configured at process launch. There is no user
  account system, token rotation, or multi-user authorization.
- The root index, `/docs`, `/redoc`, and `/openapi.json` are not protected by the
  bearer middleware. Run the server on loopback or a trusted network.
- CORS is disabled by default and accepts only an exact origin allowlist. No
  wildcard is permitted.
- There is no Host-header allowlist, DNS-rebinding defense, or rate limiter beyond
  request-size limits. Do not expose the server directly to an untrusted network.
- Request bodies are size-checked while streaming, but FastAPI still buffers each
  accepted JSON body in memory.
- Logs are structured JSON and exclude request bodies and source text, but no
  separate audit store exists.
- No shared-schema runtime model generation or runtime response validation is
  implemented yet; the contract test suites validate schemas and fixtures
  independently in each runtime.

## Non-negotiable constraints

- Missing capabilities are reported as unavailable and are never simulated.
- Heuristic scores are not probabilities. In `bugdhor.risk`, `index` is an
  Eq. (28) prioritization value and `score_kind` is always `heuristic_index`;
  a probability is emitted only with a validated, group-disjoint calibration
  artifact. No such artifact or labelled dataset ships with the project.
- Correlated evidence is never counted as independent votes. AST/CFG/DFG/taint
  collapse into `program_analysis`; model predictions/SAE/interactions collapse
  into `model_internal`, where counterfactual interactions are signed
  adjustments, not separate evidence.
- Missing evidence is reported and excluded, never imputed. Unreliable,
  failed, unavailable, or unvalidated observations carry zero reliability and
  a recorded reason.
- Counterfactual effects are model-internal interventions, not real-world causal effects.
- Advisory decisions are not optimal decisions. `bugdhor.decision` uses either
  transparent rules or a deterministic declared-preference utility ranking; it
  is not reinforcement learning and never claims an optimal policy. Model
  capabilities are declared, and blocked actions are recorded in the trace.
- Execution-based verification requires an adequate sandbox.
- Repairs require explicit user approval before application; the engine never
  writes user source. The advisory decision policy is not an approval
  mechanism and does not mutate code.
