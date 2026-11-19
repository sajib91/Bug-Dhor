# Scope analysis and data-flow analysis in `bugdhor_ast`

This document describes the flow-analysis layer added on top of the existing
`bugdhor_ast` parser and static detection engine. It deliberately reuses the
lightweight tree-sitter AST layer and the existing `Diagnostic` schema; it does
not import or depend on the heavier `security-engine` package.

## Status

Implemented:

- scope tree and symbol tables for Python, JavaScript, and Java;
- declarations, parameters, imports, assignments, references, ownership, and
  one-based declaration/usage locations;
- lexical scope, nested functions/classes, closures, shadowing, Python
  `global`/`nonlocal`, JavaScript `var` vs. block bindings, arrow functions,
  Java fields/parameters/locals;
- definitions, uses, def-use/use-def chains, reaching definitions, liveness,
  dependencies, assignment propagation, function summaries, call edges, and
  recorded call sites;
- validated control-flow graphs (CFGs) for module, function, and class scopes;
- configurable taint rule packs for Python, JavaScript, and Java over a
  documented syntactic subset;
- conservative Python object-field, subscript/container, simple-alias, and
  string-concatenation flow;
- bounded interprocedural argument-to-parameter and return-to-caller taint
  mapping with recursion safeguards;
- CLI/JSON integration through optional sections, including JSON taint config;
- tests for scopes, data flow, CFG, taint, interprocedural flow, object flow,
  cross-language source-to-sink behavior, grammar profiles, and CLI behavior.

Not implemented: full heap/alias/type analysis, dynamic dispatch, reflection,
precise exception semantics, or complete Java/JavaScript framework and security
semantics. See [Limitations](#limitations).

## Architecture

All passes share one parse-tree context and one language profile:

```
BugDhorASTEngine / tree-sitter
            |
       FlowContext
            |
     LanguageProfile
            |
     ScopeAnalyzer  -------> scopes + symbols + references
            |
        IRBuilder   -------> IRStatement stream
         /    \
 CFGBuilder  DataFlowAnalyzer --> CFGs, defs/uses, chains, liveness
         \    /
      TaintAnalyzer ---------> TaintFinding list
            |
        FlowEngine ----------> FlowAnalysisResult / JSON
```

### `FlowContext`

`FlowContext` wraps source text, parse root, parent lookup, field access, and
one-based location conversion. Node identity uses the stable tuple
`(start_byte, end_byte, type)` rather than Python object identity, so wrapper
recreation cannot corrupt cross-pass maps.

### `LanguageProfile`

Grammar-specific behavior is isolated in `PythonProfile`,
`JavaScriptProfile`, and `JavaProfile`. Profiles provide declaration names,
statement kinds, function/class metadata, body/alternative/handler regions,
call names and arguments, literal extraction, and "is this identifier a use?"
rules. The shared passes otherwise stay language-neutral.

## Public API

```python
from bugdhor_ast.flow import FlowEngine, TaintConfig, taint_diagnostics

result = FlowEngine().analyze_source(source, "python")
payload = result.to_dict()          # JSON-safe dictionary

config = TaintConfig.from_dict({
    "sources": [{"pattern": "get_secret", "id": "SRC"}],
    "sanitizers": [],
    "sinks": [{"pattern": "log", "id": "SNK"}],
})
engine = FlowEngine(taint_config=config)
result = engine.analyze_file("examples/sample.py")
diagnostics = taint_diagnostics(result)
```

`FlowEngine.analyze_source()` and `analyze_file()` return a
`FlowAnalysisResult`. Files with syntax errors produce `has_syntax_errors=True`
and empty/null flow sections rather than partial facts. Unsupported languages
raise `ValueError`.

## Scopes and symbols

### Scope kinds

| Kind | Python | JavaScript | Java |
| --- | --- | --- | --- |
| `module` | module | program | program |
| `function` | `def` | function declaration/expression, method, arrow | method, constructor |
| `lambda` | lambda with a `body` field | arrow functions are `function` scopes | lambda expressions are function scopes |
| `class` | `class` | `class` | `class`, interface, enum, record |
| `block` | no separate block scope | `let`/`const` blocks, catch | local blocks, catch |
| `comprehension` | list/set/dict comprehension, generator | n/a | n/a |

Scope IDs are stable strings such as `scope:function:17:200`. Each scope records
`parent_id`, `children`, source location, and its symbol table map.

### Symbol records

Each `Symbol` contains:

- `id`, `name`, `symbol_type`, `scope_id`, `language`;
- primary `declaration` and all `declaration_locations`;
- `references` with file, line, column, kind, and `statement_id`;
- `assignments` with value text, kind, and statement ID.

Symbols are keyed by `(scope_id, name)`, so shadowing creates distinct symbols
instead of duplicate entries. Augmented assignments (`x += 1`, `i++`-style
patterns where represented by a compound assignment node) are both definitions
and uses. Plain JavaScript/Java assignment expressions reuse an existing
resolved symbol; an otherwise unresolved plain assignment becomes an implicit
module-level binding rather than an unrelated duplicate symbol.

### Language-specific resolution

- **Python**: module, function, lambda, class, block, and comprehension scopes.
  Class scopes are skipped during non-local lookup after the first hop, matching
  Python's method name-resolution behavior. `global` redirects declarations and
  references to the module scope; `nonlocal` binds to the nearest enclosing
  function/lambda scope with an existing binding. Forward references are
  resolved after all declarations are collected.
- **JavaScript**: `var` declarations target the nearest function/module scope;
  `let`/`const` and catch parameters target the current block scope. Arrow
  functions and methods are function scopes. Function bodies do not create an
  extra block scope.
- **Java**: fields target the class scope; formal parameters target the method
  scope; local declarations and catch parameters target the nearest block.
  Constructors are function scopes, and `this.field` attribute writes are not
  treated as new symbol declarations.

## Statement IR

`IRBuilder` lowers statement-like syntax nodes into `IRStatement` records with:

- stable `id`, `kind`, `node_type`, one-based `location`, and source `text`;
- owning `scope_id`;
- `definitions`, `uses`, `calls`, `call_arguments`, and optional `literal`.

The IR is shared by CFG and data-flow construction. Boundary nodes (function,
lambda, class, comprehension) prevent a parent pass from walking into a child
execution region.

## Control-flow graphs

`CFGBuilder` emits one `ControlFlowGraph` per `module`, `function`, or `class`
scope. Block and comprehension scopes remain symbol/data-flow scopes only.

### Node kinds

`entry`, `exit`, `params`, `assign`, `decl`, `import`, `call`, `if`, `else`,
`loop`, `break`, `continue`, `return`, `throw`, `try`, `handler`, `finally`,
and synthetic `try_join`.

Nodes carry a stable ID, statement kind, source location, source text, scope ID,
optional `statement_id`, and explicit `successors`/`predecessors` lists. Edges
carry `source`, `target`, and typed `kind`: `entry`, `params`, `assign`, `decl`,
`call`, `return`, `throw`, `break`, `continue`, `true`, `false`, `body`, `else`,
`exit`, `handler`, and `normal`.

### Construct coverage

- sequenced statements;
- `if` / `else` / Python `elif`, where `elif` is carried by the `if` node;
- `for`, `while`, `do`, enhanced `for`, and `for-in` loops;
- `break`, `continue`, `return`, and `throw`/`raise`;
- Python `try`/`except`/`finally` and JavaScript/Java `try`/`catch`/`finally`.

A synthetic `try_join` node joins normal and handler paths before the finalizer.

### Validation

`ControlFlowGraph.validate()` checks that:

1. entry and exit nodes exist;
2. every edge endpoint exists;
3. there are no duplicate `(source, target, kind)` edges;
4. every node's `successors` and `predecessors` exactly match the edge list.

The JSON representation adds `consistent: true` when validation succeeds. All
sample and test graphs pass validation, and every node is reachable from the
graph entry in the exercised cases.

## Data flow

`DataFlowAnalyzer` computes facts per syntax scope and emits:

- `definitions` and `uses` with symbol IDs and locations;
- `reaching_definitions` keyed by statement ID;
- `live_variables` with `in` and `out` sets;
- `def_use_chains` (use ID to definition IDs);
- `use_def_chains` (definition ID to use IDs);
- `dependencies` (names used when producing a definition);
- `assignment_propagation` (literal/alias value where known);
- `function_summaries` (parameters, returns, calls, globals used);
- `call_edges` (caller scope, callee symbol/name, statement ID).

Reaching definitions use a forward fixed point with definition kills by symbol.
Liveness uses a backward fixed point over names. Both walk CFG predecessors and
successors, so branch and loop joins are represented.

Function summaries record parameters, returns, calls, globals used, and the
statement IDs of call sites. `call_edges` records caller scope, callee
symbol/name, and statement ID. Taint analysis uses these facts for bounded
argument-to-parameter and return-to-caller mapping; callee parameters may still
be merged across call sites. See [Limitations](#limitations).

## Taint analysis

### Default language packs

| Language | Sources | Sanitizers | Sinks | Diagnostic rule |
| --- | ---: | ---: | ---: | --- |
| Python | 7 | 4 | 7 | `PY-TAINT001` |
| JavaScript | 14 | 6 | 12 | `JS-TAINT001` |
| Java | 11 | 6 | 8 | `JAVA-TAINT001` |

Representative default patterns:

| Language | Sources | Sanitizers | Sinks |
| --- | --- | --- | --- |
| Python | `input`, `request.args.get`, `request.form.get`, `os.getenv`, `os.environ.get`, `open`, `sys.stdin.readline` | `int`, `float`, `shlex.quote`, `html.escape` | `eval`, `exec`, `os.system`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `cursor.execute` |
| JavaScript | `req.query`, `req.params`, `req.body`, `location.search`, `prompt`, `process.env`, `localStorage.getItem`, `URLSearchParams`, `navigator.userAgent` | `encodeURIComponent`, `DOMPurify.sanitize`, `Number`, `parseInt`, `parseFloat`, `sanitizeHtml` | `eval`, `Function`, `innerHTML`, `outerHTML`, `document.write`, `child_process.exec`, `execSync`, `spawn`, DB query patterns |
| Java | `request.getParameter`, `getParameterValues`, `getHeader`, `getQueryString`, `System.getenv`, `System.getProperty`, `FileInputStream`, `Files.readAllLines`, `Scanner`, generic `getParameter` | `Integer.parseInt`, `Long.parseLong`, `Double.parseDouble`, `URLEncoder.encode`, `sanitize`, `escapeHtml` | `Runtime.getRuntime().exec`, `ProcessBuilder`, `executeQuery`, `executeUpdate`, `ObjectInputStream`, `readObject`, `ScriptEngine.eval`, `eval` |

Rule IDs are prefixed `PY-`, `JS-`, and `JAVA-`. Finding confidence is taken
from the matched sink rule; default high-confidence sinks include evaluation,
command execution, DOM HTML writes, and SQL execution. The original Python
rule count and IDs are unchanged.

### Matching and propagation

Matching is syntactic over IR call names, call arguments, and selected
expression candidates. Dotted patterns match equal, longer-qualified, and
suffix names; `new` is normalized; string literals and comments are stripped
from expression candidates. Compound statements such as `function`, `class`,
`loop`, and `if` do not contribute their body text as candidates, avoiding
duplicate findings at enclosing lines.

Taint flows through:

- assignment definitions and their def-use chains;
- simple expressions, including string concatenation;
- call arguments at sinks and into known callee parameters;
- a function returning a source or tainted parameter, then assignment of that
  call's result;
- conservative Python object slots: object fields, dictionary/list subscripts,
  `append()` arguments, simple aliases, and reads back into locals.

States carry the source rule, source name, one-based source location, and an
ordered path. The fixpoint keeps the shortest path per source occurrence and
bounds passes dynamically (`statements * 2 + 8`, minimum 32, maximum 500) with
recursion safeguards, so repeated calls and cyclic call graphs converge.

A sanitizer match marks the statement's definitions clean. Literal-only sink
values do not produce findings. Findings include source rule/name/location,
sink rule/name/location, an ordered `path`, `confidence`, sanitizer and
limitation metadata, and the same limitations carried by the result.
`taint_diagnostics()` maps findings to the existing `Diagnostic` shape using
the language-specific rule ID from the table above.

### Custom rules

```python
from bugdhor_ast.flow import FlowEngine, TaintConfig

config = TaintConfig.from_dict({
    "sources": [{"pattern": "get_secret", "id": "SRC"}],
    "sanitizers": [],
    "sinks": [{"pattern": "log", "id": "SNK"}],
})
result = FlowEngine(taint_config=config).analyze_source(source, "python")
```

Top-level `sources`, `sanitizers`, and `sinks` remain backward-compatible and
configure Python. Language-specific packs use `language_packs` (or the alias
`languages`):

```json
{
  "language_packs": {
    "javascript": {
      "sources": [{"id": "JS-SRC", "pattern": "getToken"}],
      "sanitizers": [],
      "sinks": [{"id": "JS-SNK", "pattern": "send"}]
    }
  }
}
```

Omitted rule roles in an existing language pack inherit that language's
defaults. A `taint_config` argument can also be passed to a single
`analyze_source()` or `analyze_file()` call. CLI runs use the same
`TaintConfig` JSON format through `--taint-config`.

## CLI and JSON integration

Default CLI output is unchanged. Flow sections are added only with `--flow`.

```bash
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.py \
  --detect --flow --taint-diagnostics -o outputs/sample-flow.json

PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.js \
  --detect --flow --taint-diagnostics -o outputs/sample-js-flow.json

PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.java \
  --detect --flow --taint-diagnostics -o outputs/sample-java-flow.json

PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.js \
  --flow --taint-config taint-rules.json -o outputs/sample-js-custom.json
```

Flags:

| Flag | Effect |
| --- | --- |
| `--flow` | Adds `symbols`, `scopes`, `control_flow_graph`, `data_flow`, and `taint_analysis`. |
| `--taint-diagnostics` | Requires `--flow`; with `--detect`, appends `PY-TAINT001`, `JS-TAINT001`, or `JAVA-TAINT001` diagnostics based on the finding's sink rule. |
| `--taint-config PATH` | Requires `--flow`; loads the JSON rule config described above. Invalid JSON/shape exits with status 1 and a message rather than a traceback. |
| `--output`, `-o` | Writes the same JSON payload to a file. |

Existing detection keys remain `file`, `language`, `has_syntax_errors`,
`summary`, `rules_executed`, and `diagnostics`. In AST mode, the original AST
keys and summary are preserved and the five flow sections are appended.

## Limitations

- Taint matching is syntactic and rule-based. It matches names and selected
  expression text, not library semantics, data types, or string contents. It is
  not a complete security analysis for any language.
- Object and container flow is Python-first and textual. Bracketed keys and
  indexes are collapsed to one `[]` slot, so `data["a"]` and `data["b"]` can
  share taint. Only simple aliases are normalized; there is no full heap,
  alias, points-to, or type analysis.
- Interprocedural taint is bounded. Call-site argument mapping is tracked, but
  callee parameter states can be merged across call sites; recursion is capped;
  unresolved calls do not receive argument-derived taint. `argument_index` is
  accepted in config but is not used semantically yet.
- Sanitizers are sink-agnostic and rule-name based. Custom helper functions
  such as `sanitize(x)` are not inferred unless configured as sanitizer names.
- JavaScript and Java rule packs are heuristic defaults. Complex framework
  request binding, template engines, reactive values, dependency injection, and
  Spring/Express lifecycle semantics are not modeled.
- Exception edges are conservative and do not model abrupt control flow through
  `finally` precisely.
- CFGs exist only for module, function, and class scopes.
- Finding confidence is inherited from the matched sink rule. Every finding,
  including high-confidence sinks, requires manual review.
- A syntax-error file yields empty/null flow sections.

## Verification record

Commands run on 2026-11-19 in the repository environment:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -v
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ \
  --cov=bugdhor_ast --cov-report=term-missing
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase4_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase4-performance/results.json
```

Results:

- `205 passed in 0.24s` for the full verbose suite; the Phase 3 baseline was
  `163 passed in 0.16s`.
- Coverage run: `205 passed in 0.89s`; `3811` statements, `186` missed,
  **95%** total.
- Flow package coverage: `__init__.py` 100%, `cfg.py` 96%, `dataflow.py` 99%,
  `engine.py` 92%, `ir.py` 98%, `models.py` 97%, `profiles.py` 94%,
  `scopes.py` 97%, `taint.py` 94%, `tree.py` 98%. The grammar-specific tests
  raised `profiles.py` from 74% to 94% and `tree.py` from 80% to 98%.
- Full verbose output is saved in `reports/PHASE_4_TEST_REPORT.txt`; the coverage
  output is saved in `reports/PHASE_4_COVERAGE_REPORT.txt`.

CLI sample checks:

| Sample | Symbols | Scopes | CFGs (all consistent) | Taint rules (S/San/Sink) | Taint findings |
| --- | ---: | ---: | --- | --- | ---: |
| `examples/sample.py` with `--detect --flow --taint-diagnostics` | 12 | 5 | 5 | 7 / 4 / 7 | 0 |
| `examples/sample.js` with `--detect --flow --taint-diagnostics` | 9 | 5 | 4 | 14 / 6 / 12 | 0 |
| `examples/sample.java` with `--detect --flow --taint-diagnostics` | 8 | 4 | 4 | 11 / 6 / 8 | 0 |

`sample.py` retained the existing detections `[('PY005', 2)]`. CFG nodes used
one-based locations, and edge endpoints matched node IDs. Example edge sequence
from a function graph:

```
entry -> formal_parameters [entry]
formal_parameters -> assignment [params]
assignment -> exit [assign]
```

The five-repetition performance run produced medians from `0.004550 s` for the
24-line Python workload to `0.433720 s` for the 1007-line JavaScript workload,
with peak `tracemalloc` allocations from `0.211 MiB` to `12.208 MiB`. Raw data
is in `benchmarks/results/phase4-performance/results.json`; methodology and
limitations are in `reports/PHASE_4_BENCHMARK_REPORT.md`.

Focused test modules:

- `tests/test_flow_scopes.py`
- `tests/test_flow_dataflow.py`
- `tests/test_flow_cfg.py`
- `tests/test_flow_taint.py`
- `tests/test_flow_cli.py`
- `tests/test_flow_taint_cross_language.py`
- `tests/test_flow_interprocedural.py`
- `tests/test_flow_object_flow.py`
- `tests/test_flow_security_validation.py`
- `tests/test_flow_profiles_tree.py`

These ten modules collect 68 flow-focused tests.

---

## Phase 6 extension: evidence-based explanation and repair

Phase 6 is an **additive local-engine layer** over the flow-analysis results
described above. It does not change flow schemas, detection schemas, the
existing CLI, or the FastAPI backend. It is available through the Python package
`bugdhor_ast.phase6`; in VS Code it is opt-in and does not replace backend
scans.

### Evidence and explanation

Explanations are built from actual AST, CFG, data-flow, and taint evidence.
Every evidence item is categorized as `observed`, `derived`, `heuristic`, or
`unavailable`, with confidence `high`, `medium`, or `low`. Missing evidence
stays unavailable; explanations do not fill gaps with invented claims. Engine
coordinates remain one-based, matching the existing flow-analysis output.

Root-cause localization reports `determined`, `heuristic`, or `unknown`. CWE
mappings are emitted only when a concrete taint sink rule or a direct
null-access rule supports them; dangerous calls without taint evidence remain
unmapped. There are 33 configured CWE rules.

### Repair and verification

Deterministic repair strategies cover supported Python, JavaScript, and Java
syntactic patterns:

| Language | Strategy | Verification result in the measured matrix |
|---|---|---|
| Python | parameterized SQL query | `failed`; current taint rules still flag tainted query arguments |
| Python | subprocess argument list | `failed`; current taint rules still flag a tainted argument list |
| JavaScript | HTML property to `textContent` | `verified` under static reanalysis |
| Java | `PreparedStatement` with bound parameter | `verified` under static reanalysis |

Recommendation statuses are `ready`, `needs_review`, and `unsupported`.
Verification states are `verified`, `partially_verified`, `failed`, and
`not_verified`. Verification reruns parse, detection, flow, and taint analysis
from current source bytes and checks baseline reproduction, reparse, target
resolution, new finding signatures, and exact patch identity. It never executes
source and is not a functional, compiler, dynamic, or sandbox test.

Patch previews include a unified diff and exact span/hash metadata. Apply and
revert require exact `patch_id` confirmation, source-file identity checks,
freshness/overlap checks, exact backups, history, and external-change refusal.
The local session file is written atomically with mode `0600`.

Optional AI repair is deterministic-last, disabled by default, provider-neutral,
and returns untrusted candidates that always require approval. No provider is
registered by default and no generated code is executed.

### Local CLI and VS Code integration

The JSON-only local CLI supports:

```text
analyze, explain, suggest, preview, apply, verify, revert, history
```

Source writes additionally require `--allow-source-write` and exact
confirmation. All VS Code local-engine commands are disabled until
`bugdhor.localEngine.enabled` is true; source writes additionally require
`bugdhor.localEngine.allowSourceWrite`, a modal warning, and typed `patch_id`
confirmation. The five settings are:

| Setting | Default |
|---|---|
| `bugdhor.localEngine.enabled` | `false` |
| `bugdhor.localEngine.pythonPath` | `"python"` |
| `bugdhor.localEngine.requestTimeoutMs` | `15000` |
| `bugdhor.localEngine.allowSourceWrite` | `false` |
| `bugdhor.localEngine.sessionPath` | `".bugdhor/phase6-session.json"` |

The seven command IDs are `bugdhor.explainFindingPhase6`,
`bugdhor.suggestRepairPhase6`, `bugdhor.previewRepairPhase6`,
`bugdhor.applyRepairPhase6`, `bugdhor.verifyRepairPhase6`,
`bugdhor.revertRepairPhase6`, and `bugdhor.showRepairHistoryPhase6`. The adapter
converts VS Code zero-based diagnostic ranges to one-based engine findings by
matching rule ID and start position.

### Verification record

Measured on 2026-11-19:

- AST/Phase 6 suite: `275 passed in 1.51s`.
- Coverage run: `275 passed in 2.46s`; `TOTAL 6526 719 89%`.
- Focused local workflow suite: `9 passed in 0.73s`.
- Phase 6 core workflow medians: `0.005509 s`–`0.065821 s`; peak traced memory
  `0.197 MiB`–`1.914 MiB`.
- Extension Phase 6 adapter tests: `10/10 pass`; full extension unit suite
  `400 pass / 1 fail`, with only the pre-existing user-owned manifest identity
  assertion failing.

Details are in `../reports/PHASE_6_FINAL_REPORT.md`,
`../reports/PHASE_6_TEST_REPORT.txt`,
`../reports/PHASE_6_COVERAGE_REPORT.txt`,
`../reports/PHASE_6_REPAIR_VALIDATION_REPORT.md`, and
`../reports/PHASE_6_BENCHMARK_REPORT.md`. The coding benchmark remains
`not_run`; Phase 6 does not claim security effectiveness, exploitability,
functional correctness, sandboxing, or guaranteed repair.
