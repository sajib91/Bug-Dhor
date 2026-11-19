# Phase 3 Final Development Report

**Project:** Bug-Dhor lightweight AST / static-analysis layer (`bugdhor_ast`)
**Phase:** Phase 3 – scope analysis, symbol tables, data flow, control-flow graphs, and taint analysis
**Report file:** `reports/PHASE_3_FINAL_REPORT.md`
**Verification date:** 2026-11-19
**Basis:** Direct inspection of the working tree, source files, documentation, focused test collection, full test execution, coverage execution, and CLI sample runs. No unsupported capability is claimed.

---

## 1. Project architecture changes

Phase 3 adds a new flow-analysis layer on top of the existing lightweight tree-sitter wrapper. It does **not** import or modify the heavier `security-engine` package, and it does **not** change the existing AST JSON schema or the existing rule-based detection output by default.

### New analysis pipeline

```
BugDhorASTEngine / tree-sitter
            |
       FlowContext
            |
      LanguageProfile
            |
     ScopeAnalyzer -------> scopes + symbols + references
            |
        IRBuilder -------> IRStatement stream
         /      \
  CFGBuilder   DataFlowAnalyzer --> CFGs, defs/uses, chains, liveness
         \      /
      TaintAnalyzer ---------> TaintFinding list
            |
        FlowEngine ----------> FlowAnalysisResult / JSON
```

### Key architectural decisions

| Decision | Result |
| --- | --- |
| Reuse `BugDhorASTEngine` and `detect_language()` | No second parser stack; phase stays inside `bugdhor_ast`. |
| One shared `IRStatement` layer | Scope, CFG, data-flow, and taint passes consume the same normalized statement facts. |
| Grammar-specific behavior isolated in `LanguageProfile` subclasses | Python, JavaScript, and Java differences stay in `profiles.py`; shared passes remain language-neutral. |
| Stable node identity via `node_key() = (start_byte, end_byte, type)` | Cross-pass maps are not corrupted by recreated tree-sitter wrapper objects. |
| One-based line/column locations | JSON output is consistent with existing diagnostics. |
| CFGs generated only for `module`, `function`, and `class` scopes | Block and comprehension scopes remain symbol/data-flow scopes only. |
| Flow sections are opt-in via `--flow` | Default CLI output keys and behavior are preserved. |
| `--taint-diagnostics` requires `--flow` | Prevents misleading taint diagnostics without flow facts. |
| Syntax-error files short-circuit to empty/null flow sections | No partial or fabricated analysis facts are emitted. |

### Public API added

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

`FlowAnalysisResult.to_dict(sections=...)` controls which JSON sections are emitted. `FLOW_SECTIONS` is:

```python
("symbols", "scopes", "control_flow_graph", "data_flow", "taint_analysis")
```

---

## 2. All newly created files

The following files were created as part of Phase 3. Line counts are from the verified working tree.

### Core flow package

| File | Lines | Purpose |
| --- | ---: | --- |
| `src/bugdhor_ast/flow/__init__.py` | 53 | Public exports: `FlowEngine`, models, `FLOW_SECTIONS`, `TaintConfig`, `taint_diagnostics`. |
| `src/bugdhor_ast/flow/tree.py` | 113 | `FlowContext`, stable `node_key()`, statement IDs, parent/field access, one-based locations. |
| `src/bugdhor_ast/flow/models.py` | 521 | JSON-safe schemas for scopes, symbols, IR, CFG nodes/edges, data flow, taint, and result aggregation. |
| `src/bugdhor_ast/flow/profiles.py` | 1023 | `LanguageProfile`, `PythonProfile`, `JavaScriptProfile`, `JavaProfile`, `get_profile()`. |
| `src/bugdhor_ast/flow/scopes.py` | 652 | Scope tree construction and symbol-table resolution. |
| `src/bugdhor_ast/flow/ir.py` | 281 | Statement lowering into shared `IRStatement` records and region helpers. |
| `src/bugdhor_ast/flow/cfg.py` | 331 | CFG construction for module/function/class scopes and CFG assembly. |
| `src/bugdhor_ast/flow/dataflow.py` | 424 | Fixed-point reaching-definition/liveness passes, chains, summaries, and call edges. |
| `src/bugdhor_ast/flow/taint.py` | 487 | Default/custom taint rules, taint state propagation, findings, and limitations. |
| `src/bugdhor_ast/flow/engine.py` | 196 | `FlowEngine`, `analyze_source()`, `analyze_file()`, `taint_diagnostics()`, `PY-TAINT001`. |

### Tests

| File | Lines | Focused tests collected |
| --- | ---: | ---: |
| `tests/test_flow_scopes.py` | 268 | 5 |
| `tests/test_flow_dataflow.py` | 200 | 5 |
| `tests/test_flow_cfg.py` | 209 | 4 |
| `tests/test_flow_taint.py` | 164 | 6 |
| `tests/test_flow_cli.py` | 155 | 6 |
| **Flow tests total** | **996** | **26** |

### Documentation and this report

| File | Lines | Purpose |
| --- | ---: | --- |
| `docs/scope-data-flow-analysis.md` | 343 | Authoritative Phase 3 feature, API, CLI, limitation, and verification record. |
| `reports/PHASE_3_FINAL_REPORT.md` | this file | Consolidated final development report. |

### Workspace files created in earlier phases, not Phase 3

The repository also contains untracked files from earlier AST/detection phases. These are **not** Phase 3 deliverables and are listed only for transparency:

- `src/bugdhor_ast/__init__.py`
- `src/bugdhor_ast/engine.py`
- `src/bugdhor_ast/languages.py`
- `src/bugdhor_ast/detection/**` (context, engine, models, registry, reporting, and rule modules)
- `tests/test_ast_engine.py`, `tests/test_cli.py`, `tests/test_languages.py`
- `tests/test_detection_*.py` (8 modules)
- `examples/sample.py`, `examples/sample.js`, `examples/sample.java`
- `outputs/sample_*_ast*.json` (9 files)
- `requirements-ast.txt`
- `docs/static-bug-detection.md`

---

## 3. All modified files

### Phase 3 modifications

| File | Change |
| --- | --- |
| `src/bugdhor_ast/cli.py` | Added `from .flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics`; added `--flow`; added `--taint-diagnostics` with `--flow` validation; injected the five flow sections in both detection mode and AST mode; appended `PY-TAINT001` diagnostics only when `--detect --flow --taint-diagnostics` is used. Existing keys, error messages, and exit behavior were preserved. |
| `docs/README.md` | Added the documentation index link for `scope-data-flow-analysis.md` (line 7). |

> Note: `src/` is untracked relative to `HEAD`, so `cli.py` appears as an untracked workspace file in `git status`. It was nevertheless modified during Phase 3 relative to the Phase 2 working version.

### Pre-existing user-owned modifications, deliberately untouched

`git status --short` also shows modified files under `vscode-extension/`:

- `vscode-extension/package.json`
- `vscode-extension/src/commands/runEngineCommand.js`
- `vscode-extension/test/integration/index.js`

These are pre-existing user changes and were **not** edited, reverted, or included in the Phase 3 implementation.

---

## 4. Symbol Table implementation

**Status: Completed for Python, JavaScript, and Java.**

### Data model

`Symbol` records contain:

- `id`, `name`, `symbol_type`, `scope_id`, `language`;
- primary `declaration` location;
- all `declaration_locations`;
- `references` with file, line, column, kind, and `statement_id`;
- `assignments` with value text, kind, and statement ID.

`Scope` records contain `id`, `kind`, `name`, `parent_id`, `language`, location, `children`, and a `name -> symbol_id` map.

### Behavior

- Symbols are keyed by `(scope_id, name)`, so shadowing creates distinct symbols rather than duplicate entries.
- Declarations include variables, functions, classes, parameters, imports, and assignments.
- Augmented assignments such as `x += 1` are both definitions and uses.
- Plain JavaScript/Java assignment expressions reuse an already resolved symbol; an unresolved plain assignment becomes an implicit module-level binding instead of an unrelated duplicate symbol.
- Python `global` redirects declarations and references to the module scope.
- Python `nonlocal` binds to the nearest enclosing function/lambda scope with an existing binding.
- Forward references are resolved after all declarations are collected.
- Java `this.field` attribute writes are not treated as new symbol declarations.

Implementation entry points: `ScopeAnalyzer._register_declaration()`, `_register_reference()`, `_resolve_symbol()`, `_target_scope_id()`, and `_resolve_directive_targets()` in `src/bugdhor_ast/flow/scopes.py`.

---

## 5. Scope Analysis implementation

**Status: Completed for the documented subset in Python, JavaScript, and Java.**

### Scope kinds

| Kind | Python | JavaScript | Java |
| --- | --- | --- | --- |
| `module` | module | program | program |
| `function` | `def` | function declaration/expression, method, arrow | method, constructor |
| `lambda` | lambda with a `body` field | arrow functions are `function` scopes | lambda expressions are function scopes |
| `class` | `class` | `class` | `class`, interface, enum, record |
| `block` | no separate block scope | `let`/`const` blocks, catch | local blocks, catch |
| `comprehension` | list/set/dict comprehension, generator | n/a | n/a |

### Language-specific resolution

- **Python:** module, function, lambda, class, block, and comprehension scopes. Class scopes are skipped during non-local lookup after the first hop, matching Python method name-resolution behavior.
- **JavaScript:** `var` targets the nearest function/module scope; `let`, `const`, and catch parameters target the current block; arrow functions and methods are function scopes; function bodies do not create an extra block scope.
- **Java:** fields target the class scope; formal parameters target the method scope; local declarations and catch parameters target the nearest block; constructors are function scopes.

Scope IDs are stable strings such as `scope:function:17:200`. Each scope records its parent, children, location, and symbol table. Nested functions/classes, closures, and shadowing are represented through the parent chain and `(scope_id, name)` symbol keys.

---

## 6. Data Flow Analysis implementation

**Status: Completed for intraprocedural analysis; partial for interprocedural precision.**

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

### Algorithms

- Reaching definitions: forward fixed point with definition kills by symbol.
- Liveness: backward fixed point over names.
- Both passes walk CFG predecessors and successors, so branch and loop joins are represented.
- Results are aggregated into `DataFlowResult.scopes`, `.function_summaries`, and `.call_edges`.

### Interprocedural boundary

Implemented: summaries, call edges, and taint through returned values.
Not implemented: substitution of caller arguments into callee bodies, recursion resolution, and higher-order call resolution.

---

## 7. Control Flow Graph implementation

**Status: Completed for module, function, and class scopes.**

`CFGBuilder` emits one `ControlFlowGraph` per `module`, `function`, or `class` scope. Block and comprehension scopes remain symbol/data-flow scopes only by design.

### Node kinds

`entry`, `exit`, `params`, `assign`, `decl`, `import`, `call`, `if`, `else`, `loop`, `break`, `continue`, `return`, `throw`, `try`, `handler`, `finally`, and synthetic `try_join`.

### Edge kinds

`entry`, `params`, `assign`, `decl`, `call`, `return`, `throw`, `break`, `continue`, `true`, `false`, `body`, `else`, `exit`, `handler`, and `normal`.

### Construct coverage

- sequenced statements;
- `if` / `else` / Python `elif`, where `elif` is carried by the `if` node;
- `for`, `while`, `do`, enhanced `for`, and `for-in` loops;
- `break`, `continue`, `return`, and `throw`/`raise`;
- Python `try`/`except`/`finally` and JavaScript/Java `try`/`catch`/`finally`.

A synthetic `try_join` node joins normal and handler paths before the finalizer.

### Validation

`ControlFlowGraph.validate()` checks:

1. entry and exit nodes exist;
2. every edge endpoint exists;
3. there are no duplicate `(source, target, kind)` edges;
4. every node's `successors` and `predecessors` exactly match the edge list.

`to_dict()` adds `"consistent": true` when validation succeeds. All sample and test graphs pass validation, and every node is reachable from the graph entry in the exercised cases.

---

## 8. Taint Analysis implementation

**Status: Completed for a documented Python subset; not implemented for JavaScript/Java findings.**

### Default rules

| Role | Patterns |
| --- | --- |
| Sources | `input`, `request.args.get`, `request.form.get`, `os.getenv`, `os.environ.get`, `open`, `sys.stdin.readline` |
| Sanitizers | `int`, `float`, `shlex.quote`, `html.escape` |
| Sinks | `eval`, `exec`, `os.system`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `cursor.execute` |

Dotted patterns also match longer qualified names beginning with the pattern. Matching is syntactic on call names.

### Propagation

Taint flows through:

- assignment definitions and their def-use chains;
- simple expressions that consume a tainted definition;
- call arguments at sinks;
- a function returning a source or tainted parameter, then assignment of that call's result.

A sanitizer match marks the statement's definitions clean. Literal-only sink values do not produce findings.

### Findings and diagnostics

Findings include source rule/name/location, sink rule/name/location, an ordered `path` of source/assignment/sink steps, `confidence: "medium"`, and the shared limitations string.

`taint_diagnostics()` maps each finding to the existing `Diagnostic` shape using rule ID `PY-TAINT001`, severity `warning`, and language `python`.

### Configuration

Custom rules are available through the Python API via `TaintConfig.from_dict()` or by passing `taint_config` to `analyze_source()` / `analyze_file()`. The CLI uses default rules only. For non-Python languages, `TaintAnalyzer.analyze()` returns a `TaintResult` with the configured rules and empty findings; it does not run taint propagation.

---

## 9. Language-wise feature support

| Capability | Python | JavaScript | Java |
| --- | --- | --- | --- |
| Scope tree | Completed: module, function, lambda, class, block, comprehension | Completed: program, function, class, block; arrows are functions | Completed: program, class/interface/enum/record, method/constructor, block |
| Symbol table | Completed: declarations, params, imports, assignments, references, `global`, `nonlocal` | Completed: `var` vs `let`/`const`, catch params, plain assignment handling | Completed: fields, params, locals, catch params, constructor scopes |
| Shared IR | Completed | Completed | Completed |
| CFG | Completed for module/function/class | Completed for module/function/class | Completed for module/function/class |
| Data flow / chains / liveness | Completed per documented subset | Completed per documented subset | Completed per documented subset |
| Function summaries / call edges | Completed | Completed | Completed |
| Taint findings | Completed for syntactic Python subset | **Not implemented** (empty findings; rules returned) | **Not implemented** (empty findings; rules returned) |
| CLI flow sections | Completed | Completed | Completed |
| Syntax-error behavior | Empty/null flow sections | Empty/null flow sections | Empty/null flow sections |

---

## 10. Implemented features vs partially implemented features

### Completed

- `FlowContext` with stable node keys and one-based locations.
- Language profiles for Python, JavaScript, and Java.
- Scope trees and symbol tables with declarations, references, assignments, shadowing, closures, and language-specific binding rules.
- Shared `IRStatement` lowering.
- CFGs for module, function, and class scopes with explicit nodes, edges, and validation.
- Data-flow facts: definitions, uses, reaching definitions, liveness, def-use/use-def chains, dependencies, propagation, summaries, and call edges.
- Python-only configurable taint analysis over the documented subset.
- `PY-TAINT001` diagnostic conversion.
- CLI `--flow` and `--taint-diagnostics` with preserved default output.
- Focused tests, documentation, and verification record.

### Partially implemented

| Area | What exists | What is missing |
| --- | --- | --- |
| Interprocedural analysis | Summaries, call edges, returned taint | Argument substitution into callees; recursive and higher-order flow |
| Exception control flow | Conservative `try`/`handler`/`finally` nodes and `try_join` | Precise abrupt control flow through `finally` |
| CFG scope coverage | Module, function, class | Block and comprehension CFGs (intentionally symbol/data-flow only) |
| JavaScript/Java taint | Config rules returned in `TaintResult` | Any finding computation or propagation |
| Grammar profile coverage | Profiles implemented for three languages | `profiles.py` has 74% line coverage; many grammar-specific branches are untested |
| Taint configuration | Python API supports custom rules | CLI/file-based custom taint config |

### Not implemented in Phase 3

- Heap aliasing, object-field flow, container flow, and string-content modeling.
- Dynamic dispatch and reflection.
- Precise exception semantics.
- JavaScript and Java taint findings.
- Recursive/higher-order taint resolution.
- Argument substitution into callees.

---

## 11. Known limitations and unresolved issues

1. **Taint is Python-only.** JavaScript and Java return `TaintResult.findings = []`.
2. **Syntactic matching.** Taint rules match call names and variable definitions, not library semantics or string contents.
3. **No memory modeling.** No heap, alias, object-field, container, or string-content analysis.
4. **Limited interprocedural flow.** Only summaries, call edges, and return taint are resolved; arguments are not substituted into callees.
5. **Conservative exceptions.** Exception edges do not precisely model abrupt control flow through `finally`.
6. **CFG scope boundary.** CFGs are generated only for module, function, and class scopes.
7. **Medium-confidence findings.** Taint findings require manual review; they are not a security guarantee.
8. **Syntax-error files.** Flow sections are empty/null rather than partially inferred.
9. **Grammar test gaps.** `profiles.py` is the lowest-covered flow module at 74%, mainly due to untested grammar-specific branches.
10. **No performance benchmark.** No large-file timing or scalability benchmark was run in this phase.
11. **VS Code integration not part of this change.** Pre-existing user-owned `vscode-extension/` modifications were left untouched.

There are no known blocking test failures or validation errors in the Phase 3 change set.

---

## 12. Actual test execution results

Commands executed on 2026-11-19 from the repository root:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -v
```

Observed summary:

```text
============================= 163 passed in 0.16s ==============================
```

Focused flow test collection:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_flow_scopes.py --collect-only -q
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_flow_dataflow.py --collect-only -q
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_flow_cfg.py --collect-only -q
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_flow_taint.py --collect-only -q
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_flow_cli.py --collect-only -q
```

Collected counts:

| Test module | Tests |
| --- | ---: |
| `tests/test_flow_scopes.py` | 5 |
| `tests/test_flow_dataflow.py` | 5 |
| `tests/test_flow_cfg.py` | 4 |
| `tests/test_flow_taint.py` | 6 |
| `tests/test_flow_cli.py` | 6 |
| **Total flow tests** | **26** |

### CLI sample verification

Actual commands and summarized output:

```bash
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.py \
  --detect --flow --taint-diagnostics

PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.js --flow

PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.java --flow
```

| Sample | Symbols | Scopes | CFGs | All CFGs consistent | Taint findings | Existing diagnostics retained |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| `examples/sample.py` with `--detect --flow --taint-diagnostics` | 12 | 5 | 5 | yes | 0 | `[('PY005', 2)]` |
| `examples/sample.js` with `--flow` | 9 | 5 | 4 | yes | 0 | n/a |
| `examples/sample.java` with `--flow` | 8 | 4 | 4 | yes | 0 | n/a |

The Python output contained exactly the top-level keys expected for combined detection + flow mode:

```text
control_flow_graph, data_flow, diagnostics, file, has_syntax_errors,
language, rules_executed, scopes, summary, symbols, taint_analysis
```

---

## 13. Actual code coverage

Command executed:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ \
  --cov=bugdhor_ast --cov-report=term-missing
```

Observed summary:

```text
======================== 163 passed in 0.52s ========================
TOTAL                                         3452    276    92%
```

### Flow package coverage

| File | Statements | Missed | Coverage |
| --- | ---: | ---: | ---: |
| `src/bugdhor_ast/flow/__init__.py` | 4 | 0 | 100% |
| `src/bugdhor_ast/flow/cfg.py` | 153 | 6 | 96% |
| `src/bugdhor_ast/flow/dataflow.py` | 162 | 1 | 99% |
| `src/bugdhor_ast/flow/engine.py` | 65 | 6 | 91% |
| `src/bugdhor_ast/flow/ir.py` | 141 | 3 | 98% |
| `src/bugdhor_ast/flow/models.py` | 262 | 8 | 97% |
| `src/bugdhor_ast/flow/profiles.py` | 476 | 123 | 74% |
| `src/bugdhor_ast/flow/scopes.py` | 276 | 9 | 97% |
| `src/bugdhor_ast/flow/taint.py` | 187 | 12 | 94% |
| `src/bugdhor_ast/flow/tree.py` | 64 | 13 | 80% |

Raw `term-missing` lines for the flow package and total:

```text
src/bugdhor_ast/flow/__init__.py                          4      0   100%
src/bugdhor_ast/flow/cfg.py                             153      6    96%   85, 100, 146, 177, 271-272
src/bugdhor_ast/flow/dataflow.py                        162      1    99%   293
src/bugdhor_ast/flow/engine.py                           65      6    91%   51, 74-78, 124, 129, 154
src/bugdhor_ast/flow/ir.py                              141      3    98%   105, 160, 252
src/bugdhor_ast/flow/models.py                          262      8    97%   142, 191, 193, 198, 202, 207, 222, 226
src/bugdhor_ast/flow/profiles.py                        476    123    74%   65, 98, 103, 108, 113, 118, 123, 128-132, 137-141, 172-176, 191, 207, 214, 216, 218, 227, 230, 237, 239-243, 245-247, 262-266, 337, 344, 351, 363, 381, 383-386, 390-391, 397, 408, 456-460, 478, 486, 502, 504, 529, 531, 551, 596-604, 617-627, 629-639, 650, 663, 670-685, 690, 728-736, 749, 752, 765, 841-850, 852-860, 907, 918-922, 977-983, 988-991, 1007
src/bugdhor_ast/flow/scopes.py                          276      9    97%   115, 323, 341-342, 438, 445, 457, 506, 636
src/bugdhor_ast/flow/taint.py                           187     12    94%   127, 137-138, 142-143, 147, 346, 412-413, 434, 448-449
src/bugdhor_ast/flow/tree.py                             64     13    80%   12, 19, 53-56, 65-66, 77, 97-100
TOTAL                                                  3452    276    92%
```

---

## 14. Remaining TODOs

Prioritized follow-up work from the verified gaps:

1. **Raise `profiles.py` coverage above 74%.** Add grammar-specific tests for uncovered declaration, call, literal, handler, and statement-kind branches in all three profiles.
2. **Implement JavaScript taint analysis.** Reuse `TaintConfig` and def-use chains; add language-appropriate sources/sinks and call-name matching for JavaScript.
3. **Implement Java taint analysis.** Add sources/sinks for Java APIs and connect to existing call edges and definitions.
4. **Improve interprocedural data flow.** Substitute arguments into callee summaries and handle recursion with bounded fixed points.
5. **Improve interprocedural taint.** Track tainted arguments through callee bodies and recursive/higher-order calls.
6. **Model object/container flow.** Support object fields, aliases, list/dict contents, and string operations at least in a conservative mode.
7. **Refine exception CFGs.** Model precise abrupt control flow and `finally` semantics rather than conservative joins.
8. **Add block/comprehension CFGs if downstream consumers need them.** Keep module/function/class CFGs as the stable default.
9. **Add CLI custom taint configuration.** Allow a JSON rule file while preserving default behavior.
10. **Add performance benchmarks.** Measure flow-analysis time and memory on large Python/JavaScript/Java files.
11. **Integrate flow sections into downstream consumers.** Do this only with explicit coordination because `vscode-extension/` currently contains pre-existing user-owned changes.

---

## 15. Recommended next development phase

### Recommended Phase 4: Cross-language taint and interprocedural precision

**Goal.** Turn the Phase 3 foundation into a more complete multi-language flow engine while preserving the stable schemas and default CLI compatibility.

#### Scope

- JavaScript and Java taint finding computation using the same `TaintConfig` contract.
- Argument-sensitive function summaries and bounded recursive interprocedural flow.
- Conservative object/field/container modeling for Python first.
- Grammar-profile test expansion to close the 74% coverage gap.
- Optional CLI taint-rule file support.

#### Suggested deliverables

1. `TaintConfig` language packs for Python, JavaScript, and Java.
2. Tests proving JavaScript and Java produce real findings for documented source-to-sink cases.
3. Argument-substitution tests for function summaries and taint.
4. Expanded profile tests with measured coverage target, e.g. `profiles.py >= 90%`.
5. Benchmark report on representative large files.
6. Updated docs and a Phase 4 verification record.

#### Acceptance criteria

- Full suite remains green with no regression in the existing 163 tests.
- Default CLI JSON keys remain unchanged unless `--flow` is supplied.
- All emitted CFGs continue to pass `ControlFlowGraph.validate()`.
- New taint findings include source, sink, path, confidence, and limitations exactly as in the current schema.
- Unsupported or partial capabilities remain explicitly documented rather than inferred.

#### Risk control

Keep flow sections opt-in, keep taint findings medium-confidence, preserve the syntax-error short-circuit, and avoid touching pre-existing user-owned `vscode-extension/` changes without separate approval.
