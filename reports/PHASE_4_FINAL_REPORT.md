# Phase 4 Final Development Report

**Project:** Bug-Dhor lightweight AST / static-analysis layer (`bugdhor_ast`)
**Phase:** Phase 4 – cross-language taint analysis, interprocedural precision, conservative Python object flow, language-specific config, tests, and benchmarks
**Report file:** `reports/PHASE_4_FINAL_REPORT.md`
**Verification date:** 2026-11-19
**Basis:** Direct inspection of the working tree and source files, full test execution, coverage execution, CLI sample checks, and a completed five-repetition performance benchmark. No unsupported security or performance claim is made.

---

## 1. Executive summary

Phase 4 extends the Phase 3 flow layer from Python-only taint to a shared,
language-aware taint engine with default rule packs for Python, JavaScript, and
Java. It adds bounded interprocedural argument/return mapping, conservative
Python object/container flow, language-specific rule configuration from JSON,
language-specific diagnostic rule IDs, grammar-focused profile/tree tests, and
a reproducible performance harness.

Verification results:

- Full suite: **205 passed in 0.24s**; the Phase 3 baseline was
  **163 passed in 0.16s**.
- Coverage: **3811 statements, 186 missed, 95%** total; `flow/profiles.py`
  rose from **74% to 94%**, `flow/tree.py` from **80% to 98%**, and
  `flow/taint.py` is **94%**.
- Security validation matrix: 8 parametrized source-to-sink cases pass with
  explicit sanitizer and literal negative checks across all three languages.
- Performance: completed small/medium/large generated workloads for all three
  languages; median analysis times ranged from **0.004550 s** to
  **0.433720 s** and peak `tracemalloc` allocations from **0.211 MiB** to
  **12.208 MiB**.
- Existing Phase 3 APIs, default JSON section names, top-level CLI output keys,
  and the original seven Python sources / four sanitizers / seven sinks remain
  intact. Additive metadata fields were introduced where needed.

---

## 2. Implemented features

### 2.1 Language-aware taint rules

`src/bugdhor_ast/flow/taint.py` now defines `LanguageRulePack` and default packs
for three languages. `TaintConfig` keeps the Phase 3 top-level Python fields and
adds `language_packs` plus the `languages` alias.

| Language | Sources | Sanitizers | Sinks | Finding diagnostic rule |
| --- | ---: | ---: | ---: | --- |
| Python | 7 | 4 | 7 | `PY-TAINT001` |
| JavaScript | 14 | 6 | 12 | `JS-TAINT001` |
| Java | 11 | 6 | 8 | `JAVA-TAINT001` |

Default Python rule IDs and counts are unchanged. JavaScript sources cover
Express/request values, URL/DOM values, prompts, process environment, local
storage, URL search parameters, and user agent. JavaScript sinks cover
evaluation, function construction, DOM HTML writes, document writes, child
process execution, and several database query APIs. Java sources cover servlet
and generic request parameters, headers, query strings, environment and system
properties, file input, and scanner input. Java sinks cover command execution,
process building, SQL execution, deserialization/readObject, and evaluation.

`TaintRule.confidence` was added. A finding's confidence is taken from the
matched sink rule, so high-confidence sinks such as evaluation, command
execution, DOM HTML writes, and SQL execution can be distinguished from
lower-confidence pattern matches.

### 2.2 Shared syntactic matching engine

The taint analyzer now works from the same IR, scope, and data-flow facts for
all three languages. It:

- normalizes `new` expressions and strips nested call parentheses for name
  matching;
- strips string literals and line comments from expression candidates;
- matches equal, longer-qualified, and suffix dotted names;
- excludes compound statement kinds (`function`, `class`, `loop`, `if`,
  `else`, `try`, `handler`, `finally`, `params`, `noop`) from expression
  candidate scanning to avoid duplicate findings at enclosing lines;
- marks matched sanitizers clean and skips literal-only sink values;
- emits an ordered path with source/assignment/argument/parameter/call/slot
  step kinds, source and sink locations, confidence, sanitizer metadata, and
  limitations.

### 2.3 Bounded interprocedural flow

`FunctionSummary.call_sites` was added in `models.py`, and
`DataFlowAnalyzer.analyze()` now builds call edges before summaries so summaries
can record those statement IDs. `TaintAnalyzer` uses call-site information for
argument-to-parameter and return-to-caller propagation.

The engine includes:

- bounded callee passes;
- recursion safeguards;
- shortest-path deduplication per source occurrence;
- dynamic iteration bounds (`statements * 2 + 8`, minimum 32, maximum 500);
- conservative unresolved-call handling (no argument-derived taint is invented
  for unknown callees).

A fixpoint convergence bug was found during benchmarking: repeated source
visits could extend a state path indefinitely. `_dedupe_states()` now keeps the
shortest path per source, and `_is_better_state()` prevents assignment, slot,
parameter, and return stores from accepting longer paths for the same source.
A regression test with twelve repeated helper calls keeps paths bounded.

### 2.4 Conservative Python object and container flow

Python taint now tracks textual slots for:

- object attribute writes and reads (`obj.field = input()` then
  `eval(obj.field)`);
- dictionary/list subscript writes and reads;
- `list.append()` with a plain variable or nested call argument;
- simple `alias = obj` normalization;
- reads from a tainted slot into a local;
- string concatenation that consumes a tainted definition.

Bracketed keys and indexes are normalized to one `[]` slot. This is
intentionally conservative: `data["a"]` and `data["b"]` share a slot, which can
produce false positives but preserves flow when keys are dynamic.

### 2.5 Configuration and CLI

`TaintConfig` remains constructible from a dict and now also loads JSON files
with `TaintConfig.from_json_file()`. CLI adds `--taint-config PATH`, which
requires `--flow`. Config loading is inside the CLI error boundary, so missing
files, invalid JSON, and invalid rule shapes exit with status 1 and a clean
message instead of a traceback. Invalid flag combinations exit with status 2.

`taint_diagnostics()` selects `PY-TAINT001`, `JS-TAINT001`, or
`JAVA-TAINT001` based on the finding's sink-rule prefix. The existing default
CLI output remains unchanged unless `--flow` is supplied.

### 2.6 Documentation updates

`docs/scope-data-flow-analysis.md` was updated from stale Phase 3 wording to
the Phase 4 support matrix, propagation model, language-pack config, CLI flags,
limitations, and verification record. `docs/README.md` now describes the scope
document as covering language-pack taint and interprocedural/object flow.
`benchmarks/README.md` distinguishes the still-not-run coding benchmark from
the executed Phase 4 performance harness and links its report.

---

## 3. Source-to-sink validation

The parametrized suite `tests/test_flow_security_validation.py` checks 8 cases.
Each case asserts the exact finding tuple and path step kinds, includes a
sanitized negative branch, and includes a literal-only negative sink.

| Case ID | Language | Positive finding | Negative checks |
| --- | --- | --- | --- |
| `python-input-eval` | Python | line 2, `PY-SNK-001`, source `input` | `int(data)` sink, literal sink |
| `python-helper-sink` | Python | line 6, `PY-SNK-001`, through `passthrough()` | literal sink |
| `javascript-query-innerhtml` | JavaScript | line 2, `JS-SNK-003`, `URLSearchParams(...).get` | `DOMPurify.sanitize`, literal sink |
| `javascript-prompt-eval` | JavaScript | line 2, `JS-SNK-001`, source `prompt` | `parseInt`, literal sink |
| `javascript-function-argument` | JavaScript | line 1, `JS-SNK-001`, `req.query.user` through function argument | `encodeURIComponent` call |
| `java-request-sql` | Java | line 4, `JAVA-SNK-003`, `request.getParameter` | `Integer.parseInt`, literal sink |
| `java-request-runtime-exec` | Java | line 4, `JAVA-SNK-001`, `request.getParameter` | custom `sanitize()` call |
| `java-method-argument` | Java | line 2, `JAVA-SNK-008`, request value through method argument | `Integer.parseInt` branch |

Additional cross-language tests in `tests/test_flow_taint_cross_language.py`
verify:

- JavaScript sinks at lines 4, 5, and 6 from query, URL parameter, and
  environment sources, with sanitized and literal sinks absent;
- Java sinks at lines 4, 5, and 6 from a request parameter, with sanitized and
  literal sinks absent;
- custom pack confidence propagation from sink rules;
- custom JavaScript packs do not change Python defaults;
- `JS-TAINT001` and `JAVA-TAINT001` diagnostic rule IDs and languages;
- the legacy compatibility case where JavaScript `input()` is not a JS source.

---

## 4. Interprocedural and object-flow evidence

`tests/test_flow_interprocedural.py` covers 6 behaviors:

1. caller argument maps through a returning parameter into `eval()`;
2. call-site-specific taint does not cross into a safe literal call site;
3. bounded recursive analysis terminates while retaining taint;
4. unresolved calls remain conservative;
5. twelve repeated calls converge with paths of length at most 4;
6. function summaries record two call-site statement IDs.

`tests/test_flow_object_flow.py` covers 8 behaviors:

1. object field write/read;
2. dictionary value write/read;
3. `append()` argument into subscript read;
4. list index write/read;
5. simple alias normalization across write and read;
6. attribute read copied into a local;
7. string concatenation preserving taint;
8. safe literals and sanitized slots producing no findings.

These are deliberately narrow, deterministic tests. They do not imply full heap
or alias analysis.

---

## 5. Compatibility decisions

| Area | Decision |
| --- | --- |
| Python defaults | Unchanged: 7 sources, 4 sanitizers, 7 sinks. |
| Legacy config | Top-level `sources`/`sanitizers`/`sinks` still map to Python. |
| New config | `language_packs` or `languages` add per-language rules. |
| JSON sections | `FLOW_SECTIONS` remains `symbols`, `scopes`, `control_flow_graph`, `data_flow`, `taint_analysis`. |
| Default CLI output | No flow sections unless `--flow`; no taint diagnostics unless `--detect --flow --taint-diagnostics`. |
| Finding schema | Existing finding keys remain; confidence/sanitizer/limitation metadata is present. |
| Rule schema | Existing rule keys remain; `confidence` is additive. |
| Summary schema | Existing function-summary keys remain; `call_sites` is additive. |
| Legacy limitation text | Still contains `"only for Python"` for the existing regression test that checks JavaScript `input()` is not a source. |

The additive fields are exercised by schema assertions in
`tests/test_flow_security_validation.py` and the full suite.

---

## 6. Test and coverage evidence

Saved outputs:

- `reports/PHASE_4_TEST_REPORT.txt` — full verbose pytest output.
- `reports/PHASE_4_COVERAGE_REPORT.txt` — full coverage output with missing
  lines.

Commands:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -v
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ \
  --cov=bugdhor_ast --cov-report=term-missing
```

Results:

| Metric | Phase 3 baseline | Phase 4 final |
| --- | ---: | ---: |
| Tests passed | 163 | 205 |
| Full suite time | 0.16s | 0.24s |
| Coverage statements | 3452 | 3811 |
| Coverage missed | 276 | 186 |
| Total coverage | 92% | 95% |
| `flow/profiles.py` | 74% | 94% |
| `flow/tree.py` | 80% | 98% |
| `flow/taint.py` | 94% | 94% |

Full flow-package coverage in the final run:

| Module | Coverage |
| --- | ---: |
| `flow/__init__.py` | 100% |
| `flow/cfg.py` | 96% |
| `flow/dataflow.py` | 99% |
| `flow/engine.py` | 92% |
| `flow/ir.py` | 98% |
| `flow/models.py` | 97% |
| `flow/profiles.py` | 94% |
| `flow/scopes.py` | 97% |
| `flow/taint.py` | 94% |
| `flow/tree.py` | 98% |

The ten flow-focused test modules collect 68 tests. The grammar-focused
`tests/test_flow_profiles_tree.py` added 8 tests covering Python import aliases,
Python statement kinds, JavaScript import/binding patterns, Java declarations
and calls, tree helpers, and unsupported-profile errors.

CLI sample checks were rerun against the examples:

| Sample | Symbols | Scopes | CFGs | Taint rules | Taint findings |
| --- | ---: | ---: | ---: | --- | ---: |
| `examples/sample.py` | 12 | 5 | 5 | 7 / 4 / 7 | 0 |
| `examples/sample.js` | 9 | 5 | 4 | 14 / 6 / 12 | 0 |
| `examples/sample.java` | 8 | 4 | 4 | 11 / 6 / 8 | 0 |

All sampled CFGs reported `consistent: true`, and `sample.py` still produced
the existing `PY005` detection.

---

## 7. Performance evidence

Harness: `benchmarks/harness/run_phase4_performance.py`
Raw data: `benchmarks/results/phase4-performance/results.json`
Full report: `reports/PHASE_4_BENCHMARK_REPORT.md`

Command:

```bash
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase4_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase4-performance/results.json
```

Environment: Python 3.11.14, macOS-26.3.1-arm64-arm-64bit, processor `arm`.

| Language | Size | Lines | Findings | Median (s) | Peak MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Python | small | 24 | 3 | 0.004550 | 0.211 |
| Python | medium | 186 | 21 | 0.039624 | 1.710 |
| Python | large | 906 | 101 | 0.293832 | 11.682 |
| JavaScript | small | 27 | 3 | 0.006308 | 0.228 |
| JavaScript | medium | 207 | 21 | 0.055066 | 1.911 |
| JavaScript | large | 1007 | 101 | 0.433720 | 12.208 |
| Java | small | 26 | 3 | 0.004945 | 0.266 |
| Java | medium | 170 | 21 | 0.037600 | 1.701 |
| Java | large | 810 | 101 | 0.236445 | 8.923 |

Timing excludes `tracemalloc`; peak Python allocations were measured in a
separate instrumented run. These are performance facts for deterministic
generated sources, not security-effectiveness evidence and not a comparison
against Phase 3.

An initial benchmark attempt before the convergence fix was stopped at the
600000 ms timeout. Those numbers were discarded. The completed run above was
produced after shortest-path deduplication and path-quality checks were added.

---

## 8. Files created or modified in Phase 4

### Created

| File | Purpose |
| --- | --- |
| `tests/test_flow_taint_cross_language.py` | JavaScript/Java source-to-sink, sanitizer, pack, and diagnostic tests. |
| `tests/test_flow_interprocedural.py` | Argument/return mapping, recursion, call-site, and convergence tests. |
| `tests/test_flow_object_flow.py` | Python object/container/alias/concatenation flow tests. |
| `tests/test_flow_security_validation.py` | 8-case cross-language security validation matrix and JSON schema checks. |
| `tests/test_flow_profiles_tree.py` | 8 grammar/profile/tree coverage tests. |
| `benchmarks/harness/run_phase4_performance.py` | Deterministic performance generator and runner. |
| `benchmarks/results/phase4-performance/results.json` | Raw five-repetition benchmark data. |
| `reports/PHASE_4_TEST_REPORT.txt` | Saved full verbose pytest output. |
| `reports/PHASE_4_COVERAGE_REPORT.txt` | Saved full coverage output. |
| `reports/PHASE_4_BENCHMARK_REPORT.md` | Executed benchmark methodology, results, and limitations. |
| `reports/PHASE_4_FINAL_REPORT.md` | This consolidated report. |

### Modified

| File | Phase 4 change |
| --- | --- |
| `src/bugdhor_ast/flow/taint.py` | Language packs, JS/Java rules, generic engine, Python slots, interprocedural mapping, config parsing, convergence fixes. |
| `src/bugdhor_ast/flow/models.py` | Added `TaintRule.confidence` and `FunctionSummary.call_sites`. |
| `src/bugdhor_ast/flow/dataflow.py` | Built call edges before summaries and attached call sites to summaries. |
| `src/bugdhor_ast/flow/profiles.py` | Java `call_arguments()` accepts `arguments` or `argument_list`; grammar coverage additions. |
| `src/bugdhor_ast/flow/engine.py` | Exported and selected language-specific taint diagnostics. |
| `src/bugdhor_ast/flow/__init__.py` | Exported Phase 4 additions. |
| `src/bugdhor_ast/cli.py` | Added validated `--taint-config` integration. |
| `tests/test_flow_cli.py` | Added config-required, custom-rule, language-pack, and invalid-config CLI tests. |
| `docs/scope-data-flow-analysis.md` | Replaced stale Phase 3 status with Phase 4 feature, API, CLI, limitation, and verification records. |
| `docs/README.md` | Updated the existing scope-document description only. |
| `benchmarks/README.md` | Distinguished coding benchmark readiness from the executed Phase 4 performance harness. |

`src/`, `tests/`, `reports/`, and the Phase 3 docs remain untracked relative to
`HEAD`, as in earlier phases; the table describes changes relative to the
Phase 3 working version.

### Pre-existing user-owned changes, deliberately untouched

`git status --short` still shows modifications under `vscode-extension/`:

- `vscode-extension/package.json`
- `vscode-extension/src/commands/runEngineCommand.js`
- `vscode-extension/test/integration/index.js`

These files were not edited, reverted, staged, or included in Phase 4 work.

---

## 9. Known limitations and false-positive risks

- Taint matching is syntactic. It does not understand library semantics, data
  types, string contents, control dependencies, or complete framework
  lifecycles. It is not a complete security analysis for any language.
- Python slots are textual and conservative. Bracketed keys and indexes are
  collapsed to `[]`, so writes and reads through different keys or indexes can
  be conflated. Only simple aliases are normalized; there is no heap, points-to,
  or type analysis.
- Interprocedural mapping is bounded but approximate. Callee parameter states
  may merge across call sites; recursion is capped; unresolved calls receive no
  argument-derived taint. `argument_index` is parsed but not used semantically.
- Sanitizers are sink-agnostic. A configured sanitizer name clears taint for
  the matched rule set even if the sink would require a different encoding.
  Custom helper sanitizers are not inferred unless configured.
- JavaScript and Java packs are heuristic. Express/Spring request binding,
  template engines, reactive values, dependency injection, and complex object
  graphs are not modeled.
- CFGs exist only for module, function, and class scopes. Exception edges and
  `finally` semantics are conservative.
- Small-workload timings are indicative. `tracemalloc` measures Python
  allocations, not full process RSS, and timing/memory come from separate runs.
- A syntax-error file yields empty/null flow sections rather than partial
  facts.

---

## 10. Remaining TODOs

1. Add field-sensitive Python slots with key/index partitioning to reduce
   container false positives.
2. Use `argument_index` for positional sink and callee argument precision.
3. Add call-site-sensitive callee summaries instead of merged parameter states.
4. Model framework-specific sources and sanitizers for Express, Spring, and
   common template engines.
5. Add branch/condition sensitivity to reduce infeasible paths.
6. Add a Phase 3-versus-Phase 4 performance comparison with fixed hardware and
   larger statistical repetition.
7. Add memory measurement that includes native process RSS where supported.
8. Continue grammar coverage for the remaining uncovered profile branches in
   `flow/profiles.py`.

---

## 11. Conclusion

Phase 4 is complete against the stated scope. The analyzer now reports real
JavaScript and Java source-to-sink findings, preserves the Python defaults and
Phase 3 API surface, uses bounded interprocedural and conservative object flow,
supports language-specific JSON rule packs, and has reproducible performance
data. All 205 tests pass, total coverage is 95%, the two targeted grammar
modules exceed their coverage targets, and the documented limitations
explicitly separate this syntactic analysis from complete security coverage.
