# Phase 4 Flow-Analysis Performance Benchmark Report

**Project:** Bug-Dhor lightweight AST / static-analysis layer (`bugdhor_ast`)
**Phase:** Phase 4 – cross-language and interprocedural taint analysis
**Report file:** `reports/PHASE_4_BENCHMARK_REPORT.md`
**Verification date:** 2026-11-19
**Raw data:** `benchmarks/results/phase4-performance/results.json`
**Harness:** `benchmarks/harness/run_phase4_performance.py`

---

## 1. Purpose and scope

This benchmark measures the execution time and practical memory usage of
`FlowEngine.analyze_source()` after the Phase 4 taint-analysis changes. It is a
**performance measurement only**. It does not measure security effectiveness,
false-positive rate, recall, or any coding-benchmark condition E0-E7. The
execution-based coding benchmark remains `not_run` as documented in
`benchmarks/README.md`.

The measured pipeline is the full flow analysis for one in-memory source:

```
parse -> FlowContext -> ScopeAnalyzer -> IRBuilder -> CFGBuilder
      -> DataFlowAnalyzer -> TaintAnalyzer -> FlowAnalysisResult
```

The benchmark records the number of taint findings so that each timing run is
known to have exercised the taint engine rather than only the earlier passes.

---

## 2. Reproduction command

Run from the repository root:

```bash
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase4_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase4-performance/results.json
```

Environment recorded in the raw JSON:

| Field | Value |
| --- | --- |
| Python | `3.11.14` |
| Platform | `macOS-26.3.1-arm64-arm-64bit` |
| Processor | `arm` |
| Timing repetitions per workload | `5` |

The harness prints a Markdown table and writes the raw per-repetition timings,
median/min/max, source size, finding count, peak MiB, and platform metadata to
JSON.

---

## 3. Workload generator

The generator is deterministic and creates three sizes per language:

| Size | Generated flow functions | Approximate shape |
| --- | ---: | --- |
| small | 2 | one outer sink, two inline flow helpers, one source, two calls |
| medium | 20 | same pattern with 20 flow helpers |
| large | 100 | same pattern with 100 flow helpers |

Each workload mixes tainted and sanitized values:

- **Python**: `input()` source; helper assignments and string concatenation;
  `eval()` sinks; `int()` sanitizer; helper calls from module scope.
- **JavaScript**: `prompt()` source; `const` assignments and concatenation;
  `eval()` sinks; `encodeURIComponent()` sanitizer; function calls from module
  scope.
- **Java**: `request.getParameter()` source; local assignments and
  concatenation; `eval()` sinks; `Integer.parseInt()` sanitizer; method calls
  from a driver method inside one class.

Line and byte counts are measured from the generated source text. The newline
count is used as the reported line count.

---

## 4. Methodology

For each language/size workload:

1. One untimed warm-up analysis runs before measurement.
2. Five timed analyses run with `time.perf_counter()`. `tracemalloc` is **off**
   during these runs so allocation tracing does not distort timing.
3. The finding count from each timed run is checked against the final value by
   the harness (`memory_findings == findings`).
4. One separate run starts `tracemalloc`, analyzes the same source, records
   `get_traced_memory()[1]` as peak bytes, and stops tracing.
5. Median, minimum, and maximum are calculated from the five timing
   repetitions. Peak bytes are converted to MiB using `1024 * 1024`.

The harness does not read or write source files during analysis; generation,
timing, and memory measurement all use in-memory strings.

---

## 5. Results

All values below are from the saved five-repetition run.

| Language | Size | Lines | Bytes | Findings | Median (s) | Min (s) | Max (s) | Peak MiB |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Python | small | 24 | 398 | 3 | 0.004550 | 0.004503 | 0.004745 | 0.211 |
| Python | medium | 186 | 3254 | 21 | 0.039624 | 0.039396 | 0.039923 | 1.710 |
| Python | large | 906 | 16054 | 101 | 0.293832 | 0.292315 | 0.308714 | 11.682 |
| JavaScript | small | 27 | 510 | 3 | 0.006308 | 0.006256 | 0.006363 | 0.228 |
| JavaScript | medium | 207 | 4122 | 21 | 0.055066 | 0.054713 | 0.056897 | 1.911 |
| JavaScript | large | 1007 | 20282 | 101 | 0.433720 | 0.399388 | 0.469808 | 12.208 |
| Java | small | 26 | 575 | 3 | 0.004945 | 0.004705 | 0.007642 | 0.266 |
| Java | medium | 170 | 3961 | 21 | 0.037600 | 0.036795 | 0.038436 | 1.701 |
| Java | large | 810 | 19081 | 101 | 0.236445 | 0.230167 | 0.259887 | 8.923 |

### Scaling

Ratios use median time and peak MiB from the table above.

| Language | Time medium/small | Time large/medium | Time large/small | Peak medium/small | Peak large/medium | Peak large/small | Large ms/line |
|---|---:|---:|---:|---:|---:|---:|---:|
| Python | 8.71x | 7.42x | 64.58x | 8.10x | 6.83x | 55.36x | 0.324 |
| JavaScript | 8.73x | 7.88x | 68.76x | 8.38x | 6.39x | 53.54x | 0.431 |
| Java | 7.60x | 6.29x | 47.81x | 6.39x | 5.25x | 33.55x | 0.292 |

Observations:

- Source size, generated functions, and findings increase several-fold between
  adjacent sizes (about 5-10x depending on metric and step), while median time
  increases about 6-9x. The measured workloads do not show pathological growth
  after the convergence fix.
- Java is fastest on the large workload in this generator (`0.236445 s`,
  `8.923 MiB` peak). JavaScript is slowest on the large workload
  (`0.433720 s`, `12.208 MiB` peak).
- Small-workload timings are under `0.007 s` and should be treated as
  indicative rather than precise; process and interpreter effects are visible
  relative to the large workloads.
- Peak allocations scale broadly with source size but are not a full resident
  set measurement.

---

## 6. Integrity notes

An earlier benchmark attempt was stopped at the harness timeout of `600000 ms`.
The cause was a taint fixpoint convergence bug: re-visiting source statements
could extend a path indefinitely, so the pass never stabilized. After adding
shortest-path deduplication and `_is_better_state()` comparisons in
`src/bugdhor_ast/flow/taint.py`, the same benchmark completed in the times
reported above. A regression test with twelve repeated helper calls was added
in `tests/test_flow_interprocedural.py` to keep this behavior bounded.

No result from the aborted run is included in this report or the saved JSON.

---

## 7. Limitations

- Results apply only to the generated sources and the recorded macOS/arm64,
  Python 3.11.14 environment. Different grammars, frameworks, file sizes, and
  rule packs will behave differently.
- `tracemalloc` reports Python allocations, not full process RSS. Native memory
  used by tree-sitter or the interpreter is not fully represented.
- Timing excludes `tracemalloc`, so timing and memory come from separate runs;
  they are not a single simultaneous measurement.
- Five repetitions are enough to show order-of-magnitude behavior but not a
  formal statistical comparison. The raw arrays are retained for inspection.
- Finding counts confirm taint work was performed, but do not validate finding
  correctness. Source-to-sink correctness is covered by the test suite and
  `reports/PHASE_4_TEST_REPORT.txt`.
- This benchmark does not compare against a Phase 3 baseline and makes no claim
  of speedup or regression relative to an earlier analyzer version.

---

## 8. Conclusion

The measured Phase 4 analyzer completes the small, medium, and large generated
workloads for all three languages. Median times range from `0.004550 s` to
`0.433720 s`, and peak Python allocations range from `0.211 MiB` to
`12.208 MiB` in this environment. These are reproducible performance facts for
the documented harness; they are not security-effectiveness evidence.
