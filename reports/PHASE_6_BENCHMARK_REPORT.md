# Phase 6 Performance Benchmark Report — Bug-Dhor

**Project:** Bug-Dhor lightweight AST / static-analysis layer (`bugdhor_ast`)  
**Phase:** Phase 6 — evidence-based explanation, repair, and verification  
**Report file:** `reports/PHASE_6_BENCHMARK_REPORT.md`  
**Verification date:** 2026-11-19  
**Raw data:** `benchmarks/results/phase6-performance/results.json`  
**Harness:** `benchmarks/harness/run_phase6_performance.py`

---

## 1. Purpose and scope

This benchmark measures the execution time and `tracemalloc` peak allocation of
one complete **read-only** Phase 6 core workflow. It is a **performance
measurement only**. It does not measure security effectiveness, false-positive
rate, recall, repair quality, exploitability, or any coding-benchmark condition
E0–E7. The execution-based coding benchmark remains `not_run`, as documented in
`benchmarks/README.md`.

No source file was written and no source code was executed by the benchmark.

---

## 2. Environment and method

Recorded metadata:

- Python: `3.11.14`
- Platform: `macOS-26.3.1-arm64-arm-64bit`
- Processor: `arm`
- Timing repetitions per workload: `5`
- Sizes: `small=2` helper functions, `medium=10`, `large=40`
- Languages: Python, JavaScript, Java

Measured stages:

1. `build_analysis_payload`
2. `explain_finding`
3. `recommend_repair`
4. `build_patch`
5. `verify_repair`

Each generated workload contains one deterministic taint finding and a variable
number of benign helper functions. Timing runs exclude `tracemalloc`; peak
Python allocations were measured in a separate run of the same workflow. A
warm-up workflow ran before timed repetitions. Medians are computed from the
five recorded totals.

Reproduce with:

```bash
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase6_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase6-performance/results.json
```

---

## 3. Measured workflow results

| Language | Size | Lines | Bytes | Findings | Evidence | Recommendation | Verification | Median total (s) | Peak MiB |
|---|---|---:|---:|---:|---:|---|---|---:|---:|
| python | small | 9 | 176 | 3 | 12 | ready | failed | 0.005509 | 0.214 |
| python | medium | 33 | 521 | 3 | 12 | ready | failed | 0.015319 | 0.555 |
| python | large | 123 | 1871 | 3 | 12 | ready | failed | 0.064109 | 1.683 |
| javascript | small | 5 | 150 | 2 | 11 | ready | verified | 0.005621 | 0.197 |
| javascript | medium | 13 | 527 | 2 | 11 | ready | verified | 0.016440 | 0.535 |
| javascript | large | 43 | 1997 | 2 | 11 | ready | verified | 0.058990 | 1.754 |
| java | small | 8 | 287 | 1 | 24 | ready | verified | 0.009072 | 0.323 |
| java | medium | 16 | 672 | 1 | 24 | ready | verified | 0.020515 | 0.607 |
| java | large | 46 | 2172 | 1 | 24 | ready | verified | 0.065821 | 1.914 |

### Median stage seconds

| Language | Size | Analysis | Explain | Recommend | Patch | Verify |
|---|---|---:|---:|---:|---:|---:|
| python | small | 0.001907 | 0.000130 | 0.000079 | 0.000035 | 0.003366 |
| python | medium | 0.005482 | 0.000172 | 0.000123 | 0.000050 | 0.009485 |
| python | large | 0.022924 | 0.000337 | 0.000407 | 0.000157 | 0.040167 |
| javascript | small | 0.001989 | 0.000123 | 0.000026 | 0.000032 | 0.003450 |
| javascript | medium | 0.005925 | 0.000186 | 0.000036 | 0.000044 | 0.010279 |
| javascript | large | 0.021374 | 0.000325 | 0.000030 | 0.000055 | 0.037260 |
| java | small | 0.002839 | 0.000176 | 0.000048 | 0.000038 | 0.005970 |
| java | medium | 0.006894 | 0.000218 | 0.000043 | 0.000043 | 0.013287 |
| java | large | 0.023215 | 0.000379 | 0.000048 | 0.000061 | 0.042118 |

Raw per-repetition totals, minima, and maxima are retained in
`benchmarks/results/phase6-performance/results.json`.

---

## 4. Observations

- Median total workflow time ranged from `0.005509 s` (small Python) to
  `0.065821 s` (large Java).
- Peak `tracemalloc` allocation ranged from `0.197 MiB` (small JavaScript) to
  `1.914 MiB` (large Java).
- Verification was the dominant stage in all nine workloads; it reruns parse,
  detection, flow, and taint analysis rather than trusting the recommendation.
- Explanation, recommendation, and patch construction were sub-millisecond in
  every measured workload.
- Python repair candidates were `ready` but verification was `failed` for the
  generated Python SQL scenario in this harness. The additional Python process
  scenario in the repair-validation matrix also failed, for a different reason;
  both are reported explicitly in
  `reports/PHASE_6_REPAIR_VALIDATION_REPORT.md`. JavaScript and Java repair
  candidates were `verified` under the defined static checks.
- Peak memory is Python allocator tracing, not whole-process RSS.

---

## 5. Limitations

- Generated workloads are small and deterministic; they are not a representative
  corpus or a security benchmark.
- Only one finding per generated workload is repaired and verified.
- No functional tests, compiler checks, dynamic analysis, or repository-wide
  analysis were run.
- No throughput, latency percentile, or comparison claim is made beyond the
  recorded medians, minima, maxima, and peak allocations.
- The coding benchmark protocol in `benchmarks/configs/coding-benchmark-v1.json`
  remains unexecuted; its readiness bundle records `status: not_run`.

---

## 6. Relation to Phase 4

The Phase 4 benchmark measured `FlowEngine.analyze_source()` only. This Phase 6
benchmark measures a different pipeline: analysis payload assembly,
explanation, repair recommendation, patch construction, and independent
verification. The two result sets should not be compared as if they measured the
same operation.

Phase 4 raw data remains at `benchmarks/results/phase4-performance/results.json`
and its report remains `reports/PHASE_4_BENCHMARK_REPORT.md`.

---

## 7. Conclusion

The measured Phase 6 core workflow completed in milliseconds on the generated
small/medium/large workloads, with peak traced allocations below 2 MiB. These
are reproducibility and performance observations only. They do not establish
security effectiveness, repair correctness, or benchmark-condition results.
