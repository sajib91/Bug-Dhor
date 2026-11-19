"""Reproducible Phase 4 flow-analysis performance benchmark.

Run from the repository root:

    PYTHONPATH=src ./.venv/bin/python \
        benchmarks/harness/run_phase4_performance.py \
        --output benchmarks/results/phase4-performance/results.json

The benchmark generates deterministic Python, JavaScript, and Java sources
at three sizes. Timing runs exclude tracemalloc; a separate tracemalloc run
records peak Python allocations for the same source.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import tracemalloc

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bugdhor_ast.flow import FlowEngine  # noqa: E402


SIZES = {"small": 2, "medium": 20, "large": 100}


def generate_source(language: str, function_count: int) -> str:
    if language == "python":
        lines = ["def outer(data):", "    total = data", "    eval(total)", ""]
        for index in range(function_count):
            lines.extend(
                [
                    f"def flow_{index}(data):",
                    "    value = data",
                    "    total = 'p-' + value",
                    "    eval(total)",
                    "    safe = int(value)",
                    "    eval(safe)",
                    "    return total",
                    "",
                ]
            )
        lines.append("source = input()")
        for index in range(function_count):
            lines.append(f"result_{index} = flow_{index}(source)")
        lines.append("outer(result_0)")
        return "\n".join(lines) + "\n"

    if language == "javascript":
        lines = [
            "function outer(data) {",
            "  const total = data;",
            "  eval(total);",
            "}",
            "",
        ]
        for index in range(function_count):
            lines.extend(
                [
                    f"function flow_{index}(data) {{",
                    "  const value = data;",
                    "  const total = 'p-' + value;",
                    "  eval(total);",
                    "  const safe = encodeURIComponent(value);",
                    "  eval(safe);",
                    "  return total;",
                    "}",
                    "",
                ]
            )
        lines.append("const source = prompt('value');")
        for index in range(function_count):
            lines.append(f"const result_{index} = flow_{index}(source);")
        lines.append("outer(result_0);")
        return "\n".join(lines) + "\n"

    if language == "java":
        lines = ["class Bench {"]
        lines.extend(
            [
                "  void outer(String data) {",
                "    String total = data;",
                "    eval(total);",
                "  }",
            ]
        )
        for index in range(function_count):
            lines.extend(
                [
                    f"  void flow_{index}(String data) {{",
                    "    String value = data;",
                    '    String total = "p-" + value;',
                    "    eval(total);",
                    "    String safe = Integer.parseInt(value);",
                    "    eval(safe);",
                    "  }",
                ]
            )
        lines.extend(
            [
                "  void run(HttpServletRequest request) {",
                '    String source = request.getParameter("q");',
            ]
        )
        for index in range(function_count):
            lines.append(f"    flow_{index}(source);")
        lines.extend(
            [
                "    outer(source);",
                "  }",
                "}",
            ]
        )
        return "\n".join(lines) + "\n"

    raise ValueError(f"Unsupported language: {language}")


def measure(
    source: str,
    language: str,
    repeats: int,
) -> dict[str, object]:
    FlowEngine().analyze_source(source, language)

    timings: list[float] = []
    findings = 0
    for _ in range(repeats):
        start = time.perf_counter()
        result = FlowEngine().analyze_source(source, language)
        timings.append(time.perf_counter() - start)
        findings = len(result.taint_analysis.findings)

    tracemalloc.start()
    memory_result = FlowEngine().analyze_source(source, language)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    memory_findings = len(memory_result.taint_analysis.findings)
    assert memory_findings == findings

    return {
        "lines": source.count("\n"),
        "source_bytes": len(source.encode("utf-8")),
        "findings": findings,
        "timings_seconds": [round(value, 6) for value in timings],
        "median_seconds": round(statistics.median(timings), 6),
        "min_seconds": round(min(timings), 6),
        "max_seconds": round(max(timings), 6),
        "peak_mib": round(peak_bytes / (1024 * 1024), 3),
    }


def markdown(rows: list[dict[str, object]], repeats: int) -> str:
    lines = [
        "| Language | Size | Lines | Bytes | Findings | Median (s) | Min (s) | Max (s) | Peak MiB |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {language} | {size} | {lines} | {source_bytes} | "
            "{findings} | {median_seconds:.6f} | {min_seconds:.6f} | "
            "{max_seconds:.6f} | {peak_mib:.3f} |".format(**row)
        )
    lines.append("")
    lines.append(f"Timing repetitions per workload: {repeats}.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "benchmarks/results/phase4-performance/results.json",
    )
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    rows: list[dict[str, object]] = []
    for language in ("python", "javascript", "java"):
        for size, function_count in SIZES.items():
            source = generate_source(language, function_count)
            row = measure(source, language, args.repeats)
            row.update(
                {
                    "language": language,
                    "size": size,
                    "functions": function_count,
                }
            )
            rows.append(row)

    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "repeats": args.repeats,
        "sizes": SIZES,
        "method": (
            "FlowEngine.analyze_source on generated sources; timing "
            "excludes tracemalloc, peak memory measured separately."
        ),
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(markdown(rows, args.repeats))
    print(f"\nSaved raw results to: {args.output}")


if __name__ == "__main__":
    main()
