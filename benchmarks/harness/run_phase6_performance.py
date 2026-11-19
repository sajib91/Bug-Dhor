"""Reproducible Phase 6 explanation, repair, and verification benchmark.

Run from the repository root:

    PYTHONPATH=src ./.venv/bin/python \
        benchmarks/harness/run_phase6_performance.py \
        --repeats 5 \
        --output benchmarks/results/phase6-performance/results.json

The benchmark uses deterministic in-memory sources. Timing runs exclude
tracemalloc; a separate tracemalloc run records peak Python allocations for the
same workflow. No source file is modified or executed.
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

from bugdhor_ast.explain import (
    explain_finding,
    recommend_repair,
    verify_repair,
)
from bugdhor_ast.explain.repair import build_patch, replace_span_text
from bugdhor_ast.phase6.service import build_analysis_payload

SIZES = {"small": 2, "medium": 10, "large": 40}
FILES = {
    "python": "sample.py",
    "javascript": "sample.js",
    "java": "Sample.java",
}


def generate_source(language: str, helper_count: int) -> str:
    """Build a source with one deterministic taint finding and benign helpers."""

    if language == "python":
        lines = [
            "q = request.args.get('q')",
            "cursor.execute(\"SELECT * FROM users WHERE name = '\" + q + \"'\")",
            "",
        ]
        for index in range(helper_count):
            lines.extend(
                [
                    f"def helper_{index}(value):",
                    f"    return value + {index + 1}",
                    "",
                ]
            )
        return "\n".join(lines) + "\n"

    if language == "javascript":
        lines = [
            "const q = req.query.user;",
            "document.body.innerHTML = q;",
            "",
        ]
        for index in range(helper_count):
            lines.append(
                f"function helper_{index}(value) {{ return value + {index + 1}; }}"
            )
        return "\n".join(lines) + "\n"

    if language == "java":
        lines = [
            "class Sample {",
            "  void run(HttpServletRequest request, Statement stmt) {",
            '    String q = request.getParameter("q");',
            "    stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + q + \"'\");",
            "  }",
        ]
        for index in range(helper_count):
            lines.append(
                f"  int helper_{index}(int value) {{ return value + {index + 1}; }}"
            )
        lines.append("}")
        return "\n".join(lines) + "\n"

    raise ValueError(f"Unsupported language: {language}")


def _finding(analysis: dict) -> dict:
    finding = next(
        (item for item in analysis["diagnostics"] if item["rule_id"].endswith("-TAINT001")),
        None,
    )
    if finding is None:
        raise RuntimeError("The generated workload did not produce a taint finding.")
    return finding


def _modified_source(source: str, patch) -> str:
    if patch is None:
        return source
    modified = source
    for edit in sorted(
        patch.edits,
        key=lambda item: (item.start_line, item.start_column),
        reverse=True,
    ):
        modified = replace_span_text(modified, edit, edit.proposed_code)
    return modified


def workflow(source: str, language: str, file: str) -> dict:
    """Run one complete read-only Phase 6 workflow and return its artifacts."""

    started = time.perf_counter()
    analysis = build_analysis_payload(source, language, file)
    analysis_seconds = time.perf_counter() - started
    finding = _finding(analysis)

    started = time.perf_counter()
    explanation = explain_finding(finding, analysis)
    explanation_payload = explanation.to_dict()
    explain_seconds = time.perf_counter() - started

    started = time.perf_counter()
    recommendation = recommend_repair(
        finding,
        analysis,
        explanation,
        source_code=source,
        file=file,
    )
    recommendation_payload = recommendation.to_dict()
    recommend_seconds = time.perf_counter() - started

    started = time.perf_counter()
    patch = None
    patch_payload = None
    if recommendation.status.value == "ready":
        patch = build_patch(recommendation, source, file=file)
        patch_payload = patch.to_dict()
    patch_seconds = time.perf_counter() - started

    started = time.perf_counter()
    verification = verify_repair(
        finding,
        _modified_source(source, patch),
        source_before=source,
        patch=patch,
        file=file,
        language=language,
    )
    verification_payload = verification.to_dict()
    verify_seconds = time.perf_counter() - started

    return {
        "timings": {
            "analysis": analysis_seconds,
            "explain": explain_seconds,
            "recommend": recommend_seconds,
            "patch": patch_seconds,
            "verify": verify_seconds,
            "total": (
                analysis_seconds
                + explain_seconds
                + recommend_seconds
                + patch_seconds
                + verify_seconds
            ),
        },
        "diagnostic_count": len(analysis["diagnostics"]),
        "evidence_count": sum(
            len(records) for records in explanation_payload["evidence"].values()
        ),
        "recommendation_status": recommendation_payload["status"],
        "strategy": recommendation_payload["strategy"],
        "patch_id": patch_payload["patch_id"] if patch_payload else None,
        "verification_status": verification_payload["status"],
        "verification_checks": len(verification_payload["checks"]),
    }


def measure(source: str, language: str, file: str, repeats: int) -> dict:
    workflow(source, language, file)

    runs: list[dict] = []
    for _ in range(repeats):
        runs.append(workflow(source, language, file))

    tracemalloc.start()
    workflow(source, language, file)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    keys = ("analysis", "explain", "recommend", "patch", "verify", "total")
    medians = {
        key: round(
            statistics.median([run["timings"][key] for run in runs]),
            6,
        )
        for key in keys
    }
    minima = {
        key: round(min(run["timings"][key] for run in runs), 6)
        for key in keys
    }
    maxima = {
        key: round(max(run["timings"][key] for run in runs), 6)
        for key in keys
    }
    final = runs[-1]
    return {
        "lines": source.count("\n"),
        "source_bytes": len(source.encode("utf-8")),
        "diagnostic_count": final["diagnostic_count"],
        "evidence_count": final["evidence_count"],
        "recommendation_status": final["recommendation_status"],
        "strategy": final["strategy"],
        "patch_id": final["patch_id"],
        "verification_status": final["verification_status"],
        "verification_checks": final["verification_checks"],
        "median_seconds": medians,
        "min_seconds": minima,
        "max_seconds": maxima,
        "peak_mib": round(peak_bytes / (1024 * 1024), 3),
        "raw_total_seconds": [round(run["timings"]["total"], 6) for run in runs],
    }


def markdown(rows: list[dict], repeats: int) -> str:
    lines = [
        "| Language | Size | Lines | Bytes | Findings | Evidence | Recommendation | Verification | Median total (s) | Peak MiB |",
        "|---|---|---:|---:|---:|---:|---|---|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {language} | {size} | {lines} | {source_bytes} | {diagnostic_count} | "
            "{evidence_count} | {recommendation_status} | {verification_status} | "
            "{median_total:.6f} | {peak_mib:.3f} |".format(
                median_total=row["median_seconds"]["total"], **row
            )
        )
    lines.extend(
        [
            "",
            f"Timing repetitions per workload: {repeats}.",
            "",
            "Median stage seconds (analysis / explain / recommend / patch / verify):",
            "",
            "| Language | Size | Analysis | Explain | Recommend | Patch | Verify |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows:
        medians = row["median_seconds"]
        lines.append(
            "| {language} | {size} | {analysis:.6f} | {explain:.6f} | "
            "{recommend:.6f} | {patch:.6f} | {verify:.6f} |".format(
                language=row["language"], size=row["size"], **medians
            )
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "benchmarks/results/phase6-performance/results.json",
    )
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    rows: list[dict] = []
    for language in ("python", "javascript", "java"):
        for size, helper_count in SIZES.items():
            source = generate_source(language, helper_count)
            row = measure(source, language, FILES[language], args.repeats)
            row.update({"language": language, "size": size, "helpers": helper_count})
            rows.append(row)

    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "repeats": args.repeats,
        "sizes": SIZES,
        "method": (
            "Phase 6 core workflow on generated sources; timing excludes "
            "tracemalloc, peak memory measured separately; no source writes."
        ),
        "stages": [
            "build_analysis_payload",
            "explain_finding",
            "recommend_repair",
            "build_patch",
            "verify_repair",
        ],
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(markdown(rows, args.repeats))
    print(f"\nSaved raw results to: {args.output}")


if __name__ == "__main__":
    main()
