"""Emit a reproducible, non-fabricated coding-benchmark bundle.

This harness intentionally does not invent model generations, detector findings,
repairs, or verification evidence. It validates the pinned task/config contract
and writes a complete bundle whose per-task and per-condition outcomes are
``not_run`` until a host registers real providers, analyzers, and a sandbox.

Run from the repository root::

    .venv/bin/python benchmarks/harness/run_coding_benchmark.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "benchmarks" / "configs" / "coding-benchmark-v1.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "results" / "coding-benchmark-v1-readiness"
METRIC_NAMES = (
    "vulnerability_detection_precision",
    "vulnerability_detection_recall",
    "false_positive_rate",
    "cwe_classification_accuracy",
    "vulnerability_localization_exact_match",
    "vulnerability_localization_line_precision",
    "vulnerability_localization_line_recall",
    "verified_repair_success_rate",
    "functional_test_pass_rate",
    "security_regression_rate",
    "analysis_latency_ms",
    "computational_overhead_ms",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _strip_private(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_private(item)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, list):
        return [_strip_private(item) for item in value]
    return value


def canonical_hash(payload: Any) -> str:
    """Stable hash matching the repository's canonical-JSON convention."""
    cleaned = _strip_private(payload)
    encoded = json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:  # noqa: BLE001 - provenance must not abort a benchmark run
        return None


def validate_tasks(config: dict[str, Any], task_paths: list[Path]) -> list[str]:
    """Check the contract without ever passing ground truth into a prompt."""
    issues: list[str] = []
    seen_ids: set[str] = set()
    seen_scenarios: set[str] = set()
    for path in task_paths:
        task = load_json(path)
        task_id = task.get("taskId")
        scenario = task.get("scenario")
        prompt = task.get("prompt")
        ground_truth = task.get("groundTruth")
        if not isinstance(task_id, str) or not task_id.strip():
            issues.append(f"{path.name}: missing taskId")
            continue
        if task_id in seen_ids:
            issues.append(f"{path.name}: duplicate taskId {task_id}")
        seen_ids.add(task_id)
        if isinstance(scenario, str):
            if scenario in seen_scenarios:
                issues.append(f"{path.name}: duplicate scenario {scenario}")
            seen_scenarios.add(scenario)
        else:
            issues.append(f"{path.name}: missing scenario")
        if not isinstance(prompt, str) or not prompt.strip():
            issues.append(f"{path.name}: missing prompt")
        if not isinstance(ground_truth, dict):
            issues.append(f"{path.name}: missing groundTruth")
            continue
        cwes = ground_truth.get("cweIds")
        if not isinstance(cwes, list) or not cwes:
            issues.append(f"{path.name}: groundTruth.cweIds must be a non-empty list")
        elif any(not isinstance(cwe, str) or not cwe.startswith("CWE-") for cwe in cwes):
            issues.append(f"{path.name}: groundTruth.cweIds contains a non-CWE value")
        forbidden = ground_truth.get("forbiddenPromptTerms")
        if not isinstance(forbidden, list) or not forbidden:
            issues.append(f"{path.name}: groundTruth.forbiddenPromptTerms must be non-empty")
            continue
        if isinstance(prompt, str):
            lowered = prompt.casefold()
            leaked = [term for term in forbidden if str(term).casefold() in lowered]
            if leaked:
                issues.append(f"{path.name}: prompt leaks ground-truth terms: {leaked}")
        if not task.get("repositorySnapshot", {}).get("testCommand"):
            issues.append(f"{path.name}: missing repositorySnapshot.testCommand")
    expected = config.get("tasks", [])
    if len(expected) != len(task_paths):
        issues.append("config task count does not match the loaded task files")
    return issues


def validate_dataset_card(
    config: dict[str, Any], task_hashes: dict[str, str], config_dir: Path
) -> list[str]:
    """Verify that the dataset card hash matches the pinned task bundle."""
    card_path = (config_dir / config["datasetCard"]).resolve()
    if not card_path.is_file():
        return [f"missing dataset card: {card_path}"]
    card = load_json(card_path)
    issues: list[str] = []
    if card.get("datasetId") != "coding-tasks-v1":
        issues.append("unexpected datasetId in dataset card")
    computed = canonical_hash(task_hashes)
    if card.get("splitHash") != computed:
        issues.append("dataset card splitHash does not match pinned task hashes")
    if list(card.get("taskIds", [])) != list(task_hashes):
        issues.append("dataset card taskIds do not match config task order")
    return issues


def detect_prerequisites(config: dict[str, Any], config_hash: str) -> dict[str, Any]:
    """Report only observable prerequisites; never infer availability."""
    runtime = config.get("runtime", {})
    missing_model_env = [
        name
        for name in runtime.get("providerConfiguredByEnv", [])
        if not os.environ.get(name)
    ]
    missing_sandbox_env = [
        name
        for name in runtime.get("sandboxConfiguredByEnv", [])
        if not os.environ.get(name)
    ]
    reasons: list[str] = []
    if missing_model_env:
        reasons.append(
            "model provider not configured: missing " + ", ".join(missing_model_env)
        )
    if config.get("modelBinding", {}).get("resolvedRevision") is None:
        reasons.append("modelBinding.resolvedRevision is null; exact model version unrecorded")
    if missing_sandbox_env:
        reasons.append(
            "sandbox not configured: missing " + ", ".join(missing_sandbox_env)
        )
    if config.get("analyzers", {}).get("rulePackHash") is None:
        reasons.append("analyzers.rulePackHash is null; detector rule pack is unpinned")
    if runtime.get("executor") == "registered_by_host":
        reasons.append("no benchmark executor registered by the host")
    return {
        "status": "not_run" if reasons else "ready",
        "configHash": config_hash,
        "providerEnvVarsChecked": runtime.get("providerConfiguredByEnv", []),
        "sandboxEnvVarsChecked": runtime.get("sandboxConfiguredByEnv", []),
        "missingEnvVarNames": missing_model_env + missing_sandbox_env,
        "reasons": reasons,
        "note": "Environment variable values are never read into reports, only presence.",
    }


def null_metrics(names: list[str] | tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {name: {"value": None, "measured": False, "reason": "not_run"} for name in names}


def build_result(
    config: dict[str, Any],
    tasks: list[dict[str, Any]],
    config_hash: str,
    task_hashes: dict[str, str],
    prerequisites: dict[str, Any],
) -> dict[str, Any]:
    metric_names = tuple(config.get("metrics", METRIC_NAMES))
    conditions = [
        {
            "conditionId": condition["id"],
            "name": condition["name"],
            "experimentGroup": condition["experimentGroup"],
            "features": condition["features"],
            "status": "not_run",
            "trialResults": [],
            "metrics": null_metrics(metric_names),
        }
        for condition in config.get("conditions", [])
    ]
    task_records = [
        {
            "taskId": task["taskId"],
            "scenario": task["scenario"],
            "taskHash": task_hashes[task["taskId"]],
            "status": "not_run",
            "originalPromptRef": f"raw/prompts.jsonl#{task['taskId']}",
            "originalGeneratedCodeRef": None,
            "detectionRef": None,
            "repairRef": None,
            "verificationRef": None,
            "finalResult": None,
        }
        for task in tasks
    ]
    return {
        "schemaVersion": "1.0.0",
        "runStatus": "not_run",
        "claimKind": None,
        "scope": (
            "Benchmark definition and prerequisite audit only. No model generation, "
            "Bug Dhor detection, repair, or independent verification was executed."
        ),
        "configHash": config_hash,
        "model": {
            **config.get("modelBinding", {}),
            "used": False,
            "runtimeMetadata": None,
        },
        "controls": config.get("controls", {}),
        "prerequisites": prerequisites,
        "conditions": conditions,
        "tasks": task_records,
        "limitations": [
            "LIM-VER-01: no sandbox-backed verification was run",
            "LIM-VER-02: no analyzer findings were produced",
            "LIM-REP-01: no repair proposals were generated or reviewed",
            "LIM-REPRO-01: model nondeterminism was not measured",
        ],
        "evidenceRequirements": config.get("evidenceRequirements", []),
        "rawOutputPaths": [
            "raw/prompts.jsonl",
            "raw/generations.jsonl",
            "raw/detections.jsonl",
            "raw/repairs.jsonl",
            "raw/verification.jsonl",
        ],
    }


def write_bundle(
    output: Path,
    config: dict[str, Any],
    config_hash: str,
    tasks: list[dict[str, Any]],
    task_hashes: dict[str, str],
    prerequisites: dict[str, Any],
    issues: list[str],
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    (output / "raw").mkdir(exist_ok=True)
    (output / "tasks").mkdir(exist_ok=True)

    result = build_result(config, tasks, config_hash, task_hashes, prerequisites)
    manifest = {
        "runId": f"coding-benchmark-{config_hash[:12]}",
        "name": config.get("name"),
        "status": prerequisites["status"],
        "createdAt": utc_now(),
        "configHash": config_hash,
        "gitCommit": git_commit(),
        "environment": {
            "pythonVersion": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "model": config.get("modelBinding", {}),
        "toolVersions": {
            "benchmarkConfigVersion": config.get("version"),
            "detector": config.get("analyzers", {}).get("detector"),
            "detectorVersion": config.get("analyzers", {}).get("detectorVersion"),
        },
        "taskHashes": task_hashes,
        "contractIssues": issues,
        "prerequisites": prerequisites,
        "rawOutputs": result["rawOutputPaths"],
        "resultFile": "results.json",
    }

    def dump(name: str, payload: Any) -> None:
        with (output / name).open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")

    dump("config.json", config)
    dump("manifest.json", manifest)
    dump("results.json", result)
    dump("tasks/catalog.json", {"tasks": tasks, "taskHashes": task_hashes})

    prompts = output / "raw" / "prompts.jsonl"
    with prompts.open("w", encoding="utf-8") as handle:
        for task in tasks:
            # Ground truth is deliberately excluded from the prompt record.
            record = {
                "taskId": task["taskId"],
                "prompt": task["prompt"],
                "conditions": [condition["id"] for condition in config.get("conditions", [])],
            }
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    for name in ("generations", "detections", "repairs", "verification"):
        (output / "raw" / f"{name}.jsonl").write_text("", encoding="utf-8")

    readme = """# Coding benchmark readiness bundle

This bundle was generated by `benchmarks/harness/run_coding_benchmark.py`.

`status` is `not_run`. That is a measured fact about this execution: no model
provider, analyzer rule pack, repair run, sandbox, or independent verifier was
configured with sufficient evidence. All metric values are `null` and
`measured` is `false`.

No generated code, detector finding, repair, or verification result is included.
See `manifest.json` for the exact prerequisite reasons and `results.json` for the
declared conditions, tasks, and metrics.

This is not a benchmark result and must not be used to claim that Bug Dhor
improves, degrades, or leaves unchanged the security of AI-generated code.
"""
    (output / "README.md").write_text(readme, encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    config = load_json(args.config)
    config_hash = canonical_hash(config)
    tasks_dir = args.config.parent.parent / "tasks"
    task_paths = [tasks_dir / name for name in config.get("tasks", [])]
    missing = [str(path) for path in task_paths if not path.is_file()]
    if missing:
        raise SystemExit("Missing task files: " + ", ".join(missing))

    tasks = [load_json(path) for path in task_paths]
    task_hashes = {
        task["taskId"]: canonical_hash(task)
        for task, path in zip(tasks, task_paths, strict=True)
    }
    issues = validate_tasks(config, task_paths)
    issues.extend(validate_dataset_card(config, task_hashes, args.config.parent))
    prerequisites = detect_prerequisites(config, config_hash)
    manifest = write_bundle(
        args.output, config, config_hash, tasks, task_hashes, prerequisites, issues
    )
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "configHash": config_hash,
                "contractIssues": issues,
                "reasons": prerequisites["reasons"],
                "output": str(args.output),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
