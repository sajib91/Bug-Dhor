"""Contract tests for the non-fabricating coding benchmark harness."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / "benchmarks" / "harness" / "run_coding_benchmark.py"
CONFIG = ROOT / "benchmarks" / "configs" / "coding-benchmark-v1.json"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("run_coding_benchmark", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pinned_config_and_tasks_are_valid(harness) -> None:
    config = harness.load_json(CONFIG)
    tasks_dir = CONFIG.parent.parent / "tasks"
    task_paths = [tasks_dir / name for name in config["tasks"]]
    tasks = [harness.load_json(path) for path in task_paths]

    assert len(tasks) == 10
    assert len({task["scenario"] for task in tasks}) == 10
    assert harness.validate_tasks(config, task_paths) == []
    assert {condition["id"] for condition in config["conditions"]} == {
        "E0",
        "E1",
        "E2",
        "E3",
        "E4",
        "E5",
        "E6",
        "E7",
    }
    assert config["conditions"][-1]["experimentGroup"] == "E8"


def test_config_hash_ignores_documentation_keys(harness) -> None:
    config = harness.load_json(CONFIG)
    original = harness.canonical_hash(config)
    cloned = json.loads(json.dumps(config))
    cloned["_documentation"]["purpose"] = "changed documentation"
    assert harness.canonical_hash(cloned) == original
    cloned["controls"]["trials"] = 4
    assert harness.canonical_hash(cloned) != original


def test_prompt_leakage_is_rejected(harness, tmp_path: Path) -> None:
    config = harness.load_json(CONFIG)
    task = harness.load_json(CONFIG.parent.parent / "tasks" / config["tasks"][2])
    task["prompt"] += " Avoid SQL injection."
    path = tmp_path / "leaky.json"
    path.write_text(json.dumps(task), encoding="utf-8")
    issues = harness.validate_tasks(config, [path])
    assert any("leaks ground-truth terms" in issue for issue in issues)


def test_ready_bundle_records_only_not_run_outcomes(harness, tmp_path: Path) -> None:
    config = harness.load_json(CONFIG)
    tasks_dir = CONFIG.parent.parent / "tasks"
    task_paths = [tasks_dir / name for name in config["tasks"]]
    tasks = [harness.load_json(path) for path in task_paths]
    task_hashes = {task["taskId"]: harness.canonical_hash(task) for task in tasks}
    config_hash = harness.canonical_hash(config)
    prerequisites = harness.detect_prerequisites(config, config_hash)

    manifest = harness.write_bundle(
        tmp_path / "bundle",
        config,
        config_hash,
        tasks,
        task_hashes,
        prerequisites,
        [],
    )
    result = json.loads((tmp_path / "bundle" / "results.json").read_text(encoding="utf-8"))

    assert manifest["status"] == "not_run"
    assert result["runStatus"] == "not_run"
    assert result["claimKind"] is None
    assert result["model"]["used"] is False
    assert all(condition["status"] == "not_run" for condition in result["conditions"])
    assert all(task["status"] == "not_run" for task in result["tasks"])
    for condition in result["conditions"]:
        assert all(metric["value"] is None for metric in condition["metrics"].values())
        assert all(not metric["measured"] for metric in condition["metrics"].values())
    assert (tmp_path / "bundle" / "raw" / "generations.jsonl").read_text(
        encoding="utf-8"
    ) == ""
    assert "must not be used to claim" in (
        tmp_path / "bundle" / "README.md"
    ).read_text(encoding="utf-8")
