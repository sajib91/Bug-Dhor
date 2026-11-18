"""Contract tests for the compatibility matrix runner."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNNER = (
    ROOT
    / "research"
    / "experiments"
    / "model_compatibility"
    / "run_compatibility_matrix.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("run_compatibility_matrix", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_declared_capabilities_are_not_observed_capabilities(tmp_path) -> None:
    runner = load_runner()
    config = {
        "schemaVersion": "1.0.0",
        "modelTargets": [
            {
                "targetId": "absent-registered",
                "runtime": "bugdhor_adapter",
                "name": "Absent",
                "checkpointIdentifier": "definitely-not-present/model",
                "revision": None,
                "declaredCapabilities": ["code_generation", "activation_extraction"],
            }
        ],
        "assistantTargets": [
            {
                "targetId": "assistant-editor",
                "providerKind": "editor",
                "label": "Editor",
                "declaredCapabilities": {"A": "supported"},
                "requiresHost": True,
                "requiresEnv": [],
            }
        ],
        "limitations": [],
    }

    report = runner.build_report(config, tmp_path)
    model = report.models[0]
    assistant = report.assistant_integrations[0]

    assert len(model.probes) == 10
    assert all(probe.status is runner.ProbeStatus.UNAVAILABLE for probe in model.probes)
    assert "checkpoint_not_present" in model.probes[0].reason
    assert model.activation_access is runner.ProbeStatus.UNAVAILABLE
    assert "activation_extraction" in model.declared_capabilities
    assert assistant.status is runner.ProbeStatus.UNAVAILABLE
    assert assistant.discovered_capabilities == ()
    assert assistant.declared_capabilities == {"A": "supported"}


def test_markdown_separates_declared_and_observed(tmp_path) -> None:
    runner = load_runner()
    config = {
        "schemaVersion": "1.0.0",
        "modelTargets": [
            {
                "targetId": "absent",
                "runtime": "unknown_runtime",
                "name": "Absent",
                "checkpointIdentifier": "org/model",
                "revision": None,
                "declaredCapabilities": ["code_generation"],
            }
        ],
        "assistantTargets": [],
        "limitations": ["LIM-ENV-01"],
    }
    report = runner.build_report(config, tmp_path)
    markdown = runner.render_markdown(report)
    assert "Declared capabilities are configuration, not evidence" in markdown
    assert "unsupported compatibility runtime" in markdown
    assert "LIM-ENV-01" in markdown
