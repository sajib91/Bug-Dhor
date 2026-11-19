from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from bugdhor.api.app import create_app
from bugdhor.core.orchestrator import Orchestrator
from bugdhor.core.pipeline import StageResult, StageStatus
from bugdhor.core.settings import Settings

EXPECTED_CAPABILITIES = {
    "scan_file",
    "scan_workspace",
    "detection_analyze",
    "explanation_analyze",
    "features_extract",
    "counterfactual_analyze",
    "prevention_steer",
    "repair_generate",
    "recommendation_generate",
    "verification_run",
}


class AvailableStage:
    available = True

    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, context: object) -> StageResult:
        del context
        return StageResult(stage=self.name, status=StageStatus.OK)


def test_health_reports_service_and_capabilities(api) -> None:
    response = api.client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "bugdhor-engine"
    assert body["status"] == "ok"
    assert body["version"]
    assert body["apiVersion"] == "v1"
    assert body["sandboxBackend"] == "docker"
    assert body["uptimeSeconds"] >= 0
    assert body["timestamp"].endswith("+00:00") or body["timestamp"].endswith("Z")
    assert set(body["capabilities"]) == EXPECTED_CAPABILITIES
    # Integrated local analysis/verification/repair interfaces are available; research/model stages
    # (SAE/counterfactual/steering) remain unavailable without runtime artifacts.
    assert body["capabilities"]["scan_file"] is True
    assert body["capabilities"]["scan_workspace"] is True
    assert body["capabilities"]["detection_analyze"] is True
    assert body["capabilities"]["explanation_analyze"] is True
    assert body["capabilities"]["repair_generate"] is True
    assert body["capabilities"]["recommendation_generate"] is True
    assert body["capabilities"]["verification_run"] is True
    assert body["capabilities"]["features_extract"] is False
    assert body["capabilities"]["counterfactual_analyze"] is False
    assert body["capabilities"]["prevention_steer"] is False


def test_health_reports_language_and_analyzer_capabilities_separately(api) -> None:
    response = api.client.get("/api/v1/health")

    assert response.status_code == 200
    report = response.json()["analysisCapabilities"]
    assert {item["language"] for item in report["languages"]} == {
        "python",
        "javascript",
        "typescript",
        "java",
        "c",
        "cpp",
        "php",
        "go",
        "rust",
        "csharp",
        "ruby",
        "kotlin",
        "swift",
    }
    assert set(report["installedParsers"]) == {"python", "javascript", "typescript"}
    assert report["programAnalysis"] == {
        "python": ["cfg", "dfg", "taint"],
        "javascript": ["cfg", "dfg", "taint"],
    }
    assert {item["tool"] for item in report["staticTools"]} == {
        "semgrep",
        "bandit",
        "codeql",
        "joern",
    }
    assert all(item["adapterAvailable"] is False for item in report["linterTypeCheckers"])
    assert report["dependencyVulnerabilityChecks"]["automated"] is True
    assert report["generalBugs"]["enabledByDefault"] is False
    assert "wired paths" in report["note"]


def test_health_reflects_integrated_and_stage_capabilities(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, workspace_roots=[tmp_path], log_level="ERROR")
    stages = {
        "static_evidence": AvailableStage("static_evidence"),
        "detection": AvailableStage("detection"),
    }
    app = create_app(settings, Orchestrator(settings, stages))

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    capabilities = response.json()["capabilities"]
    assert capabilities["scan_file"] is True
    assert capabilities["scan_workspace"] is True
    assert capabilities["detection_analyze"] is True
    assert capabilities["explanation_analyze"] is True
    assert capabilities["features_extract"] is False
    assert capabilities["verification_run"] is True
    assert capabilities["repair_generate"] is True
    assert capabilities["recommendation_generate"] is True


def test_health_never_contains_configured_secret(tmp_path: Path) -> None:
    token = "local-test-token-value"
    settings = Settings(
        _env_file=None,
        workspace_roots=[tmp_path],
        log_level="ERROR",
        api_token=token,
    )
    app = create_app(settings)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(
            "/api/v1/health",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert token not in response.text
    assert "apiToken" not in response.text
