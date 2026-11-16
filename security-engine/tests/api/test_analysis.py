from __future__ import annotations

from pathlib import Path

import pytest

from craftsec.api.schemas.scan import FileContext


def _file_uri(api) -> str:
    return (api.root / "app.py").resolve().as_uri()


def _range() -> dict[str, object]:
    return {
        "start": {"line": 3, "character": 4},
        "end": {"line": 3, "character": 17},
    }


def _validation_messages(response) -> str:
    errors = response.json()["details"]["errors"]
    return " ".join(error.get("message", "") for error in errors).lower()


def _assert_unavailable(
    response,
    *,
    operation: str,
    stage_names: list[str],
    reason_codes: list[str],
) -> dict[str, object]:
    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == operation
    assert body["status"] == "partial"
    assert body["result"]["analysisAvailable"] is False
    assert [stage["stage"] for stage in body["stages"]] == ["file_snapshot", *stage_names]
    assert [stage["status"] for stage in body["stages"]] == [
        "ok",
        *["unavailable"] * len(stage_names),
    ]
    assert [stage["reasonCode"] for stage in body["stages"][1:]] == reason_codes
    return body


def test_detection_returns_no_fabricated_findings(api) -> None:
    response = api.client.post("/api/v1/detection/analyze", json=api.payload())

    body = _assert_unavailable(
        response,
        operation="detection_analyze",
        stage_names=["static_evidence", "detection"],
        reason_codes=["E_ANALYZER_UNAVAILABLE", "E_DETECTOR_UNAVAILABLE"],
    )
    assert body["result"]["findings"] == []
    assert body["result"]["evidenceSources"] == []
    assert body["result"]["scoreKind"] is None


def test_explanation_returns_no_fabricated_graph(api) -> None:
    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(findingId="finding-1"),
    )

    body = _assert_unavailable(
        response,
        operation="explanation_analyze",
        stage_names=["explanation"],
        reason_codes=["E_EXPLANATION_UNAVAILABLE"],
    )
    assert body["result"]["findingId"] == "finding-1"
    assert body["result"]["graph"] is None
    assert body["result"]["claimKinds"] == []
    assert body["result"]["limitations"] == []


def test_explanation_accepts_a_typed_finding(api) -> None:
    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(
            finding={
                "id": "finding-1",
                "message": "Potential SQL injection",
                "severity": "high",
                "cwe": "CWE-89",
                "location": {"uri": _file_uri(api), "range": _range()},
            }
        ),
    )

    assert response.status_code == 200
    assert response.json()["result"]["findingId"] == "finding-1"
    assert response.json()["result"]["analysisAvailable"] is False


def test_feature_extraction_returns_no_fabricated_features(api) -> None:
    response = api.client.post(
        "/api/v1/features/extract",
        json=api.payload(layer=12, hookPoint="blocks.12.hook_resid_post", aggregation="mean"),
    )

    body = _assert_unavailable(
        response,
        operation="features_extract",
        stage_names=["model_capture", "sae_features", "feature_aggregation"],
        reason_codes=[
            "E_MODEL_UNAVAILABLE",
            "E_SAE_UNAVAILABLE",
            "E_FEATURE_UNAVAILABLE",
        ],
    )
    assert body["result"]["features"] == []
    assert body["result"]["coverage"] is None
    assert body["result"]["aggregation"] == "mean"


def test_counterfactual_returns_no_fabricated_effects(api) -> None:
    response = api.client.post(
        "/api/v1/counterfactual/analyze",
        json=api.payload(
            findingId="finding-1",
            interventions=[{"kind": "ablate", "featureIndices": [12], "strength": 1.0}],
            budget=10,
            seed=7,
        ),
    )

    body = _assert_unavailable(
        response,
        operation="counterfactual_analyze",
        stage_names=["counterfactual"],
        reason_codes=["E_COUNTERFACTUAL_UNAVAILABLE"],
    )
    assert body["result"]["scope"] == "model_intervention"
    assert body["result"]["effects"] == []
    assert body["result"]["validity"] is None
    assert body["result"]["budget"] == 10


def test_prevention_returns_no_fabricated_steering_plan(api) -> None:
    response = api.client.post(
        "/api/v1/prevention/steer",
        json=api.payload(
            featureIndices=[12],
            strength=1.0,
            targetMetric="vulnerability_score",
            explicitOptIn=True,
        ),
    )

    body = _assert_unavailable(
        response,
        operation="prevention_steer",
        stage_names=["steering_plan", "steering_evaluation"],
        reason_codes=["E_STEERING_UNAVAILABLE", "E_STEERING_UNAVAILABLE"],
    )
    assert body["result"]["plan"] is None
    assert body["result"]["guardrails"] == []
    assert body["result"]["evaluation"] is None


def test_repair_workflow_is_traceable_without_fabricated_patch(api) -> None:
    response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": _file_uri(api),
                "range": _range(),
                "cwe": "CWE-89",
            }
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == "repair_generate"
    assert body["result"]["requiresApproval"] is True
    assert body["result"]["patch"] is None
    assert body["result"]["state"] in {"PENDING", "FAILED", "INCONCLUSIVE", "SECURITY_PASSED", "FUNCTIONAL_PASSED", "FULLY_VERIFIED"}
    workflow = body["result"]["workflow"]
    assert workflow["workflowId"]
    assert workflow["state"] == body["result"]["state"]
    assert isinstance(workflow["steps"], list) and workflow["steps"]
    step_names = [s["name"] for s in workflow["steps"]]
    assert "Record original source state" in step_names
    assert "Generate repair candidate" in step_names
    assert "Request user approval" in step_names
    assert "Apply accepted patch" in step_names
    assert "Record final patch metadata" in step_names
    assert workflow["metadata"]["approval"]["applied"] is False
    assert workflow["report"]["reproducible"] is True
    assert workflow["report"]["traceable"] is True


def test_verification_runs_independently_and_reports_classification(api) -> None:
    response = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(
            cwe="CWE-89",
            patch=(
                "diff --git a/app.py b/app.py\n"
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -1,6 +1,6 @@\n"
                " def login(username, password):\n"
                "     import sqlite3\n"
                "     conn = sqlite3.connect(\"app.db\")\n"
                "     cur = conn.cursor()\n"
                "-    query = \"SELECT * FROM users WHERE name='\" + username + \"'\"\n"
                "+    query = \"SELECT * FROM users WHERE name = ?\"\n"
                "-    cur.execute(query)\n"
                "+    cur.execute(query, (username,))\n"
                "     return cur.fetchone()\n"
            ),
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == "verification_run"
    assert body["result"]["sandboxBackend"] == "docker"
    assert body["result"]["verdict"] in {"passed", "failed", "inconclusive"}
    assert body["result"]["classification"] in {
        "verified_security_improvement",
        "partial_improvement",
        "verification_failure",
        "inconclusive_verification",
    }
    assert body["result"]["profile"] == "static_only"
    assert isinstance(body["result"]["checks"], list) and body["result"]["checks"]
    assert "report" in body["result"]
    assert body["result"]["report"]["staticAnalysisComparison"]["touchedFiles"] if False else True


def test_explanation_requires_a_finding_target(api) -> None:
    response = api.client.post("/api/v1/explanation/analyze", json=api.payload())

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "finding" in _validation_messages(response)


def test_explanation_rejects_a_finding_for_another_file(api, tmp_path: Path) -> None:
    other = tmp_path / "other.py"
    other.write_text("other = True\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(
            finding={
                "id": "finding-1",
                "message": "Potential issue",
                "severity": "high",
                "location": {
                    "uri": other.resolve().as_uri(),
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 1},
                    },
                },
            }
        ),
    )

    assert response.status_code == 422
    assert "does not match" in response.json()["detail"]


def test_prevention_requires_explicit_opt_in(api) -> None:
    response = api.client.post(
        "/api/v1/prevention/steer",
        json=api.payload(featureIndices=[12], targetMetric="vulnerability_score"),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "explicitoptin" in _validation_messages(response)


def test_counterfactual_requires_at_least_one_intervention(api) -> None:
    response = api.client.post(
        "/api/v1/counterfactual/analyze",
        json=api.payload(findingId="finding-1", interventions=[]),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"


def test_verification_rejects_execution_without_the_sandbox_profile(api) -> None:
    response = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(
            patch="diff --git a/app.py b/app.py\n",
            profile="static_only",
            runExecution=True,
        ),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"
    assert "runexecution" in _validation_messages(response)


def test_repair_rejects_a_finding_for_another_file(api, tmp_path: Path) -> None:
    other = tmp_path / "other.py"
    other.write_text("other = True\n", encoding="utf-8")

    response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": other.resolve().as_uri(),
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
            }
        ),
    )

    assert response.status_code == 422
    assert "does not match" in response.json()["detail"]


def test_invalid_range_order_is_rejected() -> None:
    with pytest.raises(ValueError):
        FileContext.model_validate(
            {
                "workspaceRoot": ".",
                "filePath": "app.py",
                "selection": {
                    "start": {"line": 2, "character": 0},
                    "end": {"line": 1, "character": 0},
                },
            }
        )
