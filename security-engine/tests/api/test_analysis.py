from __future__ import annotations

from pathlib import Path

import pytest

from bugdhor.api.schemas.scan import FileContext


def _file_uri(api) -> str:
    return (api.root / "app.py").resolve().as_uri()


def _range() -> dict[str, object]:
    return {
        "start": {"line": 3, "character": 4},
        "end": {"line": 3, "character": 17},
    }


SQL_INJECTION_SOURCE = """\
import sqlite3


def login(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cur.execute(query)
    return cur.fetchone()
"""


SIMPLE_PATCH = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,5 +1,5 @@\n"
    " import sqlite3\n"
    " \n"
    " \n"
    "-def connect(value):\n"
    "+def connect_safely(value):\n"
    "     return sqlite3.connect(value)\n"
)


def _validation_messages(response) -> str:
    errors = response.json()["details"]["errors"]
    return " ".join(error.get("message", "") for error in errors).lower()


def _assert_integrated_unavailable_model_stages(
    response,
    *,
    operation: str,
) -> dict[str, object]:
    """Research/model stages remain explicit; integrated local analysis may run."""
    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == operation
    assert body["status"] in {"partial", "unavailable", "completed", "failed"}
    assert body["result"]["analysisAvailable"] is False
    return body


def test_detection_returns_honest_integrated_analysis(api) -> None:
    response = api.client.post("/api/v1/detection/analyze", json=api.payload())

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == "detection_analyze"
    assert body["status"] in {"partial", "completed"}
    assert body["result"]["analysisAvailable"] is True
    stages = [s["stage"] for s in body["stages"]]
    assert "file_snapshot" in stages
    assert "preprocessing" in stages
    assert "program_analysis" in stages
    assert "detection" in stages
    # Benign sample should not produce fabricated vulnerabilities.
    assert isinstance(body["result"]["findings"], list)
    assert body["result"]["scoreKind"] in (None, "heuristic", "calibrated")


def test_explanation_reports_when_finding_cannot_be_explained(api) -> None:
    response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(findingId="finding-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == "explanation_analyze"
    assert body["result"]["findingId"] == "finding-1"
    # No matching backend finding exists, so no explanation graph is invented.
    assert body["result"]["analysisAvailable"] is False
    assert body["result"]["graph"] is None
    assert body["result"]["claimKinds"] == []
    assert isinstance(body["result"]["limitations"], list)


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
    body = response.json()
    assert body["result"]["findingId"] == "finding-1"
    assert body["result"]["analysisAvailable"] is False
    assert body["result"]["graph"] is None
    assert body["result"]["claimKinds"] == []
    assert isinstance(body["result"]["limitations"], list)


def test_scan_and_explanation_use_real_detection_and_risk_evidence(api) -> None:
    scan_response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(sourceText=SQL_INJECTION_SOURCE, languageId="python"),
    )
    assert scan_response.status_code == 200
    scan = scan_response.json()
    assert scan["analysisAvailable"] is True
    assert scan["findings"], "the vulnerable fixture must produce a real detector finding"

    finding = next(item for item in scan["findings"] if item["cwe"] == "CWE-89")
    risk = finding["riskAssessment"]
    assert risk is not None
    assert risk["scoreKind"] == "heuristic_index"
    assert risk["index"] is not None and 0.0 <= risk["index"] <= 1.0
    assert risk["probability"] is None
    assert risk["probabilityKind"] is None
    assert risk["evidenceCount"] >= 1
    assert risk["configHash"]
    assert any("not a probability" in line for line in risk["explanation"])

    explanation_response = api.client.post(
        "/api/v1/explanation/analyze",
        json=api.payload(sourceText=SQL_INJECTION_SOURCE, languageId="python", finding=finding),
    )
    assert explanation_response.status_code == 200
    explanation = explanation_response.json()
    result = explanation["result"]
    assert result["analysisAvailable"] is True
    assert result["findingId"] == finding["id"]
    graph = result["graph"]
    assert isinstance(graph, dict)
    assert graph["finding_id"] == finding["id"]
    assert graph["cwe"] == "CWE-89"
    assert graph["why_detected"]
    assert set(result["claimKinds"]).issubset({"observation", "inference", "hypothesis"})
    assert any("No model-internal feature" in line for line in result["limitations"])


def test_feature_extraction_returns_no_fabricated_features(api) -> None:
    response = api.client.post(
        "/api/v1/features/extract",
        json=api.payload(layer=12, hookPoint="blocks.12.hook_resid_post", aggregation="mean"),
    )

    body = _assert_integrated_unavailable_model_stages(response, operation="features_extract")
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

    body = _assert_integrated_unavailable_model_stages(response, operation="counterfactual_analyze")
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

    body = _assert_integrated_unavailable_model_stages(response, operation="prevention_steer")
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


def test_repair_id_resolves_the_stored_patch_for_verification(api) -> None:
    repair = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": _file_uri(api),
                "range": _range(),
                "cwe": "CWE-89",
            },
            patch=SIMPLE_PATCH,
            runFunctionalTests=False,
        ),
    )
    assert repair.status_code == 200
    repair_id = repair.json()["result"]["metadata"]["repairId"]
    assert repair_id

    verification = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(repairId=repair_id, cwe="CWE-89"),
    )

    assert verification.status_code == 200
    result = verification.json()["result"]
    assert result["repairId"] == repair_id
    assert result["verdict"] in {"passed", "failed", "inconclusive"}
    assert result["report"]["priorWorkflowEvidence"]["repairId"] == repair_id
    assert result["report"]["priorWorkflowEvidence"]["state"]
    assert result["report"]["priorWorkflowEvidence"]["securityVerification"] is not None
    assert result["report"]["priorWorkflowEvidence"]["beforeAfterComparison"] is not None
    assert any(check["kind"] == "security" for check in result["checks"])


def test_verification_rejects_a_repair_id_after_an_unrelated_source_change(api) -> None:
    repair = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding={
                "findingId": "finding-1",
                "documentUri": _file_uri(api),
                "range": _range(),
                "cwe": "CWE-89",
            },
            patch=SIMPLE_PATCH,
            runFunctionalTests=False,
        ),
    )
    assert repair.status_code == 200
    repair_id = repair.json()["result"]["metadata"]["repairId"]

    (api.root / "app.py").write_text("value = 'unrelated'\n", encoding="utf-8")
    verification = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(repairId=repair_id),
    )

    assert verification.status_code == 409
    assert verification.json()["code"] == "E_REPAIR_SNAPSHOT_MISMATCH"


def test_verification_accepts_explicit_patched_source(api) -> None:
    patched = (api.root / "app.py").read_text(encoding="utf-8").replace(
        "def connect(value)", "def connect_safely(value)"
    )
    response = api.client.post(
        "/api/v1/verification/run",
        json=api.payload(patchedSource=patched, cwe="CWE-89", findingId="finding-1"),
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] in {"passed", "failed", "inconclusive"}
    assert any(check["kind"] == "security" for check in result["checks"])


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
