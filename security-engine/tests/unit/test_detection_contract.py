"""Contract tests for serialized detection findings.

Serialization is a public boundary: every engine finding must validate against
``shared/schemas/vulnerability-finding.json``, and a heuristic score must never
acquire a calibrator object or a probability interpretation by accident.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from bugdhor.detection.config import DetectionConfig
from bugdhor.detection.engine import DetectionEngine
from bugdhor.detection.models import CalibratedProbability
from bugdhor.static.models import (
    AvailabilityStatus,
    ScanStatus,
    SourceLocation,
    StaticAnalysisResult,
    StaticFinding,
    ToolAvailability,
    ToolScanResult,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"
_SPLIT_HASH = "c" * 64

_SCHEMAS = {
    schema["$id"]: schema
    for path in SCHEMA_DIR.glob("*.json")
    if path.name != "manifest.json"
    for schema in (json.loads(path.read_text(encoding="utf-8")),)
}
_REGISTRY = Registry().with_resources(
    (
        schema_id,
        Resource.from_contents(schema, default_specification=DRAFT202012),
    )
    for schema_id, schema in _SCHEMAS.items()
)
_VALIDATOR = Draft202012Validator(
    json.loads((SCHEMA_DIR / "vulnerability-finding.json").read_text(encoding="utf-8")),
    registry=_REGISTRY,
)

_MIXED_PYTHON = """
import hashlib
import pickle
import subprocess

password = "supersecret123abc"

def get_user(request, cursor):
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
    subprocess.run(user, shell=True)
    eval(user)
    hashlib.md5(password.encode())
    pickle.loads(user)
"""


class _Calibrator:
    provider_id = "contract-calibrator"

    def calibrate(self, **_kwargs: object) -> CalibratedProbability:
        return CalibratedProbability(
            value=0.88,
            calibrator_artifact_id="calibrator-contract",
            method="isotonic",
            dataset_id="bugdhor-contract-set",
            split_hash=_SPLIT_HASH,
            brier_score=0.09,
            expected_calibration_error=0.03,
        )


def _assert_schema_valid(payload: dict[str, object]) -> None:
    errors = sorted(_VALIDATOR.iter_errors(payload), key=lambda error: list(error.path))
    assert not errors, "\n".join(
        f"{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in errors
    )


def _semgrep_sql_finding() -> StaticFinding:
    return StaticFinding(
        finding_id="semgrep-contract-1",
        tool="semgrep",
        rule_id="python.lang.security.audit.formatted-sql-query",
        message="Formatted SQL query.",
        severity="high",
        location=SourceLocation(
            path="app.py",
            start_line=9,
            start_column=4,
            end_line=9,
            end_column=70,
        ),
        cwes=("CWE-89",),
        tool_version="1.99.0",
        config_hash="d" * 64,
    )


def _static_result(finding: StaticFinding) -> StaticAnalysisResult:
    availability = ToolAvailability(
        tool="semgrep",
        status=AvailabilityStatus.AVAILABLE,
        executable="semgrep",
    )
    return StaticAnalysisResult(
        status=ScanStatus.OK,
        findings=(finding,),
        scans=(
            ToolScanResult(
                tool="semgrep",
                status=ScanStatus.OK,
                availability=availability,
                version="1.99.0",
                configuration={},
                config_hash="d" * 64,
                findings=(finding,),
            ),
        ),
    )


def test_heuristic_findings_validate_against_the_shared_contract() -> None:
    result = DetectionEngine(expected_tools=()).detect_source(
        _MIXED_PYTHON,
        path="app.py",
    )
    assert result.findings
    for payload in result.to_contract_dicts():
        _assert_schema_valid(payload)
        assert payload["riskScore"]["kind"] == "heuristic"
        assert payload["riskScore"]["interpretation"] == "heuristic_risk"
        assert "calibrator" not in payload["riskScore"]


def test_merged_static_and_program_analysis_finding_validates() -> None:
    engine = DetectionEngine(expected_tools=("semgrep",))
    result = engine.detect_source(
        _MIXED_PYTHON,
        path="app.py",
        static=_static_result(_semgrep_sql_finding()),
    )
    (finding,) = [item for item in result.findings if item.category.value == "sql_injection"]
    assert set(finding.families) == {"program_analysis", "static_tool"}
    _assert_schema_valid(finding.to_contract_dict())


def test_calibrated_finding_validates_and_carries_calibrator_metadata() -> None:
    engine = DetectionEngine(expected_tools=(), calibration=_Calibrator())
    result = engine.detect_source(_MIXED_PYTHON, path="app.py")
    assert result.findings
    for finding in result.findings:
        payload = finding.to_contract_dict()
        _assert_schema_valid(payload)
        assert payload["riskScore"]["kind"] == "calibrated"
        assert payload["riskScore"]["interpretation"] == "calibrated_probability"
        assert payload["riskScore"]["calibrator"]["artifactId"] == "calibrator-contract"
        assert payload["riskScore"]["calibrator"]["splitHash"] == _SPLIT_HASH


def test_unreachable_refuted_finding_still_validates() -> None:
    source = """
def find(request, cursor):
    return 1
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
"""
    result = DetectionEngine(expected_tools=()).detect_source(source, path="app.py")
    (finding,) = result.findings
    _assert_schema_valid(finding.to_contract_dict())
    assert finding.risk.heuristic.refutation_penalty > 0


def test_contract_never_emits_more_than_fifty_evidence_sources() -> None:
    config = DetectionConfig(max_evidence=80)
    engine = DetectionEngine(expected_tools=(), config=config)
    result = engine.detect_source(_MIXED_PYTHON, path="app.py")
    for payload in result.to_contract_dicts():
        assert 1 <= len(payload["evidenceSources"]) <= 50
        _assert_schema_valid(payload)


def test_api_serialization_is_complete_for_the_existing_api_shape() -> None:
    result = DetectionEngine(expected_tools=()).detect_source(
        _MIXED_PYTHON,
        path="app.py",
    )
    api_findings = result.to_api_findings()
    assert len(api_findings) == len(result.findings)
    for payload in api_findings:
        assert payload["id"]
        assert payload["message"]
        assert payload["severity"] in {"critical", "high", "medium", "low", "info"}
        assert payload["cwe"].startswith("CWE-")
        assert payload["location"]["uri"].startswith("file:")
        assert payload["location"]["range"]["start"]["line"] >= 0
        assert payload["explanation"]


def test_unknown_cwe_is_not_serialized_as_a_finding() -> None:
    unknown = StaticFinding(
        finding_id="semgrep-unknown",
        tool="semgrep",
        rule_id="acme.custom.check",
        message="Review this code because policy says so.",
        severity="medium",
        location=SourceLocation(
            path="app.py",
            start_line=0,
            start_column=0,
            end_line=0,
            end_column=10,
        ),
        cwes=(),
        tool_version="1.0",
        config_hash="e" * 64,
    )
    availability = ToolAvailability(
        tool="semgrep",
        status=AvailabilityStatus.AVAILABLE,
        executable="semgrep",
    )
    static = StaticAnalysisResult(
        status=ScanStatus.OK,
        findings=(unknown,),
        scans=(
            ToolScanResult(
                tool="semgrep",
                status=ScanStatus.OK,
                availability=availability,
                version="1.0",
                configuration={},
                config_hash="e" * 64,
                findings=(unknown,),
            ),
        ),
    )
    result = DetectionEngine(expected_tools=("semgrep",)).detect_source(
        "value = 1\n",
        path="app.py",
        static=static,
    )
    assert result.findings == ()
    assert result.to_contract_dicts() == []
    (candidate,) = result.unclassified
    assert all(item.cwe is None for item in candidate.evidence)
    assert "CWE-" not in candidate.reason


@pytest.mark.parametrize("path", ("app.py", "src/pkg/app.py"))
def test_file_path_is_preserved_in_the_contract(path: str) -> None:
    result = DetectionEngine(expected_tools=()).detect_source(
        'password = "supersecret123abc"\n',
        path=path,
    )
    payload = result.findings[0].to_contract_dict()
    assert payload["filePath"] == path
    _assert_schema_valid(payload)
