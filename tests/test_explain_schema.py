import copy

import pytest

from bugdhor_ast.explain import (
    EXPLANATION_SCHEMA_VERSION,
    FindingExplanation,
    validate_explanation,
)
from bugdhor_ast.explain.evidence import build_explanation


def minimal_finding():
    return {
        "rule_id": "PY001",
        "rule_name": "Undefined Variable",
        "severity": "error",
        "message": "Undefined variable 'x'.",
        "file": "sample.py",
        "line": 2,
        "column": 5,
        "end_line": 2,
        "end_column": 6,
        "explanation": "Name used without a visible definition.",
        "suggestion": "Define the name before use.",
        "language": "python",
    }


def test_explanation_schema_has_stable_top_level_keys():
    explanation = build_explanation(minimal_finding(), {})

    payload = explanation.to_dict()

    assert payload["schema_version"] == EXPLANATION_SCHEMA_VERSION
    assert set(payload) == {
        "schema_version",
        "finding_id",
        "rule_id",
        "severity",
        "language",
        "category",
        "cwe",
        "location",
        "root_cause",
        "trigger",
        "evidence",
        "source_to_sink_path",
        "confidence",
        "limitations",
        "suggested_remediation",
        "verification_requirements",
    }
    assert set(payload["location"]) == {
        "file",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    }
    assert set(payload["evidence"]) == {
        "observed",
        "derived",
        "heuristic",
        "unavailable",
    }


def test_explanation_round_trip_preserves_values():
    explanation = build_explanation(minimal_finding(), {})
    payload = explanation.to_dict()

    parsed = FindingExplanation.from_dict(payload)

    assert parsed.to_dict() == payload


def test_validate_explanation_rejects_unknown_and_missing_keys():
    payload = build_explanation(minimal_finding(), {}).to_dict()
    del payload["confidence"]
    with pytest.raises(ValueError, match="missing="):
        validate_explanation(payload)

    payload = build_explanation(minimal_finding(), {}).to_dict()
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="unknown="):
        validate_explanation(payload)


def test_validate_explanation_rejects_wrong_schema_version():
    payload = build_explanation(minimal_finding(), {}).to_dict()
    payload["schema_version"] = "2.0"

    with pytest.raises(ValueError, match="schema_version"):
        validate_explanation(payload)


def test_validate_explanation_rejects_invalid_evidence_status():
    payload = build_explanation(minimal_finding(), {}).to_dict()
    record = copy.deepcopy(payload["evidence"]["observed"][0])
    record["status"] = "speculative"
    payload["evidence"]["observed"] = [record]

    with pytest.raises(ValueError, match="one of"):
        validate_explanation(payload)
