from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.explain import (
    RootCauseStatus,
    analyze_root_cause,
    explain_finding,
    explain_findings,
)
from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics


def combined_payload(source, language="python"):
    ast_payload = BugDhorASTEngine().analyze_source(source, language)
    detection = BugDhorDetectionEngine().analyze_source(source, language).to_dict()
    flow = FlowEngine().analyze_source(source, language)
    flow_payload = flow.to_dict(FLOW_SECTIONS)

    payload = dict(detection)
    payload["diagnostics"] = list(detection["diagnostics"]) + [
        item.to_dict() for item in taint_diagnostics(flow)
    ]
    for section in FLOW_SECTIONS:
        payload[section] = flow_payload[section]
    payload["unresolved_references"] = flow_payload["unresolved_references"]
    payload["limitations"] = flow_payload["limitations"]
    for key in (
        "functions",
        "classes",
        "variables",
        "function_calls",
        "imports",
        "syntax_errors",
    ):
        payload[key] = ast_payload[key]
    return payload


def finding_by_rule(payload, rule_id):
    return next(
        item for item in payload["diagnostics"] if item["rule_id"] == rule_id
    )


def test_undefined_variable_root_cause_uses_scope_evidence():
    payload = combined_payload("def f():\n    return missing_name\n")
    finding = finding_by_rule(payload, "PY001")

    result = analyze_root_cause(finding, payload)

    assert result.analysis_kind == "undefined_reference"
    assert result.root_cause.status is RootCauseStatus.DETERMINED
    assert result.root_cause.location is not None
    assert result.root_cause.location.start_line == 2
    assert any(
        item.kind == "root_cause_unresolved_reference" for item in result.evidence
    )
    assert "does not model dynamic" in " ".join(result.limitations)


def test_taint_root_cause_is_source_origin_without_feasibility_claim():
    payload = combined_payload("data = input()\neval(data)\n")
    finding = finding_by_rule(payload, "PY-TAINT001")

    explanation = explain_finding(finding, payload)

    assert explanation.root_cause.status is RootCauseStatus.HEURISTIC
    assert explanation.root_cause.location is not None
    assert explanation.root_cause.location.start_line == 1
    assert "input" in explanation.root_cause.rationale
    assert "runtime feasibility" in explanation.root_cause.rationale
    assert any(
        item.kind == "root_cause_taint_origin"
        for item in explanation.evidence.derived
    )
    assert explanation.confidence.value in {"low", "medium", "high"}


def test_dangerous_call_root_cause_uses_ast_call_site():
    payload = combined_payload("eval('1')\n")
    finding = finding_by_rule(payload, "PY010")

    result = analyze_root_cause(finding, payload)

    assert result.analysis_kind == "dangerous_call"
    assert result.root_cause.status is RootCauseStatus.DETERMINED
    assert result.root_cause.location is not None
    assert result.root_cause.location.start_line == 1
    assert "eval" in result.root_cause.rationale
    assert any(
        item.kind == "root_cause_dangerous_call" for item in result.evidence
    )


def test_unsupported_rule_returns_unknown_without_inference():
    result = analyze_root_cause(
        {
            "rule_id": "PY003",
            "message": "Unreachable code detected.",
            "file": "sample.py",
            "line": 4,
            "column": 1,
            "end_line": 4,
            "end_column": 8,
            "language": "python",
        },
        {},
    )

    assert result.analysis_kind == "unsupported"
    assert result.root_cause.status is RootCauseStatus.UNKNOWN
    assert result.root_cause.location is None
    assert result.evidence == ()
    assert "was not localized" in " ".join(result.limitations)


def test_root_cause_evidence_is_merged_without_changing_schema():
    payload = combined_payload("data = input()\neval(data)\n")
    finding = finding_by_rule(payload, "PY-TAINT001")

    explanation = explain_finding(finding, payload)
    payload_out = explanation.to_dict()

    assert set(payload_out["root_cause"]) == {
        "status",
        "location",
        "rationale",
        "evidence_refs",
    }
    assert "root-cause:taint-origin" in payload_out["root_cause"]["evidence_refs"]
    assert any(
        item["id"] == "root-cause:taint-origin"
        for item in payload_out["evidence"]["derived"]
    )


def test_explain_findings_preserves_detection_order():
    payload = combined_payload("data = input()\neval(data)\nreturn missing_name\n")

    explanations = explain_findings(payload["diagnostics"], payload)

    assert [item.rule_id for item in explanations] == [
        item["rule_id"] for item in payload["diagnostics"]
    ]
