from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.explain import build_explanation, build_explanations
from bugdhor_ast.explain.schema import EvidenceStatus, RootCauseStatus
from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics

SOURCE = "data = input()\neval(data)\nreturn missing_name\n"


def combined_payload(source=SOURCE, language="python"):
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


def test_taint_explanation_preserves_real_source_to_sink_evidence():
    payload = combined_payload()
    finding = next(
        item
        for item in payload["diagnostics"]
        if item["rule_id"] == "PY-TAINT001"
    )

    explanation = build_explanation(finding, payload)
    payload_out = explanation.to_dict()

    assert explanation.category == "taint_flow"
    assert explanation.cwe == ()
    assert explanation.root_cause.status is RootCauseStatus.UNKNOWN
    assert explanation.location.start_line == finding["line"]
    assert explanation.location.start_column == finding["column"]

    assert next(step["kind"] for step in explanation.source_to_sink_path) == "source"
    assert explanation.source_to_sink_path[-1]["kind"] == "sink"

    kinds = {record.kind for record in explanation.evidence.all_records()}
    assert "ast_function_calls" in kinds
    assert "taint_source_sink" in kinds
    assert "taint_path" in kinds

    source_sink = next(
        record
        for record in explanation.evidence.all_records()
        if record.kind == "taint_source_sink"
    )
    assert source_sink.value["source_rule"].startswith("PY-SRC-")
    assert source_sink.value["sink_rule"].startswith("PY-SNK-")
    assert source_sink.status is EvidenceStatus.OBSERVED

    assert payload_out["source_to_sink_path"] == [
        step for step in explanation.source_to_sink_path
    ]
    assert any("exploitability" in item for item in explanation.limitations)


def test_detection_explanation_uses_observed_finding_and_one_based_location():
    payload = combined_payload()
    finding = next(
        item for item in payload["diagnostics"] if item["rule_id"] == "PY001"
    )

    explanation = build_explanation(finding, payload)

    assert explanation.rule_id == "PY001"
    assert explanation.location.start_line == finding["line"]
    assert explanation.location.start_column == finding["column"]
    assert explanation.location.end_line == finding["end_line"]
    assert explanation.location.end_column == finding["end_column"]
    assert any(record.kind == "finding" for record in explanation.evidence.observed)
    assert explanation.trigger is not None


def test_missing_evidence_is_explicit_and_not_inferred():
    finding = {
        "rule_id": "PY010",
        "severity": "error",
        "message": "Dangerous call.",
        "file": "sample.py",
        "line": 1,
        "column": 1,
        "end_line": 1,
        "end_column": 5,
        "language": "python",
    }

    explanation = build_explanation(finding, {})

    unavailable = {
        record.kind for record in explanation.evidence.unavailable
    }
    assert {
        "ast_evidence",
        "cfg_evidence",
        "data_flow_evidence",
        "flow_section_symbols",
        "flow_section_control_flow_graph",
        "flow_section_data_flow",
        "flow_section_taint_analysis",
    } <= unavailable
    assert explanation.trigger is not None
    assert explanation.trigger["kind"] == "finding"
    assert explanation.root_cause.status is RootCauseStatus.UNKNOWN
    assert explanation.root_cause.location is None
    assert explanation.source_to_sink_path == ()
    assert explanation.cwe == ()
    assert explanation.confidence.value is not None


def test_evidence_status_groups_match_record_status():
    explanation = build_explanation(
        {
            "rule_id": "PY001",
            "severity": "error",
            "message": "Undefined.",
            "file": "sample.py",
            "line": 1,
            "column": 1,
            "end_line": 1,
            "end_column": 2,
            "language": "python",
        },
        {},
    )

    for group in ("observed", "derived", "heuristic", "unavailable"):
        records = getattr(explanation.evidence, group)
        assert all(record.status.value == group for record in records)
        assert explanation.evidence.to_dict()[group] == [
            record.to_dict() for record in records
        ]


def test_build_explanations_preserves_input_order():
    payload = combined_payload()

    explanations = build_explanations(payload["diagnostics"], payload)

    assert [item.rule_id for item in explanations] == [
        item["rule_id"] for item in payload["diagnostics"]
    ]
