import re

from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.explain import (
    CWE_RULES,
    ConfidenceLevel,
    explain_finding,
    map_cwe,
)
from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics


def combined_payload(source, language):
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


def taint_finding(payload):
    return next(
        item
        for item in payload["diagnostics"]
        if item["rule_id"] in {"PY-TAINT001", "JS-TAINT001", "JAVA-TAINT001"}
    )


def test_all_cwe_rule_definitions_are_valid():
    assert CWE_RULES
    for rule in CWE_RULES:
        assert re.match(r"^CWE-\d+$", rule.cwe_id)
        assert rule.confidence in {
            ConfidenceLevel.HIGH,
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.LOW,
        }
        assert rule.rationale.strip()
        assert rule.evidence_requirement in {"taint_path", "detection_rule"}
        assert rule.to_dict()["cwe_id"] == rule.cwe_id


def test_python_eval_taint_has_two_defensible_code_injection_mappings():
    payload = combined_payload("data = input()\neval(data)\n", "python")
    finding = taint_finding(payload)

    explanation = explain_finding(finding, payload)
    ids = {item.id for item in explanation.cwe}

    assert {"CWE-94", "CWE-95"} == ids
    cwe_94 = next(item for item in explanation.cwe if item.id == "CWE-94")
    assert cwe_94.confidence is ConfidenceLevel.HIGH
    assert "dynamically constructed Python code" in cwe_94.rationale
    for ref in cwe_94.evidence_refs:
        assert any(
            record.id == ref for record in explanation.evidence.all_records()
        )


def test_python_sql_taint_maps_to_cwe_89():
    payload = combined_payload(
        "q = request.args.get('q')\ncursor.execute(q)\n", "python"
    )
    finding = taint_finding(payload)

    explanation = explain_finding(finding, payload)

    assert [item.id for item in explanation.cwe] == ["CWE-89"]
    assert "cursor.execute" in explanation.cwe[0].rationale


def test_python_command_taint_maps_to_cwe_78():
    payload = combined_payload(
        "token = os.getenv('T')\nos.system('echo ' + token)\n", "python"
    )
    finding = taint_finding(payload)

    explanation = explain_finding(finding, payload)

    assert "CWE-78" in {item.id for item in explanation.cwe}


def test_javascript_dom_xss_taint_maps_to_cwe_79():
    payload = combined_payload(
        "const q = req.query.user;\ndocument.body.innerHTML = q;\n",
        "javascript",
    )
    finding = taint_finding(payload)

    explanation = explain_finding(finding, payload)

    assert "CWE-79" in {item.id for item in explanation.cwe}


def test_java_sql_taint_maps_to_cwe_89():
    payload = combined_payload(
        "class C {\n"
        "  void f(HttpServletRequest request, Statement stmt) {\n"
        "    String q = request.getParameter('q');\n"
        "    stmt.executeQuery(q);\n"
        "  }\n"
        "}\n",
        "java",
    )
    finding = taint_finding(payload)

    explanation = explain_finding(finding, payload)

    assert "CWE-89" in {item.id for item in explanation.cwe}


def test_dangerous_call_without_taint_is_unmapped():
    payload = combined_payload("eval('1')\n", "python")
    finding = next(
        item for item in payload["diagnostics"] if item["rule_id"] == "PY010"
    )

    explanation = explain_finding(finding, payload)

    assert explanation.cwe == ()


def test_unrelated_rule_is_unmapped():
    payload = combined_payload("def f():\n    return missing_name\n", "python")
    finding = next(
        item for item in payload["diagnostics"] if item["rule_id"] == "PY001"
    )

    explanation = explain_finding(finding, payload)

    assert explanation.cwe == ()


def test_map_cwe_without_explanation_still_returns_serializable_mappings():
    payload = combined_payload(
        "q = request.args.get('q')\ncursor.execute(q)\n", "python"
    )
    finding = taint_finding(payload)

    mappings = map_cwe(finding, payload)

    assert [item.id for item in mappings] == ["CWE-89"]
    assert mappings[0].to_dict()["id"] == "CWE-89"
