import pytest

from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.explain.repair import (
    RepairRecommendation,
    RepairStatus,
    recommend_repair,
    validate_recommendation,
)
from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics


def analysis_payload(source, language):
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
        if item["rule_id"].endswith("-TAINT001")
    )


def test_recommendation_schema_round_trip_and_approval_guard():
    source = "def f():\n    return missing_name\n"
    payload = analysis_payload(source, "python")
    finding = next(
        item for item in payload["diagnostics"] if item["rule_id"] == "PY001"
    )

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )
    serialized = recommendation.to_dict()

    assert set(serialized) == {
        "schema_version",
        "finding_id",
        "rule_id",
        "strategy",
        "status",
        "original_code",
        "proposed_code",
        "target",
        "explanation",
        "security_rationale",
        "functional_considerations",
        "confidence",
        "required_tests",
        "known_limitations",
        "requires_approval",
    }
    assert serialized["requires_approval"] is True
    assert serialized["status"] == "unsupported"
    assert serialized["proposed_code"] is None
    assert RepairRecommendation.from_dict(serialized).to_dict() == serialized

    serialized["requires_approval"] = False
    with pytest.raises(ValueError, match="requires_approval"):
        validate_recommendation(serialized)


def test_python_sql_taint_recommends_parameterized_statement():
    source = (
        "q = request.args.get('q')\n"
        "cursor.execute(\"SELECT * FROM users WHERE name = '\" + q + \"'\")\n"
    )
    payload = analysis_payload(source, "python")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )

    assert recommendation.status is RepairStatus.READY
    assert recommendation.strategy == "python_sql_parameterization"
    assert recommendation.original_code == source.splitlines()[1]
    assert (
        recommendation.proposed_code
        == "cursor.execute('SELECT * FROM users WHERE name = ?', (q,))"
    )
    assert recommendation.target.file == "sample.py"
    assert recommendation.target.start_line == 2
    assert recommendation.requires_approval is True
    assert "Bound parameters" in recommendation.security_rationale


def test_python_command_taint_recommends_argument_list():
    source = (
        "import subprocess\n"
        "token = os.getenv('T')\n"
        "os.system('echo ' + token)\n"
    )
    payload = analysis_payload(source, "python")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )

    assert recommendation.status is RepairStatus.READY
    assert recommendation.strategy == "python_process_argument_list"
    assert recommendation.proposed_code == "subprocess.call(['echo', token])"
    assert "shell parsing" in recommendation.security_rationale
    assert "Shell metacharacter" in recommendation.functional_considerations


def test_python_command_without_import_requires_review():
    source = "token = os.getenv('T')\nos.system('echo ' + token)\n"
    payload = analysis_payload(source, "python")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )

    assert recommendation.status is RepairStatus.NEEDS_REVIEW
    assert recommendation.proposed_code == "subprocess.call(['echo', token])"
    assert any("import" in item for item in recommendation.known_limitations)


def test_python_shell_string_with_command_chaining_is_unsupported():
    source = (
        "import subprocess\n"
        "token = os.getenv('T')\n"
        "os.system('echo ' + token + '; rm -rf /')\n"
    )
    payload = analysis_payload(source, "python")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )

    assert recommendation.status is RepairStatus.UNSUPPORTED
    assert recommendation.proposed_code is None
    assert "argument list" in recommendation.explanation


def test_javascript_html_taint_recommends_text_content():
    source = "const q = req.query.user;\ndocument.body.innerHTML = q;\n"
    payload = analysis_payload(source, "javascript")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.js"
    )

    assert recommendation.status is RepairStatus.READY
    assert recommendation.strategy == "javascript_html_property_to_text_content"
    assert recommendation.original_code == source.splitlines()[1]
    assert recommendation.proposed_code == "document.body.textContent = q;"
    assert "text" in recommendation.security_rationale.lower()


def test_javascript_sanitizer_and_markup_contexts_are_unsupported():
    finding = {
        "rule_id": "JS-TAINT001",
        "severity": "warning",
        "message": "Untrusted data reaches HTML.",
        "file": "sample.js",
        "line": 1,
        "column": 1,
        "end_line": 1,
        "end_column": 49,
        "language": "javascript",
    }

    sanitized = "document.body.innerHTML = DOMPurify.sanitize(q);\n"
    sanitized_result = recommend_repair(
        finding, source_code=sanitized, file="sample.js"
    )
    assert sanitized_result.status is RepairStatus.UNSUPPORTED
    assert sanitized_result.proposed_code is None
    assert "sanitizer" in sanitized_result.explanation

    markup = "document.body.innerHTML = '<b>' + q;\n"
    finding["end_column"] = len(markup.rstrip("\n")) + 1
    markup_result = recommend_repair(finding, source_code=markup, file="sample.js")
    assert markup_result.status is RepairStatus.UNSUPPORTED
    assert markup_result.proposed_code is None
    assert "markup" in markup_result.explanation


def test_java_sql_taint_recommends_prepared_statement():
    source = (
        "class C {\n"
        "  void f(HttpServletRequest request, Statement stmt) {\n"
        "    String q = request.getParameter(\"q\");\n"
        "    stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + q + \"'\");\n"
        "  }\n"
        "}\n"
    )
    payload = analysis_payload(source, "java")
    finding = taint_finding(payload)

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="Sample.java"
    )

    assert recommendation.status is RepairStatus.READY
    assert recommendation.strategy == "java_prepared_statement"
    proposed = recommendation.proposed_code
    assert proposed is not None
    assert 'String __bugdhorQuery_' in proposed
    assert '"SELECT * FROM users WHERE name = ?"' in proposed
    assert "java.sql.PreparedStatement __bugdhorStatement_" in proposed
    assert "stmt.getConnection().prepareStatement" in proposed
    assert ".setString(1, q)" in proposed
    assert ".executeQuery();" in proposed
    assert "JDBC driver" in recommendation.functional_considerations


def test_unsupported_rule_returns_no_recommended_code():
    source = "def f():\n    return missing_name\n"
    payload = analysis_payload(source, "python")
    finding = next(
        item for item in payload["diagnostics"] if item["rule_id"] == "PY001"
    )

    recommendation = recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )

    assert recommendation.status is RepairStatus.UNSUPPORTED
    assert recommendation.strategy == "unsupported"
    assert recommendation.proposed_code is None
    assert recommendation.requires_approval is True
    assert "No deterministic repair strategy" in recommendation.explanation


def test_missing_source_span_is_unsupported_without_inference():
    finding = {
        "rule_id": "PY-TAINT001",
        "severity": "warning",
        "message": "Untrusted data reaches a sink.",
        "file": "sample.py",
        "line": 99,
        "column": 1,
        "end_line": 99,
        "end_column": 20,
        "language": "python",
    }

    recommendation = recommend_repair(finding, source_code="eval(data)\n")

    assert recommendation.status is RepairStatus.UNSUPPORTED
    assert recommendation.proposed_code is None
    assert "source span" in recommendation.explanation
