from bugdhor_ast.flow import (
    FlowEngine,
    TaintConfig,
    taint_diagnostics,
)


JS_POSITIVE = """const q = req.query.user;
const u = new URLSearchParams(location.search).get('u');
const p = process.env.API_KEY;
document.body.innerHTML = q;
eval(u);
Function(p)();
const safe = encodeURIComponent(q);
document.body.innerHTML = safe;
eval("literal");
"""


JAVA_POSITIVE = """class C {
  void f(HttpServletRequest request, Statement stmt) {
    String q = request.getParameter("q");
    stmt.executeQuery(q);
    Runtime.getRuntime().exec(q);
    new ProcessBuilder(q).start();
    String safe = Integer.parseInt(q);
    stmt.executeQuery(safe);
    stmt.executeQuery("SELECT 1");
  }
}
"""


def sink_lines(result):
    return [item.sink_location.line for item in result.taint_analysis.findings]


def test_javascript_source_to_sink_and_sanitizer():
    result = FlowEngine().analyze_source(JS_POSITIVE, "javascript")

    assert sink_lines(result) == [4, 5, 6]
    assert result.taint_analysis.language == "javascript"

    summary = result.to_dict()["taint_analysis"]["summary"]
    assert summary["sources"] == 14
    assert summary["sanitizers"] == 6
    assert summary["sinks"] == 12

    for finding in result.taint_analysis.findings:
        assert finding.source_rule.startswith("JS-SRC-")
        assert finding.sink_rule.startswith("JS-SNK-")
        assert finding.path[0]["kind"] == "source"
        assert finding.path[-1]["kind"] == "sink"
        assert finding.path[0]["location"]["line"] < finding.path[-1]["location"]["line"]

    assert {finding.sink_rule for finding in result.taint_analysis.findings} == {
        "JS-SNK-003",
        "JS-SNK-001",
        "JS-SNK-002",
    }


def test_javascript_does_not_claim_python_input_source():
    result = FlowEngine().analyze_source(
        "const x = input();\neval(x);\n", "javascript"
    )
    assert result.taint_analysis.findings == []
    assert any(
        "only for Python" in item
        for item in result.taint_analysis.limitations
    )


def test_java_source_to_sink_and_sanitizer():
    result = FlowEngine().analyze_source(JAVA_POSITIVE, "java")

    assert sink_lines(result) == [4, 5, 6]
    assert result.taint_analysis.language == "java"
    assert {
        finding.sink_rule for finding in result.taint_analysis.findings
    } == {
        "JAVA-SNK-003",
        "JAVA-SNK-001",
        "JAVA-SNK-002",
    }
    for finding in result.taint_analysis.findings:
        assert finding.source_rule.startswith("JAVA-SRC-")
        assert finding.path[0]["kind"] == "source"
        assert finding.path[-1]["kind"] == "sink"


def test_language_specific_rule_packs_and_confidence():
    config = TaintConfig.from_dict(
        {
            "language_packs": {
                "javascript": {
                    "sources": [
                        {
                            "pattern": "getToken",
                            "id": "JSSRC",
                            "confidence": "low",
                        }
                    ],
                    "sanitizers": [],
                    "sinks": [
                        {
                            "pattern": "logIt",
                            "id": "JSSNK",
                            "confidence": "high",
                        }
                    ],
                }
            }
        }
    )
    result = FlowEngine(taint_config=config).analyze_source(
        "const t = getToken();\nlogIt(t);\n", "javascript"
    )

    assert len(result.taint_analysis.findings) == 1
    finding = result.taint_analysis.findings[0]
    assert (finding.source_rule, finding.sink_rule) == ("JSSRC", "JSSNK")
    assert finding.confidence == "high"
    assert finding.source_name == "getToken"


def test_custom_pack_does_not_change_python_defaults():
    config = TaintConfig.from_dict(
        {
            "language_packs": {
                "javascript": {
                    "sources": [{"pattern": "getToken", "id": "JSSRC"}],
                    "sanitizers": [],
                    "sinks": [{"pattern": "logIt", "id": "JSSNK"}],
                }
            }
        }
    )
    result = FlowEngine(taint_config=config).analyze_source(
        "x = input()\neval(x)\n", "python"
    )
    assert len(result.taint_analysis.findings) == 1
    assert result.taint_analysis.findings[0].source_rule == "PY-SRC-001"


def test_taint_diagnostics_use_language_specific_rule_ids():
    js = FlowEngine().analyze_source(
        "const q = req.query.x;\neval(q);\n", "javascript"
    )
    java = FlowEngine().analyze_source(
        "class C { void f(HttpServletRequest r) { "
        "String q = r.getParameter(\"q\"); eval(q); } }",
        "java",
    )

    js_diagnostics = taint_diagnostics(js)
    java_diagnostics = taint_diagnostics(java)

    assert [item.rule_id for item in js_diagnostics] == ["JS-TAINT001"]
    assert [item.rule_id for item in java_diagnostics] == ["JAVA-TAINT001"]
    assert js_diagnostics[0].language == "javascript"
    assert java_diagnostics[0].language == "java"
