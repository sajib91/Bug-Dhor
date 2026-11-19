from bugdhor_ast.flow import (
    FlowEngine,
    TaintConfig,
    taint_diagnostics,
)


DEFAULT_SOURCE = """import os

def bad():
    data = input()
    eval(data)

def safe():
    data = input()
    value = int(data)
    eval(value)

def env():
    token = os.getenv("TOKEN")
    os.system("echo " + token)

def literal():
    value = "trusted"
    eval(value)
"""


def findings_pairs(result):
    return [
        (
            finding.source_name,
            finding.source_location.line,
            finding.sink_location.line,
        )
        for finding in result.taint_analysis.findings
    ]


def test_default_sources_sanitizers_and_sinks():
    result = FlowEngine().analyze_source(DEFAULT_SOURCE, "python")

    assert findings_pairs(result) == [
        ("input", 4, 5),
        ("os.getenv", 13, 14),
    ]

    finding = result.taint_analysis.findings[0]
    assert finding.source_rule.startswith("PY-SRC-")
    assert finding.sink_rule.startswith("PY-SNK-")
    assert finding.confidence == "medium"
    assert [step["kind"] for step in finding.path] == [
        "source",
        "assignment",
        "sink",
    ]
    assert finding.path[0]["location"]["line"] == 4
    assert finding.path[-1]["location"]["line"] == 5

    payload = result.to_dict()
    summary = payload["taint_analysis"]["summary"]
    assert summary["findings"] == 2
    assert summary["sources"] == 7
    assert summary["sanitizers"] == 4
    assert summary["sinks"] == 7


def test_sanitizer_and_literal_sinks_are_not_reported():
    result = FlowEngine().analyze_source(DEFAULT_SOURCE, "python")
    sink_lines = {
        finding.sink_location.line
        for finding in result.taint_analysis.findings
    }

    assert 9 not in sink_lines
    assert 18 not in sink_lines


def test_custom_taint_rules_on_engine_and_per_call():
    source = (
        "def f():\n"
        "    x = get_secret()\n"
        "    log(x)\n"
    )
    config = TaintConfig.from_dict(
        {
            "sources": [
                {"pattern": "get_secret", "id": "SRC"}
            ],
            "sanitizers": [],
            "sinks": [{"pattern": "log", "id": "SNK"}],
        }
    )
    engine = FlowEngine(taint_config=config)

    result = engine.analyze_source(source, "python")
    assert [
        (item.source_rule, item.sink_rule)
        for item in result.taint_analysis.findings
    ] == [("SRC", "SNK")]

    summary = result.to_dict()["taint_analysis"]["summary"]
    assert summary == {
        "findings": 1,
        "sources": 1,
        "sanitizers": 0,
        "sinks": 1,
    }

    overridden = engine.analyze_source(
        source,
        "python",
        taint_config={
            "sources": [{"pattern": "nothing", "id": "NONE"}],
            "sanitizers": [],
            "sinks": [{"pattern": "log", "id": "SNK"}],
        },
    )
    assert overridden.taint_analysis.findings == []


def test_interprocedural_return_taint():
    source = (
        "def get_input():\n"
        "    return input()\n"
        "\n"
        "def run():\n"
        "    value = get_input()\n"
        "    eval(value)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    assert findings_pairs(result) == [("input", 2, 6)]


def test_non_python_has_empty_taint_findings():
    result = FlowEngine().analyze_source(
        "const x = input();\n", "javascript"
    )

    assert result.taint_analysis.findings == []
    assert result.taint_analysis.language == "javascript"
    assert any(
        "only for Python" in item
        for item in result.taint_analysis.limitations
    )


def test_taint_findings_convert_to_existing_diagnostic_schema():
    result = FlowEngine().analyze_source(
        "data = input()\neval(data)\n", "python"
    )
    diagnostics = taint_diagnostics(result)

    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic.rule_id == "PY-TAINT001"
    assert diagnostic.rule_name == "Potential tainted data flow"
    assert diagnostic.severity == "warning"
    assert diagnostic.language == "python"
    assert diagnostic.line == 2
    assert diagnostic.file == "<source>"
    assert "input" in diagnostic.message
    assert "PY-SNK-001" in diagnostic.explanation
