import pytest

from bugdhor_ast.detection import (
    BugDhorDetectionEngine,
    DEFAULT_REGISTRY,
    DetectionResult,
    Diagnostic,
    RuleMetadata,
    render_text,
)


ENGINE = BugDhorDetectionEngine()

REQUIRED_DIAGNOSTIC_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "message",
    "file",
    "line",
    "column",
    "end_line",
    "end_column",
    "explanation",
    "suggestion",
    "language",
}


def test_diagnostic_and_result_schema():
    diagnostic = Diagnostic(
        rule_id="PY001",
        rule_name="Undefined Variable",
        severity="error",
        message="Variable 'x' is not defined.",
        file="sample.py",
        line=3,
        column=5,
        end_line=3,
        end_column=6,
        explanation="A variable is used without a visible definition.",
        suggestion="Define the variable before using it.",
        language="python",
    )
    result = DetectionResult(
        file="sample.py",
        language="python",
        diagnostics=[diagnostic],
        rules_executed=["PY001"],
    )

    payload = result.to_dict()

    assert set(payload) == {
        "file",
        "language",
        "has_syntax_errors",
        "summary",
        "rules_executed",
        "diagnostics",
    }
    assert set(payload["diagnostics"][0]) == REQUIRED_DIAGNOSTIC_FIELDS
    assert payload["diagnostics"][0]["message"] == (
        "Variable 'x' is not defined."
    )
    assert result.summary == {
        "total": 1,
        "error": 1,
        "warning": 0,
        "info": 0,
    }
    assert diagnostic.location_key == (3, 5, 3, 6, "PY001")


def test_rule_metadata_rejects_unknown_severity():
    with pytest.raises(ValueError, match="Unsupported severity"):
        RuleMetadata(
            "X001",
            "Invalid",
            "Invalid severity.",
            "critical",
            "python",
        )


def test_registry_selects_rules_by_language_id_and_severity():
    registry = DEFAULT_REGISTRY

    assert len(registry.all_rules()) == 30
    for language in ("python", "javascript", "java"):
        rules = registry.select(language=language)
        assert len(rules) == 10
        assert all(
            rule.metadata.language == language for rule in rules
        )

    errors = registry.select(
        language="python", severities=["error"]
    )
    assert {rule.rule_id for rule in errors} == {
        "PY001",
        "PY004",
        "PY010",
    }

    selected = registry.select(rule_ids=["py005", "JS005"])
    assert {rule.rule_id for rule in selected} == {
        "PY005",
        "JS005",
    }

    metadata = registry.metadata("python")
    assert metadata[0].to_dict()["limitations"] == list(
        metadata[0].limitations
    )

    with pytest.raises(KeyError):
        registry.get_rule("NOPE")

    with pytest.raises(ValueError, match="Duplicate rule id"):
        registry.register(registry.get_rule("PY001"))


def test_engine_returns_unique_sorted_structured_diagnostics():
    result = ENGINE.analyze_source(
        "def f():\n    unused = 1\n    return missing\n",
        "python",
        file="sample.py",
    )

    assert result.file == "sample.py"
    assert result.language == "python"
    assert result.has_syntax_errors is False
    assert len(result.rules_executed) == 10

    payload = result.to_dict()
    assert payload["summary"]["total"] == len(result.diagnostics)
    assert all(
        REQUIRED_DIAGNOSTIC_FIELDS <= set(item)
        for item in payload["diagnostics"]
    )
    assert all(
        item["line"] >= 1 and item["column"] >= 1
        for item in payload["diagnostics"]
    )

    locations = [item.location_key for item in result.diagnostics]
    assert len(locations) == len(set(locations))
    assert locations == sorted(locations)
    assert [item.rule_id for item in result.diagnostics] == [
        "PY002",
        "PY001",
    ]
    assert all(
        item.file == "sample.py" for item in result.diagnostics
    )


def test_engine_filters_by_rule_and_severity():
    source = (
        "import os\n"
        "def f():\n"
        "    return missing_name\n"
    )

    rule_only = ENGINE.analyze_source(
        source, "python", rule_ids=["PY005"]
    )
    assert {item.rule_id for item in rule_only.diagnostics} == {
        "PY005"
    }
    assert rule_only.rules_executed == ["PY005"]

    warning_only = ENGINE.analyze_source(
        source, "python", severities=["warning"]
    )
    assert {item.rule_id for item in warning_only.diagnostics} == {
        "PY005"
    }
    assert warning_only.rules_executed == [
        rule.rule_id
        for rule in DEFAULT_REGISTRY.select(
            language="python", severities=["warning"]
        )
    ]

    error_only = ENGINE.analyze_source(
        source, "python", severities=["error"]
    )
    assert {item.rule_id for item in error_only.diagnostics} == {
        "PY001"
    }


@pytest.mark.parametrize(
    ("language", "source"),
    [
        ("python", "def broken(:\n"),
        ("javascript", "function f( {"),
        ("java", "class X { void f( }"),
    ],
)
def test_syntax_errors_short_circuit_rules(language, source):
    result = ENGINE.analyze_source(source, language)

    assert result.has_syntax_errors is True
    assert result.rules_executed == ["AST001"]
    assert result.diagnostics
    assert all(
        item.rule_id == "AST001" for item in result.diagnostics
    )
    assert all(
        item.severity == "error" for item in result.diagnostics
    )


def test_engine_file_errors(tmp_path):
    with pytest.raises(FileNotFoundError, match="File not found"):
        ENGINE.analyze_file(tmp_path / "missing.py")

    text_file = tmp_path / "notes.txt"
    text_file.write_text("plain text", encoding="utf-8")

    with pytest.raises(
        ValueError, match="Unsupported file extension: .txt"
    ):
        ENGINE.analyze_file(text_file)


def test_engine_analyze_file_populates_file_field(tmp_path):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        "def f():\n    unused = 1\n", encoding="utf-8"
    )

    result = ENGINE.analyze_file(source_file)

    assert result.file == str(source_file)
    assert result.language == "python"
    assert all(
        item.file == str(source_file) for item in result.diagnostics
    )


def test_list_rules_includes_metadata():
    rules = ENGINE.list_rules()

    assert len(rules) == 30
    assert len(ENGINE.list_rules("java")) == 10
    assert all(
        {
            "rule_id",
            "rule_name",
            "description",
            "severity",
            "language",
            "suggestion",
            "limitations",
        } <= set(rule)
        for rule in rules
    )


def test_render_text_for_no_diagnostics():
    result = ENGINE.analyze_source("value = 1\n", "python")

    rendered = render_text(result)

    assert "Bug-Dhor diagnostics for <source> (python)" in rendered
    assert "No diagnostics found." in rendered


def test_render_text_includes_rule_details_and_summary():
    result = ENGINE.analyze_source(
        "def f():\n    unused = 1\n", "python"
    )

    rendered = render_text(result)

    assert "[WARNING] PY002" in rendered
    assert "Rule: Unused Variable" in rendered
    assert "Explanation:" in rendered
    assert "Suggestion:" in rendered
    assert "Summary:" in rendered
