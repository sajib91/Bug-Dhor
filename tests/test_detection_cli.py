import json
import sys

import pytest

from bugdhor_ast.cli import main


SOURCE = (
    "import os\n"
    "def f():\n"
    "    return missing_name\n"
)


def run_cli(monkeypatch, *arguments):
    monkeypatch.setattr(
        sys, "argv", ["bugdhor-ast", *arguments]
    )
    main()


def write_source(tmp_path, language="python"):
    suffix = {
        "python": ".py",
        "javascript": ".js",
        "java": ".java",
    }[language]
    source_file = tmp_path / f"sample{suffix}"
    source_file.write_text(SOURCE, encoding="utf-8")
    return source_file


def test_cli_detect_json_output(tmp_path, monkeypatch, capsys):
    source_file = write_source(tmp_path)

    run_cli(monkeypatch, str(source_file), "--detect")

    result = json.loads(capsys.readouterr().out)

    assert set(result) == {
        "file",
        "language",
        "has_syntax_errors",
        "summary",
        "rules_executed",
        "diagnostics",
    }
    assert result["file"] == str(source_file)
    assert result["language"] == "python"
    assert result["has_syntax_errors"] is False
    assert len(result["rules_executed"]) == 10
    assert result["summary"]["total"] == 2
    assert {
        item["rule_id"] for item in result["diagnostics"]
    } == {"PY001", "PY005"}
    assert all(
        item["file"] == str(source_file)
        for item in result["diagnostics"]
    )


def test_cli_detect_text_output(tmp_path, monkeypatch, capsys):
    source_file = write_source(tmp_path)

    run_cli(
        monkeypatch,
        str(source_file),
        "--detect",
        "--format",
        "text",
    )

    output = capsys.readouterr().out

    assert f"Bug-Dhor diagnostics for {source_file} (python)" in output
    assert "[ERROR] PY001" in output
    assert "[WARNING] PY005" in output
    assert "Rule: Undefined Variable" in output
    assert "Summary:" in output


def test_cli_detect_severity_filter(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)

    run_cli(
        monkeypatch,
        str(source_file),
        "--detect",
        "--severity",
        "warning",
    )

    result = json.loads(capsys.readouterr().out)

    assert {item["rule_id"] for item in result["diagnostics"]} == {
        "PY005"
    }
    assert all(
        item["severity"] == "warning"
        for item in result["diagnostics"]
    )


def test_cli_detect_rule_filter(tmp_path, monkeypatch, capsys):
    source_file = write_source(tmp_path)

    run_cli(
        monkeypatch,
        str(source_file),
        "--detect",
        "--rule",
        "PY001",
    )

    result = json.loads(capsys.readouterr().out)

    assert result["rules_executed"] == ["PY001"]
    assert {item["rule_id"] for item in result["diagnostics"]} == {
        "PY001"
    }


def test_cli_detect_unknown_rule(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "--detect",
            "--rule",
            "BOGUS",
        )

    assert error.value.code == 1
    assert "Unknown rule id(s): BOGUS" in capsys.readouterr().err


def test_cli_detect_writes_json_with_text_terminal_output(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)
    output_path = tmp_path / "reports" / "diagnostics.json"

    run_cli(
        monkeypatch,
        str(source_file),
        "--detect",
        "--format",
        "text",
        "--output",
        str(output_path),
    )

    stdout = capsys.readouterr().out
    terminal_output, saved_line = stdout.split(
        "\nAnalysis saved to: ", 1
    )

    assert "[ERROR] PY001" in terminal_output
    assert saved_line.strip() == str(output_path)
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["summary"]["total"] == 2
    assert saved["file"] == str(source_file)


def test_cli_detect_reports_syntax_errors(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)
    source_file.write_text("def broken(:\n", encoding="utf-8")

    run_cli(monkeypatch, str(source_file), "--detect")

    result = json.loads(capsys.readouterr().out)

    assert result["has_syntax_errors"] is True
    assert result["rules_executed"] == ["AST001"]
    assert all(
        item["rule_id"] == "AST001"
        for item in result["diagnostics"]
    )
    assert all(
        item["file"] == str(source_file)
        for item in result["diagnostics"]
    )


def test_cli_detect_invalid_severity_is_argparse_error(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "--detect",
            "--severity",
            "critical",
        )

    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_cli_ast_mode_ignores_detection_flags(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path)

    run_cli(
        monkeypatch,
        str(source_file),
        "--format",
        "text",
        "--severity",
        "error",
        "--rule",
        "PY001",
    )

    result = json.loads(capsys.readouterr().out)

    assert "diagnostics" not in result
    assert result["language"] == "python"
    assert "summary" in result
    assert "variables" in result
