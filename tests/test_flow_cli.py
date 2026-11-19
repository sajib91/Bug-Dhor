import json
import sys

import pytest

from bugdhor_ast.cli import main
from bugdhor_ast.flow import FLOW_SECTIONS


def run_cli(monkeypatch, *arguments):
    monkeypatch.setattr(
        sys, "argv", ["bugdhor-ast", *arguments]
    )
    main()


def write_source(tmp_path, suffix, source):
    source_file = tmp_path / f"sample{suffix}"
    source_file.write_text(source, encoding="utf-8")
    return source_file


def test_cli_ast_default_output_has_no_flow_sections(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path, ".py", "x = 1\n")

    run_cli(monkeypatch, str(source_file))

    result = json.loads(capsys.readouterr().out)
    assert result["language"] == "python"
    assert "summary" in result
    assert all(section not in result for section in FLOW_SECTIONS)


def test_cli_ast_flow_output(tmp_path, monkeypatch, capsys):
    source_file = write_source(
        tmp_path, ".py", "data = input()\neval(data)\n"
    )

    run_cli(monkeypatch, str(source_file), "--flow")

    result = json.loads(capsys.readouterr().out)
    assert all(section in result for section in FLOW_SECTIONS)
    assert len(result["scopes"]) >= 1
    assert len(result["symbols"]) >= 1
    assert result["taint_analysis"]["summary"]["findings"] == 1
    assert result["control_flow_graph"]
    assert all(
        graph["consistent"] is True
        for graph in result["control_flow_graph"]
    )
    assert result["scopes"][0]["kind"] == "module"
    assert "diagnostics" not in result


def test_cli_detect_flow_taint_diagnostics(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(
        tmp_path,
        ".py",
        "data = input()\neval(data)\nreturn missing_name\n",
    )

    run_cli(
        monkeypatch,
        str(source_file),
        "--detect",
        "--flow",
        "--taint-diagnostics",
    )

    result = json.loads(capsys.readouterr().out)
    assert {
        "file",
        "language",
        "has_syntax_errors",
        "summary",
        "rules_executed",
        "diagnostics",
    } <= set(result)
    assert all(section in result for section in FLOW_SECTIONS)
    assert result["taint_analysis"]["summary"]["findings"] == 1

    rule_ids = {
        item["rule_id"] for item in result["diagnostics"]
    }
    assert {"PY001", "PY-TAINT001"} <= rule_ids

    taint_diagnostic = next(
        item
        for item in result["diagnostics"]
        if item["rule_id"] == "PY-TAINT001"
    )
    assert taint_diagnostic["line"] == 2
    assert taint_diagnostic["severity"] == "warning"
    assert taint_diagnostic["file"] == str(source_file)
    assert "PY-SRC-001" in taint_diagnostic["explanation"]
    assert "PY-SNK-001" in taint_diagnostic["explanation"]


def test_cli_taint_diagnostics_requires_flow(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(tmp_path, ".py", "x = 1\n")

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "--taint-diagnostics",
        )

    assert error.value.code == 2
    assert "requires --flow" in capsys.readouterr().err


def test_cli_taint_config_requires_flow(tmp_path, monkeypatch, capsys):
    source_file = write_source(tmp_path, ".py", "x = 1\n")
    config_file = tmp_path / "config.json"
    config_file.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "--taint-config",
            str(config_file),
        )

    assert error.value.code == 2
    assert "--taint-config requires --flow" in capsys.readouterr().err


def test_cli_taint_config_json_uses_custom_rules(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(
        tmp_path,
        ".py",
        "x = get_secret()\nlog(x)\n",
    )
    config_file = tmp_path / "taint.json"
    config_file.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "id": "FILE-SRC",
                        "name": "File secret",
                        "pattern": "get_secret",
                    }
                ],
                "sanitizers": [],
                "sinks": [{"id": "FILE-SNK", "pattern": "log"}],
            }
        ),
        encoding="utf-8",
    )

    run_cli(
        monkeypatch,
        str(source_file),
        "--flow",
        "--taint-config",
        str(config_file),
    )

    result = json.loads(capsys.readouterr().out)
    findings = result["taint_analysis"]["findings"]
    assert [(item["source_rule"], item["sink_rule"]) for item in findings] == [
        ("FILE-SRC", "FILE-SNK")
    ]
    assert result["taint_analysis"]["summary"] == {
        "findings": 1,
        "sources": 1,
        "sanitizers": 0,
        "sinks": 1,
    }


def test_cli_taint_config_language_pack_from_file(
    tmp_path, monkeypatch, capsys
):
    source_file = write_source(
        tmp_path,
        ".js",
        "const token = getToken();\nsend(token);\n",
    )
    config_file = tmp_path / "packs.json"
    config_file.write_text(
        json.dumps(
            {
                "language_packs": {
                    "javascript": {
                        "sources": [{"id": "JS-SRC", "pattern": "getToken"}],
                        "sanitizers": [],
                        "sinks": [{"id": "JS-SNK", "pattern": "send"}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    run_cli(
        monkeypatch,
        str(source_file),
        "--flow",
        "--taint-config",
        str(config_file),
    )

    result = json.loads(capsys.readouterr().out)
    findings = result["taint_analysis"]["findings"]
    assert [(item["source_rule"], item["sink_rule"]) for item in findings] == [
        ("JS-SRC", "JS-SNK")
    ]


@pytest.mark.parametrize(
    "content,message",
    [
        ("{invalid json", "Invalid taint configuration JSON"),
        ('{"sources": "input"}', "Taint sources must be a list"),
    ],
)
def test_cli_invalid_taint_config_reports_error(
    tmp_path, monkeypatch, capsys, content, message
):
    source_file = write_source(tmp_path, ".py", "x = 1\n")
    config_file = tmp_path / "invalid.json"
    config_file.write_text(content, encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "--flow",
            "--taint-config",
            str(config_file),
        )

    assert error.value.code == 1
    captured = capsys.readouterr()
    assert message in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "suffix,language,source",
    [
        (
            ".js",
            "javascript",
            "var g = 1;\n"
            "function f(a) { let x = a; return x + g; }\n",
        ),
        (
            ".java",
            "java",
            "class C {\n"
            "  int field = 1;\n"
            "  void f(int a) { int x = a; field = x; }\n"
            "}\n",
        ),
    ],
)
def test_cli_flow_multilanguage(
    tmp_path, monkeypatch, capsys, suffix, language, source
):
    source_file = write_source(tmp_path, suffix, source)

    run_cli(monkeypatch, str(source_file), "--flow")

    result = json.loads(capsys.readouterr().out)
    assert result["language"] == language
    assert all(section in result for section in FLOW_SECTIONS)
    assert result["symbols"]
    assert result["scopes"]
    assert result["control_flow_graph"]
    assert all(
        graph["consistent"] is True
        for graph in result["control_flow_graph"]
    )
    assert result["taint_analysis"]["summary"]["findings"] == 0
