import json
import runpy
import sys

import pytest

from bugdhor_ast.cli import main


def run_cli(monkeypatch, *arguments):
    monkeypatch.setattr(
        sys,
        "argv",
        ["bugdhor-ast", *arguments],
    )
    main()


@pytest.mark.parametrize(
    (
        "filename",
        "source",
        "language",
        "expected_variable",
        "expected_function",
    ),
    [
        (
            "sample.py",
            "def add(a, b):\n    return a + b\n",
            "python",
            "a",
            "add",
        ),
        (
            "sample.js",
            "const value = 1;\n"
            "function run() { return value; }\n",
            "javascript",
            "value",
            "run",
        ),
        (
            "Sample.java",
            "class Sample { void run() { int value = 1; } }\n",
            "java",
            "value",
            "run",
        ),
    ],
)
def test_cli_scans_supported_language_files(
    tmp_path,
    monkeypatch,
    capsys,
    filename,
    source,
    language,
    expected_variable,
    expected_function,
):
    source_file = tmp_path / filename
    source_file.write_text(source, encoding="utf-8")

    run_cli(monkeypatch, str(source_file))

    result = json.loads(capsys.readouterr().out)

    assert result["language"] == language
    assert result["file"] == str(source_file)
    assert result["has_syntax_errors"] is False
    assert expected_variable in {
        item["name"] for item in result["variables"]
    }
    assert expected_function in {
        item["name"] for item in result["functions"]
    }


def test_cli_writes_json_to_nested_output_directory(
    tmp_path, monkeypatch, capsys
):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        "answer = 42\n", encoding="utf-8"
    )
    output_path = (
        tmp_path / "reports" / "nested" / "result.json"
    )

    run_cli(
        monkeypatch,
        str(source_file),
        "--output",
        str(output_path),
    )

    stdout = capsys.readouterr().out
    json_text, saved_line = stdout.split(
        "\nAnalysis saved to: ", 1
    )
    result = json.loads(json_text)

    assert output_path.is_file()
    assert saved_line.strip() == str(output_path)
    assert json.loads(
        output_path.read_text(encoding="utf-8")
    ) == result
    assert result["summary"]["variables"] == 1


def test_cli_missing_input_file(tmp_path, monkeypatch, capsys):
    missing_file = tmp_path / "missing.py"

    with pytest.raises(SystemExit) as error:
        run_cli(monkeypatch, str(missing_file))

    assert error.value.code == 1
    assert "Bug-Dhor Error: File not found:" in (
        capsys.readouterr().err
    )


def test_cli_unsupported_language(tmp_path, monkeypatch, capsys):
    source_file = tmp_path / "notes.txt"
    source_file.write_text("plain text", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        run_cli(monkeypatch, str(source_file))

    assert error.value.code == 1
    assert "Unsupported file extension: .txt" in (
        capsys.readouterr().err
    )


def test_cli_output_write_error(
    tmp_path, monkeypatch, capsys
):
    source_file = tmp_path / "sample.py"
    source_file.write_text("value = 1\n", encoding="utf-8")
    output_directory = tmp_path / "result.json"
    output_directory.mkdir()

    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            str(source_file),
            "-o",
            str(output_directory),
        )

    assert error.value.code == 1
    assert "Bug-Dhor Error:" in capsys.readouterr().err


def test_cli_invalid_arguments_missing_file(
    monkeypatch, capsys
):
    with pytest.raises(SystemExit) as error:
        run_cli(monkeypatch)

    assert error.value.code == 2
    assert "the following arguments are required: file" in (
        capsys.readouterr().err
    )


def test_cli_invalid_arguments_unknown_option(
    monkeypatch, capsys
):
    with pytest.raises(SystemExit) as error:
        run_cli(monkeypatch, "sample.py", "--bogus")

    assert error.value.code == 2
    assert "unrecognized arguments: --bogus" in (
        capsys.readouterr().err
    )


@pytest.mark.filterwarnings(
    "ignore:.*found in sys.modules.*:RuntimeWarning"
)
def test_cli_module_entry_point(tmp_path, monkeypatch, capsys):
    source_file = tmp_path / "sample.py"
    source_file.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["bugdhor-ast", str(source_file)]
    )

    runpy.run_module("bugdhor_ast.cli", run_name="__main__")

    result = json.loads(capsys.readouterr().out)
    assert result["language"] == "python"
    assert result["summary"]["variables"] == 1
