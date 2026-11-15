from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

from craftsec.static import (
    BanditAdapter,
    BanditConfig,
    CodeQLAdapter,
    CodeQLConfig,
    JoernAdapter,
    JoernConfig,
    ScanStatus,
    SemgrepAdapter,
    SemgrepConfig,
    StaticAnalysisRunner,
)


def make_executable(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / "bin" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"#!{sys.executable}\n" + textwrap.dedent(body).lstrip(),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def write_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    source = root / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("result = eval(user_input)\n", encoding="utf-8")
    return root


SEMGREP_PAYLOAD: dict[str, Any] = {
    "version": "1.99.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "src/app.py",
            "start": {"line": 1, "col": 10},
            "end": {"line": 1, "col": 28},
            "fingerprint": "semgrep-eval",
            "extra": {
                "message": "Avoid use of eval.",
                "severity": "ERROR",
                "lines": "result = eval(user_input)",
                "metadata": {
                    "shortDescription": "Eval detected",
                    "cwe": ["CWE-95: Improper Neutralization of Directives"],
                },
            },
        }
    ],
    "errors": [],
}

BANDIT_PAYLOAD: dict[str, Any] = {
    "errors": [],
    "results": [
        {
            "filename": "src/app.py",
            "test_id": "B307",
            "test_name": "blacklist",
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": ("Use of possibly insecure function; consider ast.literal_eval."),
            "line_number": 1,
            "col_offset": 9,
            "end_col_offset": 28,
            "line_range": [1],
        }
    ],
}

SARIF_PAYLOAD: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "semanticVersion": "2.20.1",
                    "rules": [
                        {
                            "id": "py/code-injection",
                            "name": "CodeInjection",
                            "shortDescription": {"text": "Code injection"},
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-095"],
                                "security-severity": "9.1",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "py/code-injection",
                    "ruleIndex": 0,
                    "message": {"text": "User input reaches eval."},
                    "partialFingerprints": {"primaryLocationLineHash": "codeql-eval"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 10,
                                    "endLine": 1,
                                    "endColumn": 28,
                                    "snippet": {"text": "eval(user_input)"},
                                },
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

JOERN_PAYLOAD: dict[str, Any] = {
    "findings": [
        {
            "ruleId": "joern/command-injection",
            "message": "Tainted value reaches a command sink.",
            "file": "src/app.py",
            "start": {"line": 0, "column": 9},
            "end": {"line": 0, "column": 28},
            "cwe": "CWE-95",
            "severity": "high",
        }
    ]
}


def semgrep_executable(tmp_path: Path, *, stdout_payload: Any = None) -> Path:
    payload = stdout_payload or SEMGREP_PAYLOAD
    return make_executable(
        tmp_path,
        "fake-semgrep",
        f"""
        import json
        import sys

        if "--version" in sys.argv:
            print("1.99.0")
            raise SystemExit(0)

        print(json.dumps({payload!r}))
        raise SystemExit(1)
        """,
    )


def bandit_executable(tmp_path: Path) -> Path:
    return make_executable(
        tmp_path,
        "fake-bandit",
        f"""
        import json
        import sys

        if "--version" in sys.argv:
            print("bandit 1.8.6")
            raise SystemExit(0)

        print(json.dumps({BANDIT_PAYLOAD!r}))
        print("bandit diagnostic on stderr", file=sys.stderr)
        raise SystemExit(1)
        """,
    )


def codeql_executable(tmp_path: Path) -> Path:
    return make_executable(
        tmp_path,
        "fake-codeql",
        f"""
        import json
        import sys
        from pathlib import Path

        if sys.argv[1:2] == ["version"]:
            print("CodeQL command-line toolchain release 2.20.1.")
            raise SystemExit(0)

        if "database" in sys.argv and "analyze" in sys.argv:
            output = next(
                arg.split("=", 1)[1]
                for arg in sys.argv
                if arg.startswith("--output=")
            )
            Path(output).write_text(json.dumps({SARIF_PAYLOAD!r}), encoding="utf-8")
            raise SystemExit(0)

        print("unexpected CodeQL invocation", file=sys.stderr)
        raise SystemExit(2)
        """,
    )


def joern_executable(tmp_path: Path, *, version: str = "4.0.0") -> Path:
    return make_executable(
        tmp_path,
        "fake-joern",
        f"""
        import json
        import sys

        if "--version" in sys.argv:
            print("Joern version {version}")
            raise SystemExit(0)

        print(json.dumps({JOERN_PAYLOAD!r}))
        raise SystemExit(0)
        """,
    )


def test_semgrep_adapter_runs_subprocess_and_normalizes_findings(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = semgrep_executable(tmp_path)
    adapter = SemgrepAdapter(SemgrepConfig(executable=str(executable), timeout_seconds=10))

    result = adapter.scan(root)

    assert result.status is ScanStatus.OK
    assert result.succeeded is True
    assert result.version == "1.99.0"
    assert result.availability.available is True
    assert result.execution is not None
    assert result.execution.return_code == 1
    assert result.execution.argv[0] == str(executable.resolve())
    assert "--json" in result.execution.argv
    assert "src/app.py" in result.execution.stdout
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "python.lang.security.audit.eval-detected"
    assert finding.cwe == "CWE-95"
    assert finding.location.path == "src/app.py"
    assert (finding.location.start_line, finding.location.start_column) == (0, 9)
    assert finding.tool_version == "1.99.0"
    assert finding.config_hash == result.config_hash
    assert result.configuration["timeoutSeconds"] == 10
    assert len(result.config_hash) == 64


def test_bandit_adapter_captures_stderr_and_maps_cwe(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = bandit_executable(tmp_path)
    adapter = BanditAdapter(BanditConfig(executable=str(executable), timeout_seconds=10))

    result = adapter.scan(root)

    assert result.status is ScanStatus.PARTIAL
    assert result.execution is not None
    assert "bandit diagnostic on stderr" in result.execution.stderr
    assert any("Bandit stderr" in warning for warning in result.warnings)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "B307"
    assert finding.cwe == "CWE-95"
    assert finding.severity == "high"
    assert finding.tool == "bandit"


def test_codeql_adapter_requires_license_and_analyzes_configured_database(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = codeql_executable(tmp_path)
    database = tmp_path / "codeql-db"
    database.mkdir()
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(executable),
            database_path=database,
            query_suites=("codeql/python-queries",),
            license_accepted=True,
            timeout_seconds=10,
        )
    )

    result = adapter.scan(root)

    assert result.status is ScanStatus.OK
    assert result.version == "2.20.1"
    assert result.execution is not None
    assert "database" in result.execution.argv
    assert str(database) in result.execution.argv
    assert "codeql/python-queries" in result.execution.argv
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.tool == "codeql"
    assert finding.rule_id == "py/code-injection"
    assert finding.cwe == "CWE-95"
    assert finding.severity == "critical"


def test_codeql_without_license_acceptance_is_explicitly_unavailable(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = codeql_executable(tmp_path)
    database = tmp_path / "codeql-db"
    database.mkdir()
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(executable),
            database_path=database,
            query_suites=("codeql/python-queries",),
            license_accepted=False,
        )
    )

    result = adapter.scan(root)

    assert result.status is ScanStatus.UNAVAILABLE
    assert result.succeeded is False
    assert result.reason_code == "E_TOOL_LICENSE_NOT_ACCEPTED"
    assert result.findings == ()
    assert result.execution is None


def test_codeql_without_a_database_is_explicitly_unavailable(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = codeql_executable(tmp_path)
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(executable),
            query_suites=("codeql/python-queries",),
            license_accepted=True,
        )
    )

    result = adapter.scan(root)

    assert result.status is ScanStatus.UNAVAILABLE
    assert result.reason_code == "E_TOOL_NOT_CONFIGURED"
    assert result.findings == ()


def test_joern_adapter_uses_configured_cpg_and_script(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = joern_executable(tmp_path)
    cpg = tmp_path / "app.cpg"
    cpg.mkdir()
    script = tmp_path / "query.sc"
    script.write_text('println("[]")\n', encoding="utf-8")
    adapter = JoernAdapter(
        JoernConfig(
            executable=str(executable),
            cpg_path=cpg,
            script_path=script,
            timeout_seconds=10,
        )
    )

    result = adapter.scan(root)

    assert result.status is ScanStatus.OK
    assert result.version == "4.0.0"
    assert result.execution is not None
    assert "--script" in result.execution.argv
    assert str(script) in result.execution.argv
    assert f"cpgPath={cpg}" in result.execution.argv
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.tool == "joern"
    assert finding.rule_id == "joern/command-injection"
    assert finding.cwe == "CWE-95"


def test_joern_version_below_minimum_is_unsupported(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = joern_executable(tmp_path, version="1.1.0")
    cpg = tmp_path / "app.cpg"
    cpg.mkdir()
    script = tmp_path / "query.sc"
    script.write_text('println("[]")\n', encoding="utf-8")
    adapter = JoernAdapter(
        JoernConfig(
            executable=str(executable),
            cpg_path=cpg,
            script_path=script,
            minimum_version="2.0.0",
        )
    )

    result = adapter.scan(root)

    assert result.status is ScanStatus.UNAVAILABLE
    assert result.reason_code == "E_TOOL_UNSUPPORTED_VERSION"
    assert result.findings == ()


def test_timeout_is_reported_and_not_treated_as_an_empty_success(tmp_path) -> None:
    root = write_workspace(tmp_path)
    executable = make_executable(
        tmp_path,
        "slow-semgrep",
        """
        import sys
        import time

        if "--version" in sys.argv:
            print("1.99.0")
            raise SystemExit(0)

        time.sleep(10)
        """,
    )
    adapter = SemgrepAdapter(SemgrepConfig(executable=str(executable), timeout_seconds=0.2))

    result = adapter.scan(root)

    assert result.status is ScanStatus.TIMEOUT
    assert result.succeeded is False
    assert result.findings == ()
    assert result.execution is not None
    assert result.execution.timed_out is True
    assert result.reason_code == "E_ANALYZER_TIMEOUT"


def test_missing_tool_is_not_reported_as_a_successful_scan(tmp_path) -> None:
    root = write_workspace(tmp_path)
    adapter = SemgrepAdapter(SemgrepConfig(executable=str(tmp_path / "missing-semgrep")))

    result = adapter.scan(root)

    assert result.status is ScanStatus.UNAVAILABLE
    assert result.succeeded is False
    assert result.reason_code == "E_TOOL_MISSING"
    assert result.findings == ()
    assert result.execution is None


def test_runner_deduplicates_overlapping_findings_across_tools(tmp_path) -> None:
    root = write_workspace(tmp_path)
    semgrep = SemgrepAdapter(
        SemgrepConfig(
            executable=str(semgrep_executable(tmp_path)),
            timeout_seconds=10,
        )
    )
    database = tmp_path / "codeql-db"
    database.mkdir()
    codeql = CodeQLAdapter(
        CodeQLConfig(
            executable=str(codeql_executable(tmp_path)),
            database_path=database,
            query_suites=("codeql/python-queries",),
            license_accepted=True,
            timeout_seconds=10,
        )
    )
    runner = StaticAnalysisRunner([semgrep, codeql])

    result = runner.scan(root)

    assert result.status is ScanStatus.OK
    assert result.available_tools == ("semgrep", "codeql")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert set(finding.rule_ids) == {
        "python.lang.security.audit.eval-detected",
        "py/code-injection",
    }
    assert set(finding.tools) == {"semgrep", "codeql"}
    assert finding.severity == "critical"
    assert len(finding.related) == 1
    assert [scan.version for scan in result.scans] == ["1.99.0", "2.20.1"]


def test_runner_reports_missing_tools_instead_of_an_empty_success(tmp_path) -> None:
    root = write_workspace(tmp_path)
    runner = StaticAnalysisRunner(
        [SemgrepAdapter(SemgrepConfig(executable=str(tmp_path / "missing-semgrep")))]
    )

    result = runner.scan(root)

    assert result.status is ScanStatus.UNAVAILABLE
    assert result.findings == ()
    assert result.unavailable_tools == ("semgrep",)
    assert any("semgrep was unavailable" in warning for warning in result.warnings)


def test_runner_rejects_unknown_tool_selection(tmp_path) -> None:
    root = write_workspace(tmp_path)
    runner = StaticAnalysisRunner(
        [
            SemgrepAdapter(
                SemgrepConfig(
                    executable=str(semgrep_executable(tmp_path)),
                    timeout_seconds=10,
                )
            )
        ]
    )

    try:
        runner.scan(root, tools=("bandit",))
    except ValueError as exc:
        assert "not configured" in str(exc)
    else:  # pragma: no cover - explicit failure
        raise AssertionError("unknown tool selection should fail")
