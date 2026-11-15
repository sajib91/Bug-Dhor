from __future__ import annotations

import json
from typing import Any

from craftsec.static.cwe import extract_cwes, normalize_cwe
from craftsec.static.normalize import (
    deduplicate_findings,
    normalize_path,
    normalize_severity,
    parse_bandit,
    parse_joern,
    parse_sarif,
    parse_semgrep,
    severity_from_score,
)


def semgrep_payload(
    *,
    rule_id: str = "python.lang.security.audit.eval-detected",
    path: str = "src/app.py",
    line: int = 4,
    cwe: str = "CWE-95: Improper Neutralization of Directives",
    severity: str = "ERROR",
) -> dict[str, Any]:
    return {
        "version": "1.99.0",
        "results": [
            {
                "check_id": rule_id,
                "path": path,
                "start": {"line": line, "col": 5},
                "end": {"line": line, "col": 16},
                "fingerprint": f"semgrep-{rule_id}",
                "extra": {
                    "message": "Avoid use of eval.",
                    "severity": severity,
                    "lines": "result = eval(user_input)",
                    "metadata": {
                        "shortDescription": "Eval detected",
                        "cwe": [cwe],
                    },
                },
            }
        ],
        "errors": [],
    }


def sarif_payload(
    *,
    rule_id: str = "py/sql-injection",
    path: str = "src/app.py",
    line: int = 4,
    tag: str = "external/cwe/cwe-089",
    score: str = "8.8",
    level: str = "error",
) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.20.1",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": "SqlInjection",
                                "shortDescription": {"text": "SQL injection"},
                                "defaultConfiguration": {"level": level},
                                "properties": {
                                    "tags": ["security", tag],
                                    "security-severity": score,
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "ruleIndex": 0,
                        "message": {"text": "This SQL query depends on user input."},
                        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": path},
                                    "region": {
                                        "startLine": line,
                                        "startColumn": 5,
                                        "endLine": line,
                                        "endColumn": 19,
                                        "snippet": {"text": "cursor.execute(query)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_parse_semgrep_preserves_rule_and_converts_coordinates(tmp_path) -> None:
    parsed = parse_semgrep(
        semgrep_payload(),
        workspace_root=tmp_path,
        config_hash="a" * 64,
    )

    assert parsed.warnings == ()
    assert parsed.tool_version == "1.99.0"
    assert len(parsed.findings) == 1
    finding = parsed.findings[0]
    assert finding.rule_id == "python.lang.security.audit.eval-detected"
    assert finding.tool == "semgrep"
    assert finding.cwe == "CWE-95"
    assert finding.severity == "high"
    assert finding.location.path == "src/app.py"
    assert (finding.location.start_line, finding.location.start_column) == (3, 4)
    assert (finding.location.end_line, finding.location.end_column) == (3, 15)
    assert finding.evidence == "result = eval(user_input)"
    assert finding.tool_version == "1.99.0"
    assert finding.config_hash == "a" * 64
    assert finding.raw["check_id"] == finding.rule_id


def test_semgrep_malformed_records_become_warnings(tmp_path) -> None:
    payload = semgrep_payload()
    payload["results"].append({"check_id": "missing-path"})
    payload["errors"] = [{"message": "some files were skipped"}]

    parsed = parse_semgrep(payload, workspace_root=tmp_path)

    assert len(parsed.findings) == 1
    assert any("some files were skipped" in warning for warning in parsed.warnings)
    assert any("was skipped" in warning for warning in parsed.warnings)


def test_parse_bandit_maps_test_id_to_cwe_and_coordinates(tmp_path) -> None:
    payload = {
        "errors": [],
        "results": [
            {
                "filename": "src/db.py",
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": ("Possible SQL injection through string-based query construction."),
                "line_number": 12,
                "col_offset": 4,
                "end_col_offset": 30,
                "line_range": [12],
            }
        ],
    }

    parsed = parse_bandit(payload, workspace_root=tmp_path, tool_version="1.8.6")

    assert parsed.warnings == ()
    finding = parsed.findings[0]
    assert finding.rule_id == "B608"
    assert finding.rule_name == "hardcoded_sql_expressions"
    assert finding.cwe == "CWE-89"
    assert finding.severity == "medium"
    assert (finding.location.start_line, finding.location.start_column) == (11, 4)
    assert (finding.location.end_line, finding.location.end_column) == (11, 30)
    assert finding.tool_version == "1.8.6"


def test_bandit_explicit_cwe_metadata_wins_over_the_fallback_map(tmp_path) -> None:
    payload = {
        "results": [
            {
                "filename": "src/app.py",
                "test_id": "B101",
                "issue_severity": "LOW",
                "issue_text": "Use of assert detected.",
                "line_number": 3,
                "col_offset": 0,
                "cwe": 617,
            }
        ]
    }

    finding = parse_bandit(payload, workspace_root=tmp_path).findings[0]

    assert finding.cwe == "CWE-617"


def test_parse_sarif_preserves_rule_cwe_and_security_severity(tmp_path) -> None:
    parsed = parse_sarif(sarif_payload(), workspace_root=tmp_path, tool="codeql")

    assert parsed.warnings == ()
    assert parsed.tool_version == "2.20.1"
    finding = parsed.findings[0]
    assert finding.tool == "codeql"
    assert finding.rule_id == "py/sql-injection"
    assert finding.rule_name == "SqlInjection"
    assert finding.cwe == "CWE-89"
    assert finding.severity == "high"
    assert (finding.location.start_line, finding.location.start_column) == (3, 4)
    assert finding.evidence == "cursor.execute(query)"
    assert finding.fingerprint == "abc123"


def test_parse_sarif_falls_back_to_level_without_a_score(tmp_path) -> None:
    payload = sarif_payload(score="", level="warning")

    finding = parse_sarif(payload, workspace_root=tmp_path).findings[0]

    assert finding.severity == "medium"


def test_parse_sarif_handles_file_uris_and_multiple_cwes(tmp_path) -> None:
    path = tmp_path / "src" / "app.py"
    path.parent.mkdir(parents=True)
    path.write_text("x = 1\n", encoding="utf-8")
    payload = sarif_payload(path=path.as_uri(), tag="external/cwe/cwe-078")

    finding = parse_sarif(payload, workspace_root=tmp_path).findings[0]

    assert finding.location.path == "src/app.py"
    assert finding.cwe == "CWE-78"


def test_parse_joern_accepts_nested_zero_based_locations(tmp_path) -> None:
    payload = {
        "findings": [
            {
                "ruleId": "joern/command-injection",
                "message": "Tainted command reaches ProcessBuilder.",
                "file": "src/run.py",
                "start": {"line": 7, "column": 2},
                "end": {"line": 7, "column": 18},
                "cwe": "CWE-78",
                "severity": "high",
            }
        ]
    }

    parsed = parse_joern(
        json.dumps(payload),
        workspace_root=tmp_path,
        tool_version="4.0.0",
    )

    assert parsed.warnings == ()
    finding = parsed.findings[0]
    assert finding.rule_id == "joern/command-injection"
    assert (finding.location.start_line, finding.location.start_column) == (7, 2)
    assert finding.cwe == "CWE-78"


def test_parse_joern_accepts_json_lines_and_flat_one_based_locations(tmp_path) -> None:
    text = "\n".join(
        [
            "INFO scanning CPG",
            (
                '{"ruleId": "joern/ssrf", "message": "Request target is attacker controlled.", '
                '"file": "src/http.py", "startLine": 4, "startColumn": 3, '
                '"endLine": 4, "endColumn": 9, "severity": "medium"}'
            ),
        ]
    )

    parsed = parse_joern(text, workspace_root=tmp_path)

    assert len(parsed.findings) == 1
    finding = parsed.findings[0]
    assert (finding.location.start_line, finding.location.start_column) == (3, 2)
    assert any("non-JSON" in warning for warning in parsed.warnings)


def test_deduplicate_overlapping_findings_preserves_every_rule_id(tmp_path) -> None:
    semgrep = parse_semgrep(
        semgrep_payload(rule_id="semgrep/sql-injection", cwe="CWE-89"),
        workspace_root=tmp_path,
    ).findings[0]
    codeql = parse_sarif(
        sarif_payload(rule_id="py/sql-injection", tag="external/cwe/cwe-089"),
        workspace_root=tmp_path,
    ).findings[0]

    merged = deduplicate_findings([semgrep, codeql])

    assert len(merged) == 1
    assert set(merged[0].rule_ids) == {"semgrep/sql-injection", "py/sql-injection"}
    assert set(merged[0].tools) == {"semgrep", "codeql"}
    assert merged[0].cwe == "CWE-89"
    assert len(merged[0].related) == 1


def test_deduplicate_keeps_non_overlapping_and_different_cwes_separate(tmp_path) -> None:
    sql = parse_semgrep(
        semgrep_payload(rule_id="semgrep/sql", line=4, cwe="CWE-89"),
        workspace_root=tmp_path,
    ).findings[0]
    xss = parse_semgrep(
        semgrep_payload(rule_id="semgrep/xss", line=4, cwe="CWE-79"),
        workspace_root=tmp_path,
    ).findings[0]
    distant_sql = parse_semgrep(
        semgrep_payload(rule_id="semgrep/sql-2", line=40, cwe="CWE-89"),
        workspace_root=tmp_path,
    ).findings[0]

    merged = deduplicate_findings([sql, xss, distant_sql])

    assert len(merged) == 3


def test_cwe_and_severity_helpers() -> None:
    assert normalize_cwe("CWE-089: example") == "CWE-89"
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe(79) == "CWE-79"
    assert normalize_cwe("not a cwe") is None
    assert extract_cwes(["CWE-79: xss", "cwe-089", 79]) == ("CWE-79", "CWE-89")
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity("WARNING") == "medium"
    assert severity_from_score("9.1") == "critical"
    assert severity_from_score("7.0") == "high"
    assert severity_from_score("0.0") == "info"


def test_normalize_path_handles_relative_absolute_and_file_uris(tmp_path) -> None:
    absolute = tmp_path / "src" / "app.py"
    absolute.parent.mkdir(parents=True)
    absolute.write_text("x = 1\n", encoding="utf-8")

    assert normalize_path("src/app.py", tmp_path) == "src/app.py"
    assert normalize_path(str(absolute), tmp_path) == "src/app.py"
    assert normalize_path(absolute.as_uri(), tmp_path) == "src/app.py"
