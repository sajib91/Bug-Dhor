"""End-to-end detection accuracy, false-positive handling, and coverage tests.

The engine is exercised through its public entry points. Tests assert the
behavior users rely on: known vulnerable patterns are classified with the right
CWE, obviously safe patterns do not produce findings, refuting context lowers
risk without silently deleting evidence, and unavailable analyzers are coverage
gaps rather than clean scans.
"""

from __future__ import annotations

import pytest

from bugdhor.detection.config import DetectionConfig
from bugdhor.detection.engine import DetectionEngine
from bugdhor.detection.llm import LLMClaim
from bugdhor.detection.models import (
    CalibratedProbability,
    EvidenceLocation,
    VulnerabilityCategory,
)
from bugdhor.static.models import (
    AvailabilityStatus,
    ScanStatus,
    SourceLocation,
    StaticAnalysisResult,
    StaticFinding,
    ToolAvailability,
    ToolScanResult,
)

_SPLIT_HASH = "b" * 64


def _static_finding(
    *,
    tool: str,
    rule_id: str,
    message: str,
    severity: str,
    line: int,
    path: str,
    cwes: tuple[str, ...] = (),
) -> StaticFinding:
    return StaticFinding(
        finding_id=f"{tool}-{rule_id}-{line}",
        tool=tool,
        rule_id=rule_id,
        message=message,
        severity=severity,
        location=SourceLocation(
            path=path,
            start_line=line,
            start_column=4,
            end_line=line,
            end_column=30,
        ),
        cwes=cwes,
        tool_version="1.0",
        config_hash="a" * 64,
    )


def _scan(
    tool: str,
    findings: tuple[StaticFinding, ...] = (),
    *,
    status: ScanStatus = ScanStatus.OK,
    available: bool = True,
    reason: str | None = None,
) -> ToolScanResult:
    availability = ToolAvailability(
        tool=tool,
        status=AvailabilityStatus.AVAILABLE if available else AvailabilityStatus.MISSING,
        executable=tool if available else None,
        reason_code=reason,
    )
    return ToolScanResult(
        tool=tool,
        status=status,
        availability=availability,
        version="1.0" if available else None,
        configuration={},
        config_hash="a" * 64,
        findings=findings,
        reason_code=reason,
    )


def _static_result(
    findings: tuple[StaticFinding, ...],
    scans: tuple[ToolScanResult, ...],
    *,
    status: ScanStatus = ScanStatus.OK,
) -> StaticAnalysisResult:
    return StaticAnalysisResult(status=status, findings=findings, scans=scans)


def _program_only() -> DetectionEngine:
    return DetectionEngine(expected_tools=())


def _categories(result) -> dict[str, tuple[str, str, int]]:
    return {
        finding.category.value: (
            finding.cwe,
            finding.severity,
            finding.location.start_line,
        )
        for finding in result.findings
    }


_MIXED_PYTHON = '''
import hashlib
import pickle
import subprocess

password = "supersecret123abc"

def get_user(request, cursor):
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
    subprocess.run(user, shell=True)
    eval(user)
    hashlib.md5(password.encode())
    pickle.loads(user)
'''


def test_python_taint_and_ast_detection_accuracy() -> None:
    result = _program_only().detect_source(_MIXED_PYTHON, path="app.py")
    found = _categories(result)
    assert found["sql_injection"] == ("CWE-89", "high", 9)
    assert found["command_injection"] == ("CWE-78", "critical", 10)
    assert found["code_injection"] == ("CWE-95", "critical", 11)
    assert found["hardcoded_secret"] == ("CWE-798", "high", 5)
    assert found["weak_cryptography"] == ("CWE-327", "medium", 12)
    assert found["unsafe_deserialization"] == ("CWE-502", "critical", 13)
    assert result.coverage.program_analysis is True
    assert result.unclassified == ()


def test_every_finding_carries_supporting_evidence_and_an_explanation() -> None:
    result = _program_only().detect_source(_MIXED_PYTHON, path="app.py")
    for finding in result.findings:
        assert finding.evidence
        assert finding.cwe_support
        assert finding.explanation
        assert finding.suggested_remediation
        assert finding.rule_ids
        assert "not a probability" in finding.explanation


def test_javascript_taint_detects_sql_and_xss() -> None:
    source = """
function handler(req, res) {
  const user = req.query.name;
  res.send("<h1>" + user + "</h1>");
  const query = req.query.q;
  db.query(`SELECT * FROM t WHERE a = ${query}`);
}
"""
    result = _program_only().detect_source(source, path="app.js")
    found = _categories(result)
    assert found["xss"][:2] == ("CWE-79", "high")
    assert found["sql_injection"][:2] == ("CWE-89", "high")
    assert found["xss"][2] == 3
    assert found["sql_injection"][2] == 5


def test_python_path_traversal_taint() -> None:
    source = """
import os

def read(request):
    name = request.args.get("name")
    open(name)
"""
    result = _program_only().detect_source(source, path="app.py")
    ((_, cwe, severity, line),) = [
        (finding.category, finding.cwe, finding.severity, finding.location.start_line)
        for finding in result.findings
    ]
    assert cwe == "CWE-22"
    assert severity == "high"
    assert line == 5


def test_ast_hardcoded_secret_and_insecure_tls() -> None:
    secret = 'password = "supersecret123abc"\n'
    tls = 'import requests\nrequests.get("https://example.com", verify=False)\n'
    secret_result = _program_only().detect_source(secret, path="app.py")
    tls_result = _program_only().detect_source(tls, path="app.py")
    assert {finding.category for finding in secret_result.findings} == {
        VulnerabilityCategory.HARDCODED_SECRET
    }
    assert {finding.category for finding in tls_result.findings} == {
        VulnerabilityCategory.INSECURE_TLS
    }


def test_parameterized_query_is_not_a_finding() -> None:
    source = """
def find_user(request, cursor):
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = %s", (user,))
"""
    result = _program_only().detect_source(source, path="app.py")
    assert result.findings == ()
    assert result.status == "ok"


def test_literal_sql_query_is_not_a_finding() -> None:
    source = """
def all_users(cursor):
    cursor.execute("SELECT * FROM users")
"""
    result = _program_only().detect_source(source, path="app.py")
    assert result.findings == ()


def test_placeholder_and_environment_secrets_are_not_findings() -> None:
    source = """
import os

password = "changeme"
api_key = os.environ["API_KEY"]
"""
    result = _program_only().detect_source(source, path="app.py")
    assert result.findings == ()


def test_sanitized_xss_is_downgraded_but_not_deleted() -> None:
    source = """
function render(req) {
  const user = req.query.name;
  document.getElementById("out").innerHTML = DOMPurify.sanitize(user);
}
"""
    result = _program_only().detect_source(source, path="app.js")
    (finding,) = result.findings
    assert finding.category is VulnerabilityCategory.XSS
    assert finding.severity == "low"
    assert finding.risk.heuristic.refutation_penalty > 0.0
    assert any(item.polarity.value == "refutes" for item in finding.evidence)
    assert "taint.observed-sanitizer" in {
        item.rule_id for item in finding.evidence if item.polarity.value == "refutes"
    }
    assert "sanitizer" in finding.explanation.lower()


def test_unreachable_sink_is_refuted_by_cfg_context() -> None:
    source = """
def find(request, cursor):
    return 1
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
"""
    result = _program_only().detect_source(source, path="app.py")
    (finding,) = result.findings
    assert finding.category is VulnerabilityCategory.SQL_INJECTION
    assert finding.severity == "low"
    assert finding.risk.heuristic.value < 0.5
    assert finding.risk.heuristic.refutation_penalty > 0.0
    assert "cfg.unreachable-sink" in {item.rule_id for item in finding.evidence}
    assert "unreachable" in finding.explanation.lower()


def test_static_only_semgrep_finding_is_classified() -> None:
    path = "app.py"
    finding = _static_finding(
        tool="semgrep",
        rule_id="python.lang.security.audit.ssrf",
        message="User-controlled URL passed to an HTTP client.",
        severity="high",
        line=2,
        path=path,
        cwes=("CWE-918",),
    )
    static = _static_result(
        (finding,),
        (_scan("semgrep", (finding,)),),
    )
    source = """
def fetch(url):
    return requests.get(url)
"""
    engine = DetectionEngine(
        expected_tools=("semgrep",),
        config=DetectionConfig(enrich_cfg=False, enrich_dfg=False),
    )
    result = engine.detect_source(source, path=path, static=static)
    (detected,) = result.findings
    assert detected.category is VulnerabilityCategory.SSRF
    assert detected.cwe == "CWE-918"
    assert detected.families == ("static_tool",)
    assert detected.evidence_sources == ("semgrep",)


def test_static_and_program_analysis_evidence_merge_and_raise_risk() -> None:
    source = """
def find_user(request, cursor):
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
"""
    baseline = _program_only().detect_source(source, path="app.py")
    (baseline_finding,) = baseline.findings
    semgrep = _static_finding(
        tool="semgrep",
        rule_id="python.lang.security.audit.formatted-sql-query",
        message="Formatted SQL query.",
        severity="high",
        line=3,
        path="app.py",
        cwes=("CWE-89",),
    )
    engine = DetectionEngine(expected_tools=("semgrep",))
    merged = engine.detect_source(
        source,
        path="app.py",
        static=_static_result((semgrep,), (_scan("semgrep", (semgrep,)),)),
    )
    (finding,) = merged.findings
    assert finding.category is VulnerabilityCategory.SQL_INJECTION
    assert set(finding.families) == {"program_analysis", "static_tool"}
    assert finding.risk.heuristic.value > baseline_finding.risk.heuristic.value
    assert any(item.source == "semgrep" for item in finding.evidence)


def test_unsupported_static_evidence_is_unclassified_without_a_fabricated_cwe() -> None:
    unknown = _static_finding(
        tool="semgrep",
        rule_id="acme.custom.check",
        message="Review this code because policy says so.",
        severity="medium",
        line=0,
        path="app.py",
    )
    static = _static_result((unknown,), (_scan("semgrep", (unknown,)),))
    result = DetectionEngine(expected_tools=("semgrep",)).detect_source(
        "value = 1\n",
        path="app.py",
        static=static,
    )
    assert result.findings == ()
    (candidate,) = result.unclassified
    assert candidate.heuristic_risk is not None
    assert candidate.evidence
    assert all(item.cwe is None for item in candidate.evidence)


def test_expected_tools_absent_from_a_run_are_coverage_gaps() -> None:
    result = DetectionEngine().detect_source(_MIXED_PYTHON, path="app.py")
    assert result.status == "partial"
    assert result.coverage.complete is False
    assert set(result.coverage.tools_missing) == {"semgrep", "bandit", "codeql", "joern"}
    assert result.coverage.no_findings_conclusive is False
    for tool in ("semgrep", "bandit", "codeql", "joern"):
        assert any(tool in gap for gap in result.coverage.evidence_gaps)


def test_missing_and_timed_out_tools_are_never_a_clean_scan() -> None:
    source = """
def find_user(request, cursor):
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
"""
    static = _static_result(
        (),
        (
            _scan("semgrep"),
            _scan("bandit"),
            _scan("codeql", status=ScanStatus.TIMEOUT),
            _scan("joern", available=False, reason="missing"),
        ),
        status=ScanStatus.PARTIAL,
    )
    result = DetectionEngine(
        expected_tools=("semgrep", "bandit", "codeql", "joern")
    ).detect_source(source, path="app.py", static=static)
    assert result.status == "partial"
    assert result.coverage.tools_timed_out == ("codeql",)
    assert "joern" in result.coverage.tools_missing
    assert result.coverage.tools_available == ("semgrep", "bandit", "codeql")
    assert any("timed out" in gap for gap in result.coverage.evidence_gaps)
    assert any("unavailable" in gap for gap in result.coverage.evidence_gaps)


def test_a_complete_four_tool_clean_run_is_conclusive() -> None:
    static = _static_result(
        (),
        (
            _scan("semgrep"),
            _scan("bandit"),
            _scan("codeql"),
            _scan("joern"),
        ),
    )
    result = DetectionEngine(
        expected_tools=("semgrep", "bandit", "codeql", "joern")
    ).detect_source("value = 1\n", path="app.py", static=static)
    assert result.status == "ok"
    assert result.coverage.complete is True
    assert result.coverage.no_findings_conclusive is True
    assert result.findings == ()


def test_program_analysis_only_run_can_be_complete_when_expected() -> None:
    result = DetectionEngine(expected_tools=()).detect_source(
        "value = 1\n",
        path="app.py",
    )
    assert result.status == "ok"
    assert result.coverage.complete is True
    assert result.coverage.tools_missing == ()


def _llm_claim(**overrides: object) -> LLMClaim:
    payload: dict[str, object] = {
        "provider": "acme",
        "model": "auditor",
        "model_version": "2026-01",
        "location": EvidenceLocation(
            path="app.py",
            start_line=1,
            start_column=4,
            end_line=1,
            end_column=20,
        ),
        "confidence": 0.9,
        "category": "sql_injection",
        "title": "Possible SQL injection",
    }
    payload.update(overrides)
    return LLMClaim(**payload)  # type: ignore[arg-type]


def test_llm_claim_alone_is_capped_and_never_high_severity() -> None:
    result = _program_only().detect_source(
        "def handler():\n    return 1\n",
        path="app.py",
        llm_claims=(_llm_claim(),),
    )
    (finding,) = result.findings
    assert finding.category is VulnerabilityCategory.SQL_INJECTION
    assert finding.risk.heuristic.value <= 0.35
    assert finding.severity in {"info", "low"}
    assert finding.families == ("llm",)
    assert result.coverage.llm_accepted == 1
    assert result.coverage.llm_rejected == 0
    assert "uncalibrated" in str([item.detail for item in finding.evidence]).lower()


def test_incompatible_and_unclassifiable_llm_claims_are_rejected() -> None:
    claims = (
        _llm_claim(compatible=False),
        _llm_claim(category="unknown"),
        _llm_claim(confidence=0.1),
    )
    result = _program_only().detect_source(
        "def handler():\n    return 1\n",
        path="app.py",
        llm_claims=claims,
    )
    assert result.findings == ()
    assert result.coverage.llm_accepted == 0
    assert result.coverage.llm_rejected == 3
    claim_warnings = [warning for warning in result.warnings if warning.startswith("acme/")]
    assert len(claim_warnings) == 3


def test_llm_claim_calibration_does_not_calibrate_the_finding_by_itself() -> None:
    calibrated = CalibratedProbability(
        value=0.95,
        calibrator_artifact_id="llm-calibrator",
        method="platt",
        dataset_id="llm-bench",
        split_hash=_SPLIT_HASH,
        brier_score=0.1,
        expected_calibration_error=0.05,
    )
    result = _program_only().detect_source(
        "def handler():\n    return 1\n",
        path="app.py",
        llm_claims=(_llm_claim(calibration=calibrated),),
    )
    (finding,) = result.findings
    assert finding.risk.calibrated is None
    assert finding.risk.probability is None
    assert finding.risk.to_contract_dict()["kind"] == "heuristic"


def test_llm_analyzer_interface_collects_claims() -> None:
    class Analyzer:
        analyzer_id = "acme-analyzer"

        def analyze(self, _parsed) -> tuple[LLMClaim, ...]:
            return (_llm_claim(),)

    result = _program_only().detect_source(
        "def handler():\n    return 1\n",
        path="app.py",
        llm_analyzer=Analyzer(),
    )
    assert result.coverage.llm_accepted == 1
    assert len(result.findings) == 1


def test_finding_ids_are_stable_across_identical_runs() -> None:
    first = _program_only().detect_source(_MIXED_PYTHON, path="app.py")
    second = _program_only().detect_source(_MIXED_PYTHON, path="app.py")
    assert [item.finding_id for item in first.findings] == [
        item.finding_id for item in second.findings
    ]


def test_min_risk_filter_is_applied() -> None:
    result = DetectionEngine(
        expected_tools=(),
        config=DetectionConfig(min_risk=0.9),
    ).detect_source(_MIXED_PYTHON, path="app.py")
    assert result.findings
    assert all(finding.risk.heuristic.value >= 0.9 for finding in result.findings)


def test_detect_file_reads_and_localizes(tmp_path) -> None:
    path = tmp_path / "app.py"
    path.write_text(
        'def f(request):\n    eval(request.args.get("code"))\n',
        encoding="utf-8",
    )
    result = _program_only().detect_file(path)
    (finding,) = result.findings
    assert finding.category is VulnerabilityCategory.CODE_INJECTION
    assert finding.location.path == str(path)
    assert finding.location.start_line == 1


@pytest.mark.parametrize(
    "source",
    (
        'password = "changeme"\n',
        'def f(cursor):\n    cursor.execute("SELECT * FROM t")\n',
    ),
)
def test_benign_sources_do_not_produce_findings(source: str) -> None:
    result = _program_only().detect_source(source, path="app.py")
    assert result.findings == ()
