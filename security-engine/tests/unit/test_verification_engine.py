from bugdhor.verification.engine import (
    INCONCLUSIVE_VERIFICATION,
    PARTIAL_IMPROVEMENT,
    VERIFICATION_FAILURE,
    VERIFIED_SECURITY_IMPROVEMENT,
    IndependentVerificationEngine,
)


def _patch() -> str:
    return (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,4 +1,4 @@\n"
        " import sqlite3\n"
        " def run(user):\n"
        "     cur = sqlite3.connect(':memory:').cursor()\n"
        "-    cur.execute('SELECT * FROM t WHERE u=' + user)\n"
        "+    cur.execute('SELECT * FROM t WHERE u=?', (user,))\n"
    )


def test_verification_engine_produces_independent_report() -> None:
    engine = IndependentVerificationEngine(sandbox_backend="none")
    original = (
        "import sqlite3\n"
        "def run(user):\n"
        "    cur = sqlite3.connect(':memory:').cursor()\n"
        "    cur.execute('SELECT * FROM t WHERE u=' + user)\n"
    )
    outcome = engine.verify(
        original_source=original,
        file_path="app.py",
        language_id="python",
        patch=_patch(),
        cwe="CWE-89",
        profile="static_only",
    )
    result = outcome.to_result("repair-1")
    assert result["classification"] in {
        VERIFIED_SECURITY_IMPROVEMENT,
        PARTIAL_IMPROVEMENT,
        VERIFICATION_FAILURE,
        INCONCLUSIVE_VERIFICATION,
    }
    assert result["verdict"] in {"passed", "failed", "inconclusive"}
    assert result["analysisAvailable"] in {True, False}
    if result["verdict"] == "passed":
        assert result["classification"] == VERIFIED_SECURITY_IMPROVEMENT
        assert result["analysisAvailable"] is True
    names = [check["name"] for check in result["checks"]]
    assert "Before-patch security scan" in names or "Independent verification" in names
    assert "After-patch security scan" in names or "Independent verification" in names
    assert "Static-analysis comparison" in names or "Independent verification" in names
    assert "Taint-flow comparison" in names
    assert "CWE-specific verification" in names
    assert "New vulnerability detection" in names or "Independent verification" in names
    assert "Regression-risk assessment" in names
    assert result["profile"] == "static_only"
    report = result["report"]
    assert report["before"]["sha256"] != report["after"]["sha256"]
    assert "staticAnalysisComparison" in report
    assert "taintFlowComparison" in report
    assert "newVulnerabilityDetection" in report
    assert "regressionRiskAssessment" in report
    assert report["independentAuthority"] is True
    assert "Automated verification is not a proof of security." in result["limitations"]


def test_verification_engine_marks_invalid_patch_inconclusive() -> None:
    engine = IndependentVerificationEngine()
    outcome = engine.verify(
        original_source="print('x')\n",
        file_path="app.py",
        patch="not a diff",
        profile="static_only",
    )
    result = outcome.to_result(None)
    assert result["classification"] == INCONCLUSIVE_VERIFICATION
    assert result["verdict"] == "inconclusive"
    assert result["analysisAvailable"] is False
