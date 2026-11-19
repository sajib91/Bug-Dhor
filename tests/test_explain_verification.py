from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.explain.repair import build_patch, recommend_repair
from bugdhor_ast.explain.verification import (
    CheckStatus,
    VerificationResult,
    VerificationStatus,
    signature_for_finding,
    verify_repair,
)
from bugdhor_ast.flow import FlowEngine, taint_diagnostics

JS_BEFORE = "const q = req.query.user;\ndocument.body.innerHTML = q;\n"
JAVA_BEFORE = (
    "class C {\n"
    "  void f(HttpServletRequest request, Statement stmt) {\n"
    "    String q = request.getParameter(\"q\");\n"
    "    stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + q + \"'\");\n"
    "  }\n"
    "}\n"
)
PYTHON_BEFORE = "def f():\n    return missing_name\n"
PYTHON_AFTER = "def f():\n    return 1\n"


def taint_finding(source, language, file):
    flow = FlowEngine().analyze_source(source, language, file=file)
    return next(item.to_dict() for item in taint_diagnostics(flow))


def repair_case(source, language, file):
    finding = taint_finding(source, language, file)
    recommendation = recommend_repair(
        finding, source_code=source, file=file
    )
    assert recommendation.proposed_code is not None
    after = source.replace(
        recommendation.original_code or "", recommendation.proposed_code, 1
    )
    patch = build_patch(recommendation, source, file=file)
    return finding, patch, after


def check_by_id(result, check_id):
    return next(item for item in result.checks if item.id == check_id)


def test_javascript_repair_is_verified_with_matching_patch():
    finding, patch, after = repair_case(JS_BEFORE, "javascript", "sample.js")

    result = verify_repair(
        finding,
        after,
        source_before=JS_BEFORE,
        patch=patch,
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.scope == "static_reanalysis"
    assert result.summary["target_before"] == 1
    assert result.summary["target_after"] == 0
    assert result.summary["target_resolved"] is True
    assert result.summary["new_finding_count"] == 0
    for check_id in ("baseline", "reparse", "target_resolution", "new_findings", "patch_identity"):
        assert check_by_id(result, check_id).status is CheckStatus.PASS
    assert result.evidence.unavailable == ()
    assert any("functional correctness" in item for item in result.limitations)


def test_java_repair_is_verified_with_matching_patch():
    finding, patch, after = repair_case(JAVA_BEFORE, "java", "Sample.java")

    result = verify_repair(
        finding,
        after,
        source_before=JAVA_BEFORE,
        patch=patch,
        file="Sample.java",
        language="java",
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.signature.rule_id == "JAVA-TAINT001"
    assert result.summary["target_resolved"] is True
    assert check_by_id(result, "patch_identity").status is CheckStatus.PASS


def test_python_detection_repair_is_partially_verified_without_patch():
    detection = BugDhorDetectionEngine().analyze_source(
        PYTHON_BEFORE, "python", file="sample.py"
    )
    finding = next(item.to_dict() for item in detection.diagnostics)

    result = verify_repair(
        finding,
        PYTHON_AFTER,
        source_before=PYTHON_BEFORE,
        file="sample.py",
        language="python",
    )

    assert result.status is VerificationStatus.PARTIALLY_VERIFIED
    assert result.summary["target_resolved"] is True
    assert check_by_id(result, "patch_identity").status is CheckStatus.UNAVAILABLE
    assert any(item.id == "verify.patch" for item in result.evidence.unavailable)


def test_remaining_target_finding_fails_verification():
    finding = taint_finding(JS_BEFORE, "javascript", "sample.js")

    result = verify_repair(
        finding,
        JS_BEFORE,
        source_before=JS_BEFORE,
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.FAILED
    assert result.summary["target_resolved"] is False
    assert check_by_id(result, "target_resolution").status is CheckStatus.FAIL


def test_syntax_error_after_repair_fails_verification():
    finding = taint_finding(JS_BEFORE, "javascript", "sample.js")

    result = verify_repair(
        finding,
        "const q = ;\n",
        source_before=JS_BEFORE,
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.FAILED
    assert check_by_id(result, "reparse").status is CheckStatus.FAIL


def test_new_finding_after_repair_fails_verification():
    finding, _, after = repair_case(JS_BEFORE, "javascript", "sample.js")
    changed = after + "console.log(missingName);\n"

    result = verify_repair(
        finding,
        changed,
        source_before=JS_BEFORE,
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.FAILED
    assert result.summary["new_finding_count"] >= 1
    assert check_by_id(result, "new_findings").status is CheckStatus.FAIL
    assert result.evidence.heuristic == ()
    assert any(item.id == "verify.new_findings" for item in result.evidence.derived)


def test_modified_source_not_matching_patch_fails_verification():
    finding, patch, _ = repair_case(JS_BEFORE, "javascript", "sample.js")

    result = verify_repair(
        finding,
        JS_BEFORE,
        source_before=JS_BEFORE,
        patch=patch,
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.FAILED
    assert check_by_id(result, "patch_identity").status is CheckStatus.FAIL


def test_unreproduced_baseline_is_not_verified():
    finding = {
        "rule_id": "JS-TAINT001",
        "language": "javascript",
        "message": "Synthetic finding that no analyzer emits.",
        "file": "sample.js",
    }

    result = verify_repair(
        finding,
        "const a = 2;\n",
        source_before="const a = 1;\n",
        file="sample.js",
        language="javascript",
    )

    assert result.status is VerificationStatus.NOT_VERIFIED
    assert result.summary["target_before"] == 0
    assert check_by_id(result, "baseline").status is CheckStatus.UNAVAILABLE


def test_missing_modified_source_is_not_verified():
    finding = taint_finding(JS_BEFORE, "javascript", "sample.js")

    result = verify_repair(finding, "", file="sample.js")

    assert result.status is VerificationStatus.NOT_VERIFIED
    assert check_by_id(result, "inputs").status is CheckStatus.UNAVAILABLE


def test_verification_result_schema_round_trips():
    finding, patch, after = repair_case(JS_BEFORE, "javascript", "sample.js")
    result = verify_repair(
        finding,
        after,
        source_before=JS_BEFORE,
        patch=patch,
        file="sample.js",
        language="javascript",
    )

    serialized = result.to_dict()
    assert set(serialized) == {
        "schema_version",
        "status",
        "finding_id",
        "signature",
        "scope",
        "checks",
        "evidence",
        "summary",
        "confidence",
        "limitations",
    }
    assert VerificationResult.from_dict(serialized).to_dict() == serialized
    assert signature_for_finding(finding).rule_id == "JS-TAINT001"
