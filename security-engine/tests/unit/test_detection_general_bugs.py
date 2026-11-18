"""General-bug and expanded security rules in the detection engine.

These rules are explicit opt-in evidence: they are conservative structural
observations, not linter output, type-checker output, or calibrated
probabilities. Every case must produce a finding with an exact rule identifier
and an epistemic confidence label.
"""

from __future__ import annotations

import pytest

from bugdhor.detection.config import DetectionConfig
from bugdhor.detection.engine import DetectionEngine
from bugdhor.detection.models import VulnerabilityCategory

_GENERAL_CONFIG = DetectionConfig(
    enrich_general_bugs=True,
    enrich_cfg=False,
    enrich_dfg=False,
)

_RULES = [
    pytest.param(
        "def broken(:\n",
        "app.py",
        VulnerabilityCategory.SYNTAX_ERROR,
        "parser.syntax-error",
        id="parser-syntax-error",
    ),
    pytest.param(
        "print(missing_name)\n",
        "app.py",
        VulnerabilityCategory.UNDEFINED_VARIABLE,
        "ast.undefined-variable",
        id="undefined-variable",
    ),
    pytest.param(
        "unused_value = 1\n",
        "app.py",
        VulnerabilityCategory.UNUSED_VARIABLE,
        "ast.unused-variable",
        id="unused-variable",
    ),
    pytest.param(
        'total = "items: " + 3\n',
        "app.py",
        VulnerabilityCategory.TYPE_ERROR,
        "ast.string-number-addition",
        id="python-type-error",
    ),
    pytest.param(
        "value = None\nprint(value.name)\n",
        "app.py",
        VulnerabilityCategory.NULL_REFERENCE,
        "ast.null-reference-risk",
        id="null-reference",
    ),
    pytest.param(
        "try:\n    pass\nexcept Exception:\n    pass\n",
        "app.py",
        VulnerabilityCategory.UNHANDLED_EXCEPTION,
        "ast.silent-exception-handler",
        id="silent-exception-handler",
    ),
    pytest.param(
        "try { risky(); } finally { cleanup(); }\n",
        "app.js",
        VulnerabilityCategory.UNHANDLED_EXCEPTION,
        "ast.try-without-catch",
        id="try-without-catch",
    ),
    pytest.param(
        "handle = open('data.txt')\n",
        "app.py",
        VulnerabilityCategory.RESOURCE_HANDLE,
        "ast.unmanaged-open",
        id="unmanaged-open",
    ),
    pytest.param(
        "if True:\n    pass\n",
        "app.py",
        VulnerabilityCategory.SUSPICIOUS_CONTROL_FLOW,
        "ast.constant-condition",
        id="constant-condition",
    ),
    pytest.param(
        "ratio = 10 / 0\n",
        "app.py",
        VulnerabilityCategory.RUNTIME_ERROR,
        "ast.division-by-zero",
        id="division-by-zero",
    ),
    pytest.param(
        "def append(items=[]):\n    return items\n",
        "app.py",
        VulnerabilityCategory.COMMON_MISTAKE,
        "ast.mutable-default-argument",
        id="mutable-default-argument",
    ),
    pytest.param(
        "if (value == 1) { run(); }\n",
        "app.js",
        VulnerabilityCategory.COMMON_MISTAKE,
        "ast.loose-equality",
        id="loose-equality",
    ),
    pytest.param(
        "secret_value = load_secret()\nprint(secret_value)\n",
        "app.py",
        VulnerabilityCategory.SENSITIVE_EXPOSURE,
        "ast.sensitive-value-in-log",
        id="sensitive-value-in-log",
    ),
    pytest.param(
        "def fetch(destination):\n    return requests.get(destination)\n",
        "app.py",
        VulnerabilityCategory.SSRF,
        "ast.outbound-request-dynamic-url",
        id="dynamic-outbound-url",
    ),
    pytest.param(
        "upload = request.files['file']\nupload.save('/tmp/upload.bin')\n",
        "app.py",
        VulnerabilityCategory.UNSAFE_FILE_UPLOAD,
        "ast.upload-save-call",
        id="upload-save-call",
    ),
]


@pytest.mark.parametrize(("source", "path", "category", "rule_id"), _RULES)
def test_rule_emits_a_located_finding(
    source: str,
    path: str,
    category: VulnerabilityCategory,
    rule_id: str,
) -> None:
    engine = DetectionEngine(expected_tools=(), config=_GENERAL_CONFIG)

    result = engine.detect_source(source, path=path)
    matches = [
        finding
        for finding in result.findings
        if finding.category is category and rule_id in finding.rule_ids
    ]

    assert matches, f"{rule_id} did not produce a {category.value} finding"
    finding = matches[0]
    assert finding.cwe.startswith("CWE-")
    assert finding.location.start_line >= 0
    assert finding.location.end_line >= finding.location.start_line
    assert finding.confidence in {"observation", "inference", "hypothesis"}
    assert "not a calibrated probability" in finding.confidence_basis
    assert finding.uncertainty
    assert finding.detection_method
    assert finding.evidence
    assert finding.suggested_remediation


@pytest.mark.parametrize(("source", "path", "category", "rule_id"), _RULES)
def test_general_bugs_are_opt_in(
    source: str,
    path: str,
    category: VulnerabilityCategory,
    rule_id: str,
) -> None:
    engine = DetectionEngine(expected_tools=())

    result = engine.detect_source(source, path=path)

    assert all(
        rule_id not in finding.rule_ids or finding.category is not category
        for finding in result.findings
    )


def test_parser_evidence_uses_parser_detection_method() -> None:
    engine = DetectionEngine(expected_tools=(), config=_GENERAL_CONFIG)

    result = engine.detect_source("def broken(:\n", path="app.py")
    finding = next(item for item in result.findings if "parser.syntax-error" in item.rule_ids)

    assert finding.detection_method == "parser"
    assert finding.confidence == "observation"
    assert any(item.evidence_type.value == "parser" for item in finding.evidence)


def test_general_config_changes_the_config_hash() -> None:
    assert _GENERAL_CONFIG.config_hash() != DetectionConfig().config_hash()
