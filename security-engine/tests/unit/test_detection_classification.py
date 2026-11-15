"""Classification semantics for the detection engine.

These tests protect the boundary between "we recognized a vulnerability class"
and "we fabricated a CWE". Classification must be driven by actual rule text,
CWE metadata, or evidence support, and unsupported inputs must stay unknown.
"""

from __future__ import annotations

import pytest

from craftsec.detection.classification import (
    CATEGORY_INFO,
    CATEGORY_ORDER,
    category_for_cwe,
    category_for_taint,
    classify_text,
    default_cwe,
    infer_category,
)
from craftsec.detection.models import VulnerabilityCategory


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        ("CWE-89", VulnerabilityCategory.SQL_INJECTION),
        ("CWE-78", VulnerabilityCategory.COMMAND_INJECTION),
        ("CWE-94", VulnerabilityCategory.CODE_INJECTION),
        ("CWE-79", VulnerabilityCategory.XSS),
        ("CWE-22", VulnerabilityCategory.PATH_TRAVERSAL),
        ("CWE-502", VulnerabilityCategory.UNSAFE_DESERIALIZATION),
        ("CWE-798", VulnerabilityCategory.HARDCODED_SECRET),
        ("CWE-327", VulnerabilityCategory.WEAK_CRYPTOGRAPHY),
        ("CWE-295", VulnerabilityCategory.INSECURE_TLS),
        ("CWE-611", VulnerabilityCategory.XXE),
        ("CWE-20", VulnerabilityCategory.INPUT_VALIDATION),
    ],
)
def test_cwe_metadata_maps_to_supported_category(cwe: str, category: VulnerabilityCategory) -> None:
    assert category_for_cwe(cwe) is category
    assert category_for_cwe(cwe.replace("CWE-", "cwe-")) is category


def test_unsupported_cwe_is_not_assigned_a_category() -> None:
    assert category_for_cwe("CWE-99999") is None
    assert category_for_cwe("not-a-cwe") is None


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("python.lang.security.audit.formatted-sql-query", VulnerabilityCategory.SQL_INJECTION),
        ("python.lang.security.audit.subprocess-shell-true", VulnerabilityCategory.COMMAND_INJECTION),
        ("javascript.lang.security.document-innerhtml", VulnerabilityCategory.XSS),
        ("python.lang.security.deserialization.pickle", VulnerabilityCategory.UNSAFE_DESERIALIZATION),
        ("python.lang.security.audit.md5-used", VulnerabilityCategory.WEAK_CRYPTOGRAPHY),
        ("python.lang.security.audit.insecure-tls", VulnerabilityCategory.INSECURE_TLS),
        ("python.lang.security.audit.hardcoded-password", VulnerabilityCategory.HARDCODED_SECRET),
        ("python.lang.security.audit.path-traversal", VulnerabilityCategory.PATH_TRAVERSAL),
        ("python.lang.security.audit.xxe", VulnerabilityCategory.XXE),
        ("python.lang.security.audit.ssrf", VulnerabilityCategory.SSRF),
        ("python.lang.security.audit.open-redirect", VulnerabilityCategory.OPEN_REDIRECT),
        ("python.lang.security.audit.csrf", VulnerabilityCategory.CSRF),
        ("python.lang.security.audit.auth-bypass", VulnerabilityCategory.AUTH_BYPASS),
    ],
)
def test_rule_text_inference_is_specific(rule_id: str, expected: VulnerabilityCategory) -> None:
    assert infer_category(rule_id) is expected


def test_generic_eval_does_not_override_specific_sql_rule() -> None:
    assert (
        infer_category("python.lang.security.audit.formatted-sql-query", "avoid eval")
        is VulnerabilityCategory.SQL_INJECTION
    )


def test_unknown_text_remains_unknown() -> None:
    classification = classify_text(
        rule_id="custom.rule.without.classification",
        message="Review this code because the scanner said so.",
    )
    assert classification.category is VulnerabilityCategory.UNKNOWN
    assert classification.cwe is None
    assert not classification.classified


def test_explicit_cwe_is_used_when_rule_text_is_absent() -> None:
    classification = classify_text(cwes=["CWE-611: XML external entity"])
    assert classification.category is VulnerabilityCategory.XXE
    assert classification.cwe == "CWE-611"
    assert classification.classified


def test_category_default_cwe_is_not_invented_when_rule_is_unknown() -> None:
    classification = classify_text(rule_id="custom.audit.something")
    assert classification.cwe is None


def test_explicit_cwe_metadata_wins_over_ambiguous_rule_text() -> None:
    classification = classify_text(rule_id="sql-injection", cwes=["CWE-79"])
    assert classification.category is VulnerabilityCategory.XSS
    assert classification.cwe == "CWE-79"
    assert classification.conflicts == ()


def test_conflicting_cwe_is_retained_instead_of_silently_dropped() -> None:
    from craftsec.detection.classification import classify_evidence
    from craftsec.detection.models import (
        ClaimKind,
        EvidenceFamily,
        EvidenceItem,
        EvidenceLocation,
        EvidenceType,
    )

    location = EvidenceLocation(
        path="app.py",
        start_line=0,
        start_column=0,
        end_line=0,
        end_column=10,
    )
    sql = EvidenceItem(
        evidence_id="ev-sql",
        evidence_type=EvidenceType.TAINT,
        family=EvidenceFamily.PROGRAM_ANALYSIS,
        claim_kind=ClaimKind.INFERENCE,
        source="craftsec.taint",
        location=location,
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe="CWE-89",
        strength=0.9,
        reliability=1.0,
        rule_id="taint.sql_injection",
    )
    xss_metadata = EvidenceItem(
        evidence_id="ev-xss",
        evidence_type=EvidenceType.SEMGREP,
        family=EvidenceFamily.STATIC_TOOL,
        claim_kind=ClaimKind.OBSERVATION,
        source="semgrep",
        location=location,
        category=VulnerabilityCategory.XSS,
        cwe="CWE-79",
        strength=0.2,
        reliability=1.0,
        rule_id="semgrep.xss",
    )
    classification = classify_evidence((sql, xss_metadata))
    assert classification.category is VulnerabilityCategory.SQL_INJECTION
    assert classification.cwe == "CWE-89"
    assert any("CWE-79" in conflict for conflict in classification.conflicts)
    retained = {item.cwe for item in classification.cwe_support}
    assert "CWE-79" in retained


def test_input_validation_cwe_does_not_override_specific_category() -> None:
    classification = classify_text(rule_id="sql-injection", cwes=["CWE-20"])
    assert classification.category is VulnerabilityCategory.SQL_INJECTION
    assert classification.cwe == "CWE-89"
    assert classification.conflicts == ()


def test_category_hint_wins_over_ambiguous_text() -> None:
    classification = classify_text(
        rule_id="custom.rule",
        category_hint=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    )
    assert classification.category is VulnerabilityCategory.UNSAFE_DESERIALIZATION
    assert classification.cwe == "CWE-502"


def test_every_classified_category_has_a_default_cwe_in_the_supported_set() -> None:
    for category in CATEGORY_ORDER:
        if category is VulnerabilityCategory.UNKNOWN:
            continue
        assert category in CATEGORY_INFO
        cwe = default_cwe(category)
        assert cwe is not None
        assert category_for_cwe(cwe) is category


def test_taint_kind_mapping_is_explicit() -> None:
    assert category_for_taint("sql_injection") is VulnerabilityCategory.SQL_INJECTION
    assert category_for_taint("xss") is VulnerabilityCategory.XSS
    assert category_for_taint("made_up_kind") is VulnerabilityCategory.UNKNOWN
