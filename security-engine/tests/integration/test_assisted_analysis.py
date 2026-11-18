"""Integration coverage for the AI-assisted coding analysis workflow."""

from __future__ import annotations

from typing import Any

import pytest

from bugdhor.detection.assisted import (
    WORKFLOW_STAGES,
    AssistedAnalysisRequest,
    ChangeRegion,
    CounterfactualPayload,
    IncrementalAssistedAnalyzer,
    SaeFeature,
    SaeFeaturePayload,
)
from bugdhor.detection.models import (
    ClaimKind,
    EvidenceFamily,
    VulnerabilityCategory,
)
from bugdhor.parsing.parser import parse_source
from bugdhor.static.models import SourceLocation, StaticFinding

_VULNERABLE_PYTHON = '''\
import hashlib
import os
import pickle
import subprocess

API_KEY = "supersecret123abc"

def handle(request, cursor, target):
    user = request.args.get("user")
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
    subprocess.run(user, shell=True)
    eval(user)
    open(name)
    hashlib.md5(API_KEY.encode())
    pickle.loads(user)
'''

_SQLI_PYTHON = '''\
def load(request, cursor):
    user = request.args.get("user")
    query = "SELECT * FROM users WHERE name = '%s'" % user
    cursor.execute(query)
'''

_SECURE_PYTHON = '''\
import hashlib
import os

API_KEY = os.environ["API_KEY"]

def load(request, cursor, root):
    user = request.args.get("user", "")
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (user,))
    user_id = int(request.args.get("id", "0"))
    hashlib.sha256(API_KEY.encode()).hexdigest()
'''

_SECURE_JAVASCRIPT = '''\
function render(req, res, db) {
  const name = String(req.query.name || "");
  const query = "SELECT * FROM users WHERE name = ?";
  db.query(query, [name]);
  const safe = escapeHtml(String(req.query.html || ""));
  res.send("<h1>" + safe + "</h1>");
}
'''

_VULNERABLE_JAVASCRIPT = '''\
function render(req, res, db) {
  const name = req.query.name;
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.send("<h1>" + name + "</h1>");
}
'''


class _SaeProvider:
    def __init__(self, *, validated: bool = True, features: bool = True) -> None:
        self.provider_id = "test-local-sae"
        self.artifact_id = "sae-artifact-v1"
        self.validated = validated
        self.features = features

    def extract(self, **_: Any) -> SaeFeaturePayload:
        if not (self.validated and self.features):
            return SaeFeaturePayload(
                available=False,
                validated=False,
                provider_id=self.provider_id,
                reason_code="E_TEST_NOT_VALIDATED",
            )
        return SaeFeaturePayload(
            available=True,
            validated=True,
            provider_id=self.provider_id,
            artifact_id=self.artifact_id,
            features=(
                SaeFeature(
                    feature_id="feature-7",
                    activation=0.8,
                    category=VulnerabilityCategory.SQL_INJECTION,
                    cwe="CWE-89",
                    line=3,
                    column=4,
                ),
            ),
        )


class _CounterfactualProvider:
    def __init__(self, *, configured: bool = True) -> None:
        self.provider_id = "test-counterfactual"
        self.configured = configured

    def run(self, **_: Any) -> CounterfactualPayload:
        if not self.configured:
            return CounterfactualPayload(
                available=False,
                configured=False,
                provider_id=self.provider_id,
                reason_code="E_TEST_NOT_CONFIGURED",
            )
        return CounterfactualPayload(
            available=True,
            configured=True,
            provider_id=self.provider_id,
            effect=0.9,
            category=VulnerabilityCategory.SQL_INJECTION,
            cwe="CWE-89",
            line=3,
            column=4,
        )


def _request(
    source: str,
    path: str,
    *,
    language_id: str | None = None,
    changes: tuple[ChangeRegion, ...] = (),
    **kwargs: Any,
) -> AssistedAnalysisRequest:
    return AssistedAnalysisRequest(
        source=source,
        path=path,
        language_id=language_id,
        document_uri=f"file:///workspace/{path}",
        changes=changes,
        **kwargs,
    )


def test_assisted_workflow_reports_every_stage_without_claiming_unavailable_capabilities() -> None:
    analyzer = IncrementalAssistedAnalyzer()
    result = analyzer.analyze(
        _request(
            _VULNERABLE_PYTHON,
            "app.py",
            language_id="python",
            changes=(ChangeRegion(7, 16),),
        )
    )

    assert tuple(record.stage for record in result.stages) == WORKFLOW_STAGES
    assert result.stage("change_detection") is not None
    assert result.stage("change_detection").status == "completed"  # type: ignore[union-attr]
    assert result.stage("ast_analysis").status == "completed"  # type: ignore[union-attr]
    assert result.stage("cfg_dfg_analysis").status == "completed"  # type: ignore[union-attr]
    assert result.stage("taint_analysis").status == "completed"  # type: ignore[union-attr]
    assert result.stage("static_analysis").status == "unavailable"  # type: ignore[union-attr]
    assert result.stage("sae_features").status == "skipped"  # type: ignore[union-attr]
    assert result.stage("counterfactual_analysis").status == "skipped"  # type: ignore[union-attr]
    assert result.stage("evidence_fusion").status == "completed"  # type: ignore[union-attr]
    assert result.stage("classification").status == "completed"  # type: ignore[union-attr]
    assert result.stage("diagnostic_export").status == "completed"  # type: ignore[union-attr]
    assert result.functions == ("handle",)

    categories = {finding.category for finding in result.findings}
    assert {
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.CODE_INJECTION,
        VulnerabilityCategory.HARDCODED_SECRET,
        VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        VulnerabilityCategory.PATH_TRAVERSAL,
    } <= categories

    assert result.findings
    assert all(finding.verification_status == "potential" for finding in result.findings)
    api_findings = result.to_api_findings()
    assert api_findings
    assert {item["verificationStatus"] for item in api_findings} == {"potential"}
    assert all(item["evidence"] for item in api_findings)


@pytest.mark.parametrize(
    ("source", "path", "language_id"),
    [
        (_SECURE_PYTHON, "secure.py", "python"),
        (_SECURE_JAVASCRIPT, "secure.js", "javascript"),
    ],
)
def test_secure_examples_produce_no_findings(
    source: str, path: str, language_id: str
) -> None:
    analyzer = IncrementalAssistedAnalyzer()
    result = analyzer.analyze(_request(source, path, language_id=language_id))

    assert result.findings == ()
    assert result.stage("evidence_fusion").status == "completed"  # type: ignore[union-attr]


def test_javascript_xss_and_sql_injection_are_detected_in_assisted_workflow() -> None:
    analyzer = IncrementalAssistedAnalyzer()
    result = analyzer.analyze(
        _request(_VULNERABLE_JAVASCRIPT, "app.js", language_id="javascript")
    )

    categories = {finding.category for finding in result.findings}
    assert VulnerabilityCategory.SQL_INJECTION in categories
    assert VulnerabilityCategory.XSS in categories
    for finding in result.findings:
        assert finding.location.path == "app.js"
        assert finding.verification_status in {"confirmed", "potential"}


def test_static_evidence_confirms_finding_and_preserves_location() -> None:
    engine_result = parse_source(_SQLI_PYTHON, path="app.py", language="python")
    assert engine_result.error_count == 0
    static = (
        StaticFinding(
            finding_id="semgrep.sql.injection",
            tool="semgrep",
            rule_id="python.lang.security.sqli",
            message="User-controlled data reaches a SQL query sink.",
            severity="high",
            location=SourceLocation("app.py", 3, 4, 3, 18),
            cwes=("CWE-89",),
            rule_name="SQL injection",
            evidence="cursor.execute(query)",
        ),
    )
    analyzer = IncrementalAssistedAnalyzer()
    result = analyzer.analyze(
        _request(
            _SQLI_PYTHON,
            "app.py",
            language_id="python",
            changes=(ChangeRegion(2, 3),),
            static_result=static,
        )
    )

    assert result.stage("static_analysis").status == "completed"  # type: ignore[union-attr]
    sqli = [
        finding
        for finding in result.findings
        if finding.category is VulnerabilityCategory.SQL_INJECTION
    ]
    assert sqli
    finding = sqli[0]
    assert finding.verification_status == "confirmed"
    assert finding.location.start_line == 3
    assert finding.location.end_line == 3
    families = {item.family for item in finding.evidence}
    assert EvidenceFamily.PROGRAM_ANALYSIS in families
    assert EvidenceFamily.STATIC_TOOL in families
    assert all(item.claim_kind is not ClaimKind.HYPOTHESIS for item in finding.evidence)


def test_unconfigured_sae_and_counterfactual_stages_never_report_completed() -> None:
    analyzer = IncrementalAssistedAnalyzer()
    result = analyzer.analyze(
        _request(
            _SQLI_PYTHON,
            "app.py",
            language_id="python",
            run_sae=True,
            run_counterfactual=True,
        )
    )

    assert result.stage("sae_features").reason_code == "E_SAE_PROVIDER_REQUIRED"  # type: ignore[union-attr]
    assert result.stage("sae_features").status == "unavailable"  # type: ignore[union-attr]
    counterfactual_stage = result.stage("counterfactual_analysis")
    assert counterfactual_stage is not None
    assert counterfactual_stage.reason_code == "E_COUNTERFACTUAL_PROVIDER_REQUIRED"
    assert counterfactual_stage.status == "unavailable"
    assert all(
        item.claim_kind is not ClaimKind.HYPOTHESIS
        for finding in result.findings
        for item in finding.evidence
    )


def test_unvalidated_sae_provider_is_unavailable_and_emits_no_features() -> None:
    analyzer = IncrementalAssistedAnalyzer(sae_provider=_SaeProvider(validated=False))
    result = analyzer.analyze(
        _request(_SQLI_PYTHON, "app.py", language_id="python", run_sae=True)
    )

    assert result.stage("sae_features").status == "unavailable"  # type: ignore[union-attr]
    assert result.stage("sae_features").reason_code == "E_SAE_ARTIFACT_NOT_VALIDATED"  # type: ignore[union-attr]
    assert result.sae is None
    assert all(
        item.source != "bugdhor.sae:sae-artifact-v1"
        for finding in result.findings
        for item in finding.evidence
    )


def test_validated_sae_and_counterfactual_evidence_stays_hypothesis_only() -> None:
    analyzer = IncrementalAssistedAnalyzer(
        sae_provider=_SaeProvider(),
        counterfactual_provider=_CounterfactualProvider(),
    )
    result = analyzer.analyze(
        _request(
            _SQLI_PYTHON,
            "app.py",
            language_id="python",
            run_sae=True,
            run_counterfactual=True,
        )
    )

    assert result.stage("sae_features").status == "completed"  # type: ignore[union-attr]
    assert result.stage("counterfactual_analysis").status == "completed"  # type: ignore[union-attr]
    assert result.sae is not None
    assert result.counterfactual is not None
    hypotheses = [
        item
        for finding in result.findings
        for item in finding.evidence
        if item.claim_kind is ClaimKind.HYPOTHESIS
    ]
    assert len(hypotheses) >= 2
    assert all(item.family is EvidenceFamily.LLM for item in hypotheses)
    assert all(item.strength <= 0.25 for item in hypotheses)
    assert all(
        "not independent verification" in item.detail.lower()
        or "model-internal" in item.detail.lower()
        for item in hypotheses
    )
    assert all(finding.verification_status == "potential" for finding in result.findings)


def test_cache_reuses_identical_analysis_and_records_cache_stage() -> None:
    analyzer = IncrementalAssistedAnalyzer()
    request = _request(
        _SQLI_PYTHON,
        "app.py",
        language_id="python",
        changes=(ChangeRegion(1, 3),),
    )

    first = analyzer.analyze(request)
    second = analyzer.analyze(request)

    assert not first.from_cache
    assert second.from_cache
    assert second.stage("incremental_cache") is not None
    assert second.stage("incremental_cache").status == "cached"  # type: ignore[union-attr]
    assert second.findings == first.findings
