from __future__ import annotations

from craftsec.detection.models import (
    ClaimKind,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidenceType,
    HeuristicRisk,
    Provenance,
    RiskAssessment,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from craftsec.explain import (
    CounterfactualReference,
    ExplainableVulnerabilityEngine,
    FeatureInteractionReference,
    SAEFeatureReference,
)
from craftsec.parsing.models import SourcePoint, SourceSpan
from craftsec.program_analysis.taint import (
    TaintConfidence,
    TaintFinding,
    TaintKind,
    TaintPathStep,
)


def _span(start: int, end: int) -> SourceSpan:
    return SourceSpan(
        SourcePoint(start, start, 0, start, start),
        SourcePoint(end, end, 0, end, end),
    )


def test_explanation_separates_observed_hypothesis_and_validated_research() -> None:
    location = EvidenceLocation("app.py", 0, 0, 0, 10)
    evidence = (
        EvidenceItem(
            evidence_id="ast-1",
            evidence_type=EvidenceType.AST,
            family=EvidenceFamily.PROGRAM_ANALYSIS,
            claim_kind=ClaimKind.OBSERVATION,
            source="craftsec.ast",
            location=location,
            category=VulnerabilityCategory.SQL_INJECTION,
            cwe="CWE-89",
            detail="String construction occurs at a SQL call site.",
        ),
        EvidenceItem(
            evidence_id="static-1",
            evidence_type=EvidenceType.SEMGREP,
            family=EvidenceFamily.STATIC_TOOL,
            claim_kind=ClaimKind.OBSERVATION,
            source="semgrep",
            location=location,
            category=VulnerabilityCategory.SQL_INJECTION,
            cwe="CWE-89",
            detail="Rule matched a query construction pattern.",
        ),
        EvidenceItem(
            evidence_id="llm-1",
            evidence_type=EvidenceType.LLM,
            family=EvidenceFamily.LLM,
            claim_kind=ClaimKind.HYPOTHESIS,
            source="local-llm",
            location=location,
            category=VulnerabilityCategory.SQL_INJECTION,
            cwe="CWE-89",
            detail="The model hypothesized that input reaches the query.",
        ),
    )
    finding = VulnerabilityFinding(
        finding_id="finding-1",
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe="CWE-89",
        title="Potential SQL injection",
        severity="high",
        location=location,
        document_uri="file:///app.py",
        evidence=evidence,
        cwe_support=(),
        risk=RiskAssessment(HeuristicRisk(0.8, "high")),
        explanation="Evidence indicates potentially unsafe query construction.",
        suggested_remediation="Use parameterized queries.",
        provenance=Provenance("test", "1", "2026-01-01T00:00:00Z", "hybrid"),
    )
    taint = TaintFinding(
        finding_id="taint-1",
        kind=TaintKind.SQL_INJECTION,
        title="Potential SQL injection",
        source_rule="request.args",
        sink_rule="cursor.execute",
        source_span=_span(0, 1),
        source_text="request.args",
        sink_span=_span(8, 9),
        sink_text="execute",
        path=(
            TaintPathStep("source", "source", _span(0, 1), "request.args", "module"),
            TaintPathStep("sink", "sink", _span(8, 9), "execute", "module"),
        ),
        confidence=TaintConfidence.HIGH,
        confidence_notes=("syntactic flow",),
        limitations=("runtime feasibility is not established",),
    )
    analysis = type("TaintResult", (), {"findings": (taint,)})()

    report = ExplainableVulnerabilityEngine().explain(
        finding,
        taint=analysis,
        sae_features=(SAEFeatureReference(3, activation_strength=1.2),),
        feature_interactions=(
            FeatureInteractionReference((3, 4), 0.2, "risk_score", validated=True),
            FeatureInteractionReference((4, 5), 0.4, "risk_score", validated=False),
        ),
        counterfactuals=(
            CounterfactualReference("ablate feature 3", -0.1, "risk_score"),
        ),
    )

    assert report.cwe == "CWE-89"
    assert len(report.source_to_sink_paths) == 1
    assert len(report.supporting_static_analysis) == 1
    assert len(report.directly_observed_evidence) == 2
    assert len(report.model_generated_explanations) == 1
    assert len(report.feature_interactions) == 1
    assert "Unvalidated feature interactions" in " ".join(report.limitations)
    assert "hypotheses only" in report.to_human()
    assert report.to_json().startswith("{")
