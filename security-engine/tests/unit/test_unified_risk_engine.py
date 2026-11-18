"""Contract tests for the unified mathematical risk engine.

All evidence in this file is explicitly synthetic. The tests verify that the
engine preserves provenance, refuses to invent numbers, and keeps correlated
evidence from being counted as independent votes.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from bugdhor.risk.calibration import (
    CalibrationAcceptance,
    CalibrationConfig,
    evaluate_calibration,
)
from bugdhor.risk.config import default_risk_config
from bugdhor.risk.engine import FindingRiskInput, UnifiedRiskEngine
from bugdhor.risk.models import (
    ClaimKind,
    CwePriorityProfile,
    EvidenceObservation,
    EvidencePolarity,
    EvidenceSource,
    ReliabilityEvidence,
    RiskWeights,
)
from bugdhor.risk.normalization import estimate_reliability


def observation(
    source: EvidenceSource,
    value: float,
    *,
    source_id: str | None = None,
    reliability: float = 1.0,
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS,
    claim_kind: ClaimKind = ClaimKind.OBSERVATION,
    rationale: str = "synthetic unit fixture",
) -> EvidenceObservation:
    return EvidenceObservation(
        source=source,
        source_id=source_id or f"{source.value}-1",
        value=value,
        reliability=ReliabilityEvidence(
            validation_precision=reliability,
            validation_specificity=reliability,
            basis="synthetic_validation_metrics",
        ),
        claim_kind=claim_kind,
        polarity=polarity,
        normalized_from="synthetic_unit_fixture",
        rationale=rationale,
    )


def test_reliability_uses_validation_metric_matching_polarity() -> None:
    supporting = observation(
        EvidenceSource.STATIC_ANALYSIS,
        0.8,
        reliability=0.7,
        polarity=EvidencePolarity.SUPPORTS,
    )
    refuting = replace(
        supporting,
        polarity=EvidencePolarity.REFUTES,
        reliability=ReliabilityEvidence(
            validation_precision=0.1,
            validation_specificity=0.9,
            basis="synthetic_validation_metrics",
        ),
    )
    value, method = estimate_reliability(supporting)
    assert value == pytest.approx(0.7)
    assert method == "validation_precision"
    refute_value, refute_method = estimate_reliability(refuting)
    assert refute_value == pytest.approx(0.9)
    assert refute_method == "validation_specificity"


@pytest.mark.parametrize(
    ("metadata", "expected_method"),
    [
        (ReliabilityEvidence(run_status="failed"), "run_failed"),
        (ReliabilityEvidence(run_status="unavailable"), "run_unavailable"),
        (
            ReliabilityEvidence(run_status="partial"),
            "partial_run_without_coverage",
        ),
        (ReliabilityEvidence(), "unvalidated_hypothesis"),
    ],
)
def test_unreliable_observations_get_zero_reliability(
    metadata: ReliabilityEvidence, expected_method: str
) -> None:
    item = observation(
        EvidenceSource.SAE_ACTIVATION,
        0.9,
        claim_kind=ClaimKind.HYPOTHESIS,
    )
    candidate = replace(item, reliability=metadata)
    value, method = estimate_reliability(candidate)
    assert value == 0.0
    assert method == expected_method


def test_unvalidated_hypothesis_without_metrics_has_zero_reliability() -> None:
    item = observation(
        EvidenceSource.SAE_ACTIVATION,
        0.9,
        claim_kind=ClaimKind.HYPOTHESIS,
    )
    candidate = replace(item, reliability=ReliabilityEvidence())
    value, method = estimate_reliability(candidate)
    assert value == 0.0
    assert method == "unvalidated_hypothesis"


def test_program_analysis_sources_collapse_into_one_dependency_group() -> None:
    config = default_risk_config()
    engine = UnifiedRiskEngine(config)
    finding = FindingRiskInput(
        finding_id="F-CORR",
        observations=tuple(
            observation(source, 0.8, source_id=f"{source.value}-1", reliability=0.5)
            for source in (
                EvidenceSource.AST,
                EvidenceSource.CFG,
                EvidenceSource.DFG,
                EvidenceSource.TAINT,
            )
        ),
    )
    result = engine.assess(finding)
    assert len(result.group_scores) == 1
    group = result.group_scores[0]
    assert group.group == "program_analysis"
    assert group.support == pytest.approx(0.8)
    assert group.reliability == pytest.approx(0.5)
    assert len(group.evidence_ids) == 4
    # Noisy-OR over one group, not four independent sources.
    assert result.components.p_hat == pytest.approx(1 - (1 - 0.5 * 0.8))


def test_counterfactual_interaction_adjusts_within_its_group_only() -> None:
    engine = UnifiedRiskEngine(default_risk_config())
    finding = FindingRiskInput(
        finding_id="F-INT",
        observations=(
            observation(
                EvidenceSource.SAE_ACTIVATION,
                0.5,
                source_id="sae-7",
                reliability=0.9,
            ),
            observation(
                EvidenceSource.COUNTERFACTUAL_INTERACTION,
                0.4,
                source_id="cf-7-8",
                reliability=0.8,
                rationale="measured interaction on synthetic fixture",
            ),
        ),
    )
    result = engine.assess(finding)
    assert len(result.group_scores) == 1
    group = result.group_scores[0]
    assert group.group == "model_internal"
    assert group.support == pytest.approx(0.82)
    assert group.reliability == pytest.approx(0.9)
    assert result.interaction_adjustment == pytest.approx(0.32)
    assert any("interactions adjusted" in line for line in result.explanation)


def test_negative_interaction_increases_refutation_instead_of_adding_evidence() -> None:
    engine = UnifiedRiskEngine(default_risk_config())
    finding = FindingRiskInput(
        finding_id="F-INT-NEG",
        observations=(
            observation(
                EvidenceSource.SAE_ACTIVATION,
                0.6,
                reliability=0.8,
            ),
            observation(
                EvidenceSource.COUNTERFACTUAL_INTERACTION,
                0.25,
                reliability=0.8,
                polarity=EvidencePolarity.REFUTES,
            ),
        ),
    )
    result = engine.assess(finding)
    assert result.interaction_adjustment == pytest.approx(-0.2)
    assert result.group_scores[0].refutation == pytest.approx(0.2)


def test_equation_28_contributions_are_exact_and_sum_to_index() -> None:
    config = replace(
        default_risk_config(),
        weights=RiskWeights(
            p_hat=0.4,
            severity=0.2,
            exposure=0.2,
            impact=0.2,
            basis="synthetic_test_weights",
            version="test",
        ),
        cwe_profiles={
            "CWE-79": CwePriorityProfile(
                cwe="CWE-79",
                severity=0.6,
                exposure=0.4,
                impact=0.2,
                basis="synthetic_test_profile",
            )
        },
    )
    result = UnifiedRiskEngine(config).assess(
        FindingRiskInput(
            finding_id="F-28",
            cwe="CWE-79",
            observations=(
                observation(EvidenceSource.STATIC_ANALYSIS, 0.8, reliability=1.0),
            ),
        )
    )
    assert result.components.p_hat == pytest.approx(0.8)
    assert result.index == pytest.approx(0.56)
    assert result.band == "high"
    present = [value for value in result.contributions.values() if value is not None]
    assert sum(present) == pytest.approx(0.56)


def test_missing_components_are_excluded_or_refused_but_never_imputed() -> None:
    finding = FindingRiskInput(
        finding_id="F-MISSING",
        observations=(observation(EvidenceSource.STATIC_ANALYSIS, 0.9, reliability=1.0),),
    )
    renormalized = UnifiedRiskEngine(default_risk_config()).assess(finding)
    assert renormalized.components.severity is None
    assert renormalized.contributions["severity"] is None
    assert renormalized.index == pytest.approx(0.9)
    assert any("severity evidence is unavailable" in line for line in renormalized.explanation)

    refused = UnifiedRiskEngine(
        replace(default_risk_config(), missing_policy="unavailable")
    ).assess(finding)
    assert refused.index is None
    assert refused.band == "unknown"
    assert any("No interpretable index" in line for line in refused.explanation)


def test_zero_reliability_evidence_is_excluded_with_a_reason() -> None:
    result = UnifiedRiskEngine(default_risk_config()).assess(
        FindingRiskInput(
            finding_id="F-EXCLUDE",
            observations=(
                observation(
                    EvidenceSource.SAE_ACTIVATION,
                    0.9,
                    source_id="sae-unvalidated",
                    claim_kind=ClaimKind.HYPOTHESIS,
                    reliability=0.0,
                ),
            ),
        )
    )
    assert len(result.excluded_evidence) == 1
    assert result.excluded_evidence[0].reason == "validation_precision"
    assert any("Excluded sae-unvalidated" in line for line in result.explanation)


def test_batch_ranking_is_deterministic_and_preserves_configuration_hash() -> None:
    engine = UnifiedRiskEngine(default_risk_config())
    findings = (
        FindingRiskInput(
            finding_id="F-LOW",
            cwe="CWE-79",
            observations=(observation(EvidenceSource.STATIC_ANALYSIS, 0.3, reliability=1.0),),
        ),
        FindingRiskInput(
            finding_id="F-HIGH",
            cwe="CWE-89",
            observations=(observation(EvidenceSource.STATIC_ANALYSIS, 0.9, reliability=1.0),),
        ),
    )
    assessment = engine.assess_batch(findings)
    assert [item.finding_id for item in assessment.results] == ["F-HIGH", "F-LOW"]
    assert [item.priority_rank for item in assessment.results] == [1, 2]
    assert assessment.config_hash == engine.config_hash
    assert all(item.config_hash == engine.config_hash for item in assessment.results)


def _calibration_config(*, strict: bool = False) -> CalibrationConfig:
    return CalibrationConfig(
        name="synthetic-calibration",
        version="test",
        dataset_id="synthetic-fixture",
        fit_groups=("repo-a", "repo-b"),
        validation_groups=("repo-c",),
        acceptance=CalibrationAcceptance(
            max_brier=0.0 if strict else 0.15,
            max_ece=0.1,
            max_log_loss=0.5,
            min_auroc=0.7,
            basis="synthetic_test_thresholds",
        ),
        n_boot=32,
    )


def _synthetic_rows() -> list:
    from bugdhor.risk.calibration import CalibrationRow

    rows = []
    for group in ("repo-a", "repo-b", "repo-c"):
        for index in range(40):
            score = round(index / 39.0, 6)
            label = 1 if score >= 0.5 else 0
            rows.append(
                CalibrationRow(
                    row_id=f"{group}-{index}",
                    group_id=group,
                    score=score,
                    label=label,
                )
            )
    return rows


def test_calibration_requires_disjoint_groups() -> None:
    with pytest.raises(ValueError, match="overlap"):
        CalibrationConfig(
            name="overlap",
            version="test",
            dataset_id="synthetic",
            fit_groups=("repo-a",),
            validation_groups=("repo-a",),
            acceptance=_calibration_config().acceptance,
        )


def test_validated_artifact_permits_probability_but_rejected_artifact_does_not() -> None:
    evaluation = evaluate_calibration(_synthetic_rows(), _calibration_config())
    artifact = evaluation.artifact
    assert artifact.status == "validated", artifact.failures
    assert artifact.probability(0.8) is not None
    assert artifact.split_hash
    assert artifact.data_hash

    rejected = evaluate_calibration(_synthetic_rows(), _calibration_config(strict=True)).artifact
    assert rejected.status == "rejected"
    assert rejected.probability(0.8) is None


def test_risk_result_reports_calibration_metadata_or_stays_heuristic() -> None:
    config = _calibration_config()
    rows = _synthetic_rows()
    validated = evaluate_calibration(rows, config).artifact
    rejected = evaluate_calibration(rows, _calibration_config(strict=True)).artifact
    finding = FindingRiskInput(
        finding_id="F-CAL",
        cwe="CWE-79",
        observations=(
            observation(EvidenceSource.STATIC_ANALYSIS, 0.8, reliability=1.0),
        ),
    )
    engine = UnifiedRiskEngine(default_risk_config())

    heuristic = engine.assess(finding)
    assert heuristic.probability is None
    assert heuristic.score_kind == "heuristic_index"
    assert heuristic.probability_kind is None
    assert any("not a probability" in line for line in heuristic.explanation)

    calibrated = engine.assess(replace(finding, calibration_artifact=validated))
    assert calibrated.probability is not None
    assert calibrated.score_kind == "heuristic_index"
    assert calibrated.probability_kind == "calibrated_probability"
    assert calibrated.calibration is not None
    assert calibrated.calibration.artifact_id == validated.artifact_id
    assert "brierScore" in calibrated.calibration.metrics
    assert "expectedCalibrationError" in calibrated.calibration.metrics
    assert calibrated.calibration.split_hash == validated.split_hash

    blocked = engine.assess(replace(finding, calibration_artifact=rejected))
    assert blocked.probability is None
    assert blocked.calibration is not None
    assert blocked.calibration.status == "rejected"


def test_artifact_round_trip_preserves_acceptance_state() -> None:
    from bugdhor.risk.calibration import calibration_artifact_from_mapping

    artifact = evaluate_calibration(_synthetic_rows(), _calibration_config()).artifact
    payload = artifact.to_dict()
    payload["timestamp"] = datetime.now(UTC).isoformat()
    restored = calibration_artifact_from_mapping(payload)
    assert restored.artifact_id == artifact.artifact_id
    assert restored.status == "validated"
    assert restored.probability(0.6) == pytest.approx(artifact.probability(0.6))
