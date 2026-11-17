from __future__ import annotations

import math

import pytest
from mathematics.cwe_risk import (
    CweRiskPolicy,
    CweRiskScorer,
    RiskComponents,
    RiskThresholds,
    RiskWeights,
    assess_cwe_risk,
    classify_risk_band,
    compute_risk_index,
)

WEIGHTS = RiskWeights(alpha=0.4, beta=0.2, gamma=0.2, delta=0.2)


def components(
    probability: float = 0.8,
    severity: float = 0.6,
    exposure: float = 0.4,
    impact: float = 0.2,
) -> RiskComponents:
    return RiskComponents(probability, severity, exposure, impact)


def test_equation_28_is_exact_and_contributions_sum_to_score():
    score, contributions, weights = compute_risk_index(components(), WEIGHTS)
    assert score == pytest.approx(0.8 * 0.4 + 0.6 * 0.2 + 0.4 * 0.2 + 0.2 * 0.2)
    assert score == pytest.approx(0.56)
    assert sum(contributions.values()) == pytest.approx(score)
    assert weights == {
        "probability": 0.4,
        "severity": 0.2,
        "exposure": 0.2,
        "impact": 0.2,
    }
    assert contributions == {
        "probability": pytest.approx(0.32),
        "severity": pytest.approx(0.12),
        "exposure": pytest.approx(0.08),
        "impact": pytest.approx(0.04),
    }


def test_weights_are_normalized_by_default_and_can_be_unnormalized():
    normalized = RiskWeights(alpha=2.0, beta=1.0, gamma=1.0, delta=0.0)
    assert normalized.normalized() == pytest.approx((0.5, 0.25, 0.25, 0.0))
    score, _, used = compute_risk_index(components(), normalized)
    assert score == pytest.approx(0.8 * 0.5 + 0.6 * 0.25 + 0.4 * 0.25)
    assert used["probability"] == pytest.approx(0.5)

    unnormalized = RiskWeights(alpha=1.0, beta=1.0, gamma=1.0, delta=1.0, normalize=False)
    raw_score, raw_contributions, _ = compute_risk_index(components(), unnormalized)
    assert raw_score == pytest.approx(2.0)
    assert raw_contributions["probability"] == pytest.approx(0.8)
    assert sum(raw_contributions.values()) == pytest.approx(raw_score)


def test_equation_29_band_boundaries_are_inclusive_at_the_lower_threshold():
    thresholds = RiskThresholds(low=0.25, medium=0.50, high=0.75)
    assert classify_risk_band(0.0, thresholds) == "Low"
    assert classify_risk_band(0.249999, thresholds) == "Low"
    assert classify_risk_band(0.25, thresholds) == "Medium"
    assert classify_risk_band(0.499999, thresholds) == "Medium"
    assert classify_risk_band(0.50, thresholds) == "High"
    assert classify_risk_band(0.749999, thresholds) == "High"
    assert classify_risk_band(0.75, thresholds) == "Critical"
    assert classify_risk_band(1.0, thresholds) == "Critical"
    assert classify_risk_band(math.nan, thresholds) == "Unknown"


def test_assessment_band_and_provenance():
    policy = CweRiskPolicy(cwe="CWE-89", weights=WEIGHTS)
    assessment = assess_cwe_risk(components(), policy)
    assert assessment.cwe == "CWE-89"
    assert assessment.score == pytest.approx(0.56)
    assert assessment.band == "High"
    assert assessment.is_probability is False
    assert assessment.missing_count == 0
    assert assessment.interpretation.startswith("Linear prioritization index")
    record = assessment.to_dict()
    assert record["score"] == pytest.approx(0.56)
    assert record["band"] == "High"
    assert record["missing_policy"] == "nan"
    assert record["weights_used"] == {
        "probability": 0.4,
        "severity": 0.2,
        "exposure": 0.2,
        "impact": 0.2,
    }


def test_missing_policy_nan_returns_unknown_without_imputation():
    policy = CweRiskPolicy(cwe="CWE-89", weights=WEIGHTS, missing_policy="nan")
    assessment = assess_cwe_risk(
        RiskComponents(0.8, math.nan, 0.4, 0.2),
        policy,
    )
    assert math.isnan(assessment.score)
    assert assessment.band == "Unknown"
    assert assessment.missing_count == 1
    assert assessment.contributions["probability"] == pytest.approx(0.32)
    assert math.isnan(assessment.contributions["severity"])
    assert assessment.to_dict()["score"] is None
    assert assessment.to_dict()["components"]["severity"] is None


def test_missing_policy_error_raises_naming_the_component():
    policy = CweRiskPolicy(cwe="CWE-89", weights=WEIGHTS, missing_policy="error")
    with pytest.raises(ValueError, match="severity"):
        assess_cwe_risk(RiskComponents(0.8, math.nan, 0.4, 0.2), policy)


def test_missing_policy_renormalize_uses_only_available_weights():
    policy = CweRiskPolicy(cwe="CWE-89", weights=WEIGHTS, missing_policy="renormalize")
    assessment = assess_cwe_risk(
        RiskComponents(0.8, math.nan, 0.4, 0.2),
        policy,
    )
    # Available base weights: 0.4 + 0.2 + 0.2 = 0.8.
    assert assessment.score == pytest.approx(0.8 * 0.5 + 0.4 * 0.25 + 0.2 * 0.25)
    assert assessment.score == pytest.approx(0.55)
    assert assessment.weights_used["probability"] == pytest.approx(0.5)
    assert assessment.weights_used["severity"] == 0.0
    assert assessment.weights_used["exposure"] == pytest.approx(0.25)
    assert assessment.weights_used["impact"] == pytest.approx(0.25)
    assert assessment.missing_count == 1


def test_renormalize_with_every_component_missing_is_not_a_score():
    score, contributions, weights = compute_risk_index(
        RiskComponents(math.nan, math.nan, math.nan, math.nan),
        WEIGHTS,
        missing_policy="renormalize",
    )
    assert math.isnan(score)
    assert all(math.isnan(value) for value in contributions.values())
    assert all(math.isnan(value) for value in weights.values())


def test_registry_lookup_default_fallback_and_batch():
    strict = CweRiskPolicy(cwe="CWE-89", weights=WEIGHTS)
    default = CweRiskPolicy(
        cwe="DEFAULT",
        weights=RiskWeights(alpha=0.25, beta=0.25, gamma=0.25, delta=0.25),
    )
    scorer = CweRiskScorer({"CWE-89": strict}, default_policy=default)
    assessment = scorer.assess("CWE-89", components())
    assert assessment.score == pytest.approx(0.56)
    fallback = scorer.assess("CWE-79", components())
    assert fallback.cwe == "CWE-79"
    assert fallback.policy.cwe == "CWE-79"
    assert fallback.score == pytest.approx(0.5)
    assert scorer.cwes == ("CWE-89",)

    batch = scorer.assess_batch(
        {
            "finding-1": ("CWE-89", components()),
            "finding-2": ("CWE-79", components(probability=0.5)),
        }
    )
    assert batch["finding-1"].band == "High"
    assert batch["finding-2"].score == pytest.approx(0.425)
    with pytest.raises(TypeError):
        scorer.assess_batch({"finding-3": components()})  # type: ignore[dict-item]

    without_default = CweRiskScorer({"CWE-89": strict})
    with pytest.raises(LookupError):
        without_default.assess("CWE-79", components())


def test_validation_errors():
    with pytest.raises(ValueError):
        RiskWeights(alpha=-1.0)
    with pytest.raises(ValueError):
        RiskWeights(alpha=0.0, beta=0.0, gamma=0.0, delta=0.0)
    with pytest.raises(ValueError):
        RiskThresholds(low=0.5, medium=0.4, high=0.6)
    with pytest.raises(ValueError):
        RiskThresholds(low=0.0)
    with pytest.raises(ValueError):
        RiskComponents(1.2, 0.5, 0.5, 0.5)
    with pytest.raises(ValueError):
        RiskComponents(math.inf, 0.5, 0.5, 0.5)
    with pytest.raises(ValueError):
        CweRiskPolicy(cwe=" ")
    with pytest.raises(ValueError):
        CweRiskPolicy(cwe="CWE-89", missing_policy="zero")  # type: ignore[arg-type]
