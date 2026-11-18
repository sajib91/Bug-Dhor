"""Independent re-derivation of the unified risk engine's arithmetic.

Every expected value below is computed from the stated definition with plain
Python or NumPy, not by calling the production helper being checked.
"""

from __future__ import annotations

import math
from dataclasses import replace

import numpy as np
import pytest
from bugdhor.decision import DeveloperPreferences, PolicyAction, PolicyContext
from bugdhor.decision.adaptive import OBJECTIVE, adaptive_rank
from bugdhor.decision.config import policy_config_from_mapping
from bugdhor.risk.calibration import (
    CalibrationAcceptance,
    CalibrationConfig,
    CalibrationRow,
    evaluate_calibration,
)
from bugdhor.risk.config import default_risk_config, risk_config_from_mapping
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


def _observation(
    source: EvidenceSource,
    value: float,
    *,
    source_id: str,
    reliability: float,
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS,
    claim_kind: ClaimKind = ClaimKind.OBSERVATION,
) -> EvidenceObservation:
    return EvidenceObservation(
        source=source,
        source_id=source_id,
        value=value,
        reliability=ReliabilityEvidence(
            validation_precision=reliability,
            validation_specificity=reliability,
            basis="independent_regression_fixture",
        ),
        polarity=polarity,
        claim_kind=claim_kind,
        normalized_from="independent_regression_fixture",
    )


def test_equation_28_recomputed_from_raw_weights() -> None:
    weights = RiskWeights(
        p_hat=0.4,
        severity=0.2,
        exposure=0.2,
        impact=0.2,
        basis="independent_reference_weights",
        version="test",
    )
    config = replace(
        default_risk_config(),
        weights=weights,
        cwe_profiles={
            "CWE-79": CwePriorityProfile(
                cwe="CWE-79",
                severity=0.6,
                exposure=0.4,
                impact=0.2,
                basis="independent_reference_profile",
            )
        },
    )
    result = UnifiedRiskEngine(config).assess(
        FindingRiskInput(
            finding_id="REG-28",
            cwe="CWE-79",
            observations=(
                _observation(
                    EvidenceSource.STATIC_ANALYSIS,
                    0.8,
                    source_id="static-1",
                    reliability=1.0,
                ),
            ),
        )
    )
    expected = 0.4 * 0.8 + 0.2 * 0.6 + 0.2 * 0.4 + 0.2 * 0.2
    assert expected == pytest.approx(0.56)
    assert result.index == pytest.approx(expected)
    assert result.contributions["p_hat"] == pytest.approx(0.4 * 0.8)
    assert result.contributions["severity"] == pytest.approx(0.2 * 0.6)


def test_noisy_or_over_two_independent_groups() -> None:
    # Groups: static_tool (support 0.9, reliability 0.5) and
    # exploitability (support 0.6, reliability 0.5).
    result = UnifiedRiskEngine(default_risk_config()).assess(
        FindingRiskInput(
            finding_id="REG-OR",
            observations=(
                _observation(
                    EvidenceSource.STATIC_ANALYSIS,
                    0.9,
                    source_id="static-1",
                    reliability=0.5,
                ),
                _observation(
                    EvidenceSource.EXPLOITABILITY,
                    0.6,
                    source_id="exploit-1",
                    reliability=0.5,
                ),
            ),
        )
    )
    expected = 1.0 - (1.0 - 0.5 * 0.9) * (1.0 - 0.5 * 0.6)
    assert expected == pytest.approx(0.615)
    assert result.components.p_hat == pytest.approx(expected)


def test_reliability_weighted_mean_within_one_dependency_group() -> None:
    result = UnifiedRiskEngine(default_risk_config()).assess(
        FindingRiskInput(
            finding_id="REG-WMEAN",
            observations=(
                _observation(
                    EvidenceSource.AST,
                    0.8,
                    source_id="ast-1",
                    reliability=0.9,
                ),
                _observation(
                    EvidenceSource.CFG,
                    0.4,
                    source_id="cfg-1",
                    reliability=0.1,
                ),
            ),
        )
    )
    expected = (0.9 * 0.8 + 0.1 * 0.4) / (0.9 + 0.1)
    assert expected == pytest.approx(0.76)
    assert result.group_scores[0].support == pytest.approx(expected)
    assert result.group_scores[0].reliability == pytest.approx(0.9)


def test_interaction_adjustment_is_signed_and_group_local() -> None:
    value = 0.3
    reliability = 0.8
    result = UnifiedRiskEngine(default_risk_config()).assess(
        FindingRiskInput(
            finding_id="REG-INT",
            observations=(
                _observation(
                    EvidenceSource.SAE_ACTIVATION,
                    0.5,
                    source_id="sae-1",
                    reliability=0.9,
                ),
                _observation(
                    EvidenceSource.COUNTERFACTUAL_INTERACTION,
                    value,
                    source_id="cf-1",
                    reliability=reliability,
                ),
            ),
        )
    )
    expected_delta = reliability * value
    assert result.interaction_adjustment == pytest.approx(expected_delta)
    assert result.group_scores[0].support == pytest.approx(0.5 + expected_delta)
    assert len(result.group_scores) == 1


def test_missing_component_renormalization_matches_closed_form() -> None:
    finding = FindingRiskInput(
        finding_id="REG-MISSING",
        observations=(
            _observation(
                EvidenceSource.STATIC_ANALYSIS,
                0.9,
                source_id="static-1",
                reliability=1.0,
            ),
        ),
    )
    result = UnifiedRiskEngine(default_risk_config()).assess(finding)
    # All four normalized weights are 0.25; with three missing, the sole
    # available component receives effective weight 0.25 / 0.25 = 1, so its
    # contribution equals its value.
    assert result.index == pytest.approx(0.9)
    assert result.contributions["p_hat"] == pytest.approx(0.9)


def test_calibration_metrics_recomputed_from_fitted_parameters() -> None:
    rows = []
    for group in ("g-fit", "g-validation"):
        for index in range(30):
            score = index / 29.0
            rows.append(
                CalibrationRow(
                    row_id=f"{group}-{index}",
                    group_id=group,
                    score=score,
                    label=int(score >= 0.5),
                )
            )
    config = CalibrationConfig(
        name="independent-calibration",
        version="test",
        dataset_id="independent-synthetic",
        fit_groups=("g-fit",),
        validation_groups=("g-validation",),
        acceptance=CalibrationAcceptance(
            max_brier=0.2,
            max_ece=0.2,
            max_log_loss=1.0,
            min_auroc=0.5,
            basis="independent_reference_thresholds",
        ),
        n_boot=8,
    )
    evaluation = evaluate_calibration(rows, config)
    artifact = evaluation.artifact
    slope = artifact.slope
    intercept = artifact.intercept
    probabilities = np.asarray(
        [1.0 / (1.0 + math.exp(-(slope * row.score + intercept))) for row in evaluation.validation_rows]
    )
    labels = np.asarray([row.label for row in evaluation.validation_rows], dtype=float)

    expected_brier = float(np.mean((probabilities - labels) ** 2))
    assert artifact.metrics.brier_score == pytest.approx(expected_brier)

    # Equal-width ECE with 10 bins, computed independently.
    ece = 0.0
    edges = np.linspace(0.0, 1.0, 11)
    for bin_index in range(10):
        mask = (probabilities >= edges[bin_index]) & (
            probabilities < edges[bin_index + 1]
            if bin_index < 9
            else probabilities <= edges[bin_index + 1]
        )
        if not mask.any():
            continue
        ece += float(mask.mean()) * abs(float(probabilities[mask].mean() - labels[mask].mean()))
    assert artifact.metrics.expected_calibration_error == pytest.approx(ece)

    # Mann-Whitney U form of AUROC with average ranks for ties.
    order = np.argsort(probabilities, kind="mergesort")
    sorted_scores = probabilities[order]
    ranks = np.empty(probabilities.size)
    start = 0
    while start < probabilities.size:
        end = start + 1
        while end < probabilities.size and sorted_scores[end] == sorted_scores[start]:
            end += 1
        ranks[order[start:end]] = (start + end + 1) / 2.0
        start = end
    positives = int(labels.sum())
    negatives = len(labels) - positives
    positive_rank_sum = float(ranks[labels[order] == 1].sum())
    expected_auroc = (positive_rank_sum - positives * (positives + 1) / 2) / (
        positives * negatives
    )
    assert artifact.metrics.auroc == pytest.approx(expected_auroc)


def test_utility_score_matches_declared_preference_arithmetic() -> None:
    from pathlib import Path

    payload = (
        Path(__file__).resolve().parents[1]
        / "research"
        / "configs"
        / "risk"
        / "policy.json"
    ).read_text(encoding="utf-8")
    import json

    config = policy_config_from_mapping(json.loads(payload))
    context = PolicyContext(
        cwe="CWE-79",
        risk_index=0.8,
        risk_band="high",
        evidence_strength=0.6,
        uncertainty=0.4,
        calibrated_probability=None,
        preferences=DeveloperPreferences(),
    )
    scores, actions, _ = adaptive_rank(
        context, replace(config, mode="adaptive"), (PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES,)
    )
    score = scores[0]
    efficacy_factor = 0.5 * 0.8 + 0.5 * 0.6
    harm_factor = 0.5 + 0.4
    expected = (
        efficacy_factor * config.utility.efficacy["recommend_secure_coding_practices"]
        - 1.0 * config.utility.cost["recommend_secure_coding_practices"]
        - harm_factor * config.utility.harm["recommend_secure_coding_practices"]
    )
    assert score.score == pytest.approx(round(expected, 6))
    assert score.action is PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES
    assert PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES in actions


def test_policy_objective_explicitly_disallows_optimality_and_learning() -> None:
    assert "preference_weighted_utility_ranking" in OBJECTIVE
    assert "not learned" in OBJECTIVE
    assert "not claimed to be optimal" in OBJECTIVE
    assert "reinforcement" not in OBJECTIVE.lower()


def test_config_hash_is_deterministic_and_sensitive_to_declared_weights() -> None:
    first = default_risk_config()
    second = risk_config_from_mapping(
        {
            "weights": first.weights.to_dict(),
            "thresholds": first.thresholds.to_dict(),
            "dependencyGroups": dict(first.dependency_groups),
            "missingPolicy": first.missing_policy,
            "uncertaintyBands": list(first.uncertainty_bands),
            "uncertaintyBasis": first.uncertainty_basis,
            "priorityTieBreaker": first.priority_tie_breaker,
            "name": first.name,
            "version": first.version,
        }
    )
    assert first.config_hash() == second.config_hash()
    changed = replace(
        first,
        weights=replace(first.weights, p_hat=2.0, basis="changed_reference_basis"),
    )
    assert changed.config_hash() != first.config_hash()
