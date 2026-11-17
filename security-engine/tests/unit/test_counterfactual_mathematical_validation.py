"""Mathematical validation of counterfactual feature interaction analysis.

These tests are deliberately independent of any trained model.  They check the
estimands, intervention cell construction, scale dependence, confounding,
uncertainty, and stability behaviour on controlled synthetic outcomes.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from craftsec.counterfactual import (
    FeaturePair,
    PairwiseInteractionEngine,
    estimate_higher_order_contrast,
    estimate_pairwise_contrast,
    factorial_unit_contrasts,
    interaction_on_scale,
    logit,
    sigmoid,
    stability_summary,
)
from craftsec.counterfactual.validation import bootstrap_mean_interval


def test_baseline_is_the_reference_cell_not_zero_and_constant_shifts_cancel() -> None:
    baseline = np.array([10.0, 12.0, 14.0])
    feature_a = baseline + 2.0
    feature_b = baseline + 3.0
    joint = baseline + 2.0 + 3.0 + 5.0

    result = estimate_pairwise_contrast(
        baseline,
        feature_a,
        feature_b,
        joint,
        n_boot=200,
        seed=7,
    )

    assert result.contrast == pytest.approx(5.0)
    assert np.mean(baseline) != 0.0
    assert result.standard_error == pytest.approx(0.0)
    assert result.confidence_low == pytest.approx(5.0)
    assert result.confidence_high == pytest.approx(5.0)


def test_pairwise_engine_constructs_the_four_declared_intervention_cells() -> None:
    observed: list[dict[int, float]] = []

    def runner(interventions: dict[int, float], _replicate: int) -> float:
        observed.append(dict(interventions))
        # Y = 1 + 2A + 3B + 5AB.  The contrast must be exactly 5.
        a = interventions.get(1, 0.0)
        b = interventions.get(2, 0.0)
        return 1.0 + 2.0 * a + 3.0 * b + 5.0 * a * b

    result = PairwiseInteractionEngine(
        experiment_id="cell-construction",
        outcome_scale="risk_score",
        repetitions=2,
        seed=3,
    ).run(FeaturePair(1, 2), runner, feature_a_value=1.0, feature_b_value=1.0)

    assert observed[0] == {}
    assert observed[2] == {1: 1.0}
    assert observed[4] == {2: 1.0}
    assert observed[6] == {1: 1.0, 2: 1.0}
    assert result.estimate.contrast == pytest.approx(5.0)
    assert result.estimate.standard_error == pytest.approx(0.0)
    assert "not a significance test" in result.estimate.uncertainty_method


def test_single_feature_ablation_sets_the_target_to_zero_and_leaves_others_alone() -> None:
    def runner(interventions: dict[int, float], _replicate: int) -> float:
        # Only the declared features matter.  Feature 1 is ablated; feature 2
        # stays at its baseline state unless it is explicitly intervened on.
        return float(interventions.get(1, 0.0)) + float(interventions.get(2, 0.0))

    result = PairwiseInteractionEngine(
        experiment_id="ablation",
        outcome_scale="score",
        repetitions=1,
        seed=0,
    ).run(FeaturePair(1, 2), runner, feature_a_value=0.0, feature_b_value=0.0)

    assert result.baseline.interventions == {}
    assert result.feature_a.interventions == {1: 0.0}
    assert result.feature_b.interventions == {2: 0.0}
    assert result.joint.interventions == {1: 0.0, 2: 0.0}
    assert result.estimate.contrast == pytest.approx(0.0)


def test_joint_intervention_is_simultaneous_and_not_sequential() -> None:
    def runner(interventions: dict[int, float], _replicate: int) -> float:
        # If interventions were applied sequentially and the second overwrote
        # the first, the joint cell would be 2 rather than 3.
        return float(sum(interventions.values()))

    result = PairwiseInteractionEngine(
        experiment_id="joint",
        outcome_scale="score",
        repetitions=1,
        seed=0,
    ).run(FeaturePair(4, 9), runner, feature_a_value=1.0, feature_b_value=2.0)

    assert result.joint.interventions == {4: 1.0, 9: 2.0}
    assert result.joint.mean == pytest.approx(3.0)


def test_pairwise_contrast_is_zero_for_a_purely_additive_outcome() -> None:
    baseline = np.array([1.0, 2.0, 4.0, 8.0])
    cells = {
        (): baseline,
        (0,): baseline + 2.0,
        (1,): baseline + 3.0,
        (0, 1): baseline + 2.0 + 3.0,
    }
    np.testing.assert_allclose(factorial_unit_contrasts(cells, (0, 1)), 0.0)
    assert estimate_pairwise_contrast(
        cells[()], cells[(0,)], cells[(1,)], cells[(0, 1)], n_boot=50, seed=1
    ).contrast == pytest.approx(0.0)


def test_higher_order_contrast_matches_inclusion_exclusion_by_hand() -> None:
    # Outcome = 2 + A + 2B + 3C + 7ABC; the third-order contrast is 7.
    # All features are active in every unit so the per-unit contrast is constant.
    ones = np.ones(5)
    cells: dict[tuple[int, ...], np.ndarray] = {}
    for mask in range(8):
        active = tuple(index for index in range(3) if mask & (1 << index))
        aa = ones if 0 in active else np.zeros(5)
        bb = ones if 1 in active else np.zeros(5)
        cc = ones if 2 in active else np.zeros(5)
        cells[active] = 2.0 + aa + 2.0 * bb + 3.0 * cc + 7.0 * aa * bb * cc

    result = estimate_higher_order_contrast(cells, (0, 1, 2), n_boot=200, seed=11)
    assert result.contrast == pytest.approx(7.0)
    assert result.standard_error == pytest.approx(0.0)
    assert result.confidence_low == pytest.approx(7.0)
    assert result.confidence_high == pytest.approx(7.0)


def test_higher_order_contrast_rejects_incomplete_factorial_cells() -> None:
    cells = {
        (): np.array([0.0, 0.0]),
        (0,): np.array([1.0, 1.0]),
        (1,): np.array([1.0, 1.0]),
    }
    with pytest.raises(KeyError, match="all factorial cells"):
        factorial_unit_contrasts(cells, (0, 1))


def test_interaction_direction_flips_when_the_outcome_is_negated() -> None:
    cells = {
        (): np.array([1.0, 2.0, 3.0]),
        (0,): np.array([2.0, 3.0, 4.0]),
        (1,): np.array([2.0, 3.0, 4.0]),
        (0, 1): np.array([5.0, 6.0, 7.0]),
    }
    positive = estimate_higher_order_contrast(cells, (0, 1), n_boot=100, seed=2)
    negated = {key: -values for key, values in cells.items()}
    negative = estimate_higher_order_contrast(negated, (0, 1), n_boot=100, seed=2)
    assert positive.contrast == pytest.approx(2.0)
    assert negative.contrast == pytest.approx(-2.0)


def test_probability_and_logit_interactions_are_not_the_same_estimand() -> None:
    baseline_logit = -1.5
    a_effect = 1.2
    b_effect = 0.8
    interaction = 2.0

    def probability_cell(a: float, b: float) -> float:
        return float(sigmoid(baseline_logit + a_effect * a + b_effect * b + interaction * a * b))

    cells = {
        (): np.array([probability_cell(0.0, 0.0)]),
        (0,): np.array([probability_cell(1.0, 0.0)]),
        (1,): np.array([probability_cell(0.0, 1.0)]),
        (0, 1): np.array([probability_cell(1.0, 1.0)]),
    }
    probability_contrast = estimate_higher_order_contrast(cells, (0, 1), n_boot=50, seed=0).contrast
    logit_contrast = interaction_on_scale(cells, (0, 1), logit)

    assert probability_contrast != pytest.approx(interaction)
    assert logit_contrast == pytest.approx(interaction)
    # The sign can also change on a bounded probability scale in other
    # parameterisations; this case establishes scale dependence.
    assert probability_contrast != pytest.approx(logit_contrast)


def test_paired_design_removes_a_sample_level_confounder_that_biases_unpaired_cells() -> None:
    # Same units in all four cells: sample-level baseline C_i cancels exactly.
    baseline = np.array([0.0, 10.0, 20.0, 100.0])
    paired_cells = {
        (): baseline,
        (0,): baseline + 2.0,
        (1,): baseline + 3.0,
        (0, 1): baseline + 2.0 + 3.0,
    }
    paired = factorial_unit_contrasts(paired_cells, (0, 1))
    assert np.allclose(paired, 0.0)

    # Different units in each cell with different baseline distributions.  The
    # treatment effects are additive, but the baseline imbalance creates a
    # spurious non-zero difference-in-differences.
    unpaired_means = {
        (): np.mean([0.0, 1.0]),
        (0,): np.mean([10.0, 11.0]) + 2.0,
        (1,): np.mean([10.0, 11.0]) + 3.0,
        (0, 1): np.mean([10.0, 11.0]) + 2.0 + 3.0,
    }
    spurious = (
        unpaired_means[(0, 1)] - unpaired_means[(0,)] - unpaired_means[(1,)] + unpaired_means[()]
    )
    assert spurious == pytest.approx(-10.0)


def test_off_target_change_in_only_one_cell_creates_a_spurious_interaction() -> None:
    baseline = np.array([1.0, 1.0, 1.0])
    cells = {
        (): baseline,
        (0,): baseline + 1.0,
        (1,): baseline + 1.0,
        # The joint cell changes an undeclared, off-target latent by +4.
        (0, 1): baseline + 1.0 + 1.0 + 4.0,
    }
    assert estimate_higher_order_contrast(cells, (0, 1), n_boot=50, seed=3).contrast == (
        pytest.approx(4.0)
    )


def test_bootstrap_is_reproducible_and_matches_the_paired_standard_error() -> None:
    values = np.array([1.0, 2.0, 3.0, 4.0, 10.0])
    first = bootstrap_mean_interval(values, n_boot=500, seed=17)
    second = bootstrap_mean_interval(values, n_boot=500, seed=17)
    assert first == second
    assert first[0] == pytest.approx(float(values.mean()))
    assert first[1] == pytest.approx(float(values.std(ddof=1) / math.sqrt(values.size)))
    assert first[2] < first[0] < first[3]


def test_bootstrap_interval_has_reasonable_coverage_for_a_known_interaction() -> None:
    generator = np.random.default_rng(2026)
    true_effect = 2.0
    coverage = 0
    replications = 160
    for _ in range(replications):
        n = 50
        noise = generator.normal(0.0, 1.0, size=n)
        # Y(1,1)-Y(1,0)-Y(0,1)+Y(0,0) = 2 + paired noise contrast.
        per_unit = true_effect + noise
        baseline = np.zeros(n)
        cells = {
            (): baseline,
            (0,): baseline,
            (1,): baseline,
            (0, 1): per_unit,
        }
        result = estimate_higher_order_contrast(cells, (0, 1), n_boot=300, seed=replications)
        if result.confidence_low <= true_effect <= result.confidence_high:
            coverage += 1
    assert coverage / replications >= 0.86


def test_bootstrap_interval_for_a_null_effect_usually_contains_zero() -> None:
    generator = np.random.default_rng(44)
    contained = 0
    replications = 80
    for _ in range(replications):
        n = 60
        noise = generator.normal(0.0, 1.0, size=n)
        cells = {
            (): np.zeros(n),
            (0,): np.zeros(n),
            (1,): np.zeros(n),
            (0, 1): noise,
        }
        result = estimate_higher_order_contrast(cells, (0, 1), n_boot=200, seed=replications)
        contained += int(result.confidence_low <= 0.0 <= result.confidence_high)
    assert contained / replications >= 0.85


def test_stability_summary_reports_sign_and_interval_agreement() -> None:
    noise = np.random.default_rng(5).normal(0.0, 2.0, size=20)
    zeros = np.zeros(20)
    same = {
        "cwe-89": estimate_pairwise_contrast(zeros, zeros, zeros, 2.0 + noise, n_boot=200, seed=1),
        "cwe-79": estimate_pairwise_contrast(zeros, zeros, zeros, 1.5 + noise, n_boot=200, seed=2),
    }
    different = {
        **same,
        "cwe-22": estimate_pairwise_contrast(zeros, zeros, zeros, -1.0 + noise, n_boot=200, seed=3),
    }
    summary = stability_summary(same)
    assert summary.same_sign is True
    assert summary.sign_consistency == pytest.approx(1.0)
    assert summary.all_intervals_overlap is True

    mixed = stability_summary(different)
    assert mixed.same_sign is False
    assert mixed.sign_consistency == pytest.approx(2.0 / 3.0)


def test_validation_helpers_reject_invalid_shapes_and_missing_values() -> None:
    with pytest.raises(ValueError, match="same number of units"):
        factorial_unit_contrasts(
            {
                (): np.array([0.0, 1.0]),
                (0,): np.array([0.0]),
                (1,): np.array([0.0, 1.0]),
                (0, 1): np.array([0.0, 1.0]),
            },
            (0, 1),
        )
    with pytest.raises(ValueError, match="finite"):
        factorial_unit_contrasts(
            {
                (): np.array([0.0, np.nan]),
                (0,): np.array([0.0, 0.0]),
                (1,): np.array([0.0, 0.0]),
                (0, 1): np.array([0.0, 0.0]),
            },
            (0, 1),
        )
    with pytest.raises(ValueError, match="subset"):
        factorial_unit_contrasts({(): np.array([0.0])}, ())
