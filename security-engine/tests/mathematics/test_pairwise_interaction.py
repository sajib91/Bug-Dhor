from __future__ import annotations

import numpy as np
import pytest
from mathematics.pairwise_interaction import (
    estimate_pairwise_interaction,
    pairwise_contrast,
    rank_pairwise_interactions,
    run_pairwise_experiment,
)
from mathematics.sae_encoding import SAEParameters


def identity_sae(dim: int = 2) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_equation_12_contrast():
    assert pairwise_contrast([0, 0], [1, 1], [1, 1], [5, 5]) == pytest.approx(3.0)
    assert np.isnan(pairwise_contrast([0], [1], [1], [np.nan]))


def test_paired_estimate_uses_unit_level_contrast():
    baseline = np.asarray([0.0, 1.0])
    a_only = np.asarray([1.0, 2.0])
    b_only = np.asarray([1.0, 2.0])
    joint = np.asarray([5.0, 8.0])
    estimate = estimate_pairwise_interaction(baseline, a_only, b_only, joint)
    assert estimate.contrast == pytest.approx(4.0)
    assert estimate.count == 2
    assert estimate.paired
    assert estimate.confidence_low <= estimate.contrast <= estimate.confidence_high


def test_paired_missing_unit_is_dropped():
    estimate = estimate_pairwise_interaction(
        [0.0, 0.0, 0.0],
        [1.0, 1.0, 1.0],
        [1.0, 1.0, 1.0],
        [5.0, 5.0, np.nan],
    )
    assert estimate.count == 2
    assert estimate.missing_count == 1
    assert estimate.contrast == pytest.approx(3.0)


def test_unpaired_standard_error_matches_formula():
    baseline = np.asarray([0.0, 2.0, 4.0])
    a_only = np.asarray([1.0, 3.0])
    b_only = np.asarray([0.0, 2.0, 4.0, 6.0])
    joint = np.asarray([5.0, 7.0])
    estimate = estimate_pairwise_interaction(baseline, a_only, b_only, joint, paired=False)
    contrast = 6.0 - 2.0 - 3.0 + 2.0
    variances = [
        np.var(baseline, ddof=1) / 3,
        np.var(a_only, ddof=1) / 2,
        np.var(b_only, ddof=1) / 4,
        np.var(joint, ddof=1) / 2,
    ]
    assert estimate.contrast == pytest.approx(contrast)
    assert estimate.standard_error == pytest.approx(np.sqrt(sum(variances)))
    assert estimate.count == 11


def test_run_pairwise_experiment_with_identity_sae():
    activations = np.asarray([[3.0, 5.0], [4.0, 6.0]])
    experiment = run_pairwise_experiment(
        activations,
        lambda h: h[:, 0] * h[:, 1],
        identity_sae(),
        0,
        1,
        value_a=2.0,
        value_b=2.0,
    )
    unit = (activations[:, 0] - 2.0) * (activations[:, 1] - 2.0)
    assert experiment.estimate.contrast == pytest.approx(float(np.mean(unit)))
    np.testing.assert_allclose(experiment.baseline_outcomes, [15.0, 24.0])
    np.testing.assert_allclose(experiment.feature_a_outcomes, [10.0, 12.0])
    np.testing.assert_allclose(experiment.feature_b_outcomes, [6.0, 8.0])
    np.testing.assert_allclose(experiment.joint_outcomes, [4.0, 4.0])


def test_ranking_and_validation():
    activations = np.asarray([[1.0, 1.0]])
    first = run_pairwise_experiment(
        activations,
        lambda h: h[:, 0] * h[:, 1],
        identity_sae(),
        0,
        1,
        value_a=2.0,
        value_b=2.0,
    )
    second = run_pairwise_experiment(
        activations,
        lambda h: h[:, 0] * 100.0 * h[:, 1],
        identity_sae(),
        0,
        1,
        value_a=2.0,
        value_b=2.0,
    )
    assert second.estimate.contrast > first.estimate.contrast
    ranked = rank_pairwise_interactions([first, second])
    assert ranked[0] is second
    with pytest.raises(ValueError):
        run_pairwise_experiment(activations, lambda h: h[:, 0], identity_sae(), 0, 0)
    with pytest.raises(ValueError):
        estimate_pairwise_interaction([1.0], [1.0, 2.0], [1.0], [1.0])
    with pytest.raises(ValueError):
        estimate_pairwise_interaction([1.0], [1.0], [1.0], [1.0], method="bad")
