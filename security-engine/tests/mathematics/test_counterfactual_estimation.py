from __future__ import annotations

import math

import numpy as np
import pytest
from mathematics.counterfactual_estimation import (
    CounterfactualEstimator,
    estimate_counterfactual_outcomes,
    make_decoder_intervention_function,
)
from mathematics.sae_encoding import SAEParameters
from mathematics.single_feature_intervention import FeatureIntervention


def identity_sae(dim: int = 2) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_paired_estimand_is_exact():
    estimate = estimate_counterfactual_outcomes([1.0, 2.0, 3.0], [2.0, 4.0, 6.0])
    assert estimate.delta == pytest.approx(2.0)
    assert estimate.factual_mean == pytest.approx(2.0)
    assert estimate.counterfactual_mean == pytest.approx(4.0)
    assert estimate.standard_error == pytest.approx(1.0 / np.sqrt(3.0))
    assert estimate.count == 3
    assert estimate.missing_count == 0


def test_missing_outcomes_are_dropped_pairwise():
    estimate = estimate_counterfactual_outcomes([1.0, np.nan], [2.0, 3.0])
    assert estimate.count == 1
    assert estimate.missing_count == 1
    assert estimate.delta == pytest.approx(1.0)
    assert math.isnan(estimate.standard_error)


def test_estimator_applies_real_decoder_intervention():
    activations = np.asarray([[1.0, 2.0], [3.0, 4.0]])
    estimator = CounterfactualEstimator(seed=4)
    result = estimator.estimate(
        activations,
        lambda h: h[:, 0] + h[:, 1],
        identity_sae(),
        [FeatureIntervention(0, "clamp", 5.0)],
    )
    assert result.estimate.delta == pytest.approx(3.0)
    assert result.estimate.standard_error == pytest.approx(1.0)
    np.testing.assert_allclose(result.factual_outcomes, [3.0, 7.0])
    np.testing.assert_allclose(result.counterfactual_outcomes, [7.0, 9.0])
    np.testing.assert_allclose(result.delta_outcomes, [4.0, 2.0])
    np.testing.assert_allclose(result.feature_activations, activations)
    assert len(estimator.history) == 1
    assert result.estimate.intervention_description == "do(z_0 = 5)"


def test_expected_cell_means_reuses_the_baseline():
    estimator = CounterfactualEstimator()
    cells = estimator.expected_cell_means(
        np.asarray([[1.0, 2.0], [3.0, 4.0]]),
        lambda h: h[:, 0] + h[:, 1],
        identity_sae(),
        {
            (): (),
            (0,): (FeatureIntervention(0, "clamp", 5.0),),
        },
    )
    assert cells[()] == pytest.approx(5.0)
    assert cells[(0,)] == pytest.approx(8.0)


def test_make_decoder_intervention_function():
    apply = make_decoder_intervention_function(identity_sae(), [FeatureIntervention(0, "ablate")])
    modified = apply(np.asarray([[1.0, 2.0], [3.0, 4.0]]))
    np.testing.assert_allclose(modified, [[0.0, 2.0], [0.0, 4.0]])


def test_validation_errors():
    with pytest.raises(ValueError):
        estimate_counterfactual_outcomes([1.0], [1.0, 2.0])
    with pytest.raises(ValueError):
        estimate_counterfactual_outcomes([1.0], [2.0], method="bad")
    estimator = CounterfactualEstimator()
    with pytest.raises(ValueError):
        estimator.estimate(np.zeros((1, 2)), lambda h: h[:, 0], identity_sae(), [])
    with pytest.raises(ValueError):
        make_decoder_intervention_function(identity_sae(), [])
