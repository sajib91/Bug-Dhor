from __future__ import annotations

import numpy as np
import pytest
from mathematics.feature_measurement import (
    measure_feature_activations,
    pool_token_activations,
)


def test_feature_statistics_match_definitions():
    latents = np.asarray([[1.0, 0.0], [2.0, 0.0], [0.0, 0.0], [3.0, 0.0]])
    result = measure_feature_activations(latents, threshold=0.5)
    assert result.mean[0] == pytest.approx(1.5)
    assert result.standard_deviation[0] == pytest.approx(np.std([1, 2, 0, 3], ddof=1))
    assert result.maximum[0] == pytest.approx(3.0)
    assert result.activation_frequency[0] == pytest.approx(0.75)
    assert result.active_mean[0] == pytest.approx(np.mean([1, 2, 3]))
    assert result.active_count[0] == 3
    assert result.activation_frequency[1] == pytest.approx(0.0)
    assert np.isnan(result.active_mean[1])
    assert result.quantiles.shape == (2, 3)


def test_missing_values_are_excluded_not_zeroed():
    latents = np.asarray([[1.0, np.nan], [np.nan, 2.0], [3.0, 4.0]])
    observed = np.asarray([[True, False], [False, True], [True, True]])
    result = measure_feature_activations(latents, observed=observed)
    assert result.observed_count.tolist() == [2, 2]
    assert result.mean[0] == pytest.approx(2.0)
    assert result.mean[1] == pytest.approx(3.0)
    empty = measure_feature_activations(np.asarray([[np.nan]]), feature_indices=[0], threshold=0.0)
    assert empty.observed_count.tolist() == [0]
    assert np.isnan(empty.mean[0])
    assert np.isnan(empty.standard_deviation[0])


def test_token_pooling_respects_attention_mask():
    token_latents = np.asarray(
        [
            [[1.0, 2.0], [3.0, 4.0], [100.0, 100.0]],
            [[5.0, 6.0], [0.0, 0.0], [0.0, 0.0]],
        ]
    )
    mask = np.asarray([[1, 1, 0], [1, 0, 0]])
    pooled, counts = pool_token_activations(token_latents, mask)
    np.testing.assert_allclose(pooled[0], [2.0, 3.0])
    np.testing.assert_allclose(pooled[1], [5.0, 6.0])
    assert counts.tolist() == [2, 1]

    empty_pooled, empty_counts = pool_token_activations(token_latents[:1], np.asarray([[0, 0, 0]]))
    assert empty_counts.tolist() == [0]
    assert np.isnan(empty_pooled).all()


def test_validation():
    with pytest.raises(ValueError):
        measure_feature_activations(np.zeros(3))
    with pytest.raises(ValueError):
        measure_feature_activations(np.zeros((2, 2)), feature_indices=[0, 0])
    with pytest.raises(ValueError):
        measure_feature_activations(np.zeros((2, 2)), quantiles=[1.5])
    with pytest.raises(ValueError):
        pool_token_activations(np.zeros((1, 2, 3)), np.zeros((1, 3)))
    with pytest.raises(ValueError):
        pool_token_activations(np.asarray([[[np.nan, 1.0]]]), np.asarray([[1]]))
