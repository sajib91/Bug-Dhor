from __future__ import annotations

import math

import numpy as np
import pytest
from mathematics.feature_association import (
    analyze_feature_associations,
    correlation_p_values,
    feature_correlation_matrix,
    permutation_association_test,
)


def association_data() -> tuple[np.ndarray, np.ndarray]:
    latents = np.asarray(
        [
            [1.0, 1.0, 0.5],
            [2.0, 1.0, 0.5],
            [3.0, 1.0, 0.5],
            [4.0, 1.0, 0.5],
            [5.0, 1.0, 0.5],
            [4.0, 1.0, 1.5],
            [5.0, 1.0, 1.5],
            [6.0, 1.0, 1.5],
            [7.0, 1.0, np.nan],
            [8.0, 1.0, 1.5],
        ]
    )
    labels = np.asarray([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    return latents, labels


def test_equations_9_and_10_are_exact():
    latents, labels = association_data()
    result = analyze_feature_associations(latents, labels)
    assert result.mean_vulnerable[0] == pytest.approx(6.0)
    assert result.mean_secure[0] == pytest.approx(3.0)
    assert result.mean_difference[0] == pytest.approx(3.0)
    assert result.pooled_standard_deviation[0] == pytest.approx(np.sqrt(2.5))
    assert result.cohens_d[0] == pytest.approx(3.0 / np.sqrt(2.5))
    assert result.hedges_g[0] == pytest.approx(3.0 / np.sqrt(2.5) * (1.0 - 3.0 / 31.0))
    assert result.cliffs_delta[0] == pytest.approx(0.84)
    assert result.activation_frequency_vulnerable[0] == pytest.approx(1.0)
    assert result.activation_frequency_secure[0] == pytest.approx(1.0)
    assert result.count_vulnerable[0] == 5
    assert result.count_secure[0] == 5


def test_missing_values_reduce_counts_and_do_not_impute():
    latents, labels = association_data()
    result = analyze_feature_associations(latents, labels)
    assert result.count_secure[2] == 5
    assert result.count_vulnerable[2] == 4
    assert not np.isnan(result.mean_secure[2])
    assert np.isnan(result.cohens_d[1])
    assert result.cliffs_delta[1] == pytest.approx(0.0)


def test_significance_and_multiple_testing():
    latents, labels = association_data()
    result = analyze_feature_associations(latents, labels)
    assert result.p_value[0] < 0.05
    assert result.q_value[0] >= result.p_value[0]
    assert result.q_value[0] <= 0.05
    assert result.significant(0.05)[0]
    raw = analyze_feature_associations(latents, labels, correction="none")
    np.testing.assert_allclose(raw.q_value, raw.p_value)


def test_bootstrap_interval_is_reproducible():
    latents, labels = association_data()
    first = analyze_feature_associations(latents, labels, ci_method="bootstrap", n_boot=200, seed=7)
    second = analyze_feature_associations(
        latents, labels, ci_method="bootstrap", n_boot=200, seed=7
    )
    np.testing.assert_allclose(first.confidence_low, second.confidence_low)
    np.testing.assert_allclose(first.confidence_high, second.confidence_high)
    assert first.confidence_low[0] <= first.confidence_high[0]


def test_correlation_matrix_and_p_values():
    values = np.asarray([[1.0, 2.0, 5.0], [2.0, 4.0, 4.0], [3.0, 6.0, 3.0], [4.0, 8.0, 2.0]])
    matrix = feature_correlation_matrix(values)
    assert matrix[0, 1] == pytest.approx(1.0)
    assert matrix[0, 2] == pytest.approx(-1.0)
    assert matrix[1, 2] == pytest.approx(-1.0)
    np.testing.assert_allclose(np.diag(matrix), 1.0)
    p_values, q_values = correlation_p_values(matrix, sample_count=4)
    assert p_values[0, 1] == pytest.approx(0.0)
    assert q_values[0, 1] <= 0.05
    assert np.isnan(p_values[0, 0])


def test_permutation_test_is_reproducible_and_detects_shift():
    values = np.asarray([0.0, 0.1, -0.1, 0.2, 10.0, 10.1, 9.9, 10.2])
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1])
    first = permutation_association_test(values, labels, n_permutations=300, seed=3)
    second = permutation_association_test(values, labels, n_permutations=300, seed=3)
    assert first == second
    assert first["observed_difference"] == pytest.approx(10.0)
    assert first["p_value"] <= 0.05
    assert abs(first["null_mean"]) < 0.2


def test_validation_errors():
    latents, labels = association_data()
    with pytest.raises(ValueError):
        analyze_feature_associations(latents, labels[:-1])
    with pytest.raises(ValueError):
        analyze_feature_associations(latents, labels, threshold=-1.0)
    with pytest.raises(ValueError):
        analyze_feature_associations(latents, labels, correction="holm")
    with pytest.raises(ValueError):
        analyze_feature_associations(latents, labels, observed=np.zeros((2, 2)))
    with pytest.raises(ValueError):
        analyze_feature_associations(latents, np.asarray([0, 1, 2, 0, 1, 0, 1, 0, 1, 0]))
    with pytest.raises(ValueError):
        feature_correlation_matrix(np.zeros(3))


def test_degenerate_correlation_is_nan():
    values = np.asarray([[1.0, 1.0], [1.0, 2.0], [1.0, 3.0]])
    matrix = feature_correlation_matrix(values)
    assert math.isnan(matrix[0, 1])
