from __future__ import annotations

import numpy as np
import pytest
from mathematics.sparse_representation import (
    SparseActivation,
    feature_activation,
    l0_norm,
    l1_norm,
    reconstruction_error,
    to_sparse,
)


def test_feature_activation_equation_8():
    activations = np.asarray([[1.0, 2.0], [0.0, -1.0]])
    values = feature_activation(activations, [2.0, -1.0], 0.5)
    np.testing.assert_allclose(values, [0.5, 1.5])
    single = feature_activation(np.asarray([1.0, 2.0]), [2.0, -1.0], -10.0)
    assert single == 0.0


def test_threshold_is_strict():
    latents = np.asarray([[0.5, -0.5, 0.0, 1.0]])
    assert to_sparse(latents, threshold=0.5).l0_per_sample().tolist() == [1]
    assert to_sparse(latents, threshold=0.49).l0_per_sample().tolist() == [3]
    np.testing.assert_array_equal(l0_norm(latents, threshold=0.5), [1])
    np.testing.assert_allclose(l1_norm(latents), [2.0])


def test_top_k_and_dense_roundtrip():
    latents = np.asarray([[0.1, 0.9, -0.7, 0.6], [0.0, 0.0, 0.0, 0.0]])
    sparse = to_sparse(latents, threshold=0.0, top_k=2)
    assert sparse.max_active == 2
    assert sparse.l0_per_sample().tolist() == [2, 0]
    dense = sparse.to_dense()
    np.testing.assert_allclose(dense[0, [1, 2]], [0.9, -0.7])
    np.testing.assert_allclose(dense[1], 0.0)
    error = reconstruction_error(latents, sparse)
    # Mean squared error over all dense entries: (0.1**2 + 0.6**2) / 8.
    assert error == pytest.approx((0.1**2 + 0.6**2) / 8.0)


def test_missing_values_are_explicitly_inactive():
    latents = np.asarray([[np.nan, 1.0, -2.0]])
    sparse = to_sparse(latents, threshold=0.0)
    assert sparse.missing_count == 1
    assert sparse.l0_per_sample().tolist() == [2]
    np.testing.assert_allclose(sparse.to_dense(), [[0.0, 1.0, -2.0]])


def test_observed_mask_and_validation():
    latents = np.asarray([[1.0, 2.0]])
    sparse = to_sparse(latents, observed=np.asarray([[True, False]]))
    assert sparse.l0_per_sample().tolist() == [1]
    with pytest.raises(ValueError):
        to_sparse(latents, top_k=3)
    with pytest.raises(ValueError):
        to_sparse(latents, observed=np.asarray([[True]]))
    with pytest.raises(ValueError):
        SparseActivation(
            indices=np.asarray([[0, -1]]),
            values=np.asarray([[1.0, 2.0]]),
            dense_shape=(1, 2),
            threshold=0.0,
        )
