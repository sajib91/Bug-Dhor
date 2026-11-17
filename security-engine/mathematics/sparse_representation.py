"""Sparse activation representation and per-feature activation (Eq. 8).

Equations
---------
Eq. (8): ``z_ij = ReLU(w_j . h_i + b_j)`` where ``w_j = W_e[j, :]^T``.

The sparse representation is the support set of ``z``::

    support_i = { j : |z_ij| > threshold }        (optional top-k cap)
    sparse_i  = { (j, z_ij) : j in support_i }

Inputs
------
``latents`` : finite matrix ``[N, d_s]``.
``h`` : activation vector/matrix ``[N, d]``.
``w_j`` : encoder row for feature ``j``, shape ``[d]``.
``b_j`` : encoder bias for feature ``j``, a scalar.

Outputs
-------
:class:`SparseActivation` stores padded ``indices`` ``[N, K]`` (``-1`` marks
padding) and ``values`` ``[N, K]``.  ``to_dense`` restores ``[N, d_s]``.

Missing values
--------------
Non-finite latents are treated as inactive and counted in ``missing_count``.
The dense representation fills them with zero.  This is an explicit
representation choice, not statistical imputation.

Complexity
----------
Threshold sparsification: O(N * d_s).  Top-k selection: O(N * d_s) average with
``argpartition`` plus O(N * k log k) sorting.  Dense conversion: O(N * d_s).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import as_float_array, require_2d

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class SparseActivation:
    """Padded sparse representation of a latent batch."""

    indices: Array
    values: Array
    dense_shape: tuple[int, int]
    threshold: float
    missing_count: int = 0

    def __post_init__(self) -> None:
        indices = np.asarray(self.indices, dtype=np.int64)
        values = np.asarray(self.values, dtype=np.float64)
        if indices.ndim != 2 or values.ndim != 2:
            raise ValueError("indices and values must be two-dimensional")
        if indices.shape != values.shape:
            raise ValueError("indices and values must have the same shape")
        batch, width = self.dense_shape
        if indices.shape[0] != batch:
            raise ValueError("indices batch dimension must match dense_shape")
        if indices.size and ((indices >= width).any() or (indices < -1).any()):
            raise ValueError("indices must be -1 or lie in [0, dense_width)")
        if indices.size and (indices == -1).any() and (values[indices == -1] != 0).any():
            raise ValueError("padding entries must have zero value")
        object.__setattr__(self, "indices", indices)
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "dense_shape", (int(batch), int(width)))

    @property
    def batch_size(self) -> int:
        return int(self.indices.shape[0])

    @property
    def dense_width(self) -> int:
        return int(self.dense_shape[1])

    @property
    def max_active(self) -> int:
        return int(self.indices.shape[1])

    def l0_per_sample(self) -> Array:
        """Number of active entries per sample."""
        return (self.indices >= 0).sum(axis=1)

    def density(self) -> float:
        """Fraction of active entries in the dense representation."""
        return float(self.l0_per_sample().sum() / (self.batch_size * self.dense_width))

    def to_dense(self, *, fill: float = 0.0) -> Array:
        """Expand the support set into a dense ``[N, d_s]`` matrix."""
        dense = np.full(self.dense_shape, fill, dtype=np.float64)
        for row in range(self.batch_size):
            valid = self.indices[row] >= 0
            dense[row, self.indices[row, valid]] = self.values[row, valid]
        return dense


def feature_activation(
    activations: Any,
    encoder_row: Any,
    encoder_bias: float,
) -> Array:
    """Compute Eq. (8) for one feature over one or more activation vectors."""
    h = as_float_array(activations, name="activations")
    if h.ndim == 1:
        h = h.reshape(1, -1)
        single = True
    elif h.ndim == 2:
        single = False
    else:
        raise ValueError("activations must be one- or two-dimensional")
    w = as_float_array(encoder_row, name="encoder_row").reshape(-1)
    if w.shape[0] != h.shape[1]:
        raise ValueError(f"encoder_row must have width {h.shape[1]}, got {w.shape[0]}")
    if not math.isfinite(encoder_bias):
        raise ValueError("encoder_bias must be finite")
    z = np.maximum(h @ w + float(encoder_bias), 0.0)
    return z[0] if single else z


def l0_norm(latents: Any, *, threshold: float = 0.0) -> Array:
    """Per-sample L0 pseudo-norm: count of ``|z_ij| > threshold``."""
    z = as_float_array(latents, name="latents")
    if z.ndim == 1:
        z = z.reshape(1, -1)
    elif z.ndim != 2:
        raise ValueError("latents must be one- or two-dimensional")
    if threshold < 0 or not math.isfinite(threshold):
        raise ValueError("threshold must be finite and non-negative")
    return (np.abs(np.nan_to_num(z, nan=0.0)) > threshold).sum(axis=1)


def l1_norm(latents: Any) -> Array:
    """Per-sample L1 norm with NaN treated as zero (explicit representation)."""
    z = as_float_array(latents, name="latents")
    if z.ndim == 1:
        z = z.reshape(1, -1)
    elif z.ndim != 2:
        raise ValueError("latents must be one- or two-dimensional")
    return np.sum(np.abs(np.nan_to_num(z, nan=0.0)), axis=1)


def to_sparse(
    latents: Any,
    *,
    threshold: float = 0.0,
    top_k: int | None = None,
    observed: Any | None = None,
) -> SparseActivation:
    """Build the sparse support representation of a latent batch.

    Parameters
    ----------
    threshold:
        Keep entries with ``|z_ij| > threshold``.  Must be non-negative.
    top_k:
        If supplied, keep at most the ``top_k`` largest-magnitude active entries
        per sample.  ``top_k`` must not exceed the latent width.
    observed:
        Optional boolean mask.  ``False`` entries are treated as inactive.
    """
    z = as_float_array(latents, name="latents")
    require_2d(z, name="latents")
    if not math.isfinite(threshold) or threshold < 0:
        raise ValueError("threshold must be finite and non-negative")
    width = z.shape[1]
    if top_k is not None:
        if not isinstance(top_k, int) or top_k < 1:
            raise ValueError("top_k must be a positive integer")
        if top_k > width:
            raise ValueError(f"top_k must not exceed latent width {width}")
    finite = np.isfinite(z)
    mask = finite & (np.abs(np.nan_to_num(z, nan=0.0)) > threshold)
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
        mask &= explicit
    missing_count = int((~finite).sum())

    if top_k is None:
        max_active = width
        padded_indices = np.full((z.shape[0], max_active), -1, dtype=np.int64)
        padded_values = np.zeros((z.shape[0], max_active), dtype=np.float64)
        for row in range(z.shape[0]):
            index = np.flatnonzero(mask[row])
            padded_indices[row, : index.size] = index
            padded_values[row, : index.size] = z[row, index]
    else:
        max_active = top_k
        padded_indices = np.full((z.shape[0], max_active), -1, dtype=np.int64)
        padded_values = np.zeros((z.shape[0], max_active), dtype=np.float64)
        for row in range(z.shape[0]):
            index = np.flatnonzero(mask[row])
            if index.size > top_k:
                magnitude = np.abs(z[row, index])
                keep = np.argpartition(-magnitude, top_k - 1)[:top_k]
                index = index[keep]
                index = index[np.argsort(-np.abs(z[row, index]))]
            padded_indices[row, : index.size] = index
            padded_values[row, : index.size] = z[row, index]

    return SparseActivation(
        indices=padded_indices,
        values=padded_values,
        dense_shape=(z.shape[0], width),
        threshold=threshold,
        missing_count=missing_count,
    )


def reconstruction_error(
    latents: Any,
    sparse: SparseActivation,
) -> float:
    """Mean squared representation error between dense latents and support."""
    z = as_float_array(latents, name="latents")
    require_2d(z, name="latents")
    if z.shape != sparse.dense_shape:
        raise ValueError(
            f"latents shape {z.shape} does not match sparse shape {sparse.dense_shape}"
        )
    dense = sparse.to_dense()
    finite = np.isfinite(z)
    if not finite.any():
        return math.nan
    return float(np.mean((np.nan_to_num(z, nan=0.0)[finite] - dense[finite]) ** 2))


__all__ = [
    "SparseActivation",
    "feature_activation",
    "l0_norm",
    "l1_norm",
    "reconstruction_error",
    "to_sparse",
]
