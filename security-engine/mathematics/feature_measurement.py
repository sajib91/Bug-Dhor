"""Feature activation measurement over samples and tokens.

Equations
---------
For feature ``j`` and observed values ``{z_ij}``::

    mean_j       = (1/n_j) sum_i z_ij
    sd_j         = sqrt((1/(n_j-1)) sum_i (z_ij - mean_j)^2)
    freq_j       = (1/n_j) sum_i 1[|z_ij| > threshold]
    active_mean_j = mean_i { z_ij : |z_ij| > threshold }
    L0_i         = sum_j 1[|z_ij| > threshold]

Token pooling for one sample (used to form sample-level activations)::

    z_i = (1 / sum_t m_it) sum_t m_it z_it

Inputs
------
``latents`` : matrix ``[N, d_s]``.
``token_latents`` : tensor ``[N, T, d_s]``.
``attention_mask`` : matrix ``[N, T]`` with 1 for valid tokens.

Outputs
-------
:class:`FeatureMeasurement` with per-feature arrays and observation counts.

Missing values
--------------
NaN entries and explicitly masked entries are excluded.  A feature with no
observed values reports NaN statistics and ``observed_count == 0`` instead of a
fabricated zero.  Token pooling returns NaN for a sample with no valid tokens.

Complexity
----------
Measurement: O(N * F).  Token pooling: O(N * T * d_s).  Quantiles add
O(N log N) per selected feature.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import as_float_array, require_2d

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class FeatureMeasurement:
    """Measured activation statistics for selected features."""

    feature_indices: Array
    mean: Array
    standard_deviation: Array
    maximum: Array
    activation_frequency: Array
    active_mean: Array
    active_count: Array
    quantiles: Array
    observed_count: Array
    threshold: float

    def __post_init__(self) -> None:
        for name in (
            "feature_indices",
            "mean",
            "standard_deviation",
            "maximum",
            "activation_frequency",
            "active_mean",
            "active_count",
            "observed_count",
        ):
            value = np.asarray(getattr(self, name))
            if value.ndim != 1:
                raise ValueError(f"{name} must be one-dimensional")
            if value.shape != np.asarray(self.feature_indices).shape:
                raise ValueError(f"{name} must match feature_indices shape")
        if self.quantiles.ndim != 2 or self.quantiles.shape[0] != self.feature_indices.size:
            raise ValueError("quantiles must have shape [features, quantile_count]")

    def to_records(self) -> tuple[dict[str, float | int], ...]:
        """Return serializable per-feature records."""
        records = []
        for index, feature in enumerate(self.feature_indices):
            record: dict[str, float | int] = {
                "feature_index": int(feature),
                "mean": float(self.mean[index]),
                "standard_deviation": float(self.standard_deviation[index]),
                "maximum": float(self.maximum[index]),
                "activation_frequency": float(self.activation_frequency[index]),
                "active_mean": float(self.active_mean[index]),
                "active_count": int(self.active_count[index]),
                "observed_count": int(self.observed_count[index]),
            }
            for quantile_index in range(self.quantiles.shape[1]):
                record[f"quantile_{quantile_index}"] = float(self.quantiles[index, quantile_index])
            records.append(record)
        return tuple(records)


def measure_feature_activations(
    latents: Any,
    *,
    feature_indices: Sequence[int] | None = None,
    threshold: float = 0.0,
    observed: Any | None = None,
    quantiles: Sequence[float] = (0.05, 0.5, 0.95),
) -> FeatureMeasurement:
    """Measure mean, SD, maximum, frequency, and quantiles for each feature."""
    z = as_float_array(latents, name="latents")
    require_2d(z, name="latents")
    if not math.isfinite(threshold) or threshold < 0:
        raise ValueError("threshold must be finite and non-negative")
    if any(not 0.0 <= q <= 1.0 for q in quantiles):
        raise ValueError("quantiles must lie in [0, 1]")
    width = z.shape[1]
    if feature_indices is None:
        selected = np.arange(width, dtype=np.int64)
    else:
        selected = np.asarray(feature_indices, dtype=np.int64)
        if selected.ndim != 1:
            raise ValueError("feature_indices must be one-dimensional")
        if selected.size == 0:
            raise ValueError("feature_indices must not be empty")
        if (selected < 0).any() or (selected >= width).any():
            raise ValueError(f"feature_indices must lie in [0, {width})")
        if np.unique(selected).size != selected.size:
            raise ValueError("feature_indices must be distinct")
    explicit = None
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
    finite = np.isfinite(z)
    active_all = finite & (np.abs(np.nan_to_num(z, nan=0.0)) > threshold)
    if explicit is not None:
        active_all &= explicit

    count = selected.size
    means = np.full(count, np.nan)
    sds = np.full(count, np.nan)
    maxima = np.full(count, np.nan)
    frequencies = np.full(count, np.nan)
    active_means = np.full(count, np.nan)
    active_count = np.zeros(count, dtype=np.int64)
    observed_count = np.zeros(count, dtype=np.int64)
    quantile_matrix = np.full((count, len(quantiles)), np.nan)
    for position, feature in enumerate(selected):
        valid = finite[:, feature]
        if explicit is not None:
            valid &= explicit[:, feature]
        values = z[valid, feature]
        observed_count[position] = values.size
        if values.size == 0:
            continue
        means[position] = values.mean()
        maxima[position] = values.max()
        if values.size >= 2:
            sds[position] = values.std(ddof=1)
        active_values = values[np.abs(values) > threshold]
        frequencies[position] = active_values.size / values.size
        active_count[position] = active_values.size
        if active_values.size:
            active_means[position] = active_values.mean()
        if quantiles:
            quantile_matrix[position] = np.quantile(values, quantiles)
    return FeatureMeasurement(
        feature_indices=selected,
        mean=means,
        standard_deviation=sds,
        maximum=maxima,
        activation_frequency=frequencies,
        active_mean=active_means,
        active_count=active_count,
        quantiles=quantile_matrix,
        observed_count=observed_count,
        threshold=threshold,
    )


def pool_token_activations(
    token_latents: Any,
    attention_mask: Any,
) -> tuple[Array, Array]:
    """Pool token-level latents into sample-level means.

    Returns
    -------
    pooled : ``[N, d_s]`` sample means; NaN where a sample has no valid token.
    valid_token_count : ``[N]`` number of pooled tokens per sample.
    """
    values = as_float_array(token_latents, name="token_latents")
    if values.ndim != 3:
        raise ValueError(
            "token_latents must have shape [samples, tokens, features], "
            f"got {values.ndim} dimensions"
        )
    mask = np.asarray(attention_mask)
    if mask.shape != values.shape[:2]:
        raise ValueError(f"attention_mask must have shape {values.shape[:2]}, got {mask.shape}")
    mask = mask.astype(bool)
    valid_counts = mask.sum(axis=1).astype(np.int64)
    pooled = np.full((values.shape[0], values.shape[2]), np.nan)
    if not np.isfinite(values[mask]).all():
        raise ValueError("valid token activations must be finite")
    for sample in range(values.shape[0]):
        if valid_counts[sample] == 0:
            continue
        selected = values[sample, mask[sample]]
        pooled[sample] = selected.mean(axis=0)
    return pooled, valid_counts


__all__ = [
    "FeatureMeasurement",
    "measure_feature_activations",
    "pool_token_activations",
]
