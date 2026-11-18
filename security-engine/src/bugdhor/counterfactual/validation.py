"""Rigorous validation helpers for counterfactual feature interactions.

The production pairwise and higher-order engines estimate contrasts from cell
means and, when replicate outcomes are available, an independent-cell
standard error.  This module adds validation-oriented estimators that preserve
the pairing between intervention cells:

* per-unit factorial contrasts,
* percentile bootstrap intervals over units,
* paired higher-order (Möbius / inclusion-exclusion) contrasts,
* scale-transformed contrasts,
* stability summaries across groups.

Pairing matters.  If the four cells are measured on the same code sample,
token position, layer, checkpoint, and prompt, the unit-level contrast removes
between-sample baseline variation.  Treating the cells as independent can
inflate or deflate uncertainty and can create a spurious interaction when group
baselines differ.  Nothing here turns an intervention contrast into a causal
claim about real-world vulnerability; it only quantifies the declared
counterfactual outcome under the stated design.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

Array = np.ndarray
CellMap = Mapping[tuple[int, ...], Sequence[float]]


@dataclass(frozen=True, slots=True)
class BootstrapContrast:
    """Paired factorial contrast with a percentile bootstrap interval."""

    contrast: float
    standard_error: float
    confidence_low: float
    confidence_high: float
    confidence: float
    n_units: int
    n_boot: int
    method: str


@dataclass(frozen=True, slots=True)
class StabilitySummary:
    """Sign and interval agreement across independently measured groups."""

    group_names: tuple[str, ...]
    contrasts: tuple[float, ...]
    same_sign: bool
    sign_consistency: float
    all_intervals_overlap: bool
    pooled_interval_low: float
    pooled_interval_high: float


def sigmoid(value: Array | float) -> Array:
    """Numerically stable logistic link."""
    array = np.asarray(value, dtype=np.float64)
    out = np.empty_like(array)
    positive = array >= 0
    out[positive] = 1.0 / (1.0 + np.exp(-array[positive]))
    exp_value = np.exp(array[~positive])
    out[~positive] = exp_value / (1.0 + exp_value)
    return out


def logit(probability: Array | float, *, epsilon: float = 1e-12) -> Array:
    """Log-odds with an explicit clipping epsilon for 0/1 probabilities."""
    array = np.asarray(probability, dtype=np.float64)
    if np.any(~np.isfinite(array)):
        raise ValueError("probabilities must be finite")
    if np.any((array < 0.0) | (array > 1.0)):
        raise ValueError("probabilities must lie in [0, 1]")
    clipped = np.clip(array, epsilon, 1.0 - epsilon)
    out = np.log(clipped) - np.log1p(-clipped)
    return out


def _as_cell_arrays(cells: Mapping[Any, Any]) -> dict[tuple[int, ...], Array]:
    converted: dict[tuple[int, ...], Array] = {}
    for key, values in cells.items():
        active = tuple(sorted(int(feature) for feature in key))
        if active != tuple(key):
            raise ValueError("cell keys must be sorted feature tuples")
        array = np.asarray(values, dtype=np.float64).reshape(-1)
        if array.size == 0:
            raise ValueError("cell outcome sequences must not be empty")
        converted[active] = array
    return converted


def _validate_subset(subset: Sequence[int]) -> tuple[int, ...]:
    active = tuple(sorted(int(feature) for feature in subset))
    if not active:
        raise ValueError("subset must contain at least one feature")
    if len(set(active)) != len(active):
        raise ValueError("subset features must be unique")
    return active


def _powerset(features: Sequence[int]) -> tuple[tuple[int, ...], ...]:
    ordered = tuple(sorted(features))
    return tuple(
        combination
        for order in range(len(ordered) + 1)
        for combination in itertools.combinations(ordered, order)
    )


def _required_cells(subset: Sequence[int]) -> tuple[tuple[int, ...], ...]:
    return _powerset(_validate_subset(subset))


def _validate_cells(
    cells: Mapping[Any, Any], subset: Sequence[int]
) -> dict[tuple[int, ...], Array]:
    converted = _as_cell_arrays(cells)
    required = _required_cells(subset)
    missing = [key for key in required if key not in converted]
    if missing:
        raise KeyError(f"all factorial cells are required; missing {missing}")
    lengths = {converted[key].size for key in required}
    if len(lengths) != 1:
        raise ValueError("paired factorial cells must have the same number of units")
    return {key: converted[key] for key in required}


def factorial_unit_contrasts(cells: CellMap, subset: Sequence[int]) -> Array:
    """Return the per-unit inclusion-exclusion contrast for ``subset``.

    ``cells`` maps an active-feature tuple to one outcome per experimental unit.
    The empty tuple is the baseline cell ``Y(0, 0, ...)``.  For pairwise ``A,B``
    this is exactly::

        Y_i(1,1) - Y_i(1,0) - Y_i(0,1) + Y_i(0,0)
    """
    active = _validate_subset(subset)
    validated = _validate_cells(cells, active)
    order = len(active)
    result = np.zeros_like(next(iter(validated.values())))
    for cell in _powerset(active):
        sign = -1.0 if (order - len(cell)) % 2 else 1.0
        result = result + sign * validated[cell]
    if np.any(~np.isfinite(result)):
        raise ValueError("factorial contrasts must be finite")
    return result


def bootstrap_mean_interval(
    values: Sequence[float] | Array,
    *,
    confidence: float = 0.95,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> tuple[float, float, float, float]:
    """Percentile bootstrap for a mean.

    Returns ``(estimate, standard_error, low, high)``.  The bootstrap unit is
    the experimental unit, not the intervention cell.
    """
    array = np.asarray(values, dtype=np.float64).reshape(-1)
    if array.size == 0 or np.any(~np.isfinite(array)):
        raise ValueError("bootstrap values must be finite and non-empty")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must lie in (0, 1)")
    if n_boot < 1:
        raise ValueError("n_boot must be positive")
    estimate = float(array.mean())
    if array.size < 2:
        return estimate, math.nan, math.nan, math.nan
    standard_error = float(array.std(ddof=1) / math.sqrt(array.size))
    generator = np.random.default_rng(seed)
    indices = generator.integers(0, array.size, size=(n_boot, array.size))
    means = array[indices].mean(axis=1)
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(means, (alpha, 1.0 - alpha))
    return estimate, standard_error, float(low), float(high)


def estimate_factorial_contrast(
    cells: CellMap,
    subset: Sequence[int],
    *,
    confidence: float = 0.95,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> BootstrapContrast:
    """Estimate a paired factorial contrast with bootstrap uncertainty."""
    active = _validate_subset(subset)
    unit_contrasts = factorial_unit_contrasts(cells, active)
    estimate, standard_error, low, high = bootstrap_mean_interval(
        unit_contrasts,
        confidence=confidence,
        n_boot=n_boot,
        seed=seed,
    )
    return BootstrapContrast(
        contrast=estimate,
        standard_error=standard_error,
        confidence_low=low,
        confidence_high=high,
        confidence=confidence,
        n_units=int(unit_contrasts.size),
        n_boot=n_boot,
        method="paired per-unit factorial contrast; percentile bootstrap over units",
    )


def estimate_pairwise_contrast(
    baseline: Sequence[float],
    feature_a: Sequence[float],
    feature_b: Sequence[float],
    joint: Sequence[float],
    *,
    confidence: float = 0.95,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> BootstrapContrast:
    """Paired form of ``Y(1,1) - Y(1,0) - Y(0,1) + Y(0,0)``."""
    return estimate_factorial_contrast(
        {
            (): baseline,
            (0,): feature_a,
            (1,): feature_b,
            (0, 1): joint,
        },
        (0, 1),
        confidence=confidence,
        n_boot=n_boot,
        seed=seed,
    )


def estimate_higher_order_contrast(
    cells: CellMap,
    subset: Sequence[int],
    *,
    confidence: float = 0.95,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> BootstrapContrast:
    """Paired Möbius/inclusion-exclusion contrast of arbitrary order."""
    return estimate_factorial_contrast(
        cells,
        subset,
        confidence=confidence,
        n_boot=n_boot,
        seed=seed,
    )


def interaction_on_scale(
    cells: CellMap,
    subset: Sequence[int],
    transform: Callable[[Array], Array],
    *,
    paired: bool = True,
) -> float:
    """Apply a monotone or nonlinear outcome transform before the contrast.

    The result is only comparable with other contrasts on the same transformed
    scale.  For example, a logit transform of probabilities need not preserve
    the sign or magnitude of a probability-scale interaction.
    """
    active = _validate_subset(subset)
    validated = _validate_cells(cells, active)
    if paired:
        transformed = {
            key: np.asarray(transform(values), dtype=np.float64)
            for key, values in validated.items()
        }
        return float(np.mean(factorial_unit_contrasts(transformed, active)))
    transformed_means = {
        key: float(np.mean(np.asarray(transform(values), dtype=np.float64)))
        for key, values in validated.items()
    }
    order = len(active)
    return float(
        sum(
            (-1.0 if (order - len(cell)) % 2 else 1.0) * transformed_means[cell]
            for cell in _powerset(active)
        )
    )


def stability_summary(results: Mapping[str, BootstrapContrast]) -> StabilitySummary:
    """Summarize sign and interval agreement across measured groups."""
    if not results:
        raise ValueError("at least one group result is required")
    names = tuple(results)
    contrasts = tuple(results[name].contrast for name in names)
    nonzero = [contrast for contrast in contrasts if contrast != 0.0]
    if not nonzero:
        same_sign = True
        consistency = 1.0
    else:
        positive = sum(contrast > 0.0 for contrast in nonzero)
        negative = sum(contrast < 0.0 for contrast in nonzero)
        same_sign = positive == 0 or negative == 0
        consistency = max(positive, negative) / len(nonzero)
    lows = [results[name].confidence_low for name in names]
    highs = [results[name].confidence_high for name in names]
    pooled_low = max(lows)
    pooled_high = min(highs)
    finite = all(math.isfinite(value) for value in (pooled_low, pooled_high))
    return StabilitySummary(
        group_names=names,
        contrasts=contrasts,
        same_sign=same_sign,
        sign_consistency=float(consistency),
        all_intervals_overlap=bool(finite and pooled_low <= pooled_high),
        pooled_interval_low=float(pooled_low),
        pooled_interval_high=float(pooled_high),
    )


__all__ = [
    "BootstrapContrast",
    "StabilitySummary",
    "bootstrap_mean_interval",
    "estimate_factorial_contrast",
    "estimate_higher_order_contrast",
    "estimate_pairwise_contrast",
    "factorial_unit_contrasts",
    "interaction_on_scale",
    "logit",
    "sigmoid",
    "stability_summary",
]
