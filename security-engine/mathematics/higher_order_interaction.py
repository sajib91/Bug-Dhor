"""Higher-order feature interaction effects.

Equation (Möbius/factorial generalization of Eq. 12-13)
-------------------------------------------------------
For a feature subset ``S`` with ``|S| = k``::

    I_S = sum_{T subseteq S} (-1)^(k - |T|) g(T)

where ``g(T)`` is the mean outcome under the simultaneous intervention that
clamps every feature in ``T`` and leaves features outside ``T`` at their
factual values.  All ``2^k`` cells are required.  ``I_S > 0`` means the joint
effect exceeds the alternating lower-order combination (synergy); ``I_S < 0``
means antagonism.

Inputs
------
``cells`` : mapping from sorted active-feature tuples to outcome vectors,
including the empty tuple ``()`` for the baseline cell.
``subset`` : sorted unique feature tuple of order ``k >= 1``.

Outputs
-------
:class:`HigherOrderEstimate` with contrast and descriptive uncertainty.

Missing values
--------------
Paired design: a unit is dropped if any required cell is missing.  Unpaired
design: each cell drops its own missing values.  Missing cells are an error,
not an implicit zero.

Complexity
----------
One subset: O(2^k * N).  Exhaustive subsets up to order ``K`` over ``F``
features: ``sum_{k=1..K} C(F,k) 2^k`` cell evaluations.  Caching means each
unique cell is evaluated once per experiment.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import (
    DEFAULT_SEED,
    as_float_array,
    bootstrap_ci,
    mean_estimate,
    normal_quantile,
    resolve_rng,
    validate_confidence,
)
from mathematics.sae_encoding import SAEParameters, encode
from mathematics.single_feature_intervention import (
    FeatureIntervention,
    apply_multi_feature_decoder_intervention,
)

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class HigherOrderEstimate:
    """Interaction contrast for one feature subset."""

    subset: tuple[int, ...]
    order: int
    contrast: float
    standard_error: float
    confidence_low: float
    confidence_high: float
    count: int
    missing_count: int
    paired: bool
    confidence: float
    method: str
    outcome_scale: str
    sign_convention: str = "positive = synergistic, negative = antagonistic"

    @property
    def interpretation(self) -> str:
        return (
            "Higher-order factorial contrast on the declared outcome scale; "
            "conditional on the intervention operator and not a causal claim."
        )


@dataclass(frozen=True, slots=True)
class HigherOrderExperiment:
    """Results for all requested subsets and the required cells."""

    results: tuple[HigherOrderEstimate, ...]
    cells: Mapping[tuple[int, ...], Array]
    intervention_value: float
    outcome_scale: str

    def ranked(self, *, absolute: bool = True) -> tuple[HigherOrderEstimate, ...]:
        """Rank estimates by magnitude (or signed value)."""
        return tuple(
            sorted(
                self.results,
                key=lambda item: (
                    -abs(item.contrast) if absolute else -item.contrast,
                    item.order,
                    item.subset,
                ),
            )
        )


@dataclass(frozen=True, slots=True)
class ComplexityReport:
    """Theoretical cell cost for an exhaustive or sampled higher-order plan."""

    feature_count: int
    min_order: int
    max_order: int
    theoretical_subset_count: int
    theoretical_cell_evaluations: int
    repetitions: int

    @property
    def summary(self) -> str:
        return (
            f"{self.theoretical_subset_count} subsets and "
            f"{self.theoretical_cell_evaluations} cell evaluations for F="
            f"{self.feature_count}, orders {self.min_order}..{self.max_order}, "
            f"{self.repetitions} repetition(s)"
        )


def mobius_contrast(
    cells: Mapping[tuple[int, ...], Any],
    subset: Sequence[int],
) -> float:
    """Compute the alternating contrast for already-computed cell means."""
    features = _validate_subset(subset)
    total = 0.0
    for active in _powerset(features):
        key = _cell_key(active)
        if key not in cells:
            raise ValueError(f"missing required factorial cell {key!r}")
        sign = -1.0 if (len(features) - len(active)) % 2 else 1.0
        total += sign * _mean_ignore_missing(cells[key])
    return float(total)


def estimate_higher_order_interaction(
    cells: Mapping[tuple[int, ...], Any],
    subset: Sequence[int],
    *,
    paired: bool = True,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    outcome_scale: str = "model_score",
) -> HigherOrderEstimate:
    """Estimate the k-way interaction with all ``2^k`` cells."""
    features = _validate_subset(subset)
    validate_confidence(confidence)
    if method not in {"normal", "bootstrap"}:
        raise ValueError("method must be 'normal' or 'bootstrap'")
    keys = tuple(_cell_key(active) for active in _powerset(features))
    missing_cells = [key for key in keys if key not in cells]
    if missing_cells:
        raise ValueError(
            "all factorial cells are required; missing "
            + ", ".join(repr(key) for key in missing_cells)
        )
    arrays = [as_float_array(cells[key], name=f"cell {key}").reshape(-1) for key in keys]
    sign = np.asarray(
        [-1.0 if (len(features) - len(active)) % 2 else 1.0 for active in _powerset(features)]
    )

    if paired:
        lengths = {array.size for array in arrays}
        if len(lengths) != 1:
            raise ValueError("paired higher-order cells must have the same length")
        stacked = np.stack(arrays, axis=1)
        valid = np.isfinite(stacked).all(axis=1)
        missing = int((~valid).sum())
        if not valid.any():
            return _empty_estimate(features, confidence, method, outcome_scale, True, missing)
        unit = stacked[valid] @ sign
        estimate = mean_estimate(
            unit,
            confidence=confidence,
            method=method,
            n_boot=n_boot,
            seed=seed,
        )
        if method == "bootstrap":
            low, high = bootstrap_ci(
                np.mean,
                unit,
                n_boot=n_boot,
                confidence=confidence,
                seed=seed,
            )
        else:
            low, high = estimate.confidence_low, estimate.confidence_high
        return HigherOrderEstimate(
            subset=features,
            order=len(features),
            contrast=estimate.estimate,
            standard_error=estimate.standard_error,
            confidence_low=low,
            confidence_high=high,
            count=estimate.count,
            missing_count=missing,
            paired=True,
            confidence=confidence,
            method=estimate.method,
            outcome_scale=outcome_scale,
        )

    selected = [array[np.isfinite(array)] for array in arrays]
    missing = int(
        sum(array.size - clean.size for array, clean in zip(arrays, selected, strict=True))
    )
    if any(array.size == 0 for array in selected):
        return _empty_estimate(features, confidence, method, outcome_scale, False, missing)
    contrast = float(sum(coef * array.mean() for coef, array in zip(sign, selected, strict=True)))
    variances = [
        float(array.var(ddof=1) / array.size) if array.size >= 2 else math.nan for array in selected
    ]
    if any(not math.isfinite(value) for value in variances):
        return HigherOrderEstimate(
            subset=features,
            order=len(features),
            contrast=contrast,
            standard_error=math.nan,
            confidence_low=math.nan,
            confidence_high=math.nan,
            count=int(sum(array.size for array in selected)),
            missing_count=missing,
            paired=False,
            confidence=confidence,
            method="unavailable with fewer than two observations per cell",
            outcome_scale=outcome_scale,
        )
    standard_error = math.sqrt(sum(variances))
    critical = normal_quantile(0.5 + confidence / 2.0)
    return HigherOrderEstimate(
        subset=features,
        order=len(features),
        contrast=contrast,
        standard_error=standard_error,
        confidence_low=contrast - critical * standard_error,
        confidence_high=contrast + critical * standard_error,
        count=int(sum(array.size for array in selected)),
        missing_count=missing,
        paired=False,
        confidence=confidence,
        method="independent-cell variance sum; descriptive uncertainty",
        outcome_scale=outcome_scale,
    )


def generate_subsets(
    features: Sequence[int],
    *,
    min_order: int = 1,
    max_order: int = 3,
    max_subsets: int | None = None,
    sampling_strategy: str = "exhaustive",
    seed: int | None = DEFAULT_SEED,
) -> tuple[tuple[int, ...], ...]:
    """Generate deterministic or reproducibly sampled feature subsets."""
    unique = tuple(sorted(set(_validate_feature_indices(features))))
    if min_order < 1 or max_order < min_order:
        raise ValueError("orders must satisfy 1 <= min_order <= max_order")
    if sampling_strategy not in {"exhaustive", "random"}:
        raise ValueError("sampling_strategy must be 'exhaustive' or 'random'")
    subsets = [
        tuple(combo)
        for order in range(min_order, min(max_order, len(unique)) + 1)
        for combo in itertools.combinations(unique, order)
    ]
    if max_subsets is not None:
        if max_subsets < 1:
            raise ValueError("max_subsets must be positive")
        if sampling_strategy == "random" and len(subsets) > max_subsets:
            rng = resolve_rng(seed)
            chosen = sorted(rng.choice(len(subsets), size=max_subsets, replace=False))
            subsets = [subsets[index] for index in chosen]
        else:
            subsets = subsets[:max_subsets]
    return tuple(subsets)


def run_higher_order_experiment(
    activations: Any,
    outcome_fn: Any,
    parameters: SAEParameters,
    subsets: Iterable[Sequence[int]],
    *,
    intervention_value: float = 1.0,
    paired: bool = True,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    outcome_scale: str = "model_score",
) -> HigherOrderExperiment:
    """Evaluate the factorial cells with simultaneous decoder-direction edits."""
    if not math.isfinite(intervention_value):
        raise ValueError("intervention_value must be finite")
    h = as_float_array(activations, name="activations")
    if h.ndim != 2 or h.shape[1] != parameters.input_dim:
        raise ValueError(f"activations must have shape [N, {parameters.input_dim}], got {h.shape}")
    requested = [_validate_subset(subset) for subset in subsets]
    if not requested:
        raise ValueError("at least one feature subset is required")
    if any(feature >= parameters.latent_dim for subset in requested for feature in subset):
        raise ValueError("feature index is outside the latent dimension")
    latents = encode(h, parameters)
    cache: dict[tuple[int, ...], Array] = {}

    def outcomes_for(active: tuple[int, ...]) -> Array:
        if active not in cache:
            interventions = [
                FeatureIntervention(feature, "clamp", intervention_value) for feature in active
            ]
            modified = (
                h
                if not interventions
                else apply_multi_feature_decoder_intervention(
                    h, latents, parameters, interventions
                ).modified
            )
            values = as_float_array(outcome_fn(modified), name="outcomes").reshape(-1)
            if values.size != h.shape[0]:
                raise ValueError(f"outcome_fn must return {h.shape[0]} outcomes, got {values.size}")
            cache[active] = values
        return cache[active]

    results = []
    required_cells: set[tuple[int, ...]] = set()
    for subset in requested:
        cells: dict[tuple[int, ...], Array] = {}
        for active in _powerset(subset):
            cells[active] = outcomes_for(active)
            required_cells.add(active)
        results.append(
            estimate_higher_order_interaction(
                cells,
                subset,
                paired=paired,
                confidence=confidence,
                method=method,
                n_boot=n_boot,
                seed=seed,
                outcome_scale=outcome_scale,
            )
        )
    return HigherOrderExperiment(
        results=tuple(results),
        cells={key: cache[key] for key in sorted(required_cells)},
        intervention_value=intervention_value,
        outcome_scale=outcome_scale,
    )


def complexity_report(
    feature_count: int,
    *,
    min_order: int = 1,
    max_order: int = 3,
    repetitions: int = 1,
) -> ComplexityReport:
    """Report the exhaustive factorial cost before running an experiment."""
    if feature_count < 1:
        raise ValueError("feature_count must be positive")
    if min_order < 1 or max_order < min_order:
        raise ValueError("orders must satisfy 1 <= min_order <= max_order")
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    subsets = sum(
        math.comb(feature_count, order)
        for order in range(min_order, min(max_order, feature_count) + 1)
    )
    cells = sum(
        math.comb(feature_count, order) * (2**order) * repetitions
        for order in range(min_order, min(max_order, feature_count) + 1)
    )
    return ComplexityReport(
        feature_count=feature_count,
        min_order=min_order,
        max_order=max_order,
        theoretical_subset_count=subsets,
        theoretical_cell_evaluations=cells,
        repetitions=repetitions,
    )


def _powerset(features: Sequence[int]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        combo
        for order in range(len(features) + 1)
        for combo in itertools.combinations(features, order)
    )


def _cell_key(active: Sequence[int]) -> tuple[int, ...]:
    return tuple(sorted(active))


def _validate_subset(subset: Sequence[int]) -> tuple[int, ...]:
    features = tuple(int(feature) for feature in subset)
    if not features:
        raise ValueError("feature subset must not be empty")
    if any(feature < 0 for feature in features):
        raise ValueError("feature indices must be non-negative")
    if tuple(sorted(set(features))) != features:
        raise ValueError("feature subset must be sorted and unique")
    return features


def _validate_feature_indices(features: Sequence[int]) -> tuple[int, ...]:
    unique = tuple(int(feature) for feature in features)
    if not unique:
        raise ValueError("feature indices must not be empty")
    if any(feature < 0 for feature in unique):
        raise ValueError("feature indices must be non-negative")
    return unique


def _mean_ignore_missing(value: Any) -> float:
    array = as_float_array(value, name="cell").reshape(-1)
    finite = array[np.isfinite(array)]
    return float(finite.mean()) if finite.size else math.nan


def _empty_estimate(
    subset: tuple[int, ...],
    confidence: float,
    method: str,
    outcome_scale: str,
    paired: bool,
    missing: int,
) -> HigherOrderEstimate:
    return HigherOrderEstimate(
        subset=subset,
        order=len(subset),
        contrast=math.nan,
        standard_error=math.nan,
        confidence_low=math.nan,
        confidence_high=math.nan,
        count=0,
        missing_count=missing,
        paired=paired,
        confidence=confidence,
        method=method,
        outcome_scale=outcome_scale,
    )


__all__ = [
    "ComplexityReport",
    "HigherOrderEstimate",
    "HigherOrderExperiment",
    "complexity_report",
    "estimate_higher_order_interaction",
    "generate_subsets",
    "mobius_contrast",
    "run_higher_order_experiment",
]
