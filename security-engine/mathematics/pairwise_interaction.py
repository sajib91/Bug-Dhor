"""Pairwise feature interaction effects (Eq. 12-13).

Equations
---------
Eq. (12), binary intervention::

    I_ij = g(1,1) - g(1,0) - g(0,1) + g(0,0)

Eq. (13), continuous magnitudes::

    I_ij(a,b) = g(a,b) - g(a,0) - g(0,b) + g(0,0)

Sign convention: ``I > 0`` means the joint intervention exceeds the additive
combination (synergy under this outcome scale); ``I < 0`` means antagonism.
The contrast is scale-dependent and is not invariant to nonlinear outcome
transformations.

Inputs
------
Four outcome vectors or matrices, one per factorial cell.  With
``paired=True`` they must have the same leading dimension and the contrast is
computed per unit before averaging, which removes between-unit variance.

Outputs
-------
:class:`InteractionEstimate` with contrast, standard error, confidence
interval, and provenance.  :class:`PairwiseExperiment` stores the cells and the
estimate.

Missing values
--------------
Paired design: a unit with any missing cell is dropped and counted.  Unpaired
design: each cell drops its own missing values.  No cell is imputed.

Complexity
----------
Estimate: O(N) (paired) or O(sum n_cells) (unpaired).  Bootstrap:
O(B * N).  A full experiment evaluates four outcome cells, each O(N * d).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import (
    DEFAULT_SEED,
    as_float_array,
    bootstrap_ci,
    mean_estimate,
    normal_quantile,
    validate_confidence,
)
from mathematics.sae_encoding import SAEParameters, encode
from mathematics.single_feature_intervention import (
    FeatureIntervention,
    apply_multi_feature_decoder_intervention,
)

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class InteractionEstimate:
    """Pairwise difference-in-differences contrast and uncertainty."""

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
            "Additive factorial contrast on the declared outcome scale; "
            "not a causal effect and not invariant to outcome transformations."
        )


@dataclass(frozen=True, slots=True)
class PairwiseExperiment:
    """All four cells and the estimated interaction for one feature pair."""

    feature_a: int
    feature_b: int
    value_a: float
    value_b: float
    baseline_outcomes: Array
    feature_a_outcomes: Array
    feature_b_outcomes: Array
    joint_outcomes: Array
    estimate: InteractionEstimate
    intervention_operator: str = "simultaneous_sae_decoder_direction"


def pairwise_contrast(
    y00: Any,
    y10: Any,
    y01: Any,
    y11: Any,
) -> float:
    """Compute Eq. (12) from cell means (unpaired point estimate)."""
    cells = [
        _mean_ignore_missing(y00),
        _mean_ignore_missing(y10),
        _mean_ignore_missing(y01),
        _mean_ignore_missing(y11),
    ]
    if any(not math.isfinite(value) for value in cells):
        return math.nan
    return float(cells[3] - cells[1] - cells[2] + cells[0])


def estimate_pairwise_interaction(
    y00: Any,
    y10: Any,
    y01: Any,
    y11: Any,
    *,
    paired: bool = True,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    outcome_scale: str = "model_score",
) -> InteractionEstimate:
    """Estimate Eq. (12) with a paired or independent-cell interval."""
    validate_confidence(confidence)
    if method not in {"normal", "bootstrap"}:
        raise ValueError("method must be 'normal' or 'bootstrap'")
    cells = [
        as_float_array(value, name=name).reshape(-1)
        for value, name in (
            (y00, "y00"),
            (y10, "y10"),
            (y01, "y01"),
            (y11, "y11"),
        )
    ]
    if paired:
        lengths = {cell.size for cell in cells}
        if len(lengths) != 1:
            raise ValueError(
                "paired interaction cells must all have the same length, got "
                + ", ".join(str(size) for size in (cell.size for cell in cells))
            )
        stacked = np.stack(cells, axis=1)
        valid = np.isfinite(stacked).all(axis=1)
        missing = int((~valid).sum())
        selected = stacked[valid]
        if selected.shape[0] == 0:
            return _empty_estimate(confidence, method, outcome_scale, True, missing)
        unit_contrast = selected[:, 3] - selected[:, 1] - selected[:, 2] + selected[:, 0]
        estimate = mean_estimate(
            unit_contrast,
            confidence=confidence,
            method=method,
            n_boot=n_boot,
            seed=seed,
        )
        if method == "bootstrap":
            low, high = bootstrap_ci(
                np.mean,
                unit_contrast,
                n_boot=n_boot,
                confidence=confidence,
                seed=seed,
            )
        else:
            low, high = estimate.confidence_low, estimate.confidence_high
        return InteractionEstimate(
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

    selected = [cell[np.isfinite(cell)] for cell in cells]
    missing = int(sum(cell.size - clean.size for cell, clean in zip(cells, selected, strict=True)))
    if any(cell.size == 0 for cell in selected):
        return _empty_estimate(confidence, method, outcome_scale, False, missing)
    joint, feature_a, feature_b, baseline = (selected[3], selected[1], selected[2], selected[0])
    contrast = float(joint.mean() - feature_a.mean() - feature_b.mean() + baseline.mean())
    variances = [
        float(cell.var(ddof=1) / cell.size) if cell.size >= 2 else math.nan for cell in selected
    ]
    if any(not math.isfinite(value) for value in variances):
        return InteractionEstimate(
            contrast=contrast,
            standard_error=math.nan,
            confidence_low=math.nan,
            confidence_high=math.nan,
            count=int(sum(cell.size for cell in selected)),
            missing_count=missing,
            paired=False,
            confidence=confidence,
            method="unavailable with fewer than two observations per cell",
            outcome_scale=outcome_scale,
        )
    standard_error = math.sqrt(sum(variances))
    critical = normal_quantile(0.5 + confidence / 2.0)
    return InteractionEstimate(
        contrast=contrast,
        standard_error=standard_error,
        confidence_low=contrast - critical * standard_error,
        confidence_high=contrast + critical * standard_error,
        count=int(sum(cell.size for cell in selected)),
        missing_count=missing,
        paired=False,
        confidence=confidence,
        method="independent-cell variance sum; descriptive uncertainty",
        outcome_scale=outcome_scale,
    )


def run_pairwise_experiment(
    activations: Any,
    outcome_fn: Any,
    parameters: SAEParameters,
    feature_a: int,
    feature_b: int,
    *,
    value_a: float = 1.0,
    value_b: float = 1.0,
    paired: bool = True,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    outcome_scale: str = "model_score",
) -> PairwiseExperiment:
    """Measure the four factorial cells with real decoder-direction edits."""
    if feature_a == feature_b:
        raise ValueError("feature_a and feature_b must be distinct")
    h = as_float_array(activations, name="activations")
    if h.ndim != 2 or h.shape[1] != parameters.input_dim:
        raise ValueError(f"activations must have shape [N, {parameters.input_dim}], got {h.shape}")
    if not math.isfinite(value_a) or not math.isfinite(value_b):
        raise ValueError("intervention values must be finite")
    latents = encode(h, parameters)
    if not 0 <= feature_a < parameters.latent_dim or not 0 <= feature_b < parameters.latent_dim:
        raise ValueError("feature indices must lie inside the latent dimension")

    def cell(interventions: list[FeatureIntervention]) -> Array:
        if not interventions:
            modified = h
        else:
            modified = apply_multi_feature_decoder_intervention(
                h, latents, parameters, interventions
            ).modified
        outcomes = as_float_array(outcome_fn(modified), name="outcomes").reshape(-1)
        if outcomes.size != h.shape[0]:
            raise ValueError(f"outcome_fn must return {h.shape[0]} outcomes, got {outcomes.size}")
        return outcomes

    baseline = cell([])
    a_only = cell([FeatureIntervention(feature_a, "clamp", value_a)])
    b_only = cell([FeatureIntervention(feature_b, "clamp", value_b)])
    joint = cell(
        [
            FeatureIntervention(feature_a, "clamp", value_a),
            FeatureIntervention(feature_b, "clamp", value_b),
        ]
    )
    estimate = estimate_pairwise_interaction(
        baseline,
        a_only,
        b_only,
        joint,
        paired=paired,
        confidence=confidence,
        method=method,
        n_boot=n_boot,
        seed=seed,
        outcome_scale=outcome_scale,
    )
    return PairwiseExperiment(
        feature_a=feature_a,
        feature_b=feature_b,
        value_a=value_a,
        value_b=value_b,
        baseline_outcomes=baseline,
        feature_a_outcomes=a_only,
        feature_b_outcomes=b_only,
        joint_outcomes=joint,
        estimate=estimate,
    )


def rank_pairwise_interactions(
    experiments: list[PairwiseExperiment] | tuple[PairwiseExperiment, ...],
    *,
    absolute: bool = True,
) -> tuple[PairwiseExperiment, ...]:
    """Rank measured interactions without a significance claim."""
    return tuple(
        sorted(
            experiments,
            key=lambda item: (
                -abs(item.estimate.contrast) if absolute else -item.estimate.contrast,
                item.feature_a,
                item.feature_b,
            ),
        )
    )


def _mean_ignore_missing(value: Any) -> float:
    array = as_float_array(value, name="outcomes").reshape(-1)
    finite = array[np.isfinite(array)]
    return float(finite.mean()) if finite.size else math.nan


def _empty_estimate(
    confidence: float,
    method: str,
    outcome_scale: str,
    paired: bool,
    missing: int,
) -> InteractionEstimate:
    return InteractionEstimate(
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
    "InteractionEstimate",
    "PairwiseExperiment",
    "estimate_pairwise_interaction",
    "pairwise_contrast",
    "rank_pairwise_interactions",
    "run_pairwise_experiment",
]
