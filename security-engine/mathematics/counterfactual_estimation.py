"""Counterfactual outcome estimation under feature interventions.

Estimand
--------
For an intervention set ``T`` with target values ``u_T``::

    g(T) = E_{x ~ D_eval}[ f( x ; do(z_j = u_j for j in T) ) ]

The paired estimator is::

    Delta(T) = (1/N) sum_i [ f(x_i; do(z_T = u_T)) - f(x_i) ]

with a paired standard error and confidence interval.  ``f`` is supplied by the
caller (a detector score, probability, or any declared scalar outcome); it is
never invented here.

Inputs
------
``activations`` : ``[N, d]`` real model activations.
``outcome_fn`` : callable ``[N, d] -> [N]``.
``interventions`` : one or more :class:`FeatureIntervention` objects.

Outputs
-------
:class:`CounterfactualEstimate` and :class:`CounterfactualResult`.

Missing values
--------------
A unit with a missing factual or counterfactual outcome is excluded from the
paired estimate and reported in ``missing_count``.  Missing activations are
rejected by the SAE encoder.

Complexity
----------
Each intervention cell is O(N * d).  A set of ``M`` cells is O(M * N * d).
Effect estimation is O(N), or O(B * N) for the bootstrap.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import (
    DEFAULT_SEED,
    as_float_array,
    bootstrap_ci,
    mean_estimate,
    validate_confidence,
)
from mathematics.sae_encoding import SAEParameters, encode
from mathematics.single_feature_intervention import (
    FeatureIntervention,
    apply_multi_feature_decoder_intervention,
)

Array = np.ndarray
OutcomeFunction = Callable[[Array], Array]


@dataclass(frozen=True, slots=True)
class CounterfactualEstimate:
    """Factual/counterfactual expected outcomes and their paired difference."""

    factual_mean: float
    counterfactual_mean: float
    delta: float
    standard_error: float
    confidence_low: float
    confidence_high: float
    standardized_effect: float
    count: int
    missing_count: int
    confidence: float
    method: str
    outcome_scale: str
    intervention_description: str
    interpretation: str = (
        "Model-internal counterfactual outcome comparison; not a real-world causal effect."
    )


@dataclass(frozen=True, slots=True)
class CounterfactualResult:
    """Counterfactual estimate plus the per-unit outcomes used to compute it."""

    estimate: CounterfactualEstimate
    factual_outcomes: Array
    counterfactual_outcomes: Array
    delta_outcomes: Array
    interventions: tuple[FeatureIntervention, ...]
    feature_activations: Array


def estimate_counterfactual_outcomes(
    factual: Any,
    counterfactual: Any,
    *,
    interventions: Sequence[FeatureIntervention] = (),
    outcome_scale: str = "model_score",
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
) -> CounterfactualEstimate:
    """Estimate the paired counterfactual difference from measured outcomes."""
    pre = as_float_array(factual, name="factual").reshape(-1)
    post = as_float_array(counterfactual, name="counterfactual").reshape(-1)
    if pre.shape != post.shape:
        raise ValueError(
            "factual and counterfactual outcomes must have the same length, "
            f"got {pre.size} and {post.size}"
        )
    validate_confidence(confidence)
    if method not in {"normal", "bootstrap"}:
        raise ValueError("method must be 'normal' or 'bootstrap'")
    valid = np.isfinite(pre) & np.isfinite(post)
    missing = int((~valid).sum())
    differences = post[valid] - pre[valid]
    if differences.size == 0:
        return CounterfactualEstimate(
            factual_mean=math.nan,
            counterfactual_mean=math.nan,
            delta=math.nan,
            standard_error=math.nan,
            confidence_low=math.nan,
            confidence_high=math.nan,
            standardized_effect=math.nan,
            count=0,
            missing_count=missing,
            confidence=confidence,
            method=method,
            outcome_scale=outcome_scale,
            intervention_description=_describe(interventions),
        )
    mean = mean_estimate(
        differences,
        confidence=confidence,
        method=method,
        n_boot=n_boot,
        seed=seed,
    )
    if method == "bootstrap":
        low, high = bootstrap_ci(
            np.mean,
            differences,
            n_boot=n_boot,
            confidence=confidence,
            seed=seed,
        )
    else:
        low, high = mean.confidence_low, mean.confidence_high
    sd = float(differences.std(ddof=1)) if differences.size >= 2 else math.nan
    standardized = mean.estimate / sd if math.isfinite(sd) and sd > 0 else math.nan
    return CounterfactualEstimate(
        factual_mean=float(pre[valid].mean()),
        counterfactual_mean=float(post[valid].mean()),
        delta=mean.estimate,
        standard_error=mean.standard_error,
        confidence_low=low,
        confidence_high=high,
        standardized_effect=standardized,
        count=int(differences.size),
        missing_count=missing,
        confidence=confidence,
        method=mean.method,
        outcome_scale=outcome_scale,
        intervention_description=_describe(interventions),
    )


class CounterfactualEstimator:
    """Reproducible paired counterfactual estimator over real activations."""

    def __init__(
        self,
        *,
        seed: int | None = DEFAULT_SEED,
        confidence: float = 0.95,
        method: str = "normal",
        n_boot: int = 2000,
    ) -> None:
        validate_confidence(confidence)
        if method not in {"normal", "bootstrap"}:
            raise ValueError("method must be 'normal' or 'bootstrap'")
        if n_boot < 1:
            raise ValueError("n_boot must be positive")
        self.seed = seed
        self.confidence = confidence
        self.method = method
        self.n_boot = n_boot
        self.history: list[CounterfactualResult] = []

    def estimate(
        self,
        activations: Any,
        outcome_fn: OutcomeFunction,
        parameters: SAEParameters,
        interventions: Sequence[FeatureIntervention],
        *,
        outcome_scale: str = "model_score",
        observed_latents: Any | None = None,
    ) -> CounterfactualResult:
        """Apply the intervention to every activation and estimate the delta."""
        h = as_float_array(activations, name="activations")
        if h.ndim == 1:
            h = h.reshape(1, -1)
        if h.ndim != 2 or h.shape[1] != parameters.input_dim:
            raise ValueError(
                f"activations must have shape [N, {parameters.input_dim}], got {h.shape}"
            )
        if not interventions:
            raise ValueError("at least one intervention is required")
        latents = encode(h, parameters)
        application = apply_multi_feature_decoder_intervention(
            h,
            latents,
            parameters,
            interventions,
            observed=observed_latents,
        )
        factual = _validate_outcomes(outcome_fn(h), expected=h.shape[0], name="factual")
        counterfactual = _validate_outcomes(
            outcome_fn(application.modified),
            expected=h.shape[0],
            name="counterfactual",
        )
        estimate = estimate_counterfactual_outcomes(
            factual,
            counterfactual,
            interventions=tuple(interventions),
            outcome_scale=outcome_scale,
            confidence=self.confidence,
            method=self.method,
            n_boot=self.n_boot,
            seed=self.seed,
        )
        result = CounterfactualResult(
            estimate=estimate,
            factual_outcomes=factual,
            counterfactual_outcomes=counterfactual,
            delta_outcomes=counterfactual - factual,
            interventions=tuple(interventions),
            feature_activations=latents,
        )
        self.history.append(result)
        return result

    def expected_cell_means(
        self,
        activations: Any,
        outcome_fn: OutcomeFunction,
        parameters: SAEParameters,
        intervention_sets: Mapping[tuple[int, ...], Sequence[FeatureIntervention]],
    ) -> dict[tuple[int, ...], float]:
        """Estimate ``g(T)`` for every intervention set, reusing the baseline."""
        h = as_float_array(activations, name="activations")
        if h.ndim != 2 or h.shape[1] != parameters.input_dim:
            raise ValueError(
                f"activations must have shape [N, {parameters.input_dim}], got {h.shape}"
            )
        latents = encode(h, parameters)
        baseline = _validate_outcomes(outcome_fn(h), expected=h.shape[0], name="factual")
        output: dict[tuple[int, ...], float] = {}
        for key, interventions in intervention_sets.items():
            if not interventions:
                values = baseline
            else:
                modified = apply_multi_feature_decoder_intervention(
                    h, latents, parameters, interventions
                ).modified
                values = _validate_outcomes(
                    outcome_fn(modified), expected=h.shape[0], name=f"cell {key}"
                )
            finite = values[np.isfinite(values)]
            output[tuple(key)] = float(finite.mean()) if finite.size else math.nan
        return output


def make_decoder_intervention_function(
    parameters: SAEParameters,
    interventions: Sequence[FeatureIntervention],
    *,
    observed_latents: Any | None = None,
) -> Callable[[Array], Array]:
    """Return ``h -> h'`` for use inside an external model pipeline."""
    selected = tuple(interventions)
    if not selected:
        raise ValueError("at least one intervention is required")

    def apply(activations: Array) -> Array:
        h = as_float_array(activations, name="activations")
        latents = encode(h, parameters)
        return apply_multi_feature_decoder_intervention(
            h,
            latents,
            parameters,
            selected,
            observed=observed_latents,
        ).modified

    return apply


def _validate_outcomes(value: Any, *, expected: int, name: str) -> Array:
    outcomes = as_float_array(value, name=name).reshape(-1)
    if outcomes.size != expected:
        raise ValueError(f"{name} outcomes must have length {expected}, got {outcomes.size}")
    return outcomes


def _describe(interventions: Sequence[FeatureIntervention]) -> str:
    if not interventions:
        return "no intervention"
    return "; ".join(f"do(z_{item.feature_index} = {_target_text(item)})" for item in interventions)


def _target_text(intervention: FeatureIntervention) -> str:
    if intervention.mode == "ablate":
        return "0"
    if intervention.mode == "clamp":
        return f"{intervention.value:g}"
    return f"z + {intervention.value:g}"


__all__ = [
    "CounterfactualEstimate",
    "CounterfactualEstimator",
    "CounterfactualResult",
    "estimate_counterfactual_outcomes",
    "make_decoder_intervention_function",
]
