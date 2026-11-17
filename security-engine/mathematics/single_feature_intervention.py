"""Single-feature intervention and effect estimation.

Intervention operator
---------------------
For a feature ``j`` and a target latent value ``u``::

    do(z_j = u)  with  u = 0                  (ablate)
                       u = value              (clamp)
                       u = z_j + value        (add)

A decoder-direction intervention edits the model activation without changing
the other latents explicitly::

    delta_z = u - z_j
    h'      = h + delta_z * W_d[:, j]

The per-feature effect is the paired average treatment effect::

    tau_j = (1/N) sum_i [ g(h_i') - g(h_i) ]

with a standard error, confidence interval, and standardized paired effect
``tau_j / sd(g(h') - g(h))``.

Inputs
------
``latents`` : ``[N, d_s]`` or ``[N, T, d_s]``.
``activations`` : ``[N, d]`` or ``[N, T, d]``.
``outcome_fn`` : callable mapping an activation tensor to a 1-D outcome vector.

Outputs
-------
:class:`InterventionApplication` (modified tensors and deltas) and
:class:`EffectEstimate` (paired effect and uncertainty).

Missing values
--------------
Missing latents are left unchanged and counted.  Non-finite outcomes are
dropped pairwise from the effect estimate.

Complexity
----------
Latent intervention: O(N * d_s).  Decoder-direction intervention:
O(N * d).  Effect estimation: O(N), or O(B * N) for a bootstrap interval.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import numpy as np

from mathematics.common import (
    DEFAULT_SEED,
    as_float_array,
    bootstrap_ci,
    mean_estimate,
    validate_confidence,
)
from mathematics.sae_encoding import SAEParameters, encode

Array = np.ndarray
OutcomeFunction = Callable[[Array], Array]

InterventionMode = Literal["ablate", "clamp", "add"]


@dataclass(frozen=True, slots=True)
class FeatureIntervention:
    """One controlled single-feature intervention."""

    feature_index: int
    mode: InterventionMode = "ablate"
    value: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.feature_index, int) or isinstance(self.feature_index, bool):
            raise TypeError("feature_index must be an integer")
        if self.feature_index < 0:
            raise ValueError("feature_index must be non-negative")
        if self.mode not in {"ablate", "clamp", "add"}:
            raise ValueError("mode must be 'ablate', 'clamp', or 'add'")
        if not math.isfinite(self.value):
            raise ValueError("value must be finite")
        if self.mode == "ablate" and self.value != 0.0:
            raise ValueError("ablate interventions use value=0")

    def target(self, current: Array) -> Array:
        """Return the target latent value for this intervention."""
        if self.mode == "ablate":
            return np.zeros_like(current)
        if self.mode == "clamp":
            return np.full_like(current, self.value)
        return current + self.value


@dataclass(frozen=True, slots=True)
class InterventionApplication:
    """Result of applying an intervention to latents or activations."""

    original: Array
    modified: Array
    delta: Array
    changed_count: int
    missing_count: int
    feature_index: int
    target_value: float | None


@dataclass(frozen=True, slots=True)
class EffectEstimate:
    """Paired effect estimate for one intervention."""

    estimate: float
    standard_error: float
    confidence_low: float
    confidence_high: float
    standardized_effect: float
    count: int
    missing_count: int
    confidence: float
    method: str
    interpretation: str = (
        "Model-internal paired intervention effect; it is not a real-world causal effect."
    )


@dataclass(frozen=True, slots=True)
class SingleFeatureExperiment:
    """Complete single-feature counterfactual experiment."""

    intervention: FeatureIntervention
    factual_outcomes: Array
    interventional_outcomes: Array
    effect: EffectEstimate
    application: InterventionApplication
    outcome_scale: str


def apply_latent_intervention(
    latents: Any,
    intervention: FeatureIntervention,
    *,
    observed: Any | None = None,
) -> InterventionApplication:
    """Apply Eq. (8)-style intervention directly to latent values."""
    z = as_float_array(latents, name="latents")
    if z.ndim not in (2, 3):
        raise ValueError("latents must have shape [N, d_s] or [N, T, d_s]")
    if intervention.feature_index >= z.shape[-1]:
        raise ValueError(
            f"feature_index must lie in [0, {z.shape[-1]}), got {intervention.feature_index}"
        )
    mask = np.isfinite(z)
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
        mask &= explicit
    current = z[..., intervention.feature_index]
    target = intervention.target(current)
    delta = np.where(mask[..., intervention.feature_index], target - current, 0.0)
    modified = z.copy()
    modified[..., intervention.feature_index] = current + delta
    return InterventionApplication(
        original=z.copy(),
        modified=modified,
        delta=delta,
        changed_count=int(np.count_nonzero(delta)),
        missing_count=int((~mask[..., intervention.feature_index]).sum()),
        feature_index=intervention.feature_index,
        target_value=float(np.mean(target[mask[..., intervention.feature_index]]))
        if mask[..., intervention.feature_index].any()
        else None,
    )


def apply_decoder_intervention(
    activations: Any,
    latents: Any,
    parameters: SAEParameters,
    intervention: FeatureIntervention,
    *,
    observed: Any | None = None,
) -> InterventionApplication:
    """Move an activation along the SAE decoder direction to set one latent."""
    h = as_float_array(activations, name="activations")
    z = as_float_array(latents, name="latents")
    if h.shape[:-1] != z.shape[:-1]:
        raise ValueError(
            f"activations leading shape {h.shape[:-1]} must match latents "
            f"leading shape {z.shape[:-1]}"
        )
    if h.shape[-1] != parameters.input_dim:
        raise ValueError(
            f"activations last dimension must be {parameters.input_dim}, got {h.shape[-1]}"
        )
    if z.shape[-1] != parameters.latent_dim:
        raise ValueError(
            f"latents last dimension must be {parameters.latent_dim}, got {z.shape[-1]}"
        )
    if not np.isfinite(h).all():
        raise ValueError("activations must be finite")
    if intervention.feature_index >= parameters.latent_dim:
        raise ValueError(
            f"feature_index must lie in [0, {parameters.latent_dim}), "
            f"got {intervention.feature_index}"
        )
    mask = np.isfinite(z)
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
        mask &= explicit
    current = z[..., intervention.feature_index]
    target = intervention.target(current)
    valid = mask[..., intervention.feature_index]
    delta_z = np.where(valid, target - current, 0.0)
    direction = parameters.decoder_direction(intervention.feature_index)
    delta_h = delta_z[..., None] * direction
    modified = h + delta_h
    return InterventionApplication(
        original=h.copy(),
        modified=modified,
        delta=delta_h,
        changed_count=int(np.count_nonzero(delta_z)),
        missing_count=int((~valid).sum()),
        feature_index=intervention.feature_index,
        target_value=float(np.mean(target[valid])) if valid.any() else None,
    )


def apply_multi_feature_decoder_intervention(
    activations: Any,
    latents: Any,
    parameters: SAEParameters,
    interventions: Sequence[FeatureIntervention],
    *,
    observed: Any | None = None,
) -> InterventionApplication:
    """Apply several decoder-direction interventions in one activation edit.

    The combined edit is::

        h' = h + sum_j (u_j - z_j) * W_d[:, j]

    which is the simultaneous factorial intervention used by the pairwise and
    higher-order experiments.  Duplicate feature interventions are rejected.
    """
    h = as_float_array(activations, name="activations")
    z = as_float_array(latents, name="latents")
    if h.shape[:-1] != z.shape[:-1]:
        raise ValueError("activations and latents must share leading dimensions")
    if h.shape[-1] != parameters.input_dim:
        raise ValueError(
            f"activations last dimension must be {parameters.input_dim}, got {h.shape[-1]}"
        )
    if z.shape[-1] != parameters.latent_dim:
        raise ValueError(
            f"latents last dimension must be {parameters.latent_dim}, got {z.shape[-1]}"
        )
    if not np.isfinite(h).all():
        raise ValueError("activations must be finite")
    selected = list(interventions)
    if not selected:
        raise ValueError("at least one intervention is required")
    indices = [item.feature_index for item in selected]
    if len(set(indices)) != len(indices):
        raise ValueError("interventions must target distinct features")
    if any(index < 0 or index >= parameters.latent_dim for index in indices):
        raise ValueError("intervention feature index is outside the latent dimension")
    mask = np.isfinite(z)
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
        mask &= explicit
    delta_h = np.zeros_like(h)
    changed = 0
    missing = 0
    targets: list[float] = []
    for intervention in selected:
        current = z[..., intervention.feature_index]
        valid = mask[..., intervention.feature_index]
        target = intervention.target(current)
        delta_z = np.where(valid, target - current, 0.0)
        direction = parameters.decoder_direction(intervention.feature_index)
        delta_h += delta_z[..., None] * direction
        changed += int(np.count_nonzero(delta_z))
        missing += int((~valid).sum())
        if valid.any():
            targets.append(float(np.mean(target[valid])))
    return InterventionApplication(
        original=h.copy(),
        modified=h + delta_h,
        delta=delta_h,
        changed_count=changed,
        missing_count=missing,
        feature_index=selected[0].feature_index if len(selected) == 1 else -1,
        target_value=targets[0] if len(targets) == 1 else None,
    )


def estimate_paired_effect(
    factual: Any,
    interventional: Any,
    *,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
) -> EffectEstimate:
    """Estimate ``mean(interventional - factual)`` with paired uncertainty."""
    pre = as_float_array(factual, name="factual").reshape(-1)
    post = as_float_array(interventional, name="interventional").reshape(-1)
    if pre.shape != post.shape:
        raise ValueError(
            f"factual and interventional must have the same shape, got {pre.shape} and {post.shape}"
        )
    if method not in {"normal", "bootstrap"}:
        raise ValueError("method must be 'normal' or 'bootstrap'")
    validate_confidence(confidence)
    differences = post - pre
    finite = np.isfinite(differences)
    missing = int((~finite).sum())
    selected = differences[finite]
    if selected.size == 0:
        return EffectEstimate(
            estimate=math.nan,
            standard_error=math.nan,
            confidence_low=math.nan,
            confidence_high=math.nan,
            standardized_effect=math.nan,
            count=0,
            missing_count=missing,
            confidence=confidence,
            method=method,
        )
    estimate = mean_estimate(
        selected,
        confidence=confidence,
        method=method,
        n_boot=n_boot,
        seed=seed,
    )
    sd = float(selected.std(ddof=1)) if selected.size >= 2 else math.nan
    standardized = estimate.estimate / sd if math.isfinite(sd) and sd > 0 else math.nan
    if method == "bootstrap":
        low, high = bootstrap_ci(
            np.mean,
            selected,
            n_boot=n_boot,
            confidence=confidence,
            seed=seed,
        )
    else:
        low, high = estimate.confidence_low, estimate.confidence_high
    return EffectEstimate(
        estimate=estimate.estimate,
        standard_error=estimate.standard_error,
        confidence_low=low,
        confidence_high=high,
        standardized_effect=standardized,
        count=int(selected.size),
        missing_count=missing,
        confidence=confidence,
        method=estimate.method,
    )


def _validate_outcomes(outcomes: Any, *, expected: int, name: str) -> Array:
    values = as_float_array(outcomes, name=name).reshape(-1)
    if values.size != expected:
        raise ValueError(f"{name} must contain {expected} outcomes, got {values.size}")
    return values


def run_single_feature_experiment(
    activations: Any,
    outcome_fn: OutcomeFunction,
    parameters: SAEParameters,
    intervention: FeatureIntervention,
    *,
    outcome_scale: str = "model_score",
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    observed_latents: Any | None = None,
) -> SingleFeatureExperiment:
    """Run a real single-feature decoder-direction intervention end to end.

    The outcome function is supplied by the caller (for example, a detector
    logit or vulnerability probability).  This function never invents an
    outcome value.
    """
    h = as_float_array(activations, name="activations")
    if h.ndim == 1:
        h = h.reshape(1, -1)
    if h.ndim != 2:
        raise ValueError("activations must have shape [N, d]")
    if h.shape[1] != parameters.input_dim:
        raise ValueError(f"activations must have width {parameters.input_dim}, got {h.shape[1]}")
    latents = encode(h, parameters)
    application = apply_decoder_intervention(
        h,
        latents,
        parameters,
        intervention,
        observed=observed_latents,
    )
    factual = _validate_outcomes(outcome_fn(h), expected=h.shape[0], name="factual outcomes")
    interventional = _validate_outcomes(
        outcome_fn(application.modified),
        expected=h.shape[0],
        name="interventional outcomes",
    )
    effect = estimate_paired_effect(
        factual,
        interventional,
        confidence=confidence,
        method=method,
        n_boot=n_boot,
        seed=seed,
    )
    return SingleFeatureExperiment(
        intervention=intervention,
        factual_outcomes=factual,
        interventional_outcomes=interventional,
        effect=effect,
        application=application,
        outcome_scale=outcome_scale,
    )


def sweep_intervention_values(
    activations: Any,
    outcome_fn: OutcomeFunction,
    parameters: SAEParameters,
    feature_index: int,
    values: Any,
    *,
    mode: str = "clamp",
    outcome_scale: str = "model_score",
    confidence: float = 0.95,
    method: str = "normal",
    seed: int | None = DEFAULT_SEED,
) -> tuple[SingleFeatureExperiment, ...]:
    """Run a deterministic dose-response sweep for one feature."""
    grid = as_float_array(values, name="values").reshape(-1)
    if grid.size < 2:
        raise ValueError("values must contain at least two intervention magnitudes")
    if not np.isfinite(grid).all():
        raise ValueError("values must be finite")
    results = []
    for value in grid:
        intervention = FeatureIntervention(
            feature_index=feature_index,
            mode=mode,  # type: ignore[arg-type]
            value=float(value),
        )
        results.append(
            run_single_feature_experiment(
                activations,
                outcome_fn,
                parameters,
                intervention,
                outcome_scale=outcome_scale,
                confidence=confidence,
                method=method,
                seed=seed,
            )
        )
    return tuple(results)


__all__ = [
    "EffectEstimate",
    "FeatureIntervention",
    "InterventionApplication",
    "SingleFeatureExperiment",
    "apply_decoder_intervention",
    "apply_latent_intervention",
    "apply_multi_feature_decoder_intervention",
    "estimate_paired_effect",
    "run_single_feature_experiment",
    "sweep_intervention_values",
]
