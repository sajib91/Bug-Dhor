"""Adaptive multi-feature steering allocation.

Formulation
-----------
The policy is documented (not a single numbered paper equation) and mirrors the
transparent allocation implemented by ``craftsec.steering.adaptive``.  For every
selected feature ``j``::

    i_j       = |a_j|                                  importance magnitude
    d_j       = direction(Delta mu_j)                  +1 / -1
    tau_j     = s_0 * w_individual * i_j * d_j         individual term

    tau_j    += sum_{S : j in S, |S| >= 2}
                    s_0 * w_|S| * I_S / |S|            interaction term

    tau_j    *= context_multiplier                     context adjustment
    tau_j     = clip(tau_j, -s_max, +s_max)            per-feature bound

If a global L2 budget ``B`` is supplied and ``||tau||_2 > B``, all strengths are
rescaled by ``B / ||tau||_2``.  The applied activation edit is::

    h'_i = h_i + sum_{j in selected} tau_j * W_d[:, j]

which is the same decoder-direction operator used by the single-feature,
pairwise, higher-order, and counterfactual modules.

Position schedule
-----------------
For a token position ``p`` with measured feature activations ``z_{p,j}``::

    active(p)  = { j : |z_{p,j}| > activation_threshold }
    scale_{p,j} = |z_{p,j}| / activation_reference
    tau_{p,j}  = clip(tau_j * scale_{p,j}, -s_max, +s_max) if j in active(p)
                 0 otherwise

Inputs / outputs
----------------
Importance is a finite mapping ``feature -> measured score`` (a selectivity,
mean activation difference, precision, recall, or any documented score).  No
score is invented; an empty or all-missing importance map selects no features.

Missing values
--------------
Non-finite importance, direction, contrast, or activation values are rejected.
A feature without importance is never selected.  A position without measured
activations receives no scheduled strength (it is not treated as zero
activation).

Complexity
----------
Ranking: O(F log F).  Allocation: O(F + sum_S |S|).  L2 clipping: O(F).
Schedule: O(P * F) for ``P`` positions and ``F`` selected features.  Application:
O(N * d * F) in the general case, or O(N * d + N * F) with a precomputed delta.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import numpy as np

from mathematics.common import as_float_array, require_2d
from mathematics.sae_encoding import SAEParameters

Array = np.ndarray
DirectionMode = Literal["positive", "negative", "association_reducing"]


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringConfig:
    """Explicit policy controls for strength allocation."""

    max_features: int = 8
    max_order: int = 3
    base_strength: float = 1.0
    individual_weight: float = 1.0
    pairwise_weight: float = 1.0
    higher_order_weight: float = 1.0
    minimum_importance: float = 0.0
    direction_mode: DirectionMode = "association_reducing"
    context_multiplier: float = 1.0
    activation_threshold: float = 0.0
    activation_reference: float = 1.0
    max_strength: float = 10.0
    l2_budget: float | None = None
    max_schedule_steps: int = 64

    def __post_init__(self) -> None:
        if self.max_features < 1:
            raise ValueError("max_features must be positive")
        if self.max_order < 2:
            raise ValueError("max_order must be at least 2")
        if self.max_schedule_steps < 1:
            raise ValueError("max_schedule_steps must be positive")
        if self.direction_mode not in {"positive", "negative", "association_reducing"}:
            raise ValueError(
                "direction_mode must be 'positive', 'negative', or 'association_reducing'"
            )
        for name in (
            "base_strength",
            "individual_weight",
            "pairwise_weight",
            "higher_order_weight",
            "minimum_importance",
            "context_multiplier",
            "activation_threshold",
            "activation_reference",
            "max_strength",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if self.activation_reference <= 0:
            raise ValueError("activation_reference must be positive")
        if self.max_strength <= 0:
            raise ValueError("max_strength must be positive")
        if self.l2_budget is not None and (
            not math.isfinite(self.l2_budget) or self.l2_budget <= 0
        ):
            raise ValueError("l2_budget must be positive when supplied")


@dataclass(frozen=True, slots=True)
class FeatureImportance:
    """One selected feature and its measured importance magnitude."""

    feature_index: int
    score: float
    direction: float

    def __post_init__(self) -> None:
        if self.feature_index < 0:
            raise ValueError("feature_index must be non-negative")
        if not math.isfinite(self.score) or self.score < 0:
            raise ValueError("score must be finite and non-negative")
        if self.direction not in (-1.0, 1.0):
            raise ValueError("direction must be -1 or +1")


@dataclass(frozen=True, slots=True)
class InteractionContribution:
    """One measured interaction contrast allocated to its member features."""

    features: tuple[int, ...]
    order: int
    contrast: float
    weighted_contribution: float
    per_feature_contribution: float
    source: str

    def __post_init__(self) -> None:
        if len(self.features) < 2:
            raise ValueError("interaction contributions require at least two features")
        if tuple(sorted(set(self.features))) != self.features:
            raise ValueError("interaction features must be sorted and unique")
        if self.order != len(self.features):
            raise ValueError("order must equal the number of interaction features")
        if not all(
            math.isfinite(value)
            for value in (
                self.contrast,
                self.weighted_contribution,
                self.per_feature_contribution,
            )
        ):
            raise ValueError("interaction terms must be finite")


@dataclass(frozen=True, slots=True)
class PositionSteering:
    """Scheduled strengths for one token position."""

    position: int
    active_features: tuple[int, ...]
    strengths: tuple[float, ...]

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("position must be non-negative")
        if len(self.strengths) != len(self.active_features):
            raise ValueError("strengths must align with active_features")
        if not all(math.isfinite(value) for value in self.strengths):
            raise ValueError("scheduled strengths must be finite")


@dataclass(frozen=True, slots=True)
class StrengthAllocation:
    """Individual and interaction terms that produce the final strengths."""

    selected_features: tuple[int, ...]
    importance: tuple[FeatureImportance, ...]
    individual_terms: Mapping[int, float]
    interaction_terms: tuple[InteractionContribution, ...]
    context_adjustment: float
    per_feature_clipped: Mapping[int, float]
    l2_scale: float
    strengths: Mapping[int, float]
    l2_norm: float

    def __post_init__(self) -> None:
        if not 0.0 < self.l2_scale <= 1.0:
            raise ValueError("l2_scale must lie in (0, 1]")
        if not math.isfinite(self.l2_norm) or self.l2_norm < 0:
            raise ValueError("l2_norm must be finite and non-negative")
        if set(self.strengths) != set(self.selected_features):
            raise ValueError("strengths must be defined for every selected feature")


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringPlan:
    """Complete reproducible steering decision."""

    config: AdaptiveSteeringConfig
    allocation: StrengthAllocation
    schedule: tuple[PositionSteering, ...]

    @property
    def selected_features(self) -> tuple[int, ...]:
        return self.allocation.selected_features

    @property
    def strengths(self) -> Mapping[int, float]:
        return self.allocation.strengths

    @property
    def strength_vector(self) -> Array:
        """Strengths ordered like :attr:`selected_features`."""
        return np.asarray(
            [self.allocation.strengths[feature] for feature in self.selected_features],
            dtype=np.float64,
        )


@dataclass(frozen=True, slots=True)
class SteeringApplication:
    """Activation edit produced by an adaptive steering plan."""

    original: Array
    modified: Array
    delta: Array
    strength_vector: Array
    selected_features: tuple[int, ...]
    delta_l2_norm: float
    changed_count: int


def resolve_direction(
    mean_difference: float | None,
    mode: DirectionMode,
) -> float:
    """Resolve the steering sign from a measured vulnerable-minus-secure mean.

    ``association_reducing`` steers negatively when the feature is more active
    on vulnerable samples (``mean_difference > 0``) and positively otherwise.
    A missing difference is an error: direction is never guessed from absence.
    """
    if mode == "positive":
        return 1.0
    if mode == "negative":
        return -1.0
    if mode not in {"association_reducing"}:
        raise ValueError(f"unsupported direction mode {mode!r}")
    if mean_difference is None or not math.isfinite(mean_difference):
        raise ValueError("association_reducing direction requires a finite mean difference")
    return -1.0 if mean_difference > 0.0 else 1.0


def rank_feature_importance(
    importance: Mapping[int, float] | Sequence[float],
    *,
    mean_differences: Mapping[int, float] | Sequence[float] | None = None,
    minimum_importance: float = 0.0,
    max_features: int | None = None,
    direction_mode: DirectionMode = "association_reducing",
) -> tuple[FeatureImportance, ...]:
    """Rank measured feature importance deterministically.

    Ties are broken by ascending feature index so the plan is reproducible.
    Non-finite scores and negative indices are rejected, not dropped.
    """
    if not math.isfinite(minimum_importance) or minimum_importance < 0:
        raise ValueError("minimum_importance must be finite and non-negative")
    scores = _as_feature_mapping(importance, name="importance")
    if any(not math.isfinite(value) for value in scores.values()):
        raise ValueError("importance values must be finite")
    if max_features is not None and max_features < 1:
        raise ValueError("max_features must be positive")
    differences = (
        None
        if mean_differences is None
        else _as_feature_mapping(mean_differences, name="mean_differences")
    )
    entries: list[tuple[float, int, float]] = []
    for feature, score in scores.items():
        magnitude = abs(float(score))
        if magnitude < minimum_importance:
            continue
        if direction_mode == "association_reducing":
            if differences is None or feature not in differences:
                raise ValueError(
                    "association_reducing requires a mean difference for every candidate"
                )
            difference = differences[feature]
        else:
            difference = None
        direction = resolve_direction(difference, direction_mode)
        entries.append((magnitude, feature, direction))
    entries.sort(key=lambda item: (-item[0], item[1]))
    if max_features is not None:
        entries = entries[:max_features]
    return tuple(
        FeatureImportance(feature_index=feature, score=score, direction=direction)
        for score, feature, direction in entries
    )


def allocate_feature_strengths(
    importance: Sequence[FeatureImportance] | Mapping[int, float],
    *,
    mean_differences: Mapping[int, float] | Sequence[float] | None = None,
    pairwise_contrasts: Mapping[tuple[int, int], float] | None = None,
    higher_order_contrasts: Mapping[tuple[int, ...], float] | None = None,
    config: AdaptiveSteeringConfig | None = None,
    selected_features: Sequence[int] | None = None,
) -> StrengthAllocation:
    """Allocate trajectory strengths from measured importance and interactions."""
    policy = config or AdaptiveSteeringConfig()
    if isinstance(importance, Mapping):
        candidates = rank_feature_importance(
            importance,
            mean_differences=mean_differences,
            minimum_importance=policy.minimum_importance,
            max_features=policy.max_features,
            direction_mode=policy.direction_mode,
        )
    else:
        candidates = tuple(importance)
        if not candidates:
            raise ValueError("importance must contain at least one feature")
        for item in candidates:
            if not isinstance(item, FeatureImportance):
                raise TypeError("importance sequences must contain FeatureImportance values")
    if selected_features is not None:
        requested = tuple(int(feature) for feature in selected_features)
        if len(set(requested)) != len(requested):
            raise ValueError("selected_features must be distinct")
        by_index = {item.feature_index: item for item in candidates}
        unknown = [feature for feature in requested if feature not in by_index]
        if unknown:
            raise ValueError(f"selected_features are missing importance: {unknown}")
        candidates = tuple(by_index[feature] for feature in requested)
    candidates = candidates[: policy.max_features]
    selected = tuple(item.feature_index for item in candidates)
    selected_set = set(selected)

    individual = {
        item.feature_index: (
            policy.base_strength * policy.individual_weight * item.score * item.direction
        )
        for item in candidates
    }
    totals = dict(individual)
    contributions: list[InteractionContribution] = []
    contributions.extend(
        _allocate_interactions(
            pairwise_contrasts,
            order=2,
            weight=policy.pairwise_weight,
            base_strength=policy.base_strength,
            selected=selected_set,
            source="measured_pairwise_contrast",
        )
    )
    if policy.max_order >= 3:
        contributions.extend(
            _allocate_interactions(
                higher_order_contrasts,
                order=None,
                weight=policy.higher_order_weight,
                base_strength=policy.base_strength,
                selected=selected_set,
                source="measured_higher_order_factorial_contrast",
                max_order=policy.max_order,
            )
        )
    for contribution in contributions:
        for feature in contribution.features:
            totals[feature] = totals.get(feature, 0.0) + contribution.per_feature_contribution

    adjusted = {feature: value * policy.context_multiplier for feature, value in totals.items()}
    clipped = {
        feature: max(-policy.max_strength, min(policy.max_strength, value))
        for feature, value in adjusted.items()
    }
    scale, norm = _l2_scale(clipped, policy.l2_budget)
    strengths = {feature: value * scale for feature, value in clipped.items()}
    return StrengthAllocation(
        selected_features=selected,
        importance=candidates,
        individual_terms=individual,
        interaction_terms=tuple(contributions),
        context_adjustment=policy.context_multiplier,
        per_feature_clipped=clipped,
        l2_scale=scale,
        strengths=strengths,
        l2_norm=norm,
    )


def build_position_schedule(
    strengths: Mapping[int, float],
    activations_by_position: Mapping[int, Mapping[int, float]] | None,
    *,
    activation_threshold: float = 0.0,
    activation_reference: float = 1.0,
    max_strength: float = 10.0,
    max_steps: int = 64,
) -> tuple[PositionSteering, ...]:
    """Scale selected strengths by measured per-position feature activation."""
    if not math.isfinite(activation_threshold) or activation_threshold < 0:
        raise ValueError("activation_threshold must be finite and non-negative")
    if not math.isfinite(activation_reference) or activation_reference <= 0:
        raise ValueError("activation_reference must be positive")
    if not math.isfinite(max_strength) or max_strength <= 0:
        raise ValueError("max_strength must be positive")
    if max_steps < 1:
        raise ValueError("max_steps must be positive")
    if activations_by_position is None:
        return ()
    ordered = sorted(int(position) for position in activations_by_position)
    if any(position < 0 for position in ordered):
        raise ValueError("positions must be non-negative")
    selected = tuple(sorted(strengths))
    schedule: list[PositionSteering] = []
    for position in ordered[:max_steps]:
        values = activations_by_position[position]
        if any(not math.isfinite(float(value)) for value in values.values()):
            raise ValueError("position activations must be finite")
        active = tuple(
            feature
            for feature in selected
            if abs(float(values.get(feature, 0.0))) > activation_threshold
        )
        scheduled = tuple(
            max(
                -max_strength,
                min(
                    max_strength,
                    strengths[feature]
                    * abs(float(values.get(feature, 0.0)))
                    / activation_reference,
                ),
            )
            for feature in active
        )
        schedule.append(
            PositionSteering(position=position, active_features=active, strengths=scheduled)
        )
    return tuple(schedule)


def plan_adaptive_steering(
    importance: Mapping[int, float] | Sequence[FeatureImportance],
    *,
    mean_differences: Mapping[int, float] | Sequence[float] | None = None,
    pairwise_contrasts: Mapping[tuple[int, int], float] | None = None,
    higher_order_contrasts: Mapping[tuple[int, ...], float] | None = None,
    activations_by_position: Mapping[int, Mapping[int, float]] | None = None,
    config: AdaptiveSteeringConfig | None = None,
    selected_features: Sequence[int] | None = None,
) -> AdaptiveSteeringPlan:
    """Produce a complete deterministic steering plan."""
    policy = config or AdaptiveSteeringConfig()
    allocation = allocate_feature_strengths(
        importance,
        mean_differences=mean_differences,
        pairwise_contrasts=pairwise_contrasts,
        higher_order_contrasts=higher_order_contrasts,
        config=policy,
        selected_features=selected_features,
    )
    schedule = build_position_schedule(
        allocation.strengths,
        activations_by_position,
        activation_threshold=policy.activation_threshold,
        activation_reference=policy.activation_reference,
        max_strength=policy.max_strength,
        max_steps=policy.max_schedule_steps,
    )
    return AdaptiveSteeringPlan(config=policy, allocation=allocation, schedule=schedule)


def apply_adaptive_steering(
    activations: Any,
    parameters: SAEParameters,
    plan: AdaptiveSteeringPlan,
) -> SteeringApplication:
    """Apply ``h' = h + sum_j tau_j W_d[:, j]`` to real activations."""
    h = as_float_array(activations, name="activations")
    if h.ndim == 1:
        h = h.reshape(1, -1)
    require_2d(h, name="activations")
    if h.shape[1] != parameters.input_dim:
        raise ValueError(f"activations must have width {parameters.input_dim}, got {h.shape[1]}")
    if not np.isfinite(h).all():
        raise ValueError("activations must be finite")
    vector = plan.strength_vector
    if plan.selected_features:
        directions = parameters.decoder_weight[:, list(plan.selected_features)]
        # The same feature-space displacement is applied to every activation
        # vector in the batch.
        delta = np.broadcast_to(vector @ directions.T, h.shape).copy()
    else:
        delta = np.zeros_like(h)
    return SteeringApplication(
        original=h.copy(),
        modified=h + delta,
        delta=delta,
        strength_vector=vector,
        selected_features=plan.selected_features,
        delta_l2_norm=float(np.linalg.norm(delta, axis=1).mean()) if h.size else 0.0,
        changed_count=int(np.count_nonzero(delta)),
    )


def _as_feature_mapping(
    values: Mapping[int, float] | Sequence[float],
    *,
    name: str,
) -> dict[int, float]:
    if isinstance(values, Mapping):
        output = {int(feature): float(value) for feature, value in values.items()}
        if any(feature < 0 for feature in output):
            raise ValueError(f"{name} feature indices must be non-negative")
        return output
    array = as_float_array(values, name=name).reshape(-1)
    return {index: float(value) for index, value in enumerate(array)}


def _allocate_interactions(
    contrasts: Mapping[tuple[int, ...], float] | None,
    *,
    order: int | None,
    weight: float,
    base_strength: float,
    selected: set[int],
    source: str,
    max_order: int | None = None,
) -> list[InteractionContribution]:
    if not contrasts:
        return []
    contributions: list[InteractionContribution] = []
    for key, contrast in contrasts.items():
        features = tuple(sorted(int(feature) for feature in key))
        if len(features) < 2:
            raise ValueError("interaction keys require at least two features")
        if len(set(features)) != len(features):
            raise ValueError("interaction keys must contain distinct features")
        if order is not None and len(features) != order:
            raise ValueError(f"pairwise contrast keys must have order {order}")
        if max_order is not None and len(features) > max_order:
            continue
        if not math.isfinite(float(contrast)):
            raise ValueError("interaction contrasts must be finite")
        if not set(features) <= selected:
            continue
        weighted = base_strength * weight * float(contrast)
        contributions.append(
            InteractionContribution(
                features=features,
                order=len(features),
                contrast=float(contrast),
                weighted_contribution=weighted,
                per_feature_contribution=weighted / len(features),
                source=source,
            )
        )
    return contributions


def _l2_scale(strengths: Mapping[int, float], budget: float | None) -> tuple[float, float]:
    norm = math.sqrt(sum(value * value for value in strengths.values()))
    if budget is None or norm <= budget:
        return 1.0, norm
    return budget / norm, norm


__all__ = [
    "AdaptiveSteeringConfig",
    "AdaptiveSteeringPlan",
    "FeatureImportance",
    "InteractionContribution",
    "PositionSteering",
    "SteeringApplication",
    "StrengthAllocation",
    "allocate_feature_strengths",
    "apply_adaptive_steering",
    "build_position_schedule",
    "plan_adaptive_steering",
    "rank_feature_importance",
    "resolve_direction",
]
