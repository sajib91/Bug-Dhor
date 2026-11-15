"""Transparent interaction-aware adaptive SAE steering policy."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from craftsec.counterfactual.higher_order import HigherOrderResult
from craftsec.counterfactual.pairwise import PairwiseInteractionResult
from craftsec.models.config import GenerationConfig
from craftsec.sae.association import FeatureDictionary
from craftsec.steering.engine import (
    ActivationSteeringEngine,
    SteeringResult,
    SteeringSpec,
)

ImportanceMetric = Literal[
    "selectivity",
    "mean_activation_difference",
    "active_precision",
    "active_recall",
]
DirectionMode = Literal["positive", "negative", "association_reducing"]


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringConfig:
    """All policy controls are explicit and serializable."""

    max_features: int = 8
    max_order: int = 3
    importance_metric: ImportanceMetric = "selectivity"
    minimum_importance: float = 0.0
    base_strength: float = 1.0
    individual_weight: float = 1.0
    pairwise_weight: float = 1.0
    higher_order_weight: float = 1.0
    direction_mode: DirectionMode = "association_reducing"
    context_multiplier: float = 1.0
    activation_threshold: float = 0.0
    activation_reference: float = 1.0
    max_strength: float = 10.0
    max_schedule_steps: int = 64
    cwe: str | None = None
    enabled: bool = False

    def __post_init__(self) -> None:
        if self.max_features < 1 or self.max_order < 1 or self.max_schedule_steps < 1:
            raise ValueError("feature, order, and schedule limits must be positive")
        if self.importance_metric not in {
            "selectivity",
            "mean_activation_difference",
            "active_precision",
            "active_recall",
        }:
            raise ValueError("unsupported importance_metric")
        if self.direction_mode not in {"positive", "negative", "association_reducing"}:
            raise ValueError("unsupported direction_mode")
        for name in (
            "minimum_importance",
            "base_strength",
            "individual_weight",
            "pairwise_weight",
            "higher_order_weight",
            "context_multiplier",
            "activation_threshold",
            "activation_reference",
            "max_strength",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if self.activation_reference == 0:
            raise ValueError("activation_reference must be positive")


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringContext:
    """Measured context supplied to the policy for one prompt."""

    cwe: str | None = None
    target_positions: tuple[int, ...] | None = None
    feature_activations_by_position: Mapping[int, Mapping[int, float]] | None = None
    context_multiplier: float | None = None

    def __post_init__(self) -> None:
        if self.target_positions is not None and (
            not self.target_positions
            or any(position < 0 for position in self.target_positions)
            or len(set(self.target_positions)) != len(self.target_positions)
        ):
            raise ValueError("target_positions must be unique non-negative positions")
        if self.context_multiplier is not None and (
            not math.isfinite(self.context_multiplier) or self.context_multiplier < 0
        ):
            raise ValueError("context_multiplier must be finite and non-negative")
        if self.feature_activations_by_position is not None:
            for position, activations in self.feature_activations_by_position.items():
                if position < 0 or any(not math.isfinite(value) for value in activations.values()):
                    raise ValueError(
                        "context activations must be finite and positions non-negative"
                    )


@dataclass(frozen=True, slots=True)
class FeatureImportanceContribution:
    feature_index: int
    score: float
    source: str
    direction: float


@dataclass(frozen=True, slots=True)
class InteractionContribution:
    features: tuple[int, ...]
    order: int
    contrast: float
    weighted_contribution: float
    source: str


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringDecision:
    """Policy decision with all individual and interaction terms exposed."""

    config: AdaptiveSteeringConfig
    context: AdaptiveSteeringContext
    selected_features: tuple[int, ...]
    feature_importance: tuple[FeatureImportanceContribution, ...]
    individual_effects: Mapping[int, float]
    pairwise_interactions: tuple[InteractionContribution, ...]
    higher_order_interactions: tuple[InteractionContribution, ...]
    context_adjustment: float
    strengths: Mapping[int, float]
    schedule: tuple[tuple[int, tuple[int, ...], tuple[float, ...]], ...]
    spec: SteeringSpec

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AdaptiveSteeringRun:
    """Adaptive run result plus its reproducible policy decision."""

    decision: AdaptiveSteeringDecision
    steering: SteeringResult
    history_index: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdaptiveSteeringPolicy:
    """Derive steering solely from measured associations and interactions."""

    def __init__(
        self,
        feature_dictionary: FeatureDictionary,
        *,
        pairwise_results: Sequence[PairwiseInteractionResult] = (),
        higher_order_results: Sequence[HigherOrderResult] = (),
        config: AdaptiveSteeringConfig | None = None,
    ) -> None:
        self.feature_dictionary = feature_dictionary
        self.pairwise_results = tuple(pairwise_results)
        self.higher_order_results = tuple(higher_order_results)
        self.config = config or AdaptiveSteeringConfig()

    def plan(
        self, context: AdaptiveSteeringContext | None = None
    ) -> AdaptiveSteeringDecision:
        context = context or AdaptiveSteeringContext()
        if self.config.cwe is not None and context.cwe not in {None, self.config.cwe}:
            raise ValueError("context CWE does not match the policy CWE")
        entries = []
        for entry in self.feature_dictionary.entries:
            association = (
                entry.cwe_associations.get(context.cwe)
                if context.cwe is not None
                else entry.association
            )
            if association is None:
                continue
            score = self._importance_score(entry, association, context.cwe)
            if score is not None and abs(score) >= self.config.minimum_importance:
                entries.append((abs(score), entry.feature_index, float(score), association))
        entries.sort(key=lambda item: (-item[0], item[1]))
        selected = tuple(item[1] for item in entries[: self.config.max_features])
        importance = tuple(
            FeatureImportanceContribution(
                feature_index=feature,
                score=abs(score),
                source=self.config.importance_metric,
                direction=self._direction(association),
            )
            for _, feature, score, association in entries[: self.config.max_features]
        )
        individual = {
            item.feature_index: self.config.base_strength
            * self.config.individual_weight
            * item.score
            * item.direction
            for item in importance
        }
        pairwise = self._interaction_contributions(selected, context.cwe)
        higher_order = self._higher_order_contributions(selected, context.cwe)
        totals = dict(individual)
        for contribution in (*pairwise, *higher_order):
            per_feature = contribution.weighted_contribution / contribution.order
            for feature in contribution.features:
                totals[feature] = totals.get(feature, 0.0) + per_feature
        multiplier = (
            context.context_multiplier
            if context.context_multiplier is not None
            else self.config.context_multiplier
        )
        strengths = {
            feature: max(
                -self.config.max_strength,
                min(self.config.max_strength, value * multiplier),
            )
            for feature, value in totals.items()
        }
        schedule = self._schedule(selected, strengths, context)
        position_strengths = {
            position: values for position, _, values in schedule
        } or None
        target_positions = tuple(item[0] for item in schedule) or context.target_positions
        spec = SteeringSpec(
            feature_indices=selected,
            strengths=tuple(strengths.get(feature, 0.0) for feature in selected) or None,
            target_positions=target_positions,
            position_strengths=position_strengths,
            enabled=self.config.enabled and bool(selected),
            max_delta_norm=self.config.max_strength,
        )
        return AdaptiveSteeringDecision(
            config=self.config,
            context=context,
            selected_features=selected,
            feature_importance=importance,
            individual_effects=individual,
            pairwise_interactions=pairwise,
            higher_order_interactions=higher_order,
            context_adjustment=multiplier,
            strengths=strengths,
            schedule=schedule,
            spec=spec,
        )

    def _importance_score(self, entry: Any, association: Any, cwe: str | None) -> float | None:
        if self.config.importance_metric != "selectivity":
            return getattr(association, self.config.importance_metric)
        if cwe is None:
            return entry.selectivity
        if (
            association.vulnerable_activation_frequency is None
            or association.secure_activation_frequency is None
        ):
            return None
        return (
            association.vulnerable_activation_frequency
            - association.secure_activation_frequency
        )

    def _direction(self, association: Any) -> float:
        if self.config.direction_mode == "positive":
            return 1.0
        if self.config.direction_mode == "negative":
            return -1.0
        difference = association.mean_activation_difference
        return -1.0 if difference is not None and difference > 0 else 1.0

    def _interaction_contributions(
        self, selected: Sequence[int], cwe: str | None
    ) -> tuple[InteractionContribution, ...]:
        selected_set = set(selected)
        results = []
        for result in self.pairwise_results:
            features = result.pair.ordered
            if set(features) <= selected_set and (
                cwe is None or result.metadata.cwe in {None, cwe}
            ):
                results.append(
                    InteractionContribution(
                        features=features,
                        order=2,
                        contrast=result.estimate.contrast,
                        weighted_contribution=(
                            self.config.base_strength
                            * self.config.pairwise_weight
                            * result.estimate.contrast
                        ),
                        source="measured_pairwise_contrast",
                    )
                )
        return tuple(results)

    def _higher_order_contributions(
        self, selected: Sequence[int], cwe: str | None
    ) -> tuple[InteractionContribution, ...]:
        selected_set = set(selected)
        results = []
        for result in self.higher_order_results:
            features = result.subset.features
            if (
                2 < len(features) <= self.config.max_order
                and set(features) <= selected_set
                and (
                    cwe is None
                    or getattr(result.metadata, "cwe", None) in {None, cwe}
                )
            ):
                results.append(
                    InteractionContribution(
                        features=features,
                        order=len(features),
                        contrast=result.estimate.contrast,
                        weighted_contribution=(
                            self.config.base_strength
                            * self.config.higher_order_weight
                            * result.estimate.contrast
                        ),
                        source="measured_higher_order_factorial_contrast",
                    )
                )
        return tuple(results)

    def _schedule(
        self,
        selected: Sequence[int],
        strengths: Mapping[int, float],
        context: AdaptiveSteeringContext,
    ) -> tuple[tuple[int, tuple[int, ...], tuple[float, ...]], ...]:
        activation_map = context.feature_activations_by_position
        positions = (
            sorted(activation_map)
            if activation_map is not None
            else list(context.target_positions or ())
        )
        if not positions:
            return ()
        scheduled = []
        for position in positions[: self.config.max_schedule_steps]:
            active = (
                tuple(
                    feature
                    for feature in selected
                    if abs(activation_map[position].get(feature, 0.0))
                    >= self.config.activation_threshold
                )
                if activation_map is not None
                else tuple(selected)
            )
            values = []
            for feature in selected:
                if feature not in active:
                    values.append(0.0)
                    continue
                observed = (
                    activation_map[position].get(feature, self.config.activation_reference)
                    if activation_map is not None
                    else self.config.activation_reference
                )
                scale = abs(observed) / self.config.activation_reference
                values.append(
                    max(
                        -self.config.max_strength,
                        min(self.config.max_strength, strengths[feature] * scale),
                    )
                )
            scheduled.append((position, active, tuple(values)))
        return tuple(scheduled)


class AdaptiveSteeringEngine:
    """Apply policy decisions through the genuine activation hook engine."""

    def __init__(self, steering_engine: ActivationSteeringEngine, policy: AdaptiveSteeringPolicy):
        self.steering_engine = steering_engine
        self.policy = policy
        self.history: list[AdaptiveSteeringRun] = []

    def run(
        self,
        prompt: str,
        context: AdaptiveSteeringContext | None = None,
        *,
        generation: GenerationConfig | None = None,
    ) -> AdaptiveSteeringRun:
        decision = self.policy.plan(context)
        steering = self.steering_engine.run(prompt, decision.spec, generation=generation)
        run = AdaptiveSteeringRun(decision, steering, len(self.history))
        self.history.append(run)
        return run

    def save_history(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps([run.to_dict() for run in self.history], indent=2, default=list),
            encoding="utf-8",
        )
        return target


__all__ = [
    "AdaptiveSteeringConfig",
    "AdaptiveSteeringContext",
    "AdaptiveSteeringDecision",
    "AdaptiveSteeringEngine",
    "AdaptiveSteeringPolicy",
    "AdaptiveSteeringRun",
    "FeatureImportanceContribution",
    "InteractionContribution",
]
