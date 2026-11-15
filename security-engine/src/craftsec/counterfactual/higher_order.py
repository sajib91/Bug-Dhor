"""Higher-order SAE feature interaction experiments.

For a feature subset S of order k, this module uses the k-way factorial
contrast on the declared outcome scale:

    sum(T subset S) (-1) ** (k - |T|) Outcome(T)

The contrast is conditional on the intervention design and outcome scale. It
does not receive a causal or semantic interpretation automatically.
"""

from __future__ import annotations

import itertools
import json
import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import torch

from craftsec.sae.association import FeatureDictionary

OutcomeRunner = Callable[[Mapping[int, float], int], float]


@dataclass(frozen=True, slots=True)
class FeatureSubset:
    """Canonical feature subset used as one higher-order intervention target."""

    features: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.features) < 1:
            raise ValueError("feature subsets must not be empty")
        if any(feature < 0 for feature in self.features):
            raise ValueError("feature indices must be non-negative")
        if tuple(sorted(set(self.features))) != self.features:
            raise ValueError("feature subsets must be sorted and unique")

    @property
    def order(self) -> int:
        return len(self.features)


@dataclass(frozen=True, slots=True)
class HigherOrderEstimate:
    """Factorial contrast and optional descriptive uncertainty."""

    contrast: float
    order: int
    outcome_scale: str
    standard_error: float | None
    confidence_interval_95: tuple[float, float] | None
    uncertainty_method: str


@dataclass(frozen=True, slots=True)
class HigherOrderMetadata:
    """Reproducibility and provenance metadata for a higher-order run."""

    experiment_id: str
    outcome_scale: str
    seed: int
    repetitions: int
    intervention_value: float
    max_order: int
    model_id: str | None = None
    model_version: str | None = None
    layer: str | None = None
    sae_checkpoint: str | None = None


@dataclass(frozen=True, slots=True)
class HigherOrderResult:
    """All factorial cells and one subset's interaction contrast."""

    subset: FeatureSubset
    metadata: HigherOrderMetadata
    cells: Mapping[str, tuple[float, ...]]
    estimate: HigherOrderEstimate

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ComplexityReport:
    """Theoretical and observed computational cost of a subset plan."""

    candidate_feature_count: int
    min_order: int
    max_order: int
    theoretical_subset_count: int
    theoretical_cell_evaluations: int
    selected_subset_count: int
    observed_cell_evaluations: int
    repetitions: int
    budget: int | None
    sampling_strategy: str


@dataclass(frozen=True, slots=True)
class HigherOrderExperiment:
    """Serializable collection of order-comparable interaction results."""

    metadata: HigherOrderMetadata
    results: tuple[HigherOrderResult, ...]
    complexity: ComplexityReport

    def ranked(self, *, absolute: bool = True) -> tuple[HigherOrderResult, ...]:
        return rank_higher_order(self.results, absolute=absolute)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, default=list), encoding="utf-8")
        return target


def preselect_features(
    dictionary: FeatureDictionary,
    *,
    max_features: int,
    cwe: str | None = None,
) -> tuple[int, ...]:
    """Select features by measured selectivity before subset generation."""
    if max_features < 1:
        raise ValueError("max_features must be positive")
    candidates = [
        entry
        for entry in dictionary.entries
        if cwe is None or cwe in entry.cwe_associations
    ]
    return tuple(
        entry.feature_index
        for entry in sorted(
            candidates,
            key=lambda entry: (-(abs(entry.selectivity or 0.0)), entry.feature_index),
        )[:max_features]
    )


def generate_feature_subsets(
    feature_indices: Sequence[int],
    *,
    min_order: int = 1,
    max_order: int = 3,
    max_subsets: int | None = None,
    sampling_strategy: str = "exhaustive",
    seed: int = 0,
) -> tuple[FeatureSubset, ...]:
    """Generate bounded subsets, optionally sampling the combinatorial space."""
    unique = tuple(sorted(set(feature_indices)))
    if min_order < 1 or max_order < min_order:
        raise ValueError("orders must satisfy 1 <= min_order <= max_order")
    if sampling_strategy not in {"exhaustive", "random"}:
        raise ValueError("sampling_strategy must be 'exhaustive' or 'random'")
    subsets = [
        FeatureSubset(combo)
        for order in range(min_order, min(max_order, len(unique)) + 1)
        for combo in itertools.combinations(unique, order)
    ]
    if max_subsets is not None:
        if max_subsets < 1:
            raise ValueError("max_subsets must be positive")
        if sampling_strategy == "random" and len(subsets) > max_subsets:
            generator = random.Random(seed)
            subsets = generator.sample(subsets, max_subsets)
            subsets.sort(key=lambda subset: subset.features)
        else:
            subsets = subsets[:max_subsets]
    return tuple(subsets)


class HigherOrderInteractionEngine:
    """Evaluate higher-order factorial contrasts with cached condition cells."""

    def __init__(
        self,
        *,
        experiment_id: str,
        outcome_scale: str,
        repetitions: int = 1,
        seed: int = 0,
        intervention_value: float = 1.0,
        max_order: int = 3,
        model_id: str | None = None,
        model_version: str | None = None,
        layer: str | None = None,
        sae_checkpoint: str | None = None,
    ) -> None:
        if not experiment_id.strip() or not outcome_scale.strip():
            raise ValueError("experiment_id and outcome_scale are required")
        if repetitions < 1 or max_order < 1:
            raise ValueError("repetitions and max_order must be positive")
        if not math.isfinite(intervention_value):
            raise ValueError("intervention_value must be finite")
        self.metadata = HigherOrderMetadata(
            experiment_id=experiment_id,
            outcome_scale=outcome_scale,
            seed=seed,
            repetitions=repetitions,
            intervention_value=intervention_value,
            max_order=max_order,
            model_id=model_id,
            model_version=model_version,
            layer=layer,
            sae_checkpoint=sae_checkpoint,
        )

    def run(
        self,
        subsets: Sequence[FeatureSubset],
        runner: OutcomeRunner,
        *,
        budget: int | None = None,
    ) -> HigherOrderExperiment:
        """Evaluate selected subsets while reusing identical intervention cells."""
        selected = tuple(subsets)
        if any(subset.order > self.metadata.max_order for subset in selected):
            raise ValueError("a requested subset exceeds max_order")
        if budget is not None and budget < 1:
            raise ValueError("budget must be positive")
        random.seed(self.metadata.seed)
        torch.manual_seed(self.metadata.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.metadata.seed)
        cache: dict[tuple[tuple[int, float], int], float] = {}
        results = []
        observed_cells = 0
        for subset in selected:
            cell_values: dict[str, tuple[float, ...]] = {}
            for active in _powerset(subset.features):
                interventions = tuple(
                    (feature, self.metadata.intervention_value) for feature in active
                )
                key = tuple(interventions)
                if budget is not None and key not in {
                    cached_key for cached_key, _ in cache
                }:
                    if observed_cells + self.metadata.repetitions > budget:
                        break
                outcomes = []
                for repetition in range(self.metadata.repetitions):
                    cache_key = (key, repetition)
                    if cache_key not in cache:
                        cache[cache_key] = _validate_outcome(
                            runner(dict(interventions), repetition)
                        )
                        observed_cells += 1
                    outcomes.append(cache[cache_key])
                cell_values[_cell_key(active)] = tuple(outcomes)
            if len(cell_values) != 2**subset.order:
                break
            results.append(
                HigherOrderResult(
                    subset=subset,
                    metadata=self.metadata,
                    cells=cell_values,
                    estimate=estimate_higher_order(
                        subset,
                        cell_values,
                        outcome_scale=self.metadata.outcome_scale,
                    ),
                )
            )
        complexity = complexity_report(
            candidate_feature_count=len(
                {feature for subset in selected for feature in subset.features}
            ),
            min_order=min((subset.order for subset in selected), default=1),
            max_order=max((subset.order for subset in selected), default=self.metadata.max_order),
            selected_subsets=len(results),
            observed_cell_evaluations=observed_cells,
            repetitions=self.metadata.repetitions,
            budget=budget,
            sampling_strategy="preselected",
        )
        return HigherOrderExperiment(self.metadata, tuple(results), complexity)


def estimate_higher_order(
    subset: FeatureSubset,
    cells: Mapping[str, Sequence[float]],
    *,
    outcome_scale: str,
) -> HigherOrderEstimate:
    """Compute the alternating factorial contrast for one feature subset."""
    required = tuple(_cell_key(active) for active in _powerset(subset.features))
    if any(key not in cells for key in required):
        raise ValueError("all factorial cells are required")
    contrast = 0.0
    for active in _powerset(subset.features):
        sign = -1 if (subset.order - len(active)) % 2 else 1
        contrast += sign * _mean(cells[_cell_key(active)])
    variances = [_variance(cells[key]) for key in required]
    if any(variance is None for variance in variances):
        return HigherOrderEstimate(
            contrast,
            subset.order,
            outcome_scale,
            None,
            None,
            "unavailable with fewer than two replicates per cell; no significance test",
        )
    standard_error = math.sqrt(
        sum(
            variance / len(cells[key])
            for variance, key in zip(variances, required, strict=True)
        )
    )
    return HigherOrderEstimate(
        contrast,
        subset.order,
        outcome_scale,
        standard_error,
        (contrast - 1.96 * standard_error, contrast + 1.96 * standard_error),
        "independent-cell sample-variance delta method; descriptive uncertainty, not significance",
    )


def rank_higher_order(
    results: Sequence[HigherOrderResult],
    *,
    absolute: bool = True,
) -> tuple[HigherOrderResult, ...]:
    """Rank effects across individual, pairwise, and higher orders."""
    return tuple(
        sorted(
            results,
            key=lambda result: (
                -abs(result.estimate.contrast)
                if absolute
                else -result.estimate.contrast,
                result.subset.order,
                result.subset.features,
            ),
        )
    )


def complexity_report(
    *,
    candidate_feature_count: int,
    min_order: int,
    max_order: int,
    selected_subsets: int,
    observed_cell_evaluations: int,
    repetitions: int,
    budget: int | None,
    sampling_strategy: str,
) -> ComplexityReport:
    """Describe the unbounded factorial cost and actual selected cost."""
    theoretical_subsets = sum(
        math.comb(candidate_feature_count, order)
        for order in range(min_order, min(max_order, candidate_feature_count) + 1)
    )
    theoretical_cells = sum(
        math.comb(candidate_feature_count, order) * (2**order) * repetitions
        for order in range(min_order, min(max_order, candidate_feature_count) + 1)
    )
    return ComplexityReport(
        candidate_feature_count=candidate_feature_count,
        min_order=min_order,
        max_order=max_order,
        theoretical_subset_count=theoretical_subsets,
        theoretical_cell_evaluations=theoretical_cells,
        selected_subset_count=selected_subsets,
        observed_cell_evaluations=observed_cell_evaluations,
        repetitions=repetitions,
        budget=budget,
        sampling_strategy=sampling_strategy,
    )


def _powerset(features: Sequence[int]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        combo
        for order in range(len(features) + 1)
        for combo in itertools.combinations(features, order)
    )


def _cell_key(active: Sequence[int]) -> str:
    return "baseline" if not active else ",".join(str(feature) for feature in active)


def _mean(values: Sequence[float]) -> float:
    return float(torch.tensor(values, dtype=torch.float64).mean().item())


def _variance(values: Sequence[float]) -> float | None:
    if len(values) < 2:
        return None
    return float(torch.tensor(values, dtype=torch.float64).var(unbiased=True).item())


def _validate_outcome(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError("outcome runner returned a non-finite value")
    return float(value)


__all__ = [
    "ComplexityReport",
    "FeatureSubset",
    "HigherOrderEstimate",
    "HigherOrderExperiment",
    "HigherOrderInteractionEngine",
    "HigherOrderMetadata",
    "HigherOrderResult",
    "complexity_report",
    "estimate_higher_order",
    "generate_feature_subsets",
    "preselect_features",
    "rank_higher_order",
]
