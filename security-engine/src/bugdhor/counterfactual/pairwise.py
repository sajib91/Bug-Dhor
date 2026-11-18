"""Pairwise SAE feature interaction experiments.

The interaction contrast is an additive contrast on the declared outcome
scale. It is not invariant to nonlinear outcome transformations and is not a
test of statistical significance.
"""

from __future__ import annotations

import itertools
import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

import torch

from bugdhor.sae.association import FeatureDictionary, association_selectivity


@dataclass(frozen=True, slots=True)
class FeaturePair:
    """Two distinct feature indices selected for joint testing."""

    feature_a: int
    feature_b: int
    cwe: str | None = None

    def __post_init__(self) -> None:
        if self.feature_a < 0 or self.feature_b < 0:
            raise ValueError("feature indices must be non-negative")
        if self.feature_a == self.feature_b:
            raise ValueError("a feature pair must contain two distinct features")

    @property
    def ordered(self) -> tuple[int, int]:
        return tuple(sorted((self.feature_a, self.feature_b)))


@dataclass(frozen=True, slots=True)
class PairwiseCell:
    """Repeated scalar outcomes for one intervention cell."""

    name: str
    interventions: Mapping[int, float]
    outcomes: tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.outcomes:
            raise ValueError("pairwise cells require a name and at least one outcome")
        if any(not math.isfinite(value) for value in self.outcomes):
            raise ValueError("pairwise outcomes must be finite")

    @property
    def mean(self) -> float:
        return float(torch.tensor(self.outcomes, dtype=torch.float64).mean().item())


@dataclass(frozen=True, slots=True)
class InteractionEstimate:
    """Interaction contrast and uncertainty, without a significance claim."""

    contrast: float
    standard_error: float | None
    confidence_interval_95: tuple[float, float] | None
    outcome_scale: str
    uncertainty_method: str


@dataclass(frozen=True, slots=True)
class PairwiseMetadata:
    """Design and provenance metadata for a pairwise experiment."""

    experiment_id: str
    outcome_scale: str
    seed: int
    repetitions: int
    cwe: str | None = None
    model_id: str | None = None
    model_version: str | None = None
    layer: str | None = None
    sae_checkpoint: str | None = None


@dataclass(frozen=True, slots=True)
class PairwiseInteractionResult:
    """All four cells and the resulting interaction estimate."""

    pair: FeaturePair
    metadata: PairwiseMetadata
    baseline: PairwiseCell
    feature_a: PairwiseCell
    feature_b: PairwiseCell
    joint: PairwiseCell
    estimate: InteractionEstimate

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


OutcomeRunner = Callable[[Mapping[int, float], int], float]


def select_feature_pairs(
    feature_indices: Sequence[int],
    *,
    max_pairs: int | None = None,
) -> tuple[FeaturePair, ...]:
    """Select deterministic unique pairs without assigning semantic meaning."""
    unique = tuple(sorted(set(feature_indices)))
    pairs = tuple(FeaturePair(a, b) for a, b in itertools.combinations(unique, 2))
    if max_pairs is not None:
        if max_pairs < 1:
            raise ValueError("max_pairs must be positive")
        return pairs[:max_pairs]
    return pairs


def select_association_pairs(
    dictionary: FeatureDictionary,
    *,
    top_k: int,
    cwe: str | None = None,
) -> tuple[FeaturePair, ...]:
    """Select pairs from measured association evidence, ranked by selectivity.

    When ``cwe`` is supplied, ranking uses that CWE's own association.  If the
    CWE subset lacks a two-class contrast, the feature's overall selectivity is
    used as a documented fallback rather than ranking it as zero evidence.
    """
    if top_k < 2:
        raise ValueError("top_k must be at least 2")
    candidates = []
    for entry in dictionary.entries:
        if cwe is not None:
            cwe_association = entry.cwe_associations.get(cwe)
            if cwe_association is None:
                continue
            score = association_selectivity(cwe_association)
            if score is None:
                score = entry.selectivity
        else:
            score = entry.selectivity
        candidates.append((abs(score or 0.0), entry.feature_index))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return tuple(
        FeaturePair(a, b, cwe=cwe)
        for a, b in itertools.combinations(
            [feature_index for _, feature_index in candidates[:top_k]], 2
        )
    )


class PairwiseInteractionEngine:
    """Execute four-cell pairwise experiments using a supplied outcome runner."""

    def __init__(
        self,
        *,
        experiment_id: str,
        outcome_scale: str,
        repetitions: int = 1,
        seed: int = 0,
        model_id: str | None = None,
        model_version: str | None = None,
        layer: str | None = None,
        sae_checkpoint: str | None = None,
    ) -> None:
        if not experiment_id.strip() or not outcome_scale.strip():
            raise ValueError("experiment_id and outcome_scale are required")
        if repetitions < 1:
            raise ValueError("repetitions must be positive")
        self.metadata = PairwiseMetadata(
            experiment_id=experiment_id,
            outcome_scale=outcome_scale,
            seed=seed,
            repetitions=repetitions,
            model_id=model_id,
            model_version=model_version,
            layer=layer,
            sae_checkpoint=sae_checkpoint,
        )

    def run(
        self,
        pair: FeaturePair,
        runner: OutcomeRunner,
        *,
        feature_a_value: float = 0.0,
        feature_b_value: float = 0.0,
    ) -> PairwiseInteractionResult:
        random.seed(self.metadata.seed)
        torch.manual_seed(self.metadata.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.metadata.seed)
        baseline = self._cell("baseline", {}, runner)
        feature_a = self._cell(
            "feature_a",
            {pair.feature_a: feature_a_value},
            runner,
        )
        feature_b = self._cell(
            "feature_b",
            {pair.feature_b: feature_b_value},
            runner,
        )
        joint = self._cell(
            "joint",
            {
                pair.feature_a: feature_a_value,
                pair.feature_b: feature_b_value,
            },
            runner,
        )
        estimate = estimate_interaction(
            baseline,
            feature_a,
            feature_b,
            joint,
            outcome_scale=self.metadata.outcome_scale,
        )
        return PairwiseInteractionResult(
            pair=pair,
            metadata=self.metadata,
            baseline=baseline,
            feature_a=feature_a,
            feature_b=feature_b,
            joint=joint,
            estimate=estimate,
        )

    def _cell(
        self,
        name: str,
        interventions: Mapping[int, float],
        runner: OutcomeRunner,
    ) -> PairwiseCell:
        outcomes = tuple(
            _validate_outcome(runner(interventions, repetition))
            for repetition in range(self.metadata.repetitions)
        )
        return PairwiseCell(name, dict(interventions), outcomes)


def estimate_interaction(
    baseline: PairwiseCell,
    feature_a: PairwiseCell,
    feature_b: PairwiseCell,
    joint: PairwiseCell,
    *,
    outcome_scale: str,
) -> InteractionEstimate:
    """Estimate ``joint - feature_a - feature_b + baseline``.

    The standard error assumes independent repeated outcomes in the four cells.
    A 95% normal-approximation interval is descriptive uncertainty, not a
    significance test and must not be reported as one.
    """
    contrast = joint.mean - feature_a.mean - feature_b.mean + baseline.mean
    cells = (joint, feature_a, feature_b, baseline)
    variances = [_sample_variance(cell.outcomes) for cell in cells]
    if any(variance is None for variance in variances):
        return InteractionEstimate(
            contrast=contrast,
            standard_error=None,
            confidence_interval_95=None,
            outcome_scale=outcome_scale,
            uncertainty_method="unavailable with fewer than two replicates per cell",
        )
    standard_error = math.sqrt(
        sum(variance / len(cell.outcomes) for variance, cell in zip(variances, cells, strict=True))
    )
    return InteractionEstimate(
        contrast=contrast,
        standard_error=standard_error,
        confidence_interval_95=(
            contrast - 1.96 * standard_error,
            contrast + 1.96 * standard_error,
        ),
        outcome_scale=outcome_scale,
        uncertainty_method=(
            "independent-cell sample-variance delta method; descriptive uncertainty, "
            "not a significance test"
        ),
    )


def rank_interactions(
    results: Sequence[PairwiseInteractionResult],
    *,
    absolute: bool = True,
) -> tuple[PairwiseInteractionResult, ...]:
    """Rank measured interactions without filtering or significance claims."""
    return tuple(
        sorted(
            results,
            key=lambda result: (
                -abs(result.estimate.contrast) if absolute else -result.estimate.contrast,
                result.pair.ordered,
            ),
        )
    )


def _sample_variance(values: Sequence[float]) -> float | None:
    if len(values) < 2:
        return None
    tensor = torch.tensor(values, dtype=torch.float64)
    return float(torch.var(tensor, unbiased=True).item())


def _validate_outcome(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError("outcome runner returned a non-finite value")
    return float(value)


__all__ = [
    "FeaturePair",
    "InteractionEstimate",
    "OutcomeRunner",
    "PairwiseCell",
    "PairwiseInteractionResult",
    "PairwiseMetadata",
    "PairwiseInteractionEngine",
    "estimate_interaction",
    "rank_interactions",
    "select_association_pairs",
    "select_feature_pairs",
]
