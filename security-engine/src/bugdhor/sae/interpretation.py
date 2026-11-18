"""Evidence-backed SAE feature interpretation reports.

Automatic output is deliberately described as an interpretation hypothesis.
This module does not infer semantic meaning or causal influence from activation
patterns. Controlled intervention observations must be supplied by a researcher.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import torch

from bugdhor.sae.association import (
    FeatureDictionary,
    FeatureDictionaryEntry,
)


@dataclass(frozen=True, slots=True)
class FeatureExample:
    """Source-backed example with an actual feature activation."""

    sample_id: str
    source: str
    activation: float
    vulnerable: bool
    dataset_id: str
    cwe: str | None = None

    def __post_init__(self) -> None:
        if not self.sample_id.strip() or not self.dataset_id.strip():
            raise ValueError("feature examples require sample and dataset identifiers")
        if not torch.isfinite(torch.tensor(self.activation)):
            raise ValueError("feature activation must be finite")


@dataclass(frozen=True, slots=True)
class InterventionObservation:
    """Researcher-supplied result of a controlled feature intervention."""

    intervention_id: str
    feature_index: int
    sample_id: str
    method: str
    baseline_activation: float
    intervened_activation: float
    baseline_outcome: float
    intervened_outcome: float
    control: bool = False

    @property
    def feature_delta(self) -> float:
        return self.intervened_activation - self.baseline_activation

    @property
    def outcome_delta(self) -> float:
        return self.intervened_outcome - self.baseline_outcome


@dataclass(frozen=True, slots=True)
class FeatureAnnotation:
    """Human-authored or human-revised description of a feature."""

    feature_id: str
    description: str
    annotator: str
    confidence: float | None = None
    limitations: tuple[str, ...] = ()
    revision: int = 1
    revised_at: str = ""

    def __post_init__(self) -> None:
        if not self.description.strip() or not self.annotator.strip():
            raise ValueError("annotations require a description and annotator")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("annotation confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class FeatureInterpretationReport:
    """One feature report; fields distinguish evidence from interpretation."""

    feature_id: str
    model_id: str
    model_version: str
    layer: str
    activation_strength: float
    representative_code_examples: tuple[FeatureExample, ...]
    associated_cwe_categories: tuple[str, ...]
    positive_examples: tuple[FeatureExample, ...]
    negative_examples: tuple[FeatureExample, ...]
    feature_selectivity: float | None
    interpretation_confidence: float
    limitations: tuple[str, ...]
    annotation: FeatureAnnotation | None = None
    interventions: tuple[InterventionObservation, ...] = ()
    interpretation_status: str = "hypothesis; not a proven semantic meaning"


@dataclass
class FeatureAnnotationBook:
    """Revisioned in-memory annotation store for researcher review."""

    _current: dict[str, FeatureAnnotation] = field(default_factory=dict)
    _history: dict[str, list[FeatureAnnotation]] = field(default_factory=dict)

    def annotate(
        self,
        feature_id: str,
        description: str,
        *,
        annotator: str,
        confidence: float | None = None,
        limitations: Sequence[str] = (),
    ) -> FeatureAnnotation:
        previous = self._current.get(feature_id)
        annotation = FeatureAnnotation(
            feature_id=feature_id,
            description=description,
            annotator=annotator,
            confidence=confidence,
            limitations=tuple(limitations),
            revision=(previous.revision + 1 if previous else 1),
            revised_at=datetime.now(UTC).isoformat(),
        )
        if previous:
            self._history.setdefault(feature_id, []).append(previous)
        self._current[feature_id] = annotation
        return annotation

    def current(self, feature_id: str) -> FeatureAnnotation | None:
        return self._current.get(feature_id)

    def history(self, feature_id: str) -> tuple[FeatureAnnotation, ...]:
        return tuple(self._history.get(feature_id, ()))


class FeatureInterpretationEngine:
    """Generate evidence-backed reports from a feature dictionary and examples."""

    def __init__(
        self,
        feature_dictionary: FeatureDictionary,
        examples: Mapping[int, Sequence[FeatureExample]],
        *,
        annotations: FeatureAnnotationBook | None = None,
        interventions: Sequence[InterventionObservation] = (),
        activation_threshold: float | None = None,
        representative_count: int = 3,
    ) -> None:
        if representative_count < 1:
            raise ValueError("representative_count must be positive")
        self.feature_dictionary = feature_dictionary
        self.examples = examples
        self.annotations = annotations or FeatureAnnotationBook()
        self.interventions = tuple(interventions)
        self.activation_threshold = (
            feature_dictionary.metadata.activation_threshold
            if activation_threshold is None
            else activation_threshold
        )
        if self.activation_threshold < 0:
            raise ValueError("activation_threshold must be non-negative")
        self.representative_count = representative_count

    def report(self, feature_index: int) -> FeatureInterpretationReport:
        entry = self._entry(feature_index)
        examples = tuple(self.examples.get(feature_index, ()))
        ranked = sorted(examples, key=lambda item: item.activation, reverse=True)
        positive = tuple(
            item for item in ranked if item.activation > self.activation_threshold
        )[: self.representative_count]
        negative = tuple(
            sorted(examples, key=lambda item: item.activation)
        )[: self.representative_count]
        representative = tuple(ranked[: self.representative_count])
        cwes = tuple(sorted(entry.cwe_associations))
        feature_interventions = tuple(
            item for item in self.interventions if item.feature_index == feature_index
        )
        annotation = self.annotations.current(f"feature-{feature_index}")
        return FeatureInterpretationReport(
            feature_id=f"feature-{feature_index}",
            model_id=self.feature_dictionary.metadata.model_id,
            model_version=self.feature_dictionary.metadata.model_version,
            layer=self.feature_dictionary.metadata.layer,
            activation_strength=(
                float(torch.tensor([item.activation for item in examples]).mean().item())
                if examples
                else 0.0
            ),
            representative_code_examples=representative,
            associated_cwe_categories=cwes,
            positive_examples=positive,
            negative_examples=negative,
            feature_selectivity=entry.selectivity,
            interpretation_confidence=self._confidence(entry, examples),
            limitations=self._limitations(entry, examples, feature_interventions),
            annotation=annotation,
            interventions=feature_interventions,
        )

    def reports(
        self,
        feature_indices: Sequence[int] | None = None,
    ) -> tuple[FeatureInterpretationReport, ...]:
        indices = (
            tuple(feature_indices)
            if feature_indices is not None
            else tuple(entry.feature_index for entry in self.feature_dictionary.entries)
        )
        return tuple(self.report(index) for index in indices)

    def _entry(self, feature_index: int) -> FeatureDictionaryEntry:
        for entry in self.feature_dictionary.entries:
            if entry.feature_index == feature_index:
                return entry
        raise KeyError(f"feature {feature_index} is not present in the feature dictionary")

    @staticmethod
    def _confidence(
        entry: FeatureDictionaryEntry,
        examples: Sequence[FeatureExample],
    ) -> float:
        """Compute evidence coverage, not confidence in a semantic interpretation."""
        association = entry.association
        coverage = min(1.0, len(examples) / 20)
        class_balance = (
            min(association.vulnerable_count, association.secure_count)
            / max(association.vulnerable_count, association.secure_count)
            if max(association.vulnerable_count, association.secure_count)
            else 0.0
        )
        stability = entry.stability.sign_consistency or 0.0
        return round(min(1.0, 0.4 * coverage + 0.3 * class_balance + 0.3 * stability), 6)

    @staticmethod
    def _limitations(
        entry: FeatureDictionaryEntry,
        examples: Sequence[FeatureExample],
        interventions: Sequence[InterventionObservation],
    ) -> tuple[str, ...]:
        limitations = [
            "Association does not establish a semantic feature meaning.",
            "Association does not establish causal influence.",
        ]
        if not examples:
            limitations.append("No representative source examples were supplied.")
        if not interventions:
            limitations.append("No controlled intervention observations were supplied.")
        if entry.stability.sign_consistency is None or entry.stability.sign_consistency < 1:
            limitations.append("Association direction is not stable across all available datasets.")
        if not entry.cwe_associations:
            limitations.append("No CWE-specific association was measurable from supplied labels.")
        return tuple(limitations)


def feature_activations_to_examples(
    feature_activations: torch.Tensor,
    *,
    feature_index: int,
    samples: Sequence[FeatureExample],
) -> tuple[FeatureExample, ...]:
    """Attach a selected real activation column to source examples."""
    if feature_activations.ndim != 2 or feature_activations.shape[0] != len(samples):
        raise ValueError("feature activations must have one row per source example")
    if not 0 <= feature_index < feature_activations.shape[1]:
        raise ValueError("feature_index is out of range")
    return tuple(
        FeatureExample(
            sample_id=sample.sample_id,
            source=sample.source,
            activation=float(feature_activations[index, feature_index].item()),
            vulnerable=sample.vulnerable,
            dataset_id=sample.dataset_id,
            cwe=sample.cwe,
        )
        for index, sample in enumerate(samples)
    )


def export_reports_json(
    reports: Sequence[FeatureInterpretationReport],
    path: str | Path,
) -> Path:
    """Export complete nested interpretation reports as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps([asdict(report) for report in reports], indent=2, default=list),
        encoding="utf-8",
    )
    return target


def export_reports_csv(
    reports: Sequence[FeatureInterpretationReport],
    path: str | Path,
) -> Path:
    """Export one flattened row per feature while preserving nested evidence as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "feature_id",
        "model_id",
        "model_version",
        "layer",
        "activation_strength",
        "associated_cwe_categories",
        "feature_selectivity",
        "interpretation_confidence",
        "limitations",
        "representative_code_examples",
        "positive_examples",
        "negative_examples",
        "annotation",
        "interventions",
        "interpretation_status",
    )
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for report in reports:
            payload = asdict(report)
            writer.writerow(
                {
                    field: json.dumps(payload[field], default=list)
                    if isinstance(payload[field], (list, tuple, dict))
                    else payload[field]
                    for field in fields
                }
            )
    return target


__all__ = [
    "FeatureAnnotation",
    "FeatureAnnotationBook",
    "FeatureExample",
    "FeatureInterpretationReport",
    "FeatureInterpretationEngine",
    "InterventionObservation",
    "export_reports_csv",
    "export_reports_json",
    "feature_activations_to_examples",
]
