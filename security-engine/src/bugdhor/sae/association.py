"""Statistical analysis of SAE features against explicitly supplied labels.

This module reports associations only. It never names a feature as a
vulnerability concept and cannot establish causal influence.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import torch

from bugdhor.models.activations import ActivationBatch
from bugdhor.sae.model import SparseAutoencoder
from bugdhor.sae.training import SAETrainer


@dataclass(frozen=True, slots=True)
class CodeSampleLabel:
    """Ground-truth metadata supplied by a controlled sample or dataset."""

    sample_id: str
    vulnerable: bool
    dataset_id: str
    experiment_id: str
    cwe: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.sample_id.strip()
            or not self.dataset_id.strip()
            or not self.experiment_id.strip()
        ):
            raise ValueError("sample, dataset, and experiment identifiers are required")


@dataclass(frozen=True, slots=True)
class FeatureSample:
    """One labeled sample represented by a mean SAE feature vector."""

    label: CodeSampleLabel
    features: torch.Tensor

    def __post_init__(self) -> None:
        if self.features.ndim != 1:
            raise ValueError("feature samples must be one-dimensional")
        if not torch.is_floating_point(self.features) or not torch.isfinite(self.features).all():
            raise ValueError("feature samples must be finite floating-point values")


@dataclass(frozen=True, slots=True)
class FeatureAssociation:
    """Measured association statistics for one feature."""

    feature_index: int
    sample_count: int
    vulnerable_count: int
    secure_count: int
    activation_frequency: float
    vulnerable_activation_frequency: float | None
    secure_activation_frequency: float | None
    vulnerable_mean_activation: float | None
    secure_mean_activation: float | None
    mean_activation_difference: float | None
    active_precision: float | None
    active_recall: float | None
    association_direction: str | None


@dataclass(frozen=True, slots=True)
class FeatureStability:
    """Consistency of an association's direction across datasets."""

    dataset_differences: Mapping[str, float]
    sign_consistency: float | None
    datasets_with_both_classes: int


@dataclass(frozen=True, slots=True)
class CrossDatasetMetric:
    """Out-of-dataset precision and recall for an activation association.

    ``active_precision`` and ``active_recall`` are measured on the validation
    dataset.  The train/validation direction fields record whether the feature's
    measured association direction transfers; they are not inferred from the
    validation metrics alone.
    """

    feature_index: int
    train_dataset: str
    validation_dataset: str
    activation_threshold: float
    active_precision: float | None
    active_recall: float | None
    validation_sample_count: int
    train_association_direction: str | None = None
    validation_association_direction: str | None = None
    direction_agrees: bool | None = None


@dataclass(frozen=True, slots=True)
class FeatureDictionaryEntry:
    """A provenance-backed feature record with association evidence only."""

    feature_index: int
    association: FeatureAssociation
    cwe_associations: Mapping[str, FeatureAssociation]
    selectivity: float | None
    stability: FeatureStability
    interpretation: str = "association_only; no causal or semantic claim"


@dataclass(frozen=True, slots=True)
class FeatureExperimentMetadata:
    """Provenance required to reproduce one feature analysis."""

    model_id: str
    model_version: str
    layer: str
    sae_checkpoint: str
    dataset_ids: tuple[str, ...]
    experiment_id: str
    activation_threshold: float


@dataclass(frozen=True, slots=True)
class FeatureDictionary:
    """Serializable feature analysis output."""

    metadata: FeatureExperimentMetadata
    entries: tuple[FeatureDictionaryEntry, ...]
    cross_dataset: tuple[CrossDatasetMetric, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, default=list), encoding="utf-8")
        return target


def samples_from_token_features(
    labels: Sequence[CodeSampleLabel],
    feature_activations: torch.Tensor,
    attention_mask: torch.Tensor,
) -> tuple[FeatureSample, ...]:
    """Aggregate real token-level SAE activations into labeled sample vectors."""
    if feature_activations.ndim != 3:
        raise ValueError("feature_activations must have shape [samples, tokens, features]")
    if attention_mask.shape != feature_activations.shape[:2]:
        raise ValueError("attention_mask must match sample and token dimensions")
    if len(labels) != feature_activations.shape[0]:
        raise ValueError("one label is required per activation sample")
    samples = []
    for index, label in enumerate(labels):
        valid = attention_mask[index].bool()
        if not valid.any():
            raise ValueError(f"sample {label.sample_id!r} has no active tokens")
        samples.append(FeatureSample(label, feature_activations[index, valid].mean(dim=0)))
    return tuple(samples)


def extract_feature_samples(
    activation_batch: ActivationBatch,
    *,
    layer: str,
    labels: Sequence[CodeSampleLabel],
    sae: SparseAutoencoder,
    trainer: SAETrainer,
) -> tuple[FeatureSample, ...]:
    """Encode an actual model activation layer and preserve sample labels."""
    token_activations = activation_batch.activations.get(layer)
    if token_activations is None:
        raise ValueError(f"activation layer {layer!r} is not present")
    flattened = token_activations.reshape(-1, token_activations.shape[-1])
    encoded = trainer.extract_features(sae, flattened).reshape(
        token_activations.shape[0], token_activations.shape[1], -1
    )
    return samples_from_token_features(labels, encoded, activation_batch.attention_mask)


def analyze_features(
    samples: Sequence[FeatureSample],
    *,
    activation_threshold: float = 0.0,
    metadata: FeatureExperimentMetadata,
    cwes: Sequence[str] | None = None,
) -> FeatureDictionary:
    """Compute feature, CWE, selectivity, and cross-dataset association evidence."""
    _validate_samples(samples, activation_threshold)
    feature_count = samples[0].features.shape[0]
    entries = []
    for feature_index in range(feature_count):
        association = _association(samples, feature_index, activation_threshold)
        cwe_associations = {
            cwe: _association(
                [sample for sample in samples if sample.label.cwe == cwe],
                feature_index,
                activation_threshold,
            )
            for cwe in (
                cwes or sorted({sample.label.cwe for sample in samples if sample.label.cwe})
            )
            if any(sample.label.cwe == cwe for sample in samples)
        }
        stability = _stability(samples, feature_index, activation_threshold)
        entries.append(
            FeatureDictionaryEntry(
                feature_index=feature_index,
                association=association,
                cwe_associations=cwe_associations,
                selectivity=_selectivity(association),
                stability=stability,
            )
        )
    return FeatureDictionary(
        metadata=metadata,
        entries=tuple(entries),
        cross_dataset=_cross_dataset_metrics(samples, activation_threshold),
    )


def _validate_samples(samples: Sequence[FeatureSample], threshold: float) -> None:
    if not samples:
        raise ValueError("at least one labeled feature sample is required")
    if threshold < 0:
        raise ValueError("activation_threshold must be non-negative")
    width = samples[0].features.shape[0]
    if any(sample.features.shape[0] != width for sample in samples):
        raise ValueError("all feature samples must have the same width")


def _association(
    samples: Sequence[FeatureSample],
    feature_index: int,
    threshold: float,
) -> FeatureAssociation:
    vulnerable = [sample.features[feature_index] for sample in samples if sample.label.vulnerable]
    secure = [sample.features[feature_index] for sample in samples if not sample.label.vulnerable]
    values = torch.stack([sample.features[feature_index] for sample in samples])
    active = values.abs() > threshold
    active_vulnerable = sum(
        bool(value)
        for value, sample in zip(active, samples, strict=True)
        if sample.label.vulnerable
    )
    active_secure = int(active.sum().item()) - active_vulnerable
    vulnerable_mean = float(torch.stack(vulnerable).mean().item()) if vulnerable else None
    secure_mean = float(torch.stack(secure).mean().item()) if secure else None
    difference = (
        vulnerable_mean - secure_mean
        if vulnerable_mean is not None and secure_mean is not None
        else None
    )
    direction = (
        None
        if difference is None or difference == 0
        else ("vulnerable_higher" if difference > 0 else "secure_higher")
    )
    return FeatureAssociation(
        feature_index=feature_index,
        sample_count=len(samples),
        vulnerable_count=len(vulnerable),
        secure_count=len(secure),
        activation_frequency=float(active.float().mean().item()),
        vulnerable_activation_frequency=active_vulnerable / len(vulnerable) if vulnerable else None,
        secure_activation_frequency=active_secure / len(secure) if secure else None,
        vulnerable_mean_activation=vulnerable_mean,
        secure_mean_activation=secure_mean,
        mean_activation_difference=difference,
        active_precision=active_vulnerable / int(active.sum().item()) if active.any() else None,
        active_recall=active_vulnerable / len(vulnerable) if vulnerable else None,
        association_direction=direction,
    )


def association_selectivity(association: FeatureAssociation) -> float | None:
    """Return the vulnerable-minus-secure activation-frequency difference.

    ``None`` is returned when either class is absent, because a one-class
    subset cannot support a contrast.
    """
    if (
        association.vulnerable_activation_frequency is None
        or association.secure_activation_frequency is None
    ):
        return None
    return association.vulnerable_activation_frequency - association.secure_activation_frequency


def _selectivity(association: FeatureAssociation) -> float | None:
    return association_selectivity(association)


def _stability(
    samples: Sequence[FeatureSample],
    feature_index: int,
    threshold: float,
) -> FeatureStability:
    differences: dict[str, float] = {}
    both_classes = 0
    for dataset in sorted({sample.label.dataset_id for sample in samples}):
        subset = [sample for sample in samples if sample.label.dataset_id == dataset]
        if {sample.label.vulnerable for sample in subset} == {True, False}:
            both_classes += 1
        association = _association(subset, feature_index, threshold)
        if association.mean_activation_difference is not None:
            differences[dataset] = association.mean_activation_difference
    signs = [difference > 0 for difference in differences.values() if difference != 0]
    if signs:
        positives = sum(signs)
        negatives = len(signs) - positives
        # Majority direction; ties are resolved against consistency (0.5).
        consistency = max(positives, negatives) / len(signs)
    else:
        consistency = None
    return FeatureStability(differences, consistency, both_classes)


def _cross_dataset_metrics(
    samples: Sequence[FeatureSample],
    threshold: float,
) -> tuple[CrossDatasetMetric, ...]:
    datasets = sorted({sample.label.dataset_id for sample in samples})
    metrics = []
    for train_dataset in datasets:
        train = [sample for sample in samples if sample.label.dataset_id == train_dataset]
        for validation_dataset in datasets:
            if train_dataset == validation_dataset:
                continue
            validation = [
                sample for sample in samples if sample.label.dataset_id == validation_dataset
            ]
            for feature_index in range(samples[0].features.shape[0]):
                train_association = _association(train, feature_index, threshold)
                validation_association = _association(validation, feature_index, threshold)
                if (
                    train_association.association_direction is None
                    or validation_association.association_direction is None
                ):
                    continue
                metrics.append(
                    CrossDatasetMetric(
                        feature_index=feature_index,
                        train_dataset=train_dataset,
                        validation_dataset=validation_dataset,
                        activation_threshold=threshold,
                        active_precision=validation_association.active_precision,
                        active_recall=validation_association.active_recall,
                        validation_sample_count=len(validation),
                        train_association_direction=train_association.association_direction,
                        validation_association_direction=validation_association.association_direction,
                        direction_agrees=(
                            train_association.association_direction
                            == validation_association.association_direction
                        ),
                    )
                )
    return tuple(metrics)


__all__ = [
    "CodeSampleLabel",
    "CrossDatasetMetric",
    "FeatureAssociation",
    "FeatureDictionary",
    "FeatureDictionaryEntry",
    "FeatureExperimentMetadata",
    "FeatureSample",
    "FeatureStability",
    "analyze_features",
    "association_selectivity",
    "extract_feature_samples",
    "samples_from_token_features",
]
