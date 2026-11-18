"""Independent-group calibration for the unified risk index.

A calibrated probability is emitted only after a calibration model is fitted on
one set of groups and evaluated on disjoint groups from an independent
validation dataset. Metrics and bootstrap intervals are computed on that
validation split. An artifact that fails its declared acceptance thresholds is
retained for audit but cannot be used by the risk engine.

No dataset ships with the engine. The JSONL dataset and evaluation config are
supplied by the caller so that calibration remains reproducible and falsifiable.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from bugdhor.risk.models import canonical_hash, validate_finite_unit


@dataclass(frozen=True, slots=True)
class CalibrationRow:
    """One labelled observation used for calibration or validation."""

    row_id: str
    group_id: str
    score: float
    label: int

    def __post_init__(self) -> None:
        if not self.row_id.strip() or not self.group_id.strip():
            raise ValueError("calibration rows require row_id and group_id")
        validate_finite_unit(self.score, "calibration score")
        if self.label not in (0, 1) or isinstance(self.label, bool):
            raise ValueError("calibration label must be 0 or 1")


@dataclass(frozen=True, slots=True)
class CalibrationAcceptance:
    """Explicit validation thresholds; these are not risk-model weights."""

    max_brier: float
    max_ece: float
    max_log_loss: float
    min_auroc: float
    basis: str

    def __post_init__(self) -> None:
        for name in ("max_brier", "max_ece", "max_log_loss"):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if not math.isfinite(self.min_auroc) or not 0.5 <= self.min_auroc <= 1.0:
            raise ValueError("min_auroc must lie in [0.5, 1]")
        if not self.basis.strip():
            raise ValueError("calibration acceptance thresholds require a basis")

    def to_dict(self) -> dict[str, Any]:
        return {
            "maxBrier": self.max_brier,
            "maxEce": self.max_ece,
            "maxLogLoss": self.max_log_loss,
            "minAuroc": self.min_auroc,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class CalibrationConfig:
    """Reproducible calibration/evaluation configuration."""

    name: str
    version: str
    dataset_id: str
    fit_groups: tuple[str, ...]
    validation_groups: tuple[str, ...]
    acceptance: CalibrationAcceptance
    score_field: str = "score"
    label_field: str = "label"
    group_field: str = "group"
    row_id_field: str = "rowId"
    method: str = "platt"
    bins: int = 10
    regularization: float = 1e-6
    max_iterations: int = 100
    tolerance: float = 1e-10
    seed: int = 0
    n_boot: int = 1000
    confidence: float = 0.95

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.name, self.version, self.dataset_id)):
            raise ValueError("calibration config requires name, version, and dataset_id")
        if not self.fit_groups or not self.validation_groups:
            raise ValueError("fit_groups and validation_groups must be non-empty")
        overlap = set(self.fit_groups) & set(self.validation_groups)
        if overlap:
            raise ValueError(f"calibration groups overlap validation: {sorted(overlap)}")
        if self.method != "platt":
            raise ValueError("only the platt calibration method is implemented")
        if not 2 <= self.bins <= 50:
            raise ValueError("bins must lie in [2, 50]")
        if not math.isfinite(self.regularization) or self.regularization < 0:
            raise ValueError("regularization must be finite and non-negative")
        if self.max_iterations < 1 or not math.isfinite(self.tolerance) or self.tolerance <= 0:
            raise ValueError("invalid IRLS convergence settings")
        if self.n_boot < 1 or not 0.0 < self.confidence < 1.0:
            raise ValueError("invalid bootstrap settings")

    def config_hash(self) -> str:
        return canonical_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "datasetId": self.dataset_id,
            "fitGroups": list(self.fit_groups),
            "validationGroups": list(self.validation_groups),
            "acceptance": self.acceptance.to_dict(),
            "scoreField": self.score_field,
            "labelField": self.label_field,
            "groupField": self.group_field,
            "rowIdField": self.row_id_field,
            "method": self.method,
            "bins": self.bins,
            "regularization": self.regularization,
            "maxIterations": self.max_iterations,
            "tolerance": self.tolerance,
            "seed": self.seed,
            "nBoot": self.n_boot,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class CalibrationMetrics:
    """Metrics computed on the independent validation split."""

    brier_score: float
    log_loss: float
    expected_calibration_error: float
    auroc: float
    count: int
    positives: int

    def to_dict(self) -> dict[str, float]:
        return {
            "brierScore": self.brier_score,
            "logLoss": self.log_loss,
            "expectedCalibrationError": self.expected_calibration_error,
            "auroc": self.auroc,
            "count": float(self.count),
            "positives": float(self.positives),
        }


@dataclass(frozen=True, slots=True)
class CalibrationArtifact:
    """Auditable result of one calibration fit and independent evaluation."""

    artifact_id: str
    config: CalibrationConfig
    slope: float
    intercept: float
    fit_count: int
    metrics: CalibrationMetrics
    metric_intervals: Mapping[str, tuple[float, float]] = field(default_factory=dict)
    split_hash: str = ""
    data_hash: str = ""
    failures: tuple[str, ...] = ()
    converged: bool = False
    iterations: int = 0

    @property
    def status(self) -> str:
        return "validated" if not self.failures else "rejected"

    def probability(self, score: float) -> float | None:
        """Return a probability only for a validated artifact."""
        if self.status != "validated":
            return None
        validate_finite_unit(score, "risk index")
        return float(_sigmoid(self.slope * score + self.intercept))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "status": self.status,
            "config": self.config.to_dict(),
            "method": self.config.method,
            "datasetId": self.config.dataset_id,
            "configHash": self.config.config_hash(),
            "splitHash": self.split_hash,
            "dataHash": self.data_hash,
            "parameters": {"slope": self.slope, "intercept": self.intercept},
            "fitCount": self.fit_count,
            "metrics": self.metrics.to_dict(),
            "metricIntervals": {
                key: list(value) for key, value in sorted(self.metric_intervals.items())
            },
            "failures": list(self.failures),
            "converged": self.converged,
            "iterations": self.iterations,
            "acceptance": self.config.acceptance.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CalibrationEvaluation:
    """Artifact plus the exact rows used for fitting and validation."""

    artifact: CalibrationArtifact
    fit_rows: tuple[CalibrationRow, ...]
    validation_rows: tuple[CalibrationRow, ...]
    warnings: tuple[str, ...] = ()

    def report(self) -> dict[str, Any]:
        """Return a reproducible evaluation report."""
        report = self.artifact.to_dict()
        report["evaluation"] = {
            "fitGroupCount": len({row.group_id for row in self.fit_rows}),
            "validationGroupCount": len({row.group_id for row in self.validation_rows}),
            "fitRowCount": len(self.fit_rows),
            "validationRowCount": len(self.validation_rows),
            "warnings": list(self.warnings),
        }
        return report


def calibration_config_from_mapping(payload: Mapping[str, Any]) -> CalibrationConfig:
    """Build a calibration config from a JSON/YAML-style mapping."""
    acceptance_payload = payload.get("acceptance")
    if not isinstance(acceptance_payload, Mapping):
        raise ValueError("calibration config requires an acceptance object")
    acceptance = CalibrationAcceptance(
        max_brier=float(acceptance_payload["maxBrier"]),
        max_ece=float(acceptance_payload["maxEce"]),
        max_log_loss=float(acceptance_payload["maxLogLoss"]),
        min_auroc=float(acceptance_payload["minAuroc"]),
        basis=str(acceptance_payload["basis"]),
    )
    return CalibrationConfig(
        name=str(payload["name"]),
        version=str(payload["version"]),
        dataset_id=str(payload["datasetId"]),
        fit_groups=tuple(str(item) for item in payload["fitGroups"]),
        validation_groups=tuple(str(item) for item in payload["validationGroups"]),
        acceptance=acceptance,
        score_field=str(payload.get("scoreField", "score")),
        label_field=str(payload.get("labelField", "label")),
        group_field=str(payload.get("groupField", "group")),
        row_id_field=str(payload.get("rowIdField", "rowId")),
        method=str(payload.get("method", "platt")),
        bins=int(payload.get("bins", 10)),
        regularization=float(payload.get("regularization", 1e-6)),
        max_iterations=int(payload.get("maxIterations", 100)),
        tolerance=float(payload.get("tolerance", 1e-10)),
        seed=int(payload.get("seed", 0)),
        n_boot=int(payload.get("nBoot", 1000)),
        confidence=float(payload.get("confidence", 0.95)),
    )


def load_calibration_rows(
    path: str | Path, config: CalibrationConfig
) -> tuple[CalibrationRow, ...]:
    """Load JSONL calibration rows using the config's field mapping."""
    source = Path(path)
    rows: list[CalibrationRow] = []
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if not isinstance(payload, Mapping):
                raise ValueError(f"calibration row {line_number} must be an object")
            try:
                row = CalibrationRow(
                    row_id=str(payload[config.row_id_field]),
                    group_id=str(payload[config.group_field]),
                    score=float(payload[config.score_field]),
                    label=int(payload[config.label_field]),
                )
            except KeyError as error:
                raise ValueError(
                    f"calibration row {line_number} is missing field {error.args[0]!r}"
                ) from error
            rows.append(row)
    if not rows:
        raise ValueError("calibration dataset is empty")
    return tuple(rows)


def evaluate_calibration(
    rows: Iterable[CalibrationRow],
    config: CalibrationConfig,
) -> CalibrationEvaluation:
    """Fit on fit groups and evaluate on disjoint validation groups."""
    all_rows = tuple(rows)
    fit = tuple(row for row in all_rows if row.group_id in set(config.fit_groups))
    validation = tuple(row for row in all_rows if row.group_id in set(config.validation_groups))
    warnings: list[str] = []
    if not fit:
        raise ValueError("no calibration rows matched fit_groups")
    if not validation:
        raise ValueError("no calibration rows matched validation_groups")
    if len(fit) + len(validation) != len(all_rows):
        warnings.append("rows outside the declared fit/validation groups were ignored")

    scores = np.asarray([row.score for row in fit], dtype=np.float64)
    labels = np.asarray([row.label for row in fit], dtype=np.float64)
    slope, intercept, converged, iterations = _fit_platt(
        scores,
        labels,
        regularization=config.regularization,
        max_iterations=config.max_iterations,
        tolerance=config.tolerance,
    )

    validation_scores = np.asarray([row.score for row in validation], dtype=np.float64)
    validation_labels = np.asarray([row.label for row in validation], dtype=np.float64)
    probabilities = np.asarray(
        [_sigmoid(slope * score + intercept) for score in validation_scores],
        dtype=np.float64,
    )
    metrics = _metrics(probabilities, validation_labels, bins=config.bins)
    rng = np.random.default_rng(config.seed)
    intervals: dict[str, tuple[float, float]] = {}
    for name, statistic in (
        ("brier_score", _brier),
        ("expected_calibration_error", lambda p, y: _ece(p, y, config.bins)),
    ):
        low, high = _bootstrap_interval(
            probabilities,
            validation_labels,
            statistic,
            rng=rng,
            n_boot=config.n_boot,
            confidence=config.confidence,
        )
        intervals[name] = (low, high)

    failures: list[str] = []
    acceptance = config.acceptance
    if metrics.brier_score > acceptance.max_brier:
        failures.append("brier_score_exceeds_threshold")
    if metrics.expected_calibration_error > acceptance.max_ece:
        failures.append("ece_exceeds_threshold")
    if metrics.log_loss > acceptance.max_log_loss:
        failures.append("log_loss_exceeds_threshold")
    if metrics.auroc < acceptance.min_auroc:
        failures.append("auroc_below_threshold")
    if not converged:
        failures.append("calibration_fit_did_not_converge")

    split_hash = canonical_hash(
        {
            "datasetId": config.dataset_id,
            "fitGroups": sorted(config.fit_groups),
            "validationGroups": sorted(config.validation_groups),
        }
    )
    data_hash = canonical_hash(
        {
            "rows": [
                [row.row_id, row.group_id, row.score, row.label]
                for row in sorted(all_rows, key=lambda item: item.row_id)
            ]
        }
    )
    artifact = CalibrationArtifact(
        artifact_id=canonical_hash(
            {
                "configHash": config.config_hash(),
                "splitHash": split_hash,
                "dataHash": data_hash,
            }
        ),
        config=config,
        slope=float(slope),
        intercept=float(intercept),
        fit_count=len(fit),
        metrics=metrics,
        metric_intervals=intervals,
        split_hash=split_hash,
        data_hash=data_hash,
        failures=tuple(failures),
        converged=bool(converged),
        iterations=iterations,
    )
    return CalibrationEvaluation(artifact, fit, validation, tuple(warnings))


def _sigmoid(value: float | np.ndarray) -> float | np.ndarray:
    value = np.asarray(value, dtype=np.float64)
    output = np.empty_like(value)
    positive = value >= 0
    output[positive] = 1.0 / (1.0 + np.exp(-value[positive]))
    exp_x = np.exp(value[~positive])
    output[~positive] = exp_x / (1.0 + exp_x)
    return float(output) if output.ndim == 0 else output


def _fit_platt(
    scores: np.ndarray,
    labels: np.ndarray,
    *,
    regularization: float,
    max_iterations: int,
    tolerance: float,
) -> tuple[float, float, bool, int]:
    """Ridge-regularized Newton fit of ``sigmoid(a*x + b)``."""
    design = np.column_stack([scores, np.ones(scores.size)])
    coefficients = np.zeros(2, dtype=np.float64)
    penalty = np.asarray([regularization, 0.0], dtype=np.float64)
    converged = False
    iterations = 0
    for iteration in range(1, max_iterations + 1):
        iterations = iteration
        probability = np.asarray(_sigmoid(design @ coefficients), dtype=np.float64)
        clipped = np.clip(probability, 1e-12, 1.0 - 1e-12)
        gradient = design.T @ (clipped - labels) / labels.size + penalty * coefficients
        weights = np.maximum(clipped * (1.0 - clipped), 1e-12)
        hessian = (design.T * weights) @ design / labels.size + np.diag(penalty)
        hessian += np.eye(2) * 1e-12
        try:
            step = np.linalg.solve(hessian, gradient)
        except np.linalg.LinAlgError:
            step = np.linalg.lstsq(hessian, gradient, rcond=None)[0]
        coefficients -= step
        if float(np.linalg.norm(step)) <= tolerance:
            converged = True
            break
    return float(coefficients[0]), float(coefficients[1]), converged, iterations


def _brier(probabilities: np.ndarray, labels: np.ndarray) -> float:
    return float(np.mean((probabilities - labels) ** 2))


def _log_loss(probabilities: np.ndarray, labels: np.ndarray) -> float:
    clipped = np.clip(probabilities, 1e-15, 1.0 - 1e-15)
    return float(-np.mean(labels * np.log(clipped) + (1.0 - labels) * np.log1p(-clipped)))


def _ece(probabilities: np.ndarray, labels: np.ndarray, bins: int) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = 0.0
    for index in range(bins):
        low, high = edges[index], edges[index + 1]
        mask = (probabilities >= low) & (
            probabilities < high if index < bins - 1 else probabilities <= high
        )
        if not mask.any():
            continue
        total += (
            float(mask.sum())
            / probabilities.size
            * abs(float(probabilities[mask].mean()) - float(labels[mask].mean()))
        )
    return total


def _auroc(probabilities: np.ndarray, labels: np.ndarray) -> float:
    positives = int(np.sum(labels == 1))
    negatives = int(np.sum(labels == 0))
    if positives == 0 or negatives == 0:
        return math.nan
    order = np.argsort(probabilities, kind="mergesort")
    sorted_scores = probabilities[order]
    ranks = np.empty(probabilities.size, dtype=np.float64)
    start = 0
    while start < probabilities.size:
        end = start + 1
        while end < probabilities.size and sorted_scores[end] == sorted_scores[start]:
            end += 1
        ranks[order[start:end]] = (start + end + 1) / 2.0
        start = end
    positive_rank_sum = float(ranks[labels[order] == 1].sum())
    return (positive_rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def _metrics(probabilities: np.ndarray, labels: np.ndarray, *, bins: int) -> CalibrationMetrics:
    auroc = _auroc(probabilities, labels)
    if not math.isfinite(auroc):
        auroc = 0.5
        probabilities = np.clip(probabilities, 0.0, 1.0)
    return CalibrationMetrics(
        brier_score=_brier(probabilities, labels),
        log_loss=_log_loss(probabilities, labels),
        expected_calibration_error=_ece(probabilities, labels, bins),
        auroc=auroc,
        count=int(labels.size),
        positives=int(np.sum(labels == 1)),
    )


def _bootstrap_interval(
    probabilities: np.ndarray,
    labels: np.ndarray,
    statistic: Any,
    *,
    rng: np.random.Generator,
    n_boot: int,
    confidence: float,
) -> tuple[float, float]:
    if probabilities.size < 2:
        return math.nan, math.nan
    values: list[float] = []
    for _ in range(n_boot):
        index = rng.integers(0, probabilities.size, size=probabilities.size)
        sample_p = probabilities[index]
        sample_y = labels[index]
        if np.unique(sample_y).size < 2:
            continue
        value = statistic(sample_p, sample_y)
        if math.isfinite(value):
            values.append(float(value))
    if not values:
        return math.nan, math.nan
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(np.asarray(values), [alpha, 1.0 - alpha])
    return float(low), float(high)


def calibration_artifact_from_mapping(payload: Mapping[str, Any]) -> CalibrationArtifact:
    """Rebuild an artifact from its serialized audit record."""
    config_payload = payload.get("config")
    if not isinstance(config_payload, Mapping):
        raise ValueError("calibration artifact requires an embedded config")
    config = calibration_config_from_mapping(config_payload)
    metrics_payload = payload.get("metrics")
    if not isinstance(metrics_payload, Mapping):
        raise ValueError("calibration artifact requires metrics")
    parameters = payload.get("parameters")
    if not isinstance(parameters, Mapping):
        raise ValueError("calibration artifact requires parameters")
    metrics = CalibrationMetrics(
        brier_score=float(metrics_payload["brierScore"]),
        log_loss=float(metrics_payload["logLoss"]),
        expected_calibration_error=float(metrics_payload["expectedCalibrationError"]),
        auroc=float(metrics_payload["auroc"]),
        count=int(metrics_payload["count"]),
        positives=int(metrics_payload["positives"]),
    )
    intervals = {
        key: (float(value[0]), float(value[1]))
        for key, value in dict(payload.get("metricIntervals", {})).items()
    }
    return CalibrationArtifact(
        artifact_id=str(payload["artifactId"]),
        config=config,
        slope=float(parameters["slope"]),
        intercept=float(parameters["intercept"]),
        fit_count=int(payload.get("fitCount", metrics.count)),
        metrics=metrics,
        metric_intervals=intervals,
        split_hash=str(payload.get("splitHash", "")),
        data_hash=str(payload.get("dataHash", "")),
        failures=tuple(str(item) for item in payload.get("failures", ())),
        converged=bool(payload.get("converged", False)),
        iterations=int(payload.get("iterations", 0)),
    )


__all__ = [
    "CalibrationAcceptance",
    "CalibrationArtifact",
    "CalibrationConfig",
    "CalibrationEvaluation",
    "CalibrationMetrics",
    "CalibrationRow",
    "calibration_artifact_from_mapping",
    "calibration_config_from_mapping",
    "evaluate_calibration",
    "load_calibration_rows",
]
