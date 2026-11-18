"""Experiment evaluation pipeline interfaces and E0-E8 runners.

This framework executes evaluations only when required data, models, tools, and
artifacts are actually available and configured. It does not fabricate results.
When prerequisites are missing, runs are recorded as unavailable/not_run with
explicit reasons.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence

from bugdhor.evaluation.metrics import (
    DetectionMetrics,
    ExplainabilityMetrics,
    LocalizationMetrics,
    PerformanceMetrics,
    RepairMetrics,
    aggregate_detection_metrics,
    compute_localization_metrics,
    compute_repair_metrics,
)

from .config import ExperimentConfig, ExperimentTracker, now_iso, sha256_text, canonical_json
from .datasets import DatasetSample
from .groups import EXPERIMENT_GROUPS, GROUP_REQUIREMENTS


class ModelEvaluator(Protocol):
    """Model-level evaluation interface.

    Implementations must return observations derived from actual model/tool runs.
    """

    model_id: str

    def evaluate_detection(self, samples: Sequence[DatasetSample], **kwargs: Any) -> dict[str, Any]:
        ...

    def evaluate_localization(self, samples: Sequence[DatasetSample], **kwargs: Any) -> dict[str, Any]:
        ...

    def evaluate_repair(self, samples: Sequence[DatasetSample], **kwargs: Any) -> dict[str, Any]:
        ...

    def evaluate_explainability(self, samples: Sequence[DatasetSample], **kwargs: Any) -> dict[str, Any]:
        ...


@dataclass(slots=True)
class EvaluationObservations:
    """Container for raw observations from an actual run.

    All fields are optional; absent data means not measured.
    """

    detection_true: list[int] = field(default_factory=list)
    detection_pred: list[int] = field(default_factory=list)
    detection_scores: list[float] = field(default_factory=list)
    localization_pred_lines: list[set[int]] = field(default_factory=list)
    localization_gold_lines: list[set[int]] = field(default_factory=list)
    repair_records: list[dict[str, Any]] = field(default_factory=list)
    explainability_records: list[dict[str, Any]] = field(default_factory=list)
    performance_records: list[dict[str, Any]] = field(default_factory=list)
    per_sample: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def compute_explainability_metrics(records: Sequence[Mapping[str, Any]]) -> ExplainabilityMetrics:
    if not records:
        return ExplainabilityMetrics(None, None, None, 0)
    faith = [r.get("feature_faithfulness") for r in records if isinstance(r.get("feature_faithfulness"), (int, float))]
    cons = [r.get("explanation_consistency") for r in records if isinstance(r.get("explanation_consistency"), (int, float))]
    cf = [r.get("counterfactual_validity") for r in records if isinstance(r.get("counterfactual_validity"), (int, float))]
    def avg(xs: list[Any]) -> float | None:
        return (sum(float(x) for x in xs) / len(xs)) if xs else None
    return ExplainabilityMetrics(
        feature_faithfulness=avg(faith),
        explanation_consistency=avg(cons),
        counterfactual_validity=avg(cf),
        samples=len(records),
    )


def compute_performance_metrics(records: Sequence[Mapping[str, Any]]) -> PerformanceMetrics:
    if not records:
        return PerformanceMetrics(None, None, None, 0)
    overhead = [r.get("inference_overhead_seconds") for r in records if isinstance(r.get("inference_overhead_seconds"), (int, float))]
    latency = [r.get("analysis_latency_seconds") for r in records if isinstance(r.get("analysis_latency_seconds"), (int, float))]
    mem = [r.get("memory_usage_mb") for r in records if isinstance(r.get("memory_usage_mb"), (int, float))]
    def avg(xs: list[Any]) -> float | None:
        return (sum(float(x) for x in xs) / len(xs)) if xs else None
    return PerformanceMetrics(
        inference_overhead_seconds=avg(overhead),
        analysis_latency_seconds=avg(latency),
        memory_usage_mb=avg(mem),
        samples=len(records),
    )


def evaluate_observations(obs: EvaluationObservations) -> dict[str, Any]:
    metrics: dict[str, Any] = {"measured": {}}
    # Detection
    if obs.detection_true and obs.detection_pred and len(obs.detection_true) == len(obs.detection_pred):
        scores = obs.detection_scores if len(obs.detection_scores) == len(obs.detection_true) else None
        det = aggregate_detection_metrics(obs.detection_true, obs.detection_pred, scores)
        metrics["detection"] = det.to_dict()
        metrics["measured"]["detection"] = True
    else:
        metrics["detection"] = None
        metrics["measured"]["detection"] = False
    # Localization
    if obs.localization_pred_lines and obs.localization_gold_lines:
        loc = compute_localization_metrics(obs.localization_pred_lines, obs.localization_gold_lines)
        metrics["localization"] = loc.to_dict()
        metrics["measured"]["localization"] = True
    else:
        metrics["localization"] = None
        metrics["measured"]["localization"] = False
    # Repair
    if obs.repair_records:
        rep = compute_repair_metrics(obs.repair_records)
        metrics["repair"] = rep.to_dict()
        metrics["measured"]["repair"] = True
    else:
        metrics["repair"] = None
        metrics["measured"]["repair"] = False
    # Explainability
    if obs.explainability_records:
        expl = compute_explainability_metrics(obs.explainability_records)
        metrics["explainability"] = expl.to_dict()
        metrics["measured"]["explainability"] = True
    else:
        metrics["explainability"] = None
        metrics["measured"]["explainability"] = False
    # Performance
    if obs.performance_records:
        perf = compute_performance_metrics(obs.performance_records)
        metrics["performance"] = perf.to_dict()
        metrics["measured"]["performance"] = True
    else:
        metrics["performance"] = None
        metrics["measured"]["performance"] = False
    return metrics


def check_group_prerequisites(group: str, capabilities: Mapping[str, bool] | None = None) -> tuple[bool, list[str]]:
    caps = dict(capabilities or {})
    req = GROUP_REQUIREMENTS.get(group, {})
    missing: list[str] = []
    if req.get("requires_sae") and not caps.get("sae", False):
        missing.append("sae_artifact_or_runtime")
    if req.get("requires_repair") and not caps.get("repair", False):
        missing.append("repair_capability")
    if req.get("requires_static") and not caps.get("static_analysis", False):
        missing.append("static_analysis_capability")
    if not caps.get("model", False) and group in EXPERIMENT_GROUPS:
        # most groups require a model/runtime; E2 can be static-only depending on setup
        if group != "E2":
            missing.append("model_runtime")
    return (len(missing) == 0), missing


@dataclass(slots=True)
class ExperimentRunResult:
    run_id: str
    group: str
    status: str
    manifest: dict[str, Any]
    metrics: dict[str, Any] | None = None
    raw_output_paths: list[str] = field(default_factory=list)
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            "group": self.group,
            "status": self.status,
            "manifest": self.manifest,
            "metrics": self.metrics,
            "rawOutputPaths": self.raw_output_paths,
            "reason": self.reason,
        }


class ExperimentRunner:
    """Runs configured experiment groups and records raw outputs + metrics."""

    def __init__(self, tracker: ExperimentTracker) -> None:
        self.tracker = tracker

    def run(
        self,
        config: ExperimentConfig,
        *,
        samples: Sequence[DatasetSample] | None = None,
        capabilities: Mapping[str, bool] | None = None,
        evaluator: ModelEvaluator | None = None,
        observation_provider: Callable[[str, Sequence[DatasetSample], ExperimentConfig], EvaluationObservations] | None = None,
    ) -> ExperimentRunResult:
        errors = config.validate()
        run_id = sha256_text(f"{config.config_hash()}:{now_iso()}:{config.experiment_id}")[:16]
        manifest = self.tracker.create_manifest(config, run_id)
        manifest["runId"] = run_id
        manifest["status"] = "running"
        manifest["startedAt"] = now_iso()
        self.tracker.save_manifest(run_id, manifest)

        if errors:
            manifest["status"] = "failed"
            manifest["errors"] = errors
            manifest["completedAt"] = now_iso()
            self.tracker.save_manifest(run_id, manifest)
            return ExperimentRunResult(run_id, config.group, "failed", manifest, reason="invalid_config")

        caps = dict(capabilities or {})
        if samples is None:
            # cannot run without actual loaded data
            manifest["status"] = "unavailable"
            manifest["errors"] = manifest.get("errors", []) + ["dataset_samples_unavailable"]
            manifest["notes"].append("No dataset samples provided/loaded; evaluation not run and no metrics fabricated.")
            manifest["completedAt"] = now_iso()
            self.tracker.save_manifest(run_id, manifest)
            return ExperimentRunResult(run_id, config.group, "unavailable", manifest, reason="dataset_samples_unavailable")

        ok, missing = check_group_prerequisites(config.group, caps)
        if not ok:
            manifest["status"] = "unavailable"
            manifest["errors"] = manifest.get("errors", []) + [f"missing_prerequisite:{m}" for m in missing]
            manifest["notes"].append(f"Group {config.group} prerequisites missing: {missing}. No results fabricated.")
            manifest["completedAt"] = now_iso()
            self.tracker.save_manifest(run_id, manifest)
            return ExperimentRunResult(run_id, config.group, "unavailable", manifest, reason="missing_prerequisites")

        raw_paths: list[str] = []
        # record config and sample manifest (ids/hashes only, not full data export by default)
        sample_meta = [{"sampleId": s.sample_id, "dataset": s.dataset, "contentHash": s.content_hash(), "label": s.label, "cwe": s.cwe, "language": s.language} for s in samples]
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "samples_index", sample_meta)))

        t0 = time.monotonic()
        observations: EvaluationObservations | None = None
        try:
            if observation_provider is not None:
                observations = observation_provider(config.group, samples, config)
            elif evaluator is not None:
                observations = self._observations_from_evaluator(config.group, samples, evaluator)
            else:
                manifest["status"] = "unavailable"
                manifest["errors"].append("no_evaluator_or_observation_provider")
                manifest["notes"].append("No model/tool evaluator or observation provider configured; cannot produce measured observations.")
                manifest["completedAt"] = now_iso()
                self.tracker.save_manifest(run_id, manifest)
                return ExperimentRunResult(run_id, config.group, "unavailable", manifest, reason="no_evaluator")
        except Exception as exc:  # noqa: BLE001
            manifest["status"] = "failed"
            manifest["errors"].append(f"evaluation_error:{type(exc).__name__}:{exc}")
            manifest["completedAt"] = now_iso()
            self.tracker.save_manifest(run_id, manifest)
            return ExperimentRunResult(run_id, config.group, "failed", manifest, reason="evaluation_error")

        duration = time.monotonic() - t0
        assert observations is not None
        observations.performance_records.append({"analysis_latency_seconds": duration})
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "observations_meta", observations.metadata)))
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "per_sample", observations.per_sample)))
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "repair_records", observations.repair_records)))
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "explainability_records", observations.explainability_records)))
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "performance_records", observations.performance_records)))

        metrics = evaluate_observations(observations)
        metrics["runDurationSeconds"] = duration
        metrics["group"] = config.group
        metrics["samples"] = len(samples)
        raw_paths.append(str(self.tracker.record_raw_output(run_id, "metrics", metrics)))

        manifest["status"] = "completed"
        manifest["completedAt"] = now_iso()
        manifest["metrics"] = metrics
        manifest["rawOutputs"] = raw_paths
        manifest["notes"].append("Metrics computed only from recorded observations; unmeasured metrics are null.")
        self.tracker.save_manifest(run_id, manifest)
        return ExperimentRunResult(run_id, config.group, "completed", manifest, metrics=metrics, raw_output_paths=raw_paths)

    def _observations_from_evaluator(self, group: str, samples: Sequence[DatasetSample], evaluator: ModelEvaluator) -> EvaluationObservations:
        obs = EvaluationObservations(metadata={"group": group, "modelId": getattr(evaluator, "model_id", None)})
        # Best-effort calls; evaluator may not implement all dimensions.
        if hasattr(evaluator, "evaluate_detection"):
            det = evaluator.evaluate_detection(samples) or {}
            obs.detection_true = list(det.get("y_true", []) or [])
            obs.detection_pred = list(det.get("y_pred", []) or [])
            obs.detection_scores = list(det.get("y_scores", []) or [])
            obs.per_sample.extend(list(det.get("per_sample", []) or []))
        if hasattr(evaluator, "evaluate_localization"):
            loc = evaluator.evaluate_localization(samples) or {}
            obs.localization_pred_lines = [set(x) for x in (loc.get("predicted_lines", []) or [])]
            obs.localization_gold_lines = [set(x) for x in (loc.get("gold_lines", []) or [])]
        if hasattr(evaluator, "evaluate_repair") and group in {"E6", "E7", "E8"}:
            rep = evaluator.evaluate_repair(samples) or {}
            obs.repair_records = list(rep.get("records", []) or [])
        if hasattr(evaluator, "evaluate_explainability") and group in {"E3", "E4", "E5", "E7", "E8"}:
            ex = evaluator.evaluate_explainability(samples) or {}
            obs.explainability_records = list(ex.get("records", []) or [])
        return obs


__all__ = [
    "EvaluationObservations",
    "ExperimentRunResult",
    "ExperimentRunner",
    "ModelEvaluator",
    "check_group_prerequisites",
    "compute_explainability_metrics",
    "compute_performance_metrics",
    "evaluate_observations",
]
