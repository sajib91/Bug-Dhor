"""Metric computations for reproducible CRAFT-Sec evaluation.

Metrics are computed only from provided observations. No results are fabricated.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence


def _safe_div(num: float, den: float) -> float | None:
    if den == 0:
        return None
    return num / den


def _pr_auc(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    if not scores or len(scores) != len(labels) or len(set(labels)) < 1:
        return None
    if sum(1 for l in labels if l == 1) == 0 or sum(1 for l in labels if l == 0) == 0:
        return None
    pairs = sorted(zip(scores, labels), key=lambda x: x[0], reverse=True)
    tp = 0
    fp = 0
    fn = sum(labels)
    prev_recall = 0.0
    prev_precision = 1.0
    auc = 0.0
    for _score, label in pairs:
        if label == 1:
            tp += 1
            fn -= 1
        else:
            fp += 1
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        # trapezoidal in precision-recall space
        auc += (recall - prev_recall) * (precision + prev_precision) / 2.0
        prev_recall, prev_precision = recall, precision
    return float(max(0.0, min(1.0, auc)))


@dataclass(slots=True)
class DetectionMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None
    mcc: float | None
    pr_auc: float | None
    support: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def aggregate_detection_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    y_scores: Sequence[float] | None = None,
) -> DetectionMetrics:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have same length")
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else None
    pr = _pr_auc(list(y_scores), list(y_true)) if y_scores is not None and len(y_scores) == len(y_true) else None
    return DetectionMetrics(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1, mcc=mcc, pr_auc=pr, support=len(y_true))


@dataclass(slots=True)
class LocalizationMetrics:
    line_precision: float | None
    line_recall: float | None
    localization_accuracy: float | None
    samples: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compute_localization_metrics(
    predicted_lines: Sequence[set[int]],
    gold_lines: Sequence[set[int]],
) -> LocalizationMetrics:
    if len(predicted_lines) != len(gold_lines):
        raise ValueError("predicted_lines and gold_lines must have same length")
    if not predicted_lines:
        return LocalizationMetrics(None, None, None, 0)
    total_prec_num = 0
    total_prec_den = 0
    total_rec_num = 0
    total_rec_den = 0
    exact = 0
    for pred, gold in zip(predicted_lines, gold_lines):
        inter = len(pred & gold)
        total_prec_num += inter
        total_prec_den += len(pred)
        total_rec_num += inter
        total_rec_den += len(gold)
        if pred == gold and len(gold) > 0:
            exact += 1
    lp = _safe_div(total_prec_num, total_prec_den)
    lr = _safe_div(total_rec_num, total_rec_den)
    acc = _safe_div(exact, len(gold_lines))
    return LocalizationMetrics(line_precision=lp, line_recall=lr, localization_accuracy=acc, samples=len(gold_lines))


@dataclass(slots=True)
class RepairMetrics:
    repair_success_rate: float | None
    verified_repair_success: float | None
    functional_pass_rate: float | None
    security_regression_rate: float | None
    total: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compute_repair_metrics(records: Sequence[Mapping[str, object]]) -> RepairMetrics:
    total = len(records)
    if total == 0:
        return RepairMetrics(None, None, None, None, 0)
    proposed = sum(1 for r in records if r.get("patch_proposed") or r.get("patch"))
    verified = sum(
        1
        for r in records
        if r.get("verified_secure")
        or r.get("security_verified")
        or r.get("state") == "FULLY_VERIFIED"
        or r.get("verified_repair_success")
    )
    functional = [r.get("functional_pass_rate") for r in records if isinstance(r.get("functional_pass_rate"), (int, float))]
    sec_reg = sum(1 for r in records if r.get("security_regression") or r.get("security_regression_rate") is True)
    return RepairMetrics(
        repair_success_rate=_safe_div(proposed, total),
        verified_repair_success=_safe_div(verified, total),
        functional_pass_rate=(sum(float(x) for x in functional) / len(functional)) if functional else None,
        security_regression_rate=_safe_div(sec_reg, total),
        total=total,
    )


@dataclass(slots=True)
class ExplainabilityMetrics:
    feature_faithfulness: float | None
    explanation_consistency: float | None
    counterfactual_validity: float | None
    samples: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compute_explainability_metrics(records: Sequence[Mapping[str, object]]) -> ExplainabilityMetrics:
    if not records:
        return ExplainabilityMetrics(None, None, None, 0)
    faith = [r.get("feature_faithfulness") for r in records if isinstance(r.get("feature_faithfulness"), (int, float))]
    cons = [r.get("explanation_consistency") for r in records if isinstance(r.get("explanation_consistency"), (int, float))]
    cf = [r.get("counterfactual_validity") for r in records if isinstance(r.get("counterfactual_validity"), (int, float))]
    def avg(xs: list[object]) -> float | None:
        return (sum(float(x) for x in xs) / len(xs)) if xs else None
    return ExplainabilityMetrics(
        feature_faithfulness=avg(faith),
        explanation_consistency=avg(cons),
        counterfactual_validity=avg(cf),
        samples=len(records),
    )


@dataclass(slots=True)
class PerformanceMetrics:
    inference_overhead_seconds: float | None
    analysis_latency_seconds: float | None
    memory_usage_mb: float | None
    samples: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compute_performance_metrics(records: Sequence[Mapping[str, object]]) -> PerformanceMetrics:
    if not records:
        return PerformanceMetrics(None, None, None, 0)
    overhead = [r.get("inference_overhead_seconds") for r in records if isinstance(r.get("inference_overhead_seconds"), (int, float))]
    latency = [r.get("analysis_latency_seconds") for r in records if isinstance(r.get("analysis_latency_seconds"), (int, float))]
    mem = [r.get("memory_usage_mb") for r in records if isinstance(r.get("memory_usage_mb"), (int, float))]
    def avg(xs: list[object]) -> float | None:
        return (sum(float(x) for x in xs) / len(xs)) if xs else None
    return PerformanceMetrics(
        inference_overhead_seconds=avg(overhead),
        analysis_latency_seconds=avg(latency),
        memory_usage_mb=avg(mem),
        samples=len(records),
    )


__all__ = [
    "DetectionMetrics",
    "ExplainabilityMetrics",
    "LocalizationMetrics",
    "PerformanceMetrics",
    "RepairMetrics",
    "aggregate_detection_metrics",
    "compute_explainability_metrics",
    "compute_localization_metrics",
    "compute_performance_metrics",
    "compute_repair_metrics",
]
