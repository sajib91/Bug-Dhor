"""Ablation study definitions and analysis for Bug Dhor.

Ablations compare observed results from configured runs; this module does not
fabricate outcomes. Missing/insufficient data is reported explicitly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from .statistics import PairedComparisonResult, apply_multiple_comparison_correction, paired_comparison


ABLATIONS: dict[str, str] = {
    "A1": "Without SAE features",
    "A2": "Without counterfactual analysis",
    "A3": "Without pairwise interactions",
    "A4": "Without higher-order interactions",
    "A5": "Without adaptive steering",
    "A6": "Without static-analysis fusion",
    "A7": "Without repository context",
    "A8": "Without independent verification",
}


@dataclass(slots=True)
class AblationResult:
    ablation_id: str
    description: str
    baseline_condition: str
    ablated_condition: str
    metrics: dict[str, PairedComparisonResult]
    sample_sizes: dict[str, Any]
    missing_data: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ablationId": self.ablation_id,
            "description": self.description,
            "baselineCondition": self.baseline_condition,
            "ablatedCondition": self.ablated_condition,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
            "sampleSizes": self.sample_sizes,
            "missingData": self.missing_data,
            "notes": self.notes,
        }


def run_ablation(
    ablation_id: str,
    baseline: Mapping[str, Sequence[Any]],
    ablated: Mapping[str, Sequence[Any]],
    *,
    baseline_name: str = "full_or_baseline",
    ablated_name: str | None = None,
    metric_names: Sequence[str] | None = None,
    cluster_ids_by_metric: Mapping[str, Sequence[Any]] | None = None,
    ci_level: float = 0.95,
    n_boot: int = 2000,
    n_perm: int = 5000,
    seed: int = 0,
    alpha: float = 0.05,
) -> AblationResult:
    if ablation_id not in ABLATIONS:
        raise ValueError(f"Unknown ablation id: {ablation_id}")
    desc = ABLATIONS[ablation_id]
    ablated_name = ablated_name or desc
    if metric_names is None:
        metric_names = sorted(set(baseline.keys()) & set(ablated.keys()))
    metrics: dict[str, PairedComparisonResult] = {}
    sample_sizes: dict[str, Any] = {}
    missing_data: dict[str, Any] = {}
    notes: list[str] = []
    for metric in metric_names:
        a = list(baseline.get(metric, []))
        b = list(ablated.get(metric, []))
        clusters = None
        if cluster_ids_by_metric and metric in cluster_ids_by_metric:
            clusters = list(cluster_ids_by_metric[metric])
        if len(a) != len(b):
            # align to min length but report mismatch
            n = min(len(a), len(b))
            notes.append(f"Metric {metric}: length mismatch (baseline={len(a)}, ablated={len(b)}); compared on first {n} aligned observations only.")
            a, b = a[:n], b[:n]
            if clusters is not None:
                clusters = clusters[:n]
        comp = paired_comparison(
            a,
            b,
            metric=metric,
            ci_level=ci_level,
            n_boot=n_boot,
            n_perm=n_perm,
            seed=seed,
            cluster_ids=clusters,
            alpha=alpha,
        )
        metrics[metric] = comp
        sample_sizes[metric] = {"nPairs": comp.n_pairs, "baselineN": len(a), "ablatedN": len(b)}
        missing_data[metric] = {"missingPairs": comp.missing}
        if clusters is None:
            notes.append(f"Metric {metric}: no cluster_ids provided; if samples share repositories/projects, results may understate dependence - provide cluster_ids for cluster bootstrap/dependence-aware interpretation.")
    if not metrics:
        notes.append("No overlapping metrics with observations available for comparison.")
    notes.append("Statistical significance and practical significance are reported separately; absence of significance is not evidence of absence.")
    return AblationResult(
        ablation_id=ablation_id,
        description=desc,
        baseline_condition=baseline_name,
        ablated_condition=ablated_name,
        metrics=metrics,
        sample_sizes=sample_sizes,
        missing_data=missing_data,
        notes=notes,
    )


def summarize_ablation_multiple_comparisons(
    ablation_results: Sequence[AblationResult],
    *,
    p_source: str = "permutation_test",
    method: str = "holm",
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Apply multiple-comparison correction across ablation/metric tests."""
    entries = []
    pvals = []
    for ar in ablation_results:
        for metric, comp in ar.metrics.items():
            test = getattr(comp, p_source, None) or comp.permutation_test
            if isinstance(test, dict):
                p = test.get("p_value")
            else:
                p = None
            entries.append({"ablationId": ar.ablation_id, "metric": metric, "p_source": p_source})
            pvals.append(p)
    corr = apply_multiple_comparison_correction(pvals, method=method, alpha=alpha)
    for entry, c in zip(entries, corr["results"]):
        entry.update({k: v for k, v in c.items() if k != "index"})
    return {"correction": {"method": method, "alpha": alpha}, "entries": entries}


__all__ = [
    "ABLATIONS",
    "AblationResult",
    "run_ablation",
    "summarize_ablation_multiple_comparisons",
]
