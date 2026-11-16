"""Cross-model and cross-dataset comparison analysis.

Comparisons operate on provided experimental observations only. No outcomes are
fabricated. When data are insufficient or dependent structure is unknown, this
is reported explicitly.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from .statistics import (
    apply_multiple_comparison_correction,
    bootstrap_ci,
    cliffs_delta,
    mann_whitney_u,
    paired_comparison,
)


@dataclass(slots=True)
class ComparisonResult:
    comparison_type: str  # cross_model|cross_dataset
    dimension: str
    groups: list[str]
    metric: str
    summary: dict[str, Any]
    tests: dict[str, Any]
    sample_sizes: dict[str, Any]
    missing_data: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _group_observations(records: Sequence[Mapping[str, Any]], group_key: str, metric_key: str) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = defaultdict(list)
    for r in records:
        g = r.get(group_key)
        if g is None:
            continue
        grouped[str(g)].append(r.get(metric_key))
    return dict(grouped)


def cross_model_comparison(
    records: Sequence[Mapping[str, Any]],
    *,
    model_key: str = "model",
    metric_key: str = "value",
    paired_by: str | None = None,
    cluster_key: str | None = None,
    ci_level: float = 0.95,
    n_boot: int = 2000,
    seed: int = 0,
) -> list[ComparisonResult]:
    """Compare a metric across models.

    If `paired_by` is provided (e.g. sample_id), records are aligned into paired
    comparisons per model pair. Otherwise independent-group summaries/tests are used.
    """
    if paired_by:
        # build paired_by -> model -> value
        table: dict[Any, dict[str, Any]] = defaultdict(dict)
        clusters: dict[Any, Any] = {}
        for r in records:
            pid = r.get(paired_by)
            m = r.get(model_key)
            if pid is None or m is None:
                continue
            table[pid][str(m)] = r.get(metric_key)
            if cluster_key and cluster_key in r:
                clusters[pid] = r.get(cluster_key)
        models = sorted({m for row in table.values() for m in row.keys()})
        results: list[ComparisonResult] = []
        for i in range(len(models)):
            for j in range(i + 1, len(models)):
                ma, mb = models[i], models[j]
                va, vb, cids = [], [], []
                missing = 0
                for pid, row in table.items():
                    a = row.get(ma)
                    b = row.get(mb)
                    if a is None or b is None:
                        missing += 1
                        continue
                    va.append(a); vb.append(b)
                    cids.append(clusters.get(pid))
                comp = paired_comparison(va, vb, metric=metric_key, ci_level=ci_level, n_boot=n_boot, seed=seed, cluster_ids=cids if cluster_key else None)
                results.append(ComparisonResult(
                    comparison_type="cross_model",
                    dimension=f"{ma} vs {mb}",
                    groups=[ma, mb],
                    metric=metric_key,
                    summary={"meanA": comp.mean_a, "meanB": comp.mean_b, "meanDifference": comp.mean_difference},
                    tests={"paired": comp.to_dict()},
                    sample_sizes={"nPairs": comp.n_pairs},
                    missing_data={"missingPairs": missing},
                    notes=["Paired by " + paired_by + ("; cluster-aware bootstrap used." if cluster_key else "; cluster ids not provided - repeated measures within repositories/projects must be accounted for separately if present.")],
                ))
        return results

    grouped = _group_observations(records, model_key, metric_key)
    models = sorted(grouped.keys())
    results = []
    for i in range(len(models)):
        for j in range(i + 1, len(models)):
            ma, mb = models[i], models[j]
            va, vb = grouped[ma], grouped[mb]
            valid_a = [v for v in va if v is not None]
            valid_b = [v for v in vb if v is not None]
            ci_a = bootstrap_ci(va, ci_level=ci_level, n_boot=n_boot, seed=seed).to_dict()
            ci_b = bootstrap_ci(vb, ci_level=ci_level, n_boot=n_boot, seed=seed + 1).to_dict()
            mwu = mann_whitney_u(va, vb)
            cd = cliffs_delta(va, vb)
            results.append(ComparisonResult(
                comparison_type="cross_model",
                dimension=f"{ma} vs {mb}",
                groups=[ma, mb],
                metric=metric_key,
                summary={"bootstrapCI_A": ci_a, "bootstrapCI_B": ci_b},
                tests={"mann_whitney_u": mwu, "cliffs_delta": cd},
                sample_sizes={"nA": len(valid_a), "nB": len(valid_b)},
                missing_data={"missingA": len(va) - len(valid_a), "missingB": len(vb) - len(valid_b)},
                notes=["Independent-group comparison; does not assume pairing. If samples are not independent (e.g. same repositories/projects), aggregate or provide paired/clustered design."],
            ))
    return results


def cross_dataset_comparison(
    records: Sequence[Mapping[str, Any]],
    *,
    dataset_key: str = "dataset",
    metric_key: str = "value",
    paired_by: str | None = None,
    cluster_key: str | None = None,
    ci_level: float = 0.95,
    n_boot: int = 2000,
    seed: int = 0,
) -> list[ComparisonResult]:
    # Same mechanics, different dimension label
    base = cross_model_comparison(
        records,
        model_key=dataset_key,
        metric_key=metric_key,
        paired_by=paired_by,
        cluster_key=cluster_key,
        ci_level=ci_level,
        n_boot=n_boot,
        seed=seed,
    )
    for r in base:
        r.comparison_type = "cross_dataset"
    return base


def correct_comparison_pvalues(
    comparisons: Sequence[ComparisonResult],
    *,
    method: str = "holm",
    alpha: float = 0.05,
) -> dict[str, Any]:
    pvals = []
    refs = []
    for idx, c in enumerate(comparisons):
        p = None
        if "paired" in c.tests:
            p = ((c.tests["paired"].get("permutation_test") or {}).get("p_value"))
        elif "mann_whitney_u" in c.tests:
            p = (c.tests["mann_whitney_u"] or {}).get("p_value")
        pvals.append(p)
        refs.append({"comparisonIndex": idx, "dimension": c.dimension, "metric": c.metric})
    corr = apply_multiple_comparison_correction(pvals, method=method, alpha=alpha)
    for ref, row in zip(refs, corr["results"]):
        ref.update({k: v for k, v in row.items() if k != "index"})
    return {"correction": {"method": method, "alpha": alpha}, "entries": refs}


__all__ = [
    "ComparisonResult",
    "correct_comparison_pvalues",
    "cross_dataset_comparison",
    "cross_model_comparison",
]
