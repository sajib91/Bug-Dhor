"""Statistical analysis utilities for reproducible Bug Dhor evaluation.

All functions operate on provided observations only and never fabricate values.
When assumptions/data are insufficient, results explicitly report that and
return None/insufficient outcomes instead of invented statistics.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence


def _is_missing(value: Any) -> bool:
    """Return True for None, NaN, infinities, and non-convertible values."""
    if value is None:
        return True
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return True
    return not math.isfinite(numeric)


def _to_float_list(values: Sequence[Any]) -> tuple[list[float], int]:
    out: list[float] = []
    missing = 0
    for v in values:
        if _is_missing(v):
            missing += 1
            continue
        out.append(float(v))
    return out, missing


def _aligned_pairs(
    values_a: Sequence[Any], values_b: Sequence[Any]
) -> tuple[list[tuple[float, float]], int]:
    """Drop unpaired, NaN, and non-finite observations from aligned inputs.

    Pairing requires one-to-one alignment.  A length mismatch is an error rather
    than a silent truncation; a misaligned paired test would otherwise compare
    unrelated units.
    """
    if len(values_a) != len(values_b):
        raise ValueError(
            "paired inputs must have equal length; "
            f"got {len(values_a)} and {len(values_b)}"
        )
    pairs: list[tuple[float, float]] = []
    missing = 0
    for a, b in zip(values_a, values_b, strict=True):
        if _is_missing(a) or _is_missing(b):
            missing += 1
            continue
        pairs.append((float(a), float(b)))
    return pairs, missing


def _mean(xs: Sequence[float]) -> float | None:
    return (sum(xs) / len(xs)) if xs else None


def _variance(xs: Sequence[float]) -> float | None:
    if len(xs) < 2:
        return None
    m = _mean(xs)
    assert m is not None
    return sum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def _std(xs: Sequence[float]) -> float | None:
    v = _variance(xs)
    return math.sqrt(v) if v is not None else None


@dataclass(slots=True)
class AssumptionCheck:
    test: str
    ok: bool | None
    detail: str
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_normality(values: Sequence[float]) -> AssumptionCheck:
    xs, missing = _to_float_list(values)
    n = len(xs)
    if n < 8:
        return AssumptionCheck(
            test="normality",
            ok=None,
            detail="Insufficient sample size for a reliable normality assessment (n<8).",
            stats={"n": n, "missing": missing},
        )
    m = _mean(xs)
    s = _std(xs)
    if m is None or s is None or s == 0:
        return AssumptionCheck("normality", None, "Degenerate/constant sample; normality not assessable.", {"n": n, "missing": missing})
    # skewness/kurtosis heuristic (Fisher)
    skew = sum(((x - m) / s) ** 3 for x in xs) * n / ((n - 1) * (n - 2)) if n > 2 else None
    kurt = None
    if n > 3:
        kurt = (n * (n + 1) / ((n - 1) * (n - 2) * (n - 3))) * sum(((x - m) / s) ** 4 for x in xs) - (3 * (n - 1) ** 2 / ((n - 2) * (n - 3)))
    # rough rule-of-thumb: |skew|<2 and |excess kurtosis|<7
    ok = None
    detail = "Normality assessed via skewness/excess-kurtosis heuristics (no exact Shapiro-Wilk without scipy)."
    if skew is not None and kurt is not None:
        ok = abs(skew) < 2.0 and abs(kurt) < 7.0
        if not ok:
            detail += " Distribution appears substantially non-normal; prefer nonparametric/bootstrap methods."
    return AssumptionCheck("normality", ok, detail, {"n": n, "missing": missing, "skewness": skew, "excessKurtosis": kurt, "mean": m, "std": s})


def check_paired_assumptions(diffs: Sequence[float]) -> list[AssumptionCheck]:
    xs, missing = _to_float_list(diffs)
    checks = [check_normality(xs)]
    n = len(xs)
    indep = AssumptionCheck(
        test="independence_of_paired_units",
        ok=None,
        detail="Independence cannot be verified from values alone; pair/cluster identifiers must be provided and respected (e.g. aggregate by repository/project for repeated measures).",
        stats={"n": n, "missing": missing},
    )
    checks.append(indep)
    if n < 2:
        checks.append(AssumptionCheck("sample_size", False, "Too few paired observations.", {"n": n}))
    elif n < 20:
        checks.append(AssumptionCheck("sample_size", None, "Small sample (n<20); parametric p-values may be unreliable, prefer permutation/bootstrap.", {"n": n}))
    else:
        checks.append(AssumptionCheck("sample_size", True, "Sample size adequate for approximate parametric methods if other assumptions hold.", {"n": n}))
    return checks


@dataclass(slots=True)
class EstimateResult:
    name: str
    estimate: float | None
    ci_low: float | None
    ci_high: float | None
    ci_level: float
    method: str
    n: int
    missing: int
    assumptions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def bootstrap_ci(
    values: Sequence[Any],
    statistic: Callable[[list[float]], float | None] = lambda xs: _mean(xs),
    *,
    n_boot: int = 2000,
    ci_level: float = 0.95,
    seed: int = 0,
    cluster_ids: Sequence[Any] | None = None,
) -> EstimateResult:
    rng = random.Random(seed)
    stats: list[float] = []
    if cluster_ids is not None:
        if len(cluster_ids) != len(values):
            raise ValueError(
                "cluster_ids must align one-to-one with values; "
                f"got {len(cluster_ids)} and {len(values)}"
            )
        # A cluster label of None means the observation cannot be assigned to a
        # cluster.  Such observations are excluded, not silently pooled.
        valid_pairs: list[tuple[float, Any]] = []
        missing = 0
        for value, cluster_id in zip(values, cluster_ids, strict=True):
            if _is_missing(value) or cluster_id is None:
                missing += 1
                continue
            valid_pairs.append((float(value), cluster_id))
        clusters: dict[Any, list[float]] = defaultdict(list)
        for value, cluster_id in valid_pairs:
            clusters[cluster_id].append(value)
        keys = list(clusters.keys())
        n = len(valid_pairs)
        if not keys:
            return EstimateResult("bootstrap_ci", None, None, None, ci_level, "cluster_bootstrap", 0, missing, notes=["No valid clustered observations."])
        for _ in range(n_boot):
            sample_keys = [rng.choice(keys) for _ in range(len(keys))]
            sample = [v for k in sample_keys for v in clusters[k]]
            st = statistic(sample)
            if not _is_missing(st):
                stats.append(float(st))
        method = "cluster_bootstrap_percentile"
        notes = ["Cluster bootstrap used to account for within-cluster dependence (e.g. files within repositories/projects)."]
        n_eff = len(keys)
        xs = [value for value, _ in valid_pairs]
    else:
        xs, missing = _to_float_list(values)
        n = len(xs)
        if n == 0:
            return EstimateResult("bootstrap_ci", None, None, None, ci_level, "bootstrap", 0, missing, notes=["No valid observations."])
        for _ in range(n_boot):
            sample = [rng.choice(xs) for _ in range(n)]
            st = statistic(sample)
            if not _is_missing(st):
                stats.append(float(st))
        method = "bootstrap_percentile"
        notes = ["Bootstrap over observations; if observations share repositories/projects, provide cluster_ids for cluster bootstrap."]
        n_eff = n
    est = statistic(xs)
    if not stats or est is None or _is_missing(est):
        return EstimateResult("bootstrap_ci", est, None, None, ci_level, method, n, missing, notes=notes + ["Bootstrap failed to produce estimates."])
    stats.sort()
    alpha = (1.0 - ci_level) / 2.0
    lo_idx = max(0, min(len(stats) - 1, int(math.floor(alpha * (len(stats) - 1)))))
    hi_idx = max(0, min(len(stats) - 1, int(math.ceil((1 - alpha) * (len(stats) - 1)))))
    return EstimateResult("bootstrap_ci", est, stats[lo_idx], stats[hi_idx], ci_level, method, n, missing, notes=notes, assumptions=[{"nEffectiveClustersOrUnits": n_eff}])


# --- p-values / tests ---

def _rankdata(values: Sequence[float]) -> list[float]:
    # average ranks for ties, 1-based
    indexed = sorted(enumerate(values), key=lambda x: x[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i + 1
        while j < len(indexed) and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        i = j
    return ranks


def paired_permutation_test(x: Sequence[Any], y: Sequence[Any], *, n_perm: int = 5000, seed: int = 0) -> dict[str, Any]:
    pairs, missing = _aligned_pairs(x, y)
    n = len(pairs)
    if n < 2:
        return {"test": "paired_permutation", "p_value": None, "statistic": None, "n": n, "missing": missing, "reason": "insufficient_paired_observations"}
    diffs = [a - b for a, b in pairs]
    obs = abs(_mean(diffs) or 0.0)
    rng = random.Random(seed)
    count = 0
    for _ in range(n_perm):
        s = 0.0
        for d in diffs:
            s += d if rng.random() < 0.5 else -d
        if abs(s / n) >= obs - 1e-12:
            count += 1
    p = (count + 1) / (n_perm + 1)
    return {"test": "paired_permutation", "p_value": p, "statistic": obs, "n": n, "missing": missing, "nPermutations": n_perm, "method": "sign-flip mean-difference permutation"}


def wilcoxon_signed_rank(x: Sequence[Any], y: Sequence[Any]) -> dict[str, Any]:
    # Normal approximation with tie correction; returns None p-value if too small/degenerate.
    pairs, missing = _aligned_pairs(x, y)
    diffs = [a - b for a, b in pairs if a - b != 0]
    n = len(diffs)
    if n < 1:
        return {"test": "wilcoxon_signed_rank", "p_value": None, "statistic": None, "n": n, "missing": missing, "reason": "no_nonzero_differences"}
    abs_d = [abs(d) for d in diffs]
    ranks = _rankdata(abs_d)
    w_plus = sum(r for r, d in zip(ranks, diffs) if d > 0)
    w_minus = sum(r for r, d in zip(ranks, diffs) if d < 0)
    W = min(w_plus, w_minus)
    mean_w = n * (n + 1) / 4.0
    # tie correction
    from collections import Counter
    tie_counts = Counter(abs_d)
    tie_term = sum(t ** 3 - t for t in tie_counts.values())
    var_w = (n * (n + 1) * (2 * n + 1) - tie_term / 2.0) / 24.0
    if var_w <= 0:
        return {"test": "wilcoxon_signed_rank", "p_value": None, "statistic": W, "n": n, "missing": missing, "reason": "zero_variance"}
    z = (W - mean_w) / math.sqrt(var_w)
    # two-sided normal approx
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return {"test": "wilcoxon_signed_rank", "p_value": max(0.0, min(1.0, p)), "statistic": W, "z": z, "n": n, "missing": missing, "method": "normal_approximation_with_tie_correction"}


def mann_whitney_u(x: Sequence[Any], y: Sequence[Any]) -> dict[str, Any]:
    xs, m1 = _to_float_list(x)
    ys, m2 = _to_float_list(y)
    n1, n2 = len(xs), len(ys)
    if n1 == 0 or n2 == 0:
        return {"test": "mann_whitney_u", "p_value": None, "statistic": None, "n1": n1, "n2": n2, "missing": m1 + m2, "reason": "insufficient_observations"}
    combined = [(v, 0) for v in xs] + [(v, 1) for v in ys]
    combined.sort(key=lambda t: t[0])
    ranks = _rankdata([v for v, _ in combined])
    r1 = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    U = min(u1, u2)
    mean_u = n1 * n2 / 2.0
    # tie correction
    from collections import Counter
    tie_counts = Counter([v for v, _ in combined])
    tie_term = sum(t ** 3 - t for t in tie_counts.values())
    N = n1 + n2
    var_u = (n1 * n2 / 12.0) * ((N + 1) - tie_term / (N * (N - 1))) if N > 1 else 0.0
    if var_u <= 0:
        return {"test": "mann_whitney_u", "p_value": None, "statistic": U, "n1": n1, "n2": n2, "missing": m1 + m2, "reason": "zero_variance"}
    z = (U - mean_u) / math.sqrt(var_u)
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return {"test": "mann_whitney_u", "p_value": max(0.0, min(1.0, p)), "statistic": U, "z": z, "n1": n1, "n2": n2, "missing": m1 + m2, "method": "normal_approximation_with_tie_correction"}


def _betacf(a: float, b: float, x: float) -> float:
    # Continued fraction for incomplete beta (Numerical Recipes style)
    MAXIT, EPS, FPMIN = 200, 3e-12, 1e-30
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return h


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def student_t_cdf(t: float, df: float) -> float:
    if df <= 0:
        return float("nan")
    x = df / (df + t * t)
    ib = regularized_incomplete_beta(df / 2.0, 0.5, x)
    if t >= 0:
        return 1.0 - 0.5 * ib
    return 0.5 * ib


def paired_t_test(x: Sequence[Any], y: Sequence[Any]) -> dict[str, Any]:
    pairs, missing = _aligned_pairs(x, y)
    n = len(pairs)
    if n < 2:
        return {"test": "paired_t", "p_value": None, "statistic": None, "df": None, "n": n, "missing": missing, "reason": "insufficient_paired_observations"}
    diffs = [a - b for a, b in pairs]
    mean_d = _mean(diffs)
    sd = _std(diffs)
    if mean_d is None or sd is None:
        return {"test": "paired_t", "p_value": None, "statistic": None, "df": n - 1, "n": n, "missing": missing, "reason": "undefined"}
    if sd == 0:
        # A constant nonzero difference has an infinite t statistic and a
        # two-sided p-value of 0.  A constant zero difference gives no evidence
        # against the null, but the test is degenerate, so the p-value is left
        # undefined rather than reported as exactly 1.0.
        if mean_d == 0:
            return {"test": "paired_t", "p_value": None, "statistic": None, "df": n - 1, "n": n, "missing": missing, "reason": "zero_variance_no_difference"}
        sign = 1.0 if mean_d > 0 else -1.0
        return {"test": "paired_t", "p_value": 0.0, "statistic": sign * math.inf, "df": n - 1, "mean_diff": mean_d, "n": n, "missing": missing, "method": "student_t_two_sided", "reason": "zero_variance_nonzero_mean"}
    t = mean_d / (sd / math.sqrt(n))
    df = n - 1
    try:
        p = 2.0 * (1.0 - student_t_cdf(abs(t), df))
        p = max(0.0, min(1.0, p))
    except Exception:
        p = None
    return {"test": "paired_t", "p_value": p, "statistic": t, "df": df, "mean_diff": mean_d, "n": n, "missing": missing, "method": "student_t_two_sided"}


def cohens_d_paired(x: Sequence[Any], y: Sequence[Any]) -> dict[str, Any]:
    pairs, missing = _aligned_pairs(x, y)
    diffs = [a - b for a, b in pairs]
    n = len(diffs)
    if n < 2:
        return {"effect": "cohens_d_paired", "value": None, "n": n, "missing": missing, "reason": "insufficient_paired_observations"}
    sd = _std(diffs)
    mean_d = _mean(diffs)
    if sd is None or mean_d is None or sd == 0:
        return {"effect": "cohens_d_paired", "value": None, "n": n, "missing": missing, "reason": "zero_variance"}
    return {"effect": "cohens_d_paired", "value": mean_d / sd, "mean_diff": mean_d, "sd_diff": sd, "n": n, "missing": missing, "interpretation_note": "Magnitude thresholds (e.g. small/medium/large) are context-dependent; interpret practical significance separately from statistical significance."}


def cliffs_delta(x: Sequence[Any], y: Sequence[Any]) -> dict[str, Any]:
    xs, m1 = _to_float_list(x)
    ys, m2 = _to_float_list(y)
    if not xs or not ys:
        return {"effect": "cliffs_delta", "value": None, "n1": len(xs), "n2": len(ys), "missing": m1 + m2, "reason": "insufficient_observations"}
    gt = lt = 0
    for a in xs:
        for b in ys:
            if a > b:
                gt += 1
            elif a < b:
                lt += 1
    delta = (gt - lt) / (len(xs) * len(ys))
    return {"effect": "cliffs_delta", "value": delta, "n1": len(xs), "n2": len(ys), "missing": m1 + m2, "interpretation_note": "Nonparametric effect size in [-1,1]; practical relevance depends on domain context."}


def mean_difference_ci(x: Sequence[Any], y: Sequence[Any], *, ci_level: float = 0.95) -> EstimateResult:
    pairs, missing = _aligned_pairs(x, y)
    diffs = [a - b for a, b in pairs]
    n = len(diffs)
    if n < 2:
        return EstimateResult("mean_difference", _mean(diffs), None, None, ci_level, "t_interval", n, missing, notes=["Insufficient paired observations for CI."])
    m = _mean(diffs)
    s = _std(diffs)
    if m is None or s is None:
        return EstimateResult("mean_difference", m, None, None, ci_level, "t_interval", n, missing)
    # t critical approx via inverse? easier provide bootstrap CI separately; here use normal approx for large n, else note
    if n >= 30:
        # 1.96 for 95%; approximate via inverse error function
        z = 1.959963984540054 if abs(ci_level - 0.95) < 1e-9 else _approx_norm_ppf((1 + ci_level) / 2)
        margin = z * s / math.sqrt(n)
        method = "normal_approx_ci"
    else:
        # conservative normal-ish with wider factor
        z = _approx_norm_ppf((1 + ci_level) / 2)
        margin = z * s / math.sqrt(n)
        method = "normal_approx_ci_small_n_caution"
    return EstimateResult("mean_difference", m, m - margin, m + margin, ci_level, method, n, missing, notes=["For small n or non-normal differences prefer bootstrap CI."])


def _approx_norm_ppf(p: float) -> float:
    # Acklam's approximation
    if p <= 0 or p >= 1:
        return float("nan")
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00]
    plow = 0.02425
    phigh = 1 - plow
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if phigh < p:
        q = math.sqrt(-2 * math.log(1-p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q = p - 0.5
    r = q*q
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


def holm_bonferroni(p_values: Sequence[float | None], alpha: float = 0.05) -> list[dict[str, Any]]:
    indexed = [(i, float(p)) for i, p in enumerate(p_values) if not _is_missing(p)]
    m = len(indexed)
    result: list[dict[str, Any]] = [{"index": i, "p_value": None if _is_missing(p) else float(p), "adjusted_p_value": None, "reject": None} for i, p in enumerate(p_values)]
    if m == 0:
        return result
    indexed.sort(key=lambda x: x[1])
    prev_adj = 0.0
    for rank, (i, p) in enumerate(indexed):
        adj = min(1.0, (m - rank) * p)
        adj = max(adj, prev_adj)
        prev_adj = adj
        result[i]["adjusted_p_value"] = adj
        result[i]["reject"] = adj <= alpha
    return result


def benjamini_hochberg(p_values: Sequence[float | None], alpha: float = 0.05) -> list[dict[str, Any]]:
    indexed = [(i, float(p)) for i, p in enumerate(p_values) if not _is_missing(p)]
    m = len(indexed)
    result: list[dict[str, Any]] = [{"index": i, "p_value": None if _is_missing(p) else float(p), "adjusted_p_value": None, "reject": None} for i, p in enumerate(p_values)]
    if m == 0:
        return result
    indexed.sort(key=lambda x: x[1])
    prev = 1.0
    for rank in range(m, 0, -1):
        i, p = indexed[rank - 1]
        adj = min(prev, (m / rank) * p)
        adj = min(1.0, adj)
        prev = adj
        result[i]["adjusted_p_value"] = adj
    # monotonicity fix upward not needed in this pass; determine reject
    for r in result:
        if r["adjusted_p_value"] is not None:
            r["reject"] = r["adjusted_p_value"] <= alpha
    return result


def apply_multiple_comparison_correction(
    p_values: Sequence[float | None],
    method: str = "holm",
    alpha: float = 0.05,
) -> dict[str, Any]:
    if method == "holm":
        rows = holm_bonferroni(p_values, alpha)
    elif method in {"bh", "fdr_bh", "benjamini_hochberg"}:
        rows = benjamini_hochberg(p_values, alpha)
    else:
        raise ValueError(f"unsupported correction method: {method}")
    return {"method": method, "alpha": alpha, "results": rows}


@dataclass(slots=True)
class PairedComparisonResult:
    metric: str
    n_pairs: int
    missing: int
    mean_a: float | None
    mean_b: float | None
    mean_difference: float | None
    confidence_interval: dict[str, Any]
    bootstrap_confidence_interval: dict[str, Any]
    paired_t_test: dict[str, Any]
    wilcoxon_signed_rank: dict[str, Any]
    permutation_test: dict[str, Any]
    effect_size: dict[str, Any]
    assumptions: list[dict[str, Any]]
    practical_significance_note: str
    statistical_significance_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def paired_comparison(
    values_a: Sequence[Any],
    values_b: Sequence[Any],
    *,
    metric: str = "metric",
    ci_level: float = 0.95,
    n_boot: int = 2000,
    n_perm: int = 5000,
    seed: int = 0,
    cluster_ids: Sequence[Any] | None = None,
    alpha: float = 0.05,
) -> PairedComparisonResult:
    # Differences use the a - b convention throughout.
    pairs, missing = _aligned_pairs(values_a, values_b)
    diffs = [a - b for a, b in pairs]
    n = len(diffs)
    aligned_clusters: list[Any] | None = None
    if cluster_ids is not None:
        if len(cluster_ids) != len(values_a):
            raise ValueError(
                "cluster_ids must align one-to-one with values_a; "
                f"got {len(cluster_ids)} and {len(values_a)}"
            )
        aligned_clusters = [
            cid
            for a, b, cid in zip(values_a, values_b, cluster_ids, strict=True)
            if not (_is_missing(a) or _is_missing(b))
        ]
    xs_a = [a for a, _ in pairs]
    xs_b = [b for _, b in pairs]
    assumptions = [c.to_dict() for c in check_paired_assumptions(diffs)]
    # Direct diff CI via bootstrap (cluster-aware when cluster ids are supplied).
    diff_ci = bootstrap_ci(diffs, ci_level=ci_level, n_boot=n_boot, seed=seed, cluster_ids=aligned_clusters).to_dict()
    if n >= 2:
        m = _mean(diffs)
        s = _std(diffs)
        if m is not None and s is not None:
            z = _approx_norm_ppf((1 + ci_level) / 2)
            ci = {"estimate": m, "ci_low": m - z * s / math.sqrt(n), "ci_high": m + z * s / math.sqrt(n), "ci_level": ci_level, "method": "normal_approx_on_differences", "n": n, "missing": missing}
        else:
            ci = {"estimate": m, "ci_low": None, "ci_high": None, "ci_level": ci_level, "method": "insufficient", "n": n, "missing": missing}
    else:
        ci = {"estimate": _mean(diffs), "ci_low": None, "ci_high": None, "ci_level": ci_level, "method": "insufficient", "n": n, "missing": missing}
    t_res = paired_t_test(xs_a, xs_b)
    w_res = wilcoxon_signed_rank(xs_a, xs_b)
    p_res = paired_permutation_test(xs_a, xs_b, n_perm=n_perm, seed=seed)
    d_res = cohens_d_paired(xs_a, xs_b)
    sig = "insufficient_data"
    if p_res.get("p_value") is not None:
        sig = "statistically_significant" if p_res["p_value"] <= alpha else "not_statistically_significant"
    elif t_res.get("p_value") is not None:
        sig = "statistically_significant" if t_res["p_value"] <= alpha else "not_statistically_significant"
    return PairedComparisonResult(
        metric=metric,
        n_pairs=n,
        missing=missing,
        mean_a=_mean(xs_a),
        mean_b=_mean(xs_b),
        mean_difference=_mean(diffs),
        confidence_interval=ci,
        bootstrap_confidence_interval=diff_ci,
        paired_t_test=t_res,
        wilcoxon_signed_rank=w_res,
        permutation_test=p_res,
        effect_size=d_res,
        assumptions=assumptions,
        practical_significance_note="Assess practical/clinical/engineering significance using effect sizes, confidence intervals, and domain thresholds; do not infer it from p-values alone.",
        statistical_significance_note=f"Primary nonparametric evidence: permutation test (alpha={alpha}); parametric paired t-test reported when computable but interpret in light of assumptions. Result: {sig}.",
    )


__all__ = [
    "AssumptionCheck",
    "EstimateResult",
    "PairedComparisonResult",
    "apply_multiple_comparison_correction",
    "benjamini_hochberg",
    "bootstrap_ci",
    "check_normality",
    "check_paired_assumptions",
    "cliffs_delta",
    "cohens_d_paired",
    "holm_bonferroni",
    "mann_whitney_u",
    "mean_difference_ci",
    "paired_comparison",
    "paired_permutation_test",
    "paired_t_test",
    "wilcoxon_signed_rank",
]
