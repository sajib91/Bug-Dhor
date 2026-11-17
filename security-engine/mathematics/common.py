"""Shared numerical, validation, and statistical primitives.

The helpers in this module are deliberately explicit about missing values,
degenerate variances, and extreme logits.  They underpin every mathematical
component in :mod:`mathematics`.

Complexity
----------
All estimators are O(N) or O(N log N) in the number of observations except the
bootstrap helpers, which cost O(B * N), where ``B`` is the number of resamples.
Matrix correlations cost O(N * D^2).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

Array = np.ndarray
FloatArray = np.ndarray

DEFAULT_SEED = 0
_NORMAL_95 = 1.959963984540054


# --------------------------------------------------------------------------- #
# Conversion, shape, and missing-value validation
# --------------------------------------------------------------------------- #
def as_float_array(
    value: Any,
    *,
    name: str = "array",
    copy: bool = False,
) -> FloatArray:
    """Convert an array-like or detached PyTorch tensor to float64.

    PyTorch is optional; if a tensor is supplied it must be detached and on CPU
    (``Tensor.detach().cpu().numpy()``).  No gradient information is retained.
    """
    if value is None:
        raise ValueError(f"{name} must not be None")
    if hasattr(value, "detach"):
        value = value.detach().cpu().numpy()
    try:
        # ``np.asarray`` avoids NumPy 2's strict ``copy=False`` semantics while
        # still allowing an explicit copy when the caller asks for one.
        array = np.asarray(value, dtype=np.float64)
        if copy:
            array = array.copy()
    except (TypeError, ValueError) as error:  # pragma: no cover - defensive
        raise TypeError(f"{name} must be numeric array-like data") from error
    if array.size == 0:
        raise ValueError(f"{name} must not be empty")
    return array


def as_bool_array(value: Any, *, name: str = "mask") -> np.ndarray:
    """Convert a mask-like value to a boolean NumPy array."""
    if hasattr(value, "detach"):
        value = value.detach().cpu().numpy()
    array = np.asarray(value)
    if array.dtype != np.bool_:
        array = array.astype(bool)
    return array


def require_ndim(array: Array, *, name: str, ndim: int | tuple[int, ...]) -> Array:
    """Validate the dimensionality of an array."""
    allowed = (ndim,) if isinstance(ndim, int) else ndim
    if array.ndim not in allowed:
        expected = " or ".join(str(item) for item in allowed)
        raise ValueError(f"{name} must have {expected} dimensions, got {array.ndim}")
    return array


def require_2d(array: Array, *, name: str) -> Array:
    """Validate and return a two-dimensional array."""
    return require_ndim(array, name=name, ndim=2)


def require_same_shape(*arrays: Array, names: Sequence[str] | None = None) -> None:
    """Require identical shapes across arrays."""
    if not arrays:
        return
    reference = arrays[0].shape
    for index, array in enumerate(arrays[1:], start=1):
        if array.shape != reference:
            label = names[index] if names and index < len(names) else f"array {index}"
            raise ValueError(f"{label} must match shape {reference}, got {array.shape}")


def require_same_length(*arrays: Array, names: Sequence[str] | None = None) -> None:
    """Require identical leading dimension across arrays."""
    if not arrays:
        return
    reference = arrays[0].shape[0]
    for index, array in enumerate(arrays[1:], start=1):
        if array.shape[0] != reference:
            label = names[index] if names and index < len(names) else f"array {index}"
            raise ValueError(
                f"{label} must have leading dimension {reference}, got {array.shape[0]}"
            )


def finite_mask(array: Array) -> np.ndarray:
    """Return ``True`` for finite (non-NaN, non-infinite) entries."""
    return np.isfinite(array)


def combine_mask(array: Array, observed: Any | None = None) -> np.ndarray:
    """Combine finite-value detection with an optional explicit mask.

    The returned mask is ``True`` exactly where a value is both finite and
    declared observed.
    """
    mask = finite_mask(array)
    if observed is not None:
        explicit = as_bool_array(observed, name="observed")
        if explicit.shape != array.shape:
            raise ValueError(f"observed mask must have shape {array.shape}, got {explicit.shape}")
        mask &= explicit
    return mask


def drop_missing_rows(array: Array, observed: Any | None = None) -> tuple[Array, np.ndarray]:
    """Drop rows containing a missing entry and return the kept-row index mask."""
    mask = combine_mask(array, observed)
    rows = mask.all(axis=1)
    return array[rows], rows


def require_finite(array: Array, *, name: str) -> Array:
    """Reject arrays containing NaN or infinite values."""
    if not np.isfinite(array).all():
        raise ValueError(f"{name} must contain only finite values")
    return array


# --------------------------------------------------------------------------- #
# Reproducibility
# --------------------------------------------------------------------------- #
def resolve_rng(
    seed: int | None = DEFAULT_SEED,
    rng: np.random.Generator | None = None,
) -> np.random.Generator:
    """Return a reproducible NumPy generator.

    Supplying both ``seed`` and ``rng`` is an error.  A ``None`` seed draws from
    OS entropy and is intentionally non-reproducible.
    """
    if rng is not None and seed is not None:
        raise ValueError("supply either seed or rng, not both")
    if rng is not None:
        return rng
    return np.random.default_rng(seed)


# --------------------------------------------------------------------------- #
# Numerically stable elementary functions
# --------------------------------------------------------------------------- #
def clamp(value: Array | float, lower: float, upper: float) -> FloatArray:
    """Clamp values to ``[lower, upper]``."""
    if lower > upper:
        raise ValueError("lower must not exceed upper")
    return np.clip(value, lower, upper)


def stable_sigmoid(value: Array | float) -> FloatArray:
    """Logistic sigmoid that does not overflow for large ``|value|``.

    ``sigmoid(x) = 1/(1+exp(-x))`` with the positive and negative branches
    evaluated separately.
    """
    x = np.asarray(value, dtype=np.float64)
    output = np.empty_like(x)
    positive = x >= 0
    output[positive] = 1.0 / (1.0 + np.exp(-x[positive]))
    exp_x = np.exp(x[~positive])
    output[~positive] = exp_x / (1.0 + exp_x)
    return output


def stable_logit(probability: Array | float, *, epsilon: float = 1e-12) -> FloatArray:
    """Logit with clipping to avoid infinities at 0 and 1."""
    if epsilon <= 0 or epsilon >= 0.5:
        raise ValueError("epsilon must be in (0, 0.5)")
    p = np.clip(np.asarray(probability, dtype=np.float64), epsilon, 1.0 - epsilon)
    return np.log(p / (1.0 - p))


def validate_probability(
    value: Array | float,
    *,
    name: str = "probability",
    allow_missing: bool = False,
) -> FloatArray:
    """Validate that values lie in ``[0, 1]`` (or are NaN if allowed)."""
    array = np.asarray(value, dtype=np.float64)
    finite = np.isfinite(array)
    if not allow_missing and not finite.all():
        raise ValueError(f"{name} must contain only finite values")
    if finite.any() and ((array[finite] < 0) | (array[finite] > 1)).any():
        raise ValueError(f"{name} must lie in [0, 1]")
    return array


def safe_divide(
    numerator: Array | float,
    denominator: Array | float,
    *,
    fill: float = math.nan,
    epsilon: float = 0.0,
) -> FloatArray:
    """Divide while returning ``fill`` where the denominator is near zero."""
    num = np.asarray(numerator, dtype=np.float64)
    den = np.asarray(denominator, dtype=np.float64)
    output = np.full(np.broadcast(num, den).shape, fill, dtype=np.float64)
    usable = np.abs(den) > epsilon
    np.divide(num, den, out=output, where=usable)
    return output


# --------------------------------------------------------------------------- #
# Basic estimators
# --------------------------------------------------------------------------- #
def mean(values: Sequence[float] | Array, *, observed: Any | None = None) -> float:
    """Arithmetic mean over observed finite values."""
    array = as_float_array(values, name="values")
    mask = combine_mask(array, observed)
    if not mask.any():
        return math.nan
    return float(array[mask].mean())


def sample_variance(
    values: Sequence[float] | Array,
    *,
    observed: Any | None = None,
) -> float:
    """Unbiased sample variance over observed values (NaN if ``n < 2``)."""
    array = as_float_array(values, name="values")
    mask = combine_mask(array, observed)
    selected = array[mask]
    if selected.size < 2:
        return math.nan
    return float(selected.var(ddof=1))


def sample_sd(values: Sequence[float] | Array, *, observed: Any | None = None) -> float:
    """Unbiased sample standard deviation."""
    variance = sample_variance(values, observed=observed)
    return math.sqrt(variance) if math.isfinite(variance) else math.nan


def standard_error(values: Sequence[float] | Array, *, observed: Any | None = None) -> float:
    """Standard error of the mean (NaN if ``n < 2``)."""
    array = as_float_array(values, name="values")
    mask = combine_mask(array, observed)
    count = int(mask.sum())
    if count < 2:
        return math.nan
    return float(array[mask].std(ddof=1) / math.sqrt(count))


def normal_quantile(probability: float) -> float:
    """Inverse standard-normal CDF without SciPy."""
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be in (0, 1)")
    from statistics import NormalDist

    return float(NormalDist().inv_cdf(probability))


def normal_cdf(value: float) -> float:
    """Standard-normal CDF using ``erf`` (no SciPy dependency)."""
    return 0.5 * (1.0 + math.erf(value / math.sqrt(2.0)))


def _betacf(a: float, b: float, x: float, *, max_iterations: int = 300) -> float:
    """Continued fraction for the incomplete beta function (Lentz method)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for iteration in range(1, max_iterations + 1):
        m2 = 2 * iteration
        term = iteration * (b - iteration) * x / ((qam + m2) * (a + m2))
        d = 1.0 + term * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + term / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        term = -(a + iteration) * (qab + iteration) * x / ((a + m2) * (qap + m2))
        d = 1.0 + term * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + term / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-14:
            break
    return h


def incomplete_beta(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function ``I_x(a, b)``."""
    if not 0.0 <= x <= 1.0:
        raise ValueError("x must lie in [0, 1]")
    if x == 0.0:
        return 0.0
    if x == 1.0:
        return 1.0
    log_front = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
    )
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def student_t_sf(value: float, degrees_of_freedom: float) -> float:
    """Upper tail ``P(T > value)`` of Student's t distribution."""
    if degrees_of_freedom <= 0:
        return math.nan
    x = degrees_of_freedom / (degrees_of_freedom + value * value)
    tail = 0.5 * incomplete_beta(degrees_of_freedom / 2.0, 0.5, x)
    return tail if value >= 0 else 1.0 - tail


def student_t_two_sided_p(value: float, degrees_of_freedom: float) -> float:
    """Two-sided p-value for a t statistic."""
    if not math.isfinite(value) or degrees_of_freedom <= 0:
        return math.nan
    tail = student_t_sf(abs(value), degrees_of_freedom)
    return float(min(1.0, 2.0 * tail))


def welch_degrees_of_freedom(
    variance_a: float,
    count_a: int,
    variance_b: float,
    count_b: int,
) -> float:
    """Welch–Satterthwaite degrees of freedom."""
    if count_a < 2 or count_b < 2:
        return math.nan
    numerator = (variance_a / count_a + variance_b / count_b) ** 2
    denominator = (variance_a / count_a) ** 2 / (count_a - 1) + (variance_b / count_b) ** 2 / (
        count_b - 1
    )
    if denominator <= 0:
        return math.nan
    return numerator / denominator


# --------------------------------------------------------------------------- #
# Interval estimation
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class MeanEstimate:
    """Estimated mean with standard error and confidence interval."""

    estimate: float
    standard_error: float
    confidence_low: float
    confidence_high: float
    count: int
    method: str


def bootstrap_ci(
    statistic: Callable[[Array], float],
    values: Array,
    *,
    n_boot: int = 2000,
    confidence: float = 0.95,
    seed: int | None = DEFAULT_SEED,
    rng: np.random.Generator | None = None,
) -> tuple[float, float]:
    """Percentile bootstrap interval for a scalar statistic of 1-D data."""
    data = as_float_array(values, name="values").reshape(-1)
    if data.size < 2:
        return math.nan, math.nan
    if n_boot < 1:
        raise ValueError("n_boot must be positive")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    generator = resolve_rng(seed, rng)
    index = generator.integers(0, data.size, size=(n_boot, data.size))
    samples = data[index]
    with np.errstate(all="ignore"):
        statistics = np.asarray([statistic(row) for row in samples], dtype=np.float64)
    statistics = statistics[np.isfinite(statistics)]
    if statistics.size == 0:
        return math.nan, math.nan
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(statistics, [alpha, 1.0 - alpha])
    return float(low), float(high)


def mean_estimate(
    values: Sequence[float] | Array,
    *,
    observed: Any | None = None,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    rng: np.random.Generator | None = None,
) -> MeanEstimate:
    """Estimate a mean with a normal or percentile-bootstrap interval.

    The normal interval uses Student-t critical values approximated by the
    normal quantile for ``n >= 30`` and by a small-sample t critical value
    lookup for smaller samples.  The bootstrap interval is distribution-free
    but resamples the observed units.
    """
    array = as_float_array(values, name="values")
    mask = combine_mask(array, observed)
    selected = array[mask]
    count = int(selected.size)
    if count == 0:
        return MeanEstimate(math.nan, math.nan, math.nan, math.nan, 0, method)
    estimate = float(selected.mean())
    if count < 2:
        return MeanEstimate(estimate, math.nan, math.nan, math.nan, count, method)
    stderr = float(selected.std(ddof=1) / math.sqrt(count))
    if method == "bootstrap":
        low, high = bootstrap_ci(
            np.mean,
            selected,
            n_boot=n_boot,
            confidence=confidence,
            seed=seed,
            rng=rng,
        )
        return MeanEstimate(estimate, stderr, low, high, count, "percentile_bootstrap")
    if method != "normal":
        raise ValueError("method must be 'normal' or 'bootstrap'")
    critical = _t_critical(count - 1, confidence)
    return MeanEstimate(
        estimate,
        stderr,
        estimate - critical * stderr,
        estimate + critical * stderr,
        count,
        "normal_t",
    )


def paired_mean_estimate(
    differences: Sequence[float] | Array,
    *,
    observed: Any | None = None,
    confidence: float = 0.95,
    method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
    rng: np.random.Generator | None = None,
) -> MeanEstimate:
    """Estimate the mean of paired differences."""
    return mean_estimate(
        differences,
        observed=observed,
        confidence=confidence,
        method=method,
        n_boot=n_boot,
        seed=seed,
        rng=rng,
    )


_T_CRITICAL_975 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    25: 2.060,
    30: 2.042,
}


def _t_critical(degrees_of_freedom: int, confidence: float) -> float:
    """Critical value for a two-sided interval (95% lookup, else normal)."""
    if confidence != 0.95:
        return normal_quantile(0.5 + confidence / 2.0)
    if degrees_of_freedom in _T_CRITICAL_975:
        return _T_CRITICAL_975[degrees_of_freedom]
    if degrees_of_freedom > 30:
        return _NORMAL_95
    # Conservative interpolation between tabulated values.
    keys = sorted(_T_CRITICAL_975)
    lower = max(key for key in keys if key <= degrees_of_freedom)
    upper = min(key for key in keys if key >= degrees_of_freedom)
    if lower == upper:
        return _T_CRITICAL_975[lower]
    weight = (degrees_of_freedom - lower) / (upper - lower)
    return _T_CRITICAL_975[lower] * (1 - weight) + _T_CRITICAL_975[upper] * weight


def t_critical_value(degrees_of_freedom: int, confidence: float = 0.95) -> float:
    """Public two-sided t critical value used by confidence intervals."""
    if degrees_of_freedom < 1:
        raise ValueError("degrees_of_freedom must be positive")
    validate_confidence(confidence)
    return _t_critical(degrees_of_freedom, confidence)


# --------------------------------------------------------------------------- #
# Effect sizes and correlations
# --------------------------------------------------------------------------- #
def pooled_sd(
    values_a: Sequence[float] | Array,
    values_b: Sequence[float] | Array,
) -> float:
    """Pooled standard deviation from Eq. (10).

    ``s_pool = sqrt(((n_a-1) s_a^2 + (n_b-1) s_b^2) / (n_a+n_b-2))``.
    Returns NaN when either group has fewer than two observations or when the
    pooled variance is degenerate.
    """
    a = as_float_array(values_a, name="values_a")
    b = as_float_array(values_b, name="values_b")
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    if a.size < 2 or b.size < 2:
        return math.nan
    variance = ((a.size - 1) * a.var(ddof=1) + (b.size - 1) * b.var(ddof=1)) / (a.size + b.size - 2)
    if variance < 0 or not math.isfinite(variance):
        return math.nan
    return math.sqrt(variance)


def cohens_d(
    values_a: Sequence[float] | Array,
    values_b: Sequence[float] | Array,
) -> float:
    """Standardized mean difference ``(mean(a) - mean(b)) / s_pool``."""
    a = as_float_array(values_a, name="values_a")
    b = as_float_array(values_b, name="values_b")
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    if a.size == 0 or b.size == 0:
        return math.nan
    sd = pooled_sd(a, b)
    if not math.isfinite(sd) or sd == 0.0:
        return math.nan
    return float((a.mean() - b.mean()) / sd)


def hedges_g(
    values_a: Sequence[float] | Array,
    values_b: Sequence[float] | Array,
) -> float:
    """Bias-corrected standardized mean difference (Hedges' g)."""
    a = as_float_array(values_a, name="values_a")
    b = as_float_array(values_b, name="values_b")
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    d = cohens_d(a, b)
    total = a.size + b.size
    if not math.isfinite(d) or total < 4:
        return math.nan
    correction = 1.0 - 3.0 / (4.0 * total - 9.0)
    return float(correction * d)


def cliffs_delta(
    values_a: Sequence[float] | Array,
    values_b: Sequence[float] | Array,
) -> float:
    """Cliff's delta: ``P(a > b) - P(a < b)`` using pairwise comparisons.

    This is a rank-based fallback when the pooled standard deviation is zero.
    Complexity is O(n_a * n_b) in the naive implementation; the vectorized form
    below uses a rank-based identity and costs O((n_a+n_b) log(n_a+n_b)).
    """
    a = as_float_array(values_a, name="values_a")
    b = as_float_array(values_b, name="values_b")
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    if a.size == 0 or b.size == 0:
        return math.nan
    combined = np.concatenate([a, b])
    ranks = _average_ranks(combined)
    rank_a = ranks[: a.size]
    # U statistic / (n_a n_b) is P(a > b) + 0.5 P(a == b).
    u = rank_a.sum() - a.size * (a.size + 1) / 2.0
    delta = 2.0 * u / (a.size * b.size) - 1.0
    return float(np.clip(delta, -1.0, 1.0))


def _average_ranks(values: Array) -> FloatArray:
    """Average ranks with ties handled (SciPy-free ``rankdata``)."""
    order = np.argsort(values, kind="mergesort")
    sorted_values = values[order]
    ranks = np.empty(values.size, dtype=np.float64)
    start = 0
    while start < values.size:
        end = start + 1
        while end < values.size and sorted_values[end] == sorted_values[start]:
            end += 1
        average = (start + end + 1) / 2.0
        ranks[order[start:end]] = average
        start = end
    return ranks


def pearson_correlation(
    x: Sequence[float] | Array,
    y: Sequence[float] | Array,
    *,
    observed: Any | None = None,
) -> float:
    """Pearson correlation (Eq. 11) with pairwise missing-value handling."""
    a = as_float_array(x, name="x")
    b = as_float_array(y, name="y")
    if a.shape != b.shape:
        raise ValueError(f"x and y must have the same shape, got {a.shape} and {b.shape}")
    mask = combine_mask(a, observed) & combine_mask(b, observed)
    a_sel = a[mask]
    b_sel = b[mask]
    if a_sel.size < 2:
        return math.nan
    a_centered = a_sel - a_sel.mean()
    b_centered = b_sel - b_sel.mean()
    denominator = math.sqrt(
        float(np.dot(a_centered, a_centered)) * float(np.dot(b_centered, b_centered))
    )
    if denominator == 0.0 or not math.isfinite(denominator):
        return math.nan
    return float(np.dot(a_centered, b_centered) / denominator)


def spearman_correlation(
    x: Sequence[float] | Array,
    y: Sequence[float] | Array,
    *,
    observed: Any | None = None,
) -> float:
    """Spearman rank correlation with average ranks for ties."""
    a = as_float_array(x, name="x")
    b = as_float_array(y, name="y")
    if a.shape != b.shape:
        raise ValueError(f"x and y must have the same shape, got {a.shape} and {b.shape}")
    mask = combine_mask(a, observed) & combine_mask(b, observed)
    if int(mask.sum()) < 2:
        return math.nan
    return pearson_correlation(_average_ranks(a[mask]), _average_ranks(b[mask]))


def correlation_p_value(r: float, count: int) -> float:
    """Two-sided p-value for a Pearson correlation under the null ``rho=0``."""
    if not math.isfinite(r) or count < 3:
        return math.nan
    if abs(r) >= 1.0:
        return 0.0
    statistic = abs(r) * math.sqrt((count - 2) / (1.0 - r * r))
    return student_t_two_sided_p(statistic, count - 2)


def pearson_correlation_matrix(
    values: Array,
    *,
    observed: Any | None = None,
) -> FloatArray:
    """Pairwise Pearson correlation matrix for columns of ``values``.

    Degenerate (zero-variance or insufficient-overlap) pairs return NaN, which
    propagates explicitly instead of producing a misleading zero.
    """
    matrix = as_float_array(values, name="values")
    require_2d(matrix, name="values")
    width = matrix.shape[1]
    result = np.full((width, width), np.nan, dtype=np.float64)
    for i in range(width):
        result[i, i] = 1.0
        for j in range(i + 1, width):
            pair_mask = None
            if observed is not None:
                pair_mask = combine_mask(matrix[:, i], np.asarray(observed)[:, i]) & combine_mask(
                    matrix[:, j], np.asarray(observed)[:, j]
                )
            correlation = pearson_correlation(matrix[:, i], matrix[:, j], observed=pair_mask)
            result[i, j] = result[j, i] = correlation
    return result


# --------------------------------------------------------------------------- #
# Multiple testing
# --------------------------------------------------------------------------- #
def benjamini_hochberg(p_values: Sequence[float] | Array) -> FloatArray:
    """Benjamini–Hochberg adjusted q-values, ignoring NaN entries.

    NaN p-values remain NaN and are excluded from the correction count.
    """
    p = as_float_array(p_values, name="p_values").reshape(-1)
    if ((p[np.isfinite(p)] < 0) | (p[np.isfinite(p)] > 1)).any():
        raise ValueError("p-values must lie in [0, 1]")
    q = np.full(p.shape, np.nan, dtype=np.float64)
    valid = np.flatnonzero(np.isfinite(p))
    count = valid.size
    if count == 0:
        return q
    ordered = valid[np.argsort(p[valid], kind="mergesort")]
    ranked = p[ordered]
    adjusted = ranked * count / np.arange(1, count + 1)
    adjusted = np.minimum.accumulate(adjusted[::-1])[::-1]
    q[ordered] = np.clip(adjusted, 0.0, 1.0)
    return q


def reject_null(q_values: Sequence[float] | Array, alpha: float = 0.05) -> np.ndarray:
    """Boolean discovery decisions from adjusted q-values."""
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    q = as_float_array(q_values, name="q_values")
    return np.isfinite(q) & (q <= alpha)


# --------------------------------------------------------------------------- #
# Generic validation helpers
# --------------------------------------------------------------------------- #
def validate_labels(labels: Any, *, expected_count: int | None = None) -> np.ndarray:
    """Validate a binary label vector and return it as ``int8``."""
    array = as_float_array(labels, name="labels").reshape(-1)
    if expected_count is not None and array.size != expected_count:
        raise ValueError(f"labels must have length {expected_count}, got {array.size}")
    if not np.isfinite(array).all():
        raise ValueError("labels must not contain missing values")
    if not np.isin(array, (0.0, 1.0)).all():
        raise ValueError("labels must be binary (0/1)")
    return array.astype(np.int8)


def validate_confidence(confidence: float) -> float:
    """Validate and return a confidence level."""
    if not math.isfinite(confidence) or not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    return confidence


def validate_seed(seed: int | None) -> int | None:
    """Validate a random seed."""
    if seed is not None and (not isinstance(seed, int) or isinstance(seed, bool)):
        raise TypeError("seed must be an integer or None")
    return seed


def as_feature_indices(indices: Any, *, feature_count: int) -> np.ndarray:
    """Validate a one-dimensional sequence of distinct feature indices."""
    array = np.asarray(indices)
    if array.ndim != 1:
        raise ValueError("feature indices must be one-dimensional")
    if not np.issubdtype(array.dtype, np.integer):
        raise TypeError("feature indices must be integers")
    array = array.astype(np.int64, copy=False)
    if array.size == 0:
        raise ValueError("at least one feature index is required")
    if (array < 0).any() or (array >= feature_count).any():
        raise ValueError(f"feature indices must lie in [0, {feature_count})")
    if np.unique(array).size != array.size:
        raise ValueError("feature indices must be distinct")
    return array


__all__ = [
    "DEFAULT_SEED",
    "MeanEstimate",
    "as_bool_array",
    "as_feature_indices",
    "as_float_array",
    "benjamini_hochberg",
    "bootstrap_ci",
    "clamp",
    "cliffs_delta",
    "cohens_d",
    "combine_mask",
    "correlation_p_value",
    "drop_missing_rows",
    "finite_mask",
    "hedges_g",
    "incomplete_beta",
    "mean",
    "mean_estimate",
    "normal_cdf",
    "normal_quantile",
    "paired_mean_estimate",
    "pearson_correlation",
    "pearson_correlation_matrix",
    "pooled_sd",
    "reject_null",
    "require_2d",
    "require_finite",
    "require_ndim",
    "require_same_length",
    "require_same_shape",
    "resolve_rng",
    "safe_divide",
    "sample_sd",
    "sample_variance",
    "spearman_correlation",
    "stable_logit",
    "stable_sigmoid",
    "standard_error",
    "student_t_sf",
    "student_t_two_sided_p",
    "t_critical_value",
    "validate_confidence",
    "validate_labels",
    "validate_probability",
    "validate_seed",
    "welch_degrees_of_freedom",
]
