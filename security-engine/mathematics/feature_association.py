"""Feature association statistics (Eq. 9-11).

Equations
---------
Eq. (9):  ``Delta mu_j = E[z_j | y=1] - E[z_j | y=0]``
Eq. (10): ``d_j = (mu_j1 - mu_j0) / s_pool`` with

          ``s_pool = sqrt(((n1-1)s1^2 + (n0-1)s0^2) / (n1+n0-2))``

Eq. (11): ``rho_ij = Cov(z_i, z_j) / (sigma_i sigma_j)``

Audit additions (explicitly labelled, not paper equations): Hedges' g bias
correction, Welch standard error, confidence intervals, Cliff's delta fallback
for degenerate pooled variance, Benjamini-Hochberg q-values, and a permutation
null.

Inputs
------
``latents`` : matrix ``[N, d_s]`` of measured feature activations.
``labels`` : binary vector ``[N]`` (1 = vulnerable, 0 = secure).
``observed`` : optional boolean matrix ``[N, d_s]``.
``sample_mask`` : optional boolean vector ``[N]``.

Outputs
-------
:class:`FeatureAssociationResult` with one row per feature.

Missing values
--------------
A feature with a missing observation for a sample is excluded from that
feature's two-group statistics.  A group with no observations yields NaN for
the estimand that requires it.  Missing labels are rejected, not imputed.

Numerical stability
-------------------
* Pooled variance ``<= 0`` gives NaN for Cohen's d and activates the Cliff's
  delta fallback instead of dividing by zero.
* Welch degrees of freedom use the standard Satterthwaite formula.
* BH correction ignores NaN p-values and never turns them into discoveries.

Complexity
----------
Association statistics: O(N * F).  BH: O(F log F).  Bootstrap CI:
O(B * N * F).  Pairwise correlation matrix: O(N * F^2).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import (
    DEFAULT_SEED,
    as_float_array,
    benjamini_hochberg,
    cliffs_delta,
    cohens_d,
    hedges_g,
    pearson_correlation_matrix,
    pooled_sd,
    resolve_rng,
    spearman_correlation,
    student_t_two_sided_p,
    t_critical_value,
    validate_confidence,
    validate_labels,
    welch_degrees_of_freedom,
)

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class FeatureAssociationResult:
    """Association estimates for every selected feature."""

    feature_indices: Array
    mean_vulnerable: Array
    mean_secure: Array
    mean_difference: Array
    pooled_standard_deviation: Array
    cohens_d: Array
    hedges_g: Array
    cliffs_delta: Array
    standard_error: Array
    confidence_low: Array
    confidence_high: Array
    p_value: Array
    q_value: Array
    activation_frequency_vulnerable: Array
    activation_frequency_secure: Array
    activation_frequency_difference: Array
    count_vulnerable: Array
    count_secure: Array
    threshold: float
    confidence: float
    correction: str
    ci_method: str

    def to_records(self) -> tuple[dict[str, float | int | str | None], ...]:
        """Return JSON-serializable per-feature records."""
        records: list[dict[str, float | int | str | None]] = []
        for index, feature in enumerate(self.feature_indices):
            record: dict[str, float | int | str | None] = {
                "feature_index": int(feature),
                "mean_vulnerable": _float_or_none(self.mean_vulnerable[index]),
                "mean_secure": _float_or_none(self.mean_secure[index]),
                "mean_difference": _float_or_none(self.mean_difference[index]),
                "pooled_standard_deviation": _float_or_none(self.pooled_standard_deviation[index]),
                "cohens_d": _float_or_none(self.cohens_d[index]),
                "hedges_g": _float_or_none(self.hedges_g[index]),
                "cliffs_delta": _float_or_none(self.cliffs_delta[index]),
                "standard_error": _float_or_none(self.standard_error[index]),
                "confidence_low": _float_or_none(self.confidence_low[index]),
                "confidence_high": _float_or_none(self.confidence_high[index]),
                "p_value": _float_or_none(self.p_value[index]),
                "q_value": _float_or_none(self.q_value[index]),
                "activation_frequency_vulnerable": _float_or_none(
                    self.activation_frequency_vulnerable[index]
                ),
                "activation_frequency_secure": _float_or_none(
                    self.activation_frequency_secure[index]
                ),
                "activation_frequency_difference": _float_or_none(
                    self.activation_frequency_difference[index]
                ),
                "count_vulnerable": int(self.count_vulnerable[index]),
                "count_secure": int(self.count_secure[index]),
                "threshold": self.threshold,
                "confidence": self.confidence,
                "correction": self.correction,
                "ci_method": self.ci_method,
            }
            records.append(record)
        return tuple(records)

    def significant(self, alpha: float = 0.05) -> Array:
        """Boolean mask of features with ``q_value <= alpha``."""
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        return np.isfinite(self.q_value) & (self.q_value <= alpha)


def analyze_feature_associations(
    latents: Any,
    labels: Any,
    *,
    observed: Any | None = None,
    sample_mask: Any | None = None,
    threshold: float = 0.0,
    confidence: float = 0.95,
    correction: str = "bh",
    ci_method: str = "normal",
    n_boot: int = 2000,
    seed: int | None = DEFAULT_SEED,
) -> FeatureAssociationResult:
    """Compute Eq. (9)-(10) plus documented uncertainty for every feature."""
    z = as_float_array(latents, name="latents")
    if z.ndim != 2:
        raise ValueError(f"latents must be two-dimensional, got {z.ndim}")
    y = validate_labels(labels, expected_count=z.shape[0])
    validate_confidence(confidence)
    if not math.isfinite(threshold) or threshold < 0:
        raise ValueError("threshold must be finite and non-negative")
    if correction not in {"bh", "none"}:
        raise ValueError("correction must be 'bh' or 'none'")
    if ci_method not in {"normal", "bootstrap"}:
        raise ValueError("ci_method must be 'normal' or 'bootstrap'")
    if n_boot < 1:
        raise ValueError("n_boot must be positive")

    feature_count = z.shape[1]
    finite = np.isfinite(z)
    if observed is not None:
        explicit = np.asarray(observed, dtype=bool)
        if explicit.shape != z.shape:
            raise ValueError(f"observed mask must have shape {z.shape}, got {explicit.shape}")
        finite &= explicit
    if sample_mask is not None:
        keep = np.asarray(sample_mask, dtype=bool)
        if keep.shape != (z.shape[0],):
            raise ValueError(f"sample_mask must have shape {(z.shape[0],)}, got {keep.shape}")
        finite &= keep[:, None]
    rng = resolve_rng(seed) if ci_method == "bootstrap" else None

    output = {
        "mean_vulnerable": np.full(feature_count, np.nan),
        "mean_secure": np.full(feature_count, np.nan),
        "mean_difference": np.full(feature_count, np.nan),
        "pooled_standard_deviation": np.full(feature_count, np.nan),
        "cohens_d": np.full(feature_count, np.nan),
        "hedges_g": np.full(feature_count, np.nan),
        "cliffs_delta": np.full(feature_count, np.nan),
        "standard_error": np.full(feature_count, np.nan),
        "confidence_low": np.full(feature_count, np.nan),
        "confidence_high": np.full(feature_count, np.nan),
        "p_value": np.full(feature_count, np.nan),
        "activation_frequency_vulnerable": np.full(feature_count, np.nan),
        "activation_frequency_secure": np.full(feature_count, np.nan),
        "activation_frequency_difference": np.full(feature_count, np.nan),
        "count_vulnerable": np.zeros(feature_count, dtype=np.int64),
        "count_secure": np.zeros(feature_count, dtype=np.int64),
    }

    for feature in range(feature_count):
        valid = finite[:, feature]
        vulnerable = z[valid & (y == 1), feature]
        secure = z[valid & (y == 0), feature]
        output["count_vulnerable"][feature] = vulnerable.size
        output["count_secure"][feature] = secure.size
        if vulnerable.size:
            output["mean_vulnerable"][feature] = vulnerable.mean()
            output["activation_frequency_vulnerable"][feature] = float(
                np.mean(np.abs(vulnerable) > threshold)
            )
        if secure.size:
            output["mean_secure"][feature] = secure.mean()
            output["activation_frequency_secure"][feature] = float(
                np.mean(np.abs(secure) > threshold)
            )
        if vulnerable.size and secure.size:
            difference = float(vulnerable.mean() - secure.mean())
            output["mean_difference"][feature] = difference
            output["activation_frequency_difference"][feature] = float(
                output["activation_frequency_vulnerable"][feature]
                - output["activation_frequency_secure"][feature]
            )
            pooled = pooled_sd(vulnerable, secure)
            output["pooled_standard_deviation"][feature] = pooled
            output["cohens_d"][feature] = cohens_d(vulnerable, secure)
            output["hedges_g"][feature] = hedges_g(vulnerable, secure)
            output["cliffs_delta"][feature] = cliffs_delta(vulnerable, secure)
            if vulnerable.size >= 2 and secure.size >= 2:
                variance_v = float(vulnerable.var(ddof=1))
                variance_s = float(secure.var(ddof=1))
                standard_error = math.sqrt(variance_v / vulnerable.size + variance_s / secure.size)
                output["standard_error"][feature] = standard_error
                degrees = welch_degrees_of_freedom(
                    variance_v, vulnerable.size, variance_s, secure.size
                )
                if standard_error > 0 and math.isfinite(degrees):
                    statistic = difference / standard_error
                    output["p_value"][feature] = student_t_two_sided_p(statistic, degrees)
                if ci_method == "normal" and standard_error > 0 and math.isfinite(degrees):
                    critical = t_critical_value(int(max(1, round(degrees))), confidence)
                    output["confidence_low"][feature] = difference - critical * standard_error
                    output["confidence_high"][feature] = difference + critical * standard_error

    if ci_method == "bootstrap":
        low, high = _bootstrap_difference_intervals(
            z,
            y,
            finite,
            n_boot=n_boot,
            confidence=confidence,
            rng=rng,
        )
        output["confidence_low"] = low
        output["confidence_high"] = high

    q_values = benjamini_hochberg(output["p_value"]) if correction == "bh" else output["p_value"]
    return FeatureAssociationResult(
        feature_indices=np.arange(feature_count, dtype=np.int64),
        mean_vulnerable=output["mean_vulnerable"],
        mean_secure=output["mean_secure"],
        mean_difference=output["mean_difference"],
        pooled_standard_deviation=output["pooled_standard_deviation"],
        cohens_d=output["cohens_d"],
        hedges_g=output["hedges_g"],
        cliffs_delta=output["cliffs_delta"],
        standard_error=output["standard_error"],
        confidence_low=output["confidence_low"],
        confidence_high=output["confidence_high"],
        p_value=output["p_value"],
        q_value=q_values,
        activation_frequency_vulnerable=output["activation_frequency_vulnerable"],
        activation_frequency_secure=output["activation_frequency_secure"],
        activation_frequency_difference=output["activation_frequency_difference"],
        count_vulnerable=output["count_vulnerable"],
        count_secure=output["count_secure"],
        threshold=threshold,
        confidence=confidence,
        correction=correction,
        ci_method=ci_method,
    )


def _bootstrap_difference_intervals(
    z: Array,
    labels: Array,
    finite: Array,
    *,
    n_boot: int,
    confidence: float,
    rng: np.random.Generator | None,
) -> tuple[Array, Array]:
    """Percentile bootstrap of the two-group mean difference per feature."""
    if rng is None:  # pragma: no cover - guarded by caller
        raise ValueError("bootstrap requires a random generator")
    feature_count = z.shape[1]
    low = np.full(feature_count, np.nan)
    high = np.full(feature_count, np.nan)
    alpha = (1.0 - confidence) / 2.0
    for feature in range(feature_count):
        valid = finite[:, feature]
        vulnerable = z[valid & (labels == 1), feature]
        secure = z[valid & (labels == 0), feature]
        if vulnerable.size < 2 or secure.size < 2:
            continue
        index_v = rng.integers(0, vulnerable.size, size=(n_boot, vulnerable.size))
        index_s = rng.integers(0, secure.size, size=(n_boot, secure.size))
        differences = vulnerable[index_v].mean(axis=1) - secure[index_s].mean(axis=1)
        low[feature] = np.quantile(differences, alpha)
        high[feature] = np.quantile(differences, 1.0 - alpha)
    return low, high


def feature_correlation_matrix(
    latents: Any,
    *,
    observed: Any | None = None,
    method: str = "pearson",
) -> Array:
    """Compute Eq. (11) for every feature pair.

    ``method="spearman"`` is a documented robustness alternative for
    zero-inflated features; it is not Eq. (11) itself.
    """
    z = as_float_array(latents, name="latents")
    if z.ndim != 2:
        raise ValueError(f"latents must be two-dimensional, got {z.ndim}")
    if method == "pearson":
        return pearson_correlation_matrix(z, observed=observed)
    if method == "spearman":
        return _spearman_matrix(z, observed=observed)
    raise ValueError("method must be 'pearson' or 'spearman'")


def _spearman_matrix(values: Array, *, observed: Any | None = None) -> Array:
    width = values.shape[1]
    result = np.full((width, width), np.nan)
    for i in range(width):
        result[i, i] = 1.0
        for j in range(i + 1, width):
            mask = None
            if observed is not None:
                explicit = np.asarray(observed, dtype=bool)
                mask = explicit[:, i] & explicit[:, j]
            rho = spearman_correlation(values[:, i], values[:, j], observed=mask)
            result[i, j] = result[j, i] = rho
    return result


def correlation_p_values(
    correlations: Array,
    *,
    sample_count: int | Array,
    correction: str = "bh",
) -> tuple[Array, Array]:
    """Return pairwise p-values and adjusted q-values from a correlation matrix.

    ``sample_count`` is the number of paired observations used for each column.
    When it is a vector, the smaller of the two counts is used for a pair; this
    is conservative when pairwise overlap is unknown.
    """
    rho = as_float_array(correlations, name="correlations")
    if rho.ndim != 2 or rho.shape[0] != rho.shape[1]:
        raise ValueError("correlations must be a square matrix")
    if correction not in {"bh", "none"}:
        raise ValueError("correction must be 'bh' or 'none'")
    width = rho.shape[0]
    counts = np.asarray(sample_count, dtype=np.int64)
    if counts.ndim == 0:
        counts = np.full(width, int(counts), dtype=np.int64)
    if counts.shape != (width,):
        raise ValueError(f"sample_count must be a scalar or shape {(width,)}")
    if (counts < 0).any():
        raise ValueError("sample_count must be non-negative")
    p_values = np.full((width, width), np.nan)
    for i in range(width):
        for j in range(i + 1, width):
            count = int(min(counts[i], counts[j]))
            r = rho[i, j]
            if not math.isfinite(r) or count < 3:
                continue
            if abs(r) >= 1.0:
                p = 0.0
            else:
                statistic = abs(r) * math.sqrt((count - 2) / (1.0 - r * r))
                p = student_t_two_sided_p(statistic, count - 2)
            p_values[i, j] = p_values[j, i] = p
    q_values = np.full_like(p_values, np.nan)
    upper = p_values[np.triu_indices(width, k=1)]
    if correction == "bh":
        q_values[np.triu_indices(width, k=1)] = benjamini_hochberg(upper)
        q_values = np.where(np.isnan(q_values), q_values.T, q_values)
    else:
        q_values = p_values
    return p_values, q_values


def permutation_association_test(
    values: Any,
    labels: Any,
    *,
    n_permutations: int = 2000,
    seed: int | None = DEFAULT_SEED,
    observed: Any | None = None,
) -> dict[str, float | int]:
    """Two-sided permutation test for the Eq. (9) mean difference.

    The null distribution is generated by permuting labels.  The p-value uses
    the finite-sample correction ``(1 + #{|stat| >= |observed|}) / (1 + B)``.
    """
    x = as_float_array(values, name="values").reshape(-1)
    y = validate_labels(labels, expected_count=x.size)
    if observed is not None:
        mask = np.asarray(observed, dtype=bool).reshape(-1)
        if mask.shape != x.shape:
            raise ValueError("observed mask must match values shape")
        x = x[mask]
        y = y[mask]
    if not np.isfinite(x).all():
        raise ValueError("values must be finite after applying observed mask")
    if n_permutations < 1:
        raise ValueError("n_permutations must be positive")
    rng = resolve_rng(seed)
    estimate = _difference(x, y)
    if not math.isfinite(estimate):
        raise ValueError("both label groups need at least one observation")
    null = np.empty(n_permutations)
    for index in range(n_permutations):
        permuted = rng.permutation(y)
        null[index] = _difference(x, permuted)
    exceedances = int(np.sum(np.abs(null) >= abs(estimate)))
    p_value = (1 + exceedances) / (1 + n_permutations)
    return {
        "observed_difference": float(estimate),
        "p_value": float(p_value),
        "n_permutations": int(n_permutations),
        "null_mean": float(null.mean()),
        "null_standard_deviation": float(null.std(ddof=1)) if n_permutations > 1 else math.nan,
    }


def _difference(values: Array, labels: Array) -> float:
    vulnerable = values[labels == 1]
    secure = values[labels == 0]
    if vulnerable.size == 0 or secure.size == 0:
        return math.nan
    return float(vulnerable.mean() - secure.mean())


def _float_or_none(value: float) -> float | None:
    return float(value) if math.isfinite(float(value)) else None


__all__ = [
    "FeatureAssociationResult",
    "analyze_feature_associations",
    "correlation_p_values",
    "feature_correlation_matrix",
    "permutation_association_test",
]
