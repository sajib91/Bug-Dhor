"""Independent numerical references used by the regression suite.

Nothing in this module imports ``craftsec``.  The functions are written from the
stated equations so that a match is evidence about the implementation rather
than a tautology.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterable, Mapping, Sequence

import numpy as np

# --- shared helpers -------------------------------------------------------


def powerset(features: Sequence[int]) -> list[tuple[int, ...]]:
    ordered = sorted(features)
    return [
        combo
        for order in range(len(ordered) + 1)
        for combo in itertools.combinations(ordered, order)
    ]


def sample_variance(values: Sequence[float]) -> float:
    array = np.asarray(values, dtype=np.float64)
    return float(array.var(ddof=1))


def mean(values: Sequence[float]) -> float:
    return float(np.asarray(values, dtype=np.float64).mean())


# --- SAE ------------------------------------------------------------------


def sae_encode(activations: np.ndarray, weight: np.ndarray, bias: np.ndarray) -> np.ndarray:
    return np.maximum(activations @ weight.T + bias, 0.0)


def sae_decode(latents: np.ndarray, weight: np.ndarray, bias: np.ndarray) -> np.ndarray:
    return latents @ weight.T + bias


def sae_loss(
    activations: np.ndarray,
    weight_e: np.ndarray,
    bias_e: np.ndarray,
    weight_d: np.ndarray,
    bias_d: np.ndarray,
    sparsity_coefficient: float,
) -> tuple[float, float, float]:
    latents = sae_encode(activations, weight_e, bias_e)
    reconstruction = sae_decode(latents, weight_d, bias_d)
    reconstruction_error = float(np.mean((reconstruction - activations) ** 2))
    sparsity_penalty = float(np.mean(np.abs(latents)))
    total = reconstruction_error + sparsity_coefficient * sparsity_penalty
    return total, reconstruction_error, sparsity_penalty


def threshold_latents(latents: np.ndarray, threshold: float) -> np.ndarray:
    """Strict absolute threshold, matching ``feature_statistics``."""
    return np.where(np.abs(latents) > threshold, latents, 0.0)


def feature_statistics(latents: np.ndarray, threshold: float) -> tuple[float, np.ndarray, tuple[int, ...]]:
    active = np.abs(latents) > threshold
    utilization = active.mean(axis=0)
    mean_l0 = float(active.sum(axis=1).mean())
    dead = tuple(int(index) for index, value in enumerate(utilization) if value == 0.0)
    return mean_l0, utilization, dead


def relative_reconstruction_error(inputs: np.ndarray, reconstructions: np.ndarray) -> float:
    error = float(np.mean((reconstructions - inputs) ** 2))
    baseline = float(np.mean(inputs**2))
    return error / baseline if baseline > 0 else math.inf


# --- counterfactual contrasts --------------------------------------------


def factorial_contrast(cells: Mapping[tuple[int, ...], float], subset: Sequence[int]) -> float:
    order = len(subset)
    total = 0.0
    for cell in powerset(subset):
        sign = -1.0 if (order - len(cell)) % 2 else 1.0
        total += sign * cells[tuple(sorted(cell))]
    return total


def independent_cell_standard_error(cells: Sequence[Sequence[float]]) -> float:
    total = 0.0
    for outcomes in cells:
        total += sample_variance(outcomes) / len(outcomes)
    return math.sqrt(total)


# --- paired statistics ----------------------------------------------------


def paired_differences(a: Sequence[float], b: Sequence[float]) -> list[float]:
    if len(a) != len(b):
        raise ValueError("paired inputs must have equal length")
    return [float(x) - float(y) for x, y in zip(a, b, strict=True)]


def paired_t(diffs: Sequence[float]) -> tuple[float, int]:
    n = len(diffs)
    if n < 2:
        raise ValueError("two paired observations are required")
    mean_difference = mean(diffs)
    standard_deviation = float(np.asarray(diffs, dtype=np.float64).std(ddof=1))
    if standard_deviation == 0:
        raise ZeroDivisionError("zero variance")
    return mean_difference / (standard_deviation / math.sqrt(n)), n - 1


def paired_t_p_value_df1(t: float) -> float:
    """Exact two-sided p-value for Student t with one degree of freedom."""
    return 1.0 - (2.0 / math.pi) * math.atan(abs(t))


def cohens_d(diffs: Sequence[float]) -> float:
    array = np.asarray(diffs, dtype=np.float64)
    return float(array.mean() / array.std(ddof=1))


def percentile_bootstrap_mean(
    values: Sequence[float],
    *,
    confidence: float = 0.95,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> tuple[float, float, float, float]:
    array = np.asarray(values, dtype=np.float64).reshape(-1)
    estimate = float(array.mean())
    standard_error = float(array.std(ddof=1) / math.sqrt(array.size))
    generator = np.random.default_rng(seed)
    indices = generator.integers(0, array.size, size=(n_boot, array.size))
    means = array[indices].mean(axis=1)
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(means, (alpha, 1.0 - alpha))
    return estimate, standard_error, float(low), float(high)


def sign_consistency(values: Sequence[float]) -> float:
    nonzero = np.asarray(values, dtype=np.float64)
    nonzero = nonzero[nonzero != 0.0]
    if nonzero.size == 0:
        return 1.0
    positive = float(np.mean(nonzero > 0.0))
    return max(positive, 1.0 - positive)


def jackknife_mean_range(values: Sequence[float]) -> tuple[float, float]:
    array = np.asarray(values, dtype=np.float64)
    means = [float(np.delete(array, index).mean()) for index in range(array.size)]
    return min(means), max(means)


def normal_ppf(probability: float) -> float:
    """Inverse standard-normal CDF by bisection on ``math.erf``.

    Deliberately independent of the polynomial approximation used in the
    production module: the reference brackets the quantile and bisects the exact
    error function until it converges.
    """
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must lie in (0, 1)")
    target = 2.0 * probability - 1.0
    low, high = -40.0, 40.0
    for _ in range(200):
        mid = 0.5 * (low + high)
        if math.erf(mid / math.sqrt(2.0)) < target:
            low = mid
        else:
            high = mid
    return 0.5 * (low + high)


def two_sided_normal_p(z: float) -> float:
    """Standard two-sided normal p-value from the definition."""
    return math.erfc(abs(z) / math.sqrt(2.0))


def mann_whitney_counts(
    x: Sequence[float], y: Sequence[float]
) -> tuple[float, float, float, float]:
    """Return ``(U_min, z, p, tie_term)`` from pairwise comparisons.

    ``U1`` is defined directly as the number of ``x_i > y_j`` pairs plus half of
    the ties, which is the combinatorial definition of the rank-sum statistic.
    """
    n1, n2 = len(x), len(y)
    greater = ties = 0
    for a in x:
        for b in y:
            if a > b:
                greater += 1
            elif a == b:
                ties += 1
    u1 = greater + 0.5 * ties
    u2 = n1 * n2 - u1
    u_min = min(u1, u2)
    counts = {}
    for value in list(x) + list(y):
        counts[value] = counts.get(value, 0) + 1
    tie_term = sum(count**3 - count for count in counts.values())
    n = n1 + n2
    variance = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    z = (u_min - n1 * n2 / 2.0) / math.sqrt(variance)
    return u_min, z, two_sided_normal_p(z), tie_term


def cliffs_delta_counts(x: Sequence[float], y: Sequence[float]) -> float:
    greater = sum(1 for a in x for b in y if a > b)
    less = sum(1 for a in x for b in y if a < b)
    return (greater - less) / (len(x) * len(y))


def mean_difference_interval(
    x: Sequence[float], y: Sequence[float], ci_level: float = 0.95
) -> tuple[float, float, float]:
    diffs = paired_differences(x, y)
    mean_difference = mean(diffs)
    standard_deviation = float(np.asarray(diffs, dtype=np.float64).std(ddof=1))
    z = normal_ppf(0.5 + ci_level / 2.0)
    margin = z * standard_deviation / math.sqrt(len(diffs))
    return mean_difference, mean_difference - margin, mean_difference + margin


# --- multiple comparisons -------------------------------------------------


def holm(p_values: Sequence[float | None], alpha: float = 0.05) -> list[float | None]:
    valid = [(index, float(value)) for index, value in enumerate(p_values) if value is not None]
    adjusted: list[float | None] = [None] * len(p_values)
    valid.sort(key=lambda item: item[1])
    m = len(valid)
    running = 0.0
    for rank, (index, value) in enumerate(valid):
        running = max(running, min(1.0, (m - rank) * value))
        adjusted[index] = running
    return adjusted


def benjamini_hochberg(p_values: Sequence[float | None], alpha: float = 0.05) -> list[float | None]:
    valid = [(index, float(value)) for index, value in enumerate(p_values) if value is not None]
    adjusted: list[float | None] = [None] * len(p_values)
    valid.sort(key=lambda item: item[1])
    m = len(valid)
    running = 1.0
    for rank in range(m, 0, -1):
        index, value = valid[rank - 1]
        running = min(running, min(1.0, (m / rank) * value))
        adjusted[index] = running
    return adjusted


# --- steering -------------------------------------------------------------


def decoder_directions(
    decoder_weight: np.ndarray,
    feature_indices: Sequence[int],
    strengths: Sequence[float],
) -> np.ndarray:
    """Rows are ``strength * decoder_column`` in feature order."""
    columns = decoder_weight[:, list(feature_indices)].T
    return columns * np.asarray(strengths, dtype=np.float64)[:, None]


def clamped_delta(
    decoder_weight: np.ndarray,
    feature_indices: Sequence[int],
    strengths: Sequence[float],
    max_norm: float,
) -> np.ndarray:
    delta = decoder_directions(decoder_weight, feature_indices, strengths).sum(axis=0)
    norm = float(np.linalg.norm(delta))
    if norm > max_norm:
        delta = delta * (max_norm / norm)
    return delta


def normalized_columns(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=0, keepdims=True)
    return matrix / np.maximum(norms, 1e-12)


# --- association ----------------------------------------------------------


def association_values(
    activations: Sequence[float],
    vulnerable: Sequence[bool],
    threshold: float,
) -> dict[str, float | None]:
    values = np.asarray(activations, dtype=np.float64)
    labels = np.asarray(vulnerable, dtype=bool)
    active = np.abs(values) > threshold
    active_vulnerable = int(np.sum(active & labels))
    vulnerable_values = values[labels]
    secure_values = values[~labels]
    vulnerable_mean = float(vulnerable_values.mean()) if vulnerable_values.size else None
    secure_mean = float(secure_values.mean()) if secure_values.size else None
    difference = (
        None if vulnerable_mean is None or secure_mean is None else vulnerable_mean - secure_mean
    )
    return {
        "activation_frequency": float(active.mean()),
        "vulnerable_activation_frequency": (
            float(active[labels].mean()) if vulnerable_values.size else None
        ),
        "secure_activation_frequency": (
            float(active[~labels].mean()) if secure_values.size else None
        ),
        "mean_activation_difference": difference,
        "active_precision": (
            active_vulnerable / int(active.sum()) if active.any() else None
        ),
        "active_recall": (
            active_vulnerable / int(labels.sum()) if vulnerable_values.size else None
        ),
    }


def majority_sign_consistency(differences: Iterable[float]) -> float | None:
    signs = [difference > 0 for difference in differences if difference != 0]
    if not signs:
        return None
    positives = sum(signs)
    return max(positives, len(signs) - positives) / len(signs)
