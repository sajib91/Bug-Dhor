"""Multi-source evidence fusion (Eq. 24-27).

Equations
---------
Eq. (24), concatenated evidence::

    e_i = [e_neural ; e_SAE ; e_interaction ; e_AST ; e_CFG ; e_DFG ; e_taint ; e_dynamic]

Eq. (26), masked reliability-weighted mean (implemented directly)::

    S_i = (sum_j m_ij w_j q_ij) / (sum_j m_ij w_j)

Eq. (27), learned logistic fusion head (trained here with ridge-regularized IRLS)::

    P_fusion(y_i = 1) = sigmoid(w_f^T h_fusion + b_f)

Eq. (25) is the learnable fusion representation ``h_fusion = F_phi(e_i, m_i)``.
Its architecture, objective, and calibration are not specified by the paper, so
this module does not invent one.  Callers supply ``h_fusion`` to the logistic
head; the module provides the masked mean (Eq. 26) as the transparent baseline.

Documented alternative
----------------------
The project's detector uses a family-wise noisy-OR heuristic (not Eq. 25-27).
:func:`noisy_or_fusion` reproduces that logic explicitly and labels the output
as a prioritization heuristic, not a probability.

Inputs / outputs
----------------
Evidence matrices are ``[N, J]`` (or ``[J]`` for one unit) over ``J``
modalities.  Availability masks are boolean ``[N, J]``.  Eq. (26) never imputes a
missing modality with zero: it is excluded from both numerator and denominator.

Missing values
--------------
``NaN`` entries are unavailable even when the supplied mask says observed.  A
unit with no available modality receives ``NaN`` (or raises when
``on_missing="error"``).  The logistic head rejects missing features instead of
imputing them.

Numerical stability
-------------------
The sigmoid uses separate positive/negative branches.  IRLS solves a
ridge-regularized weighted least-squares system with a least-squares fallback
when the Hessian is singular.

Complexity
----------
Eq. (26): O(N * J).  Noisy-OR: O(J log J) per unit for the damping order.
Eq. (27): O(N * D) per prediction; O(E * (N * D^2 + D^3)) for ``E`` IRLS
iterations, or O(N * D) per iteration with a linear solve.
"""

from __future__ import annotations

import math
from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import numpy as np

from mathematics.common import (
    as_bool_array,
    as_float_array,
    combine_mask,
    require_2d,
    stable_sigmoid,
    validate_labels,
    validate_probability,
)

Array = np.ndarray


# --------------------------------------------------------------------------- #
# Eq. (24): evidence assembly
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EvidenceMatrix:
    """Column-aligned evidence with an explicit availability mask."""

    names: tuple[str, ...]
    values: Array
    available: Array

    def __post_init__(self) -> None:
        values = np.asarray(self.values, dtype=np.float64)
        available = np.asarray(self.available, dtype=bool)
        require_2d(values, name="values")
        if available.shape != values.shape:
            raise ValueError(f"available must have shape {values.shape}, got {available.shape}")
        if values.size and not np.isfinite(values[available]).all():
            raise ValueError("available evidence entries must be finite")
        if len(self.names) != values.shape[1]:
            raise ValueError("names must have one entry per evidence column")
        if len(set(self.names)) != len(self.names):
            raise ValueError("evidence names must be unique")
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "available", available)

    @property
    def sample_count(self) -> int:
        return int(self.values.shape[0])

    @property
    def modality_count(self) -> int:
        return int(self.values.shape[1])

    def column(self, name: str) -> tuple[Array, Array]:
        """Return one modality's values and availability mask."""
        try:
            index = self.names.index(name)
        except ValueError as error:
            raise KeyError(f"unknown evidence modality {name!r}") from error
        return self.values[:, index], self.available[:, index]


def assemble_evidence_matrix(
    modalities: Mapping[str, Any],
    *,
    availability: Mapping[str, Any] | None = None,
) -> EvidenceMatrix:
    """Assemble Eq. (24) as a column-aligned matrix.

    Every modality must have the same number of units.  ``NaN`` and infinite
    values are marked unavailable; an explicit availability mask can only
    remove availability, never add a value that is not finite.
    """
    if not modalities:
        raise ValueError("at least one evidence modality is required")
    names = tuple(modalities)
    columns: list[Array] = []
    masks: list[Array] = []
    for name in names:
        column = as_float_array(modalities[name], name=name).reshape(-1)
        finite = np.isfinite(column)
        if availability is not None and name in availability:
            explicit = as_bool_array(availability[name], name=f"{name} availability")
            if explicit.shape != column.shape:
                raise ValueError(
                    f"{name} availability must have shape {column.shape}, got {explicit.shape}"
                )
            finite &= explicit
        columns.append(column)
        masks.append(finite)
    lengths = {column.size for column in columns}
    if len(lengths) != 1:
        raise ValueError(
            "all evidence modalities must have the same number of units, got "
            + ", ".join(str(size) for size in (column.size for column in columns))
        )
    values = np.stack(columns, axis=1)
    available = np.stack(masks, axis=1)
    values = np.where(available, values, np.nan)
    return EvidenceMatrix(names=names, values=values, available=available)


# --------------------------------------------------------------------------- #
# Eq. (26): masked reliability-weighted mean
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class MaskedFusion:
    """Output of Eq. (26) with explicit availability accounting."""

    scores: Array
    effective_weight: Array
    available: Array
    missing_count: int
    weights: Array
    interpretation: str = (
        "Reliability-weighted mean of normalized evidence; not a calibrated probability."
    )

    def __post_init__(self) -> None:
        scores = np.asarray(self.scores, dtype=np.float64).reshape(-1)
        effective = np.asarray(self.effective_weight, dtype=np.float64).reshape(-1)
        available = np.asarray(self.available, dtype=bool)
        if available.ndim != 2:
            raise ValueError("available must be two-dimensional")
        if scores.shape != (available.shape[0],) or effective.shape != scores.shape:
            raise ValueError("scores and effective_weight must match the unit count")
        object.__setattr__(self, "scores", scores)
        object.__setattr__(self, "effective_weight", effective)
        object.__setattr__(self, "available", available)


def masked_weighted_fusion(
    evidence: Any,
    weights: Any,
    *,
    availability: Any | None = None,
    on_missing: Literal["nan", "error"] = "nan",
) -> MaskedFusion:
    """Compute Eq. (26) with explicit missing-modality handling.

    ``q_ij`` must lie in ``[0, 1]`` where available.  Weights are finite and
    non-negative.  The denominator is the total weight of available modalities;
    a unit with zero effective weight yields ``NaN`` and is never assigned a
    default score.
    """
    values = as_float_array(evidence, name="evidence")
    if values.ndim == 1:
        values = values.reshape(1, -1)
    require_2d(values, name="evidence")
    weight = as_float_array(weights, name="weights").reshape(-1)
    if weight.size != values.shape[1]:
        raise ValueError(f"weights must have length {values.shape[1]}, got {weight.size}")
    if ((~np.isfinite(weight)) | (weight < 0)).any():
        raise ValueError("weights must be finite and non-negative")
    if not (weight > 0).any():
        raise ValueError("at least one modality weight must be positive")
    if on_missing not in {"nan", "error"}:
        raise ValueError("on_missing must be 'nan' or 'error'")

    mask = combine_mask(values, availability)
    valid_values = values[mask]
    if valid_values.size:
        validate_probability(valid_values, name="available evidence")
    missing = int((~mask).sum())
    if on_missing == "error" and missing:
        raise ValueError("evidence contains unavailable modalities")
    numerator = np.sum(np.where(mask, values, 0.0) * weight, axis=1)
    denominator = np.sum(mask * weight, axis=1)
    scores = np.full(values.shape[0], np.nan, dtype=np.float64)
    usable = denominator > 0
    scores[usable] = numerator[usable] / denominator[usable]
    return MaskedFusion(
        scores=scores,
        effective_weight=denominator,
        available=mask,
        missing_count=missing,
        weights=weight,
    )


# --------------------------------------------------------------------------- #
# Documented noisy-OR alternative
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class NoisyOrFusion:
    """Family-wise noisy-OR heuristic, not Eq. (25)-(27)."""

    score: float
    family_scores: Mapping[Hashable, float]
    refutation_penalty: float
    combined_before_penalty: float
    interpretation: str = (
        "Heuristic prioritization score under an independence assumption; "
        "not a probability and not Eq. (25)-(27)."
    )


def noisy_or_fusion(
    scores: Any,
    *,
    weights: Any | None = None,
    availability: Any | None = None,
    families: Sequence[Hashable] | None = None,
    redundancy_decay: float = 1.0,
    family_caps: Mapping[Hashable, float] | None = None,
    refutation_scores: Any | None = None,
    refutation_scale: float = 1.0,
) -> NoisyOrFusion:
    """Reproduce the project's family-wise noisy-OR heuristic.

    Within a family, entries are sorted by descending effective support and
    damped by ``redundancy_decay**index`` before noisy-OR combination.  Families
    are then combined by noisy-OR.  Refutations reduce the result by
    ``min(0.95, refutation_scale * noisy_or(refutations))``.
    """
    support = as_float_array(scores, name="scores").reshape(-1)
    mask = combine_mask(support, availability)
    if not mask.any():
        raise ValueError("at least one supporting score is required")
    validate_probability(support[mask], name="scores")
    if not math.isfinite(redundancy_decay) or not 0.0 <= redundancy_decay <= 1.0:
        raise ValueError("redundancy_decay must lie in [0, 1]")
    if not math.isfinite(refutation_scale) or refutation_scale < 0:
        raise ValueError("refutation_scale must be finite and non-negative")
    weight = (
        np.ones_like(support)
        if weights is None
        else as_float_array(weights, name="weights").reshape(-1)
    )
    if weight.shape != support.shape:
        raise ValueError(f"weights must have shape {support.shape}, got {weight.shape}")
    if ((~np.isfinite(weight)) | (weight < 0)).any():
        raise ValueError("weights must be finite and non-negative")
    effective = np.clip(support * weight, 0.0, 1.0)
    family_ids = tuple(range(support.size)) if families is None else tuple(families)
    if len(family_ids) != support.size:
        raise ValueError("families must have one entry per score")

    family_scores: dict[Hashable, float] = {}
    by_family: dict[Hashable, list[int]] = {}
    for index, family in enumerate(family_ids):
        if mask[index]:
            by_family.setdefault(family, []).append(index)
    for family, members in by_family.items():
        members.sort(key=lambda index: (-effective[index], index))
        combined = 0.0
        for rank, index in enumerate(members):
            decayed = effective[index] * (redundancy_decay**rank)
            combined = 1.0 - (1.0 - combined) * (1.0 - min(1.0, decayed))
        if family_caps and family in family_caps:
            cap = float(family_caps[family])
            if not math.isfinite(cap) or cap < 0:
                raise ValueError("family caps must be finite and non-negative")
            combined = min(cap, combined)
        family_scores[family] = combined
    combined = _noisy_or(family_scores.values())

    penalty = 0.0
    if refutation_scores is not None:
        refutations = as_float_array(refutation_scores, name="refutation_scores").reshape(-1)
        finite = refutations[np.isfinite(refutations)]
        if finite.size:
            validate_probability(finite, name="refutation_scores")
            penalty = min(0.95, refutation_scale * _noisy_or(finite))
    score = float(np.clip(combined * (1.0 - penalty), 0.0, 1.0))
    return NoisyOrFusion(
        score=score,
        family_scores=dict(family_scores),
        refutation_penalty=float(penalty),
        combined_before_penalty=float(combined),
    )


# --------------------------------------------------------------------------- #
# Eq. (27): logistic fusion head
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class LogisticFusionHead:
    """Trained logistic head ``sigmoid(w_f^T h + b_f)`` (Eq. 27)."""

    weights: Array
    bias: float
    n_iterations: int = 0
    converged: bool = False
    l2: float = 0.0
    final_loss: float = math.nan

    def __post_init__(self) -> None:
        weights = as_float_array(self.weights, name="weights").reshape(-1)
        if not np.isfinite(weights).all():
            raise ValueError("weights must be finite")
        if not math.isfinite(self.bias):
            raise ValueError("bias must be finite")
        object.__setattr__(self, "weights", weights)
        object.__setattr__(self, "bias", float(self.bias))

    @property
    def feature_count(self) -> int:
        return int(self.weights.size)

    def decision_function(self, fused: Any) -> Array:
        """Return ``w_f^T h + b_f`` for one or more fused representations."""
        features = _promote_features(fused, width=self.feature_count)
        return features @ self.weights + self.bias

    def predict_proba(self, fused: Any) -> Array:
        """Return Eq. (27) as a probability for each unit."""
        return stable_sigmoid(self.decision_function(fused))

    def predict(self, fused: Any, *, threshold: float = 0.5) -> Array:
        """Return binary decisions at ``threshold``."""
        if not 0.0 < threshold < 1.0:
            raise ValueError("threshold must be in (0, 1)")
        return self.predict_proba(fused) >= threshold

    def binary_cross_entropy(self, fused: Any, labels: Any) -> float:
        """Mean binary cross-entropy without clamping a label."""
        y = validate_labels(labels, expected_count=_unit_count(fused))
        p = np.clip(self.predict_proba(fused), 1e-15, 1.0 - 1e-15)
        return float(-np.mean(y * np.log(p) + (1 - y) * np.log1p(-p)))

    def brier_score(self, fused: Any, labels: Any) -> float:
        """Mean squared probability error."""
        y = validate_labels(labels, expected_count=_unit_count(fused))
        p = self.predict_proba(fused)
        return float(np.mean((p - y) ** 2))


def fit_logistic_fusion_head(
    fused: Any,
    labels: Any,
    *,
    l2: float = 1e-6,
    max_iterations: int = 100,
    tolerance: float = 1e-8,
) -> LogisticFusionHead:
    """Train Eq. (27) with ridge-regularized IRLS (deterministic, no seed).

    The intercept is not regularized.  If the weighted Hessian is singular, a
    least-squares solve is used and the result is still validated.  Perfectly
    separable data can produce large weights; ``l2`` stabilizes the fit and
    ``max_iterations`` bounds the run.
    """
    features = _promote_features(fused, width=None)
    y = validate_labels(labels, expected_count=features.shape[0]).astype(np.float64)
    if not math.isfinite(l2) or l2 < 0:
        raise ValueError("l2 must be finite and non-negative")
    if max_iterations < 1:
        raise ValueError("max_iterations must be positive")
    if not math.isfinite(tolerance) or tolerance <= 0:
        raise ValueError("tolerance must be positive")

    design = np.column_stack([np.ones(features.shape[0]), features])
    coefficients = np.zeros(design.shape[1], dtype=np.float64)
    penalty = np.full(design.shape[1], l2, dtype=np.float64)
    penalty[0] = 0.0
    converged = False
    iterations = 0
    loss = math.nan
    for iteration in range(1, max_iterations + 1):
        iterations = iteration
        linear = design @ coefficients
        probability = stable_sigmoid(linear)
        loss = _bce(probability, y)
        gradient = design.T @ (probability - y) / design.shape[0] + penalty * coefficients
        variance = np.maximum(probability * (1.0 - probability), 1e-12)
        hessian = (design.T * variance) @ design / design.shape[0] + np.diag(penalty)
        hessian += np.eye(hessian.shape[0]) * 1e-12
        try:
            step = np.linalg.solve(hessian, gradient)
        except np.linalg.LinAlgError:  # pragma: no cover - regularized guard
            step = np.linalg.lstsq(hessian, gradient, rcond=None)[0]
        if not np.isfinite(step).all():
            step = np.linalg.lstsq(hessian, gradient, rcond=None)[0]
        coefficients -= step
        if float(np.linalg.norm(step)) <= tolerance:
            converged = True
            break
    return LogisticFusionHead(
        weights=coefficients[1:],
        bias=float(coefficients[0]),
        n_iterations=iterations,
        converged=converged,
        l2=float(l2),
        final_loss=float(loss),
    )


def _promote_features(fused: Any, *, width: int | None) -> Array:
    features = as_float_array(fused, name="fused").astype(np.float64, copy=False)
    if features.ndim == 1:
        features = features.reshape(1, -1)
    require_2d(features, name="fused")
    if width is not None and features.shape[1] != width:
        raise ValueError(f"fused must have width {width}, got {features.shape[1]}")
    if not np.isfinite(features).all():
        raise ValueError("fused representation must be finite; impute explicitly first")
    return features


def _unit_count(fused: Any) -> int:
    array = np.asarray(fused)
    return 1 if array.ndim == 1 else int(array.shape[0])


def _bce(probability: Array, labels: Array) -> float:
    p = np.clip(probability, 1e-15, 1.0 - 1e-15)
    return float(-np.mean(labels * np.log(p) + (1.0 - labels) * np.log1p(-p)))


def _noisy_or(values: Sequence[float] | Any) -> float:
    product = 1.0
    for value in values:
        product *= 1.0 - max(0.0, min(1.0, float(value)))
    return 1.0 - product


__all__ = [
    "EvidenceMatrix",
    "LogisticFusionHead",
    "MaskedFusion",
    "NoisyOrFusion",
    "assemble_evidence_matrix",
    "fit_logistic_fusion_head",
    "masked_weighted_fusion",
    "noisy_or_fusion",
]
