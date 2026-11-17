"""CWE-specific security risk index and priority bands (Eq. 28-29).

Equations
---------
Eq. (28)::

    R_index(v) = alpha P(v) + beta S(v) + gamma E(v) + delta I(v)

Eq. (29)::

    C(v) = Critical  if R_index(v) >= tau_3
           High      if tau_2 <= R_index(v) < tau_3
           Medium    if tau_1 <= R_index(v) < tau_2
           Low       if R_index(v) < tau_1

Inputs
------
``P`` calibrated probability that the finding is a vulnerability, ``S``
normalized severity, ``E`` normalized exposure/exploitability, and ``I``
normalized impact.  All available components lie in ``[0, 1]``.  Weights are
finite, non-negative, and are normalized to sum to one by default so that
``R_index`` remains in ``[0, 1]`` and the thresholds are meaningful.

Outputs
-------
:class:`RiskAssessment` with the index, band, per-component contributions, the
normalized weights actually used, and an explicit statement that the index is
not a probability.

Missing values
--------------
Missing components are represented as ``NaN``.  The policy chooses one of three
documented behaviours:

``"nan"`` (default)
    Return ``score=NaN`` and band ``"Unknown"``.  No component is imputed.
``"error"``
    Raise ``ValueError``.  Use this when the policy requires complete evidence.
``"renormalize"``
    Re-normalize the weights over the available components.  This is an
    explicit extension, not Eq. (28) as written, and is reported in the result.

``P`` is assumed calibrated by the caller.  This module performs no
calibration and never calls ``R_index`` a probability.

Complexity
----------
O(1) time and memory per finding; O(K) for a registry of ``K`` CWE policies.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal

from mathematics.common import validate_probability

MissingPolicy = Literal["nan", "error", "renormalize"]

_BAND_NAMES = ("Low", "Medium", "High", "Critical")


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Non-negative weights for the four risk components (Eq. 28)."""

    alpha: float = 0.40
    beta: float = 0.20
    gamma: float = 0.20
    delta: float = 0.20
    normalize: bool = True

    def __post_init__(self) -> None:
        values = (self.alpha, self.beta, self.gamma, self.delta)
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("risk weights must be finite and non-negative")
        if sum(values) <= 0:
            raise ValueError("at least one risk weight must be positive")

    def normalized(self) -> tuple[float, float, float, float]:
        """Return the weights used by Eq. (28)."""
        values = (self.alpha, self.beta, self.gamma, self.delta)
        if not self.normalize:
            return values  # type: ignore[return-value]
        total = sum(values)
        return tuple(value / total for value in values)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    """Ordered priority thresholds ``tau_1 < tau_2 < tau_3`` (Eq. 29)."""

    low: float = 0.25
    medium: float = 0.50
    high: float = 0.75

    def __post_init__(self) -> None:
        values = (self.low, self.medium, self.high)
        if any(not math.isfinite(value) or not 0.0 < value <= 1.0 for value in values):
            raise ValueError("thresholds must be finite and lie in (0, 1]")
        if not self.low < self.medium < self.high:
            raise ValueError("thresholds must satisfy tau_1 < tau_2 < tau_3")

    @property
    def ordered(self) -> tuple[float, float, float]:
        return (self.low, self.medium, self.high)


@dataclass(frozen=True, slots=True)
class RiskComponents:
    """Measured components for one CWE-specific finding (Eq. 28)."""

    probability: float
    severity: float
    exposure: float
    impact: float

    def __post_init__(self) -> None:
        values = (self.probability, self.severity, self.exposure, self.impact)
        if any(math.isfinite(value) for value in values):
            finite = [value for value in values if math.isfinite(value)]
            validate_probability(finite, name="risk components", allow_missing=True)
        for value in values:
            if math.isinf(value):
                raise ValueError("risk components must be finite or NaN, not infinite")

    def as_tuple(self) -> tuple[float, float, float, float]:
        return (self.probability, self.severity, self.exposure, self.impact)

    def available(self) -> tuple[bool, bool, bool, bool]:
        return tuple(math.isfinite(value) for value in self.as_tuple())  # type: ignore[return-value]

    def missing_count(self) -> int:
        return sum(not math.isfinite(value) for value in self.as_tuple())


@dataclass(frozen=True, slots=True)
class CweRiskPolicy:
    """Weights, thresholds, and missing-value policy for one CWE."""

    cwe: str
    weights: RiskWeights = RiskWeights()
    thresholds: RiskThresholds = RiskThresholds()
    missing_policy: MissingPolicy = "nan"
    require_calibrated_probability: bool = False

    def __post_init__(self) -> None:
        if not self.cwe.strip():
            raise ValueError("CWE policy requires a non-empty category")
        if self.missing_policy not in {"nan", "error", "renormalize"}:
            raise ValueError("missing_policy must be 'nan', 'error', or 'renormalize'")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Result of Eq. (28)-(29) for one finding."""

    cwe: str
    score: float
    band: str
    components: RiskComponents
    contributions: Mapping[str, float]
    weights_used: Mapping[str, float]
    available_components: Mapping[str, bool]
    missing_policy: str
    policy: CweRiskPolicy
    interpretation: str = (
        "Linear prioritization index, not a probability. P must be calibrated externally."
    )

    @property
    def is_probability(self) -> bool:
        return False

    @property
    def missing_count(self) -> int:
        return int(self.components.missing_count())

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable record."""
        return {
            "cwe": self.cwe,
            "score": _optional(self.score),
            "band": self.band,
            "components": {
                name: _optional(value)
                for name, value in zip(
                    ("probability", "severity", "exposure", "impact"),
                    self.components.as_tuple(),
                    strict=True,
                )
            },
            "contributions": {name: _optional(value) for name, value in self.contributions.items()},
            "weights_used": dict(self.weights_used),
            "available_components": dict(self.available_components),
            "missing_policy": self.missing_policy,
            "missing_count": self.missing_count,
            "interpretation": self.interpretation,
        }


def classify_risk_band(score: float, thresholds: RiskThresholds) -> str:
    """Apply Eq. (29), returning ``"Unknown"`` for a missing score."""
    if not math.isfinite(score):
        return "Unknown"
    if score >= thresholds.high:
        return "Critical"
    if score >= thresholds.medium:
        return "High"
    if score >= thresholds.low:
        return "Medium"
    return "Low"


def compute_risk_index(
    components: RiskComponents,
    weights: RiskWeights,
    *,
    missing_policy: MissingPolicy = "nan",
) -> tuple[float, dict[str, float], dict[str, float]]:
    """Compute Eq. (28) and return score, contributions, and weights used."""
    values = components.as_tuple()
    available = components.available()
    names = ("probability", "severity", "exposure", "impact")
    base_weights = weights.normalized()

    if not all(available):
        if missing_policy == "error":
            missing = [name for name, ok in zip(names, available, strict=True) if not ok]
            raise ValueError(f"missing risk components: {', '.join(missing)}")
        if missing_policy == "nan":
            contributions = {
                name: (base_weights[index] * value if available[index] else math.nan)
                for index, (name, value) in enumerate(zip(names, values, strict=True))
            }
            return math.nan, contributions, dict(zip(names, base_weights, strict=True))
        if missing_policy != "renormalize":
            raise ValueError("unsupported missing_policy")
        available_weight = sum(
            weight for weight, ok in zip(base_weights, available, strict=True) if ok
        )
        if available_weight <= 0:
            return math.nan, {name: math.nan for name in names}, {name: math.nan for name in names}
        effective = tuple(
            weight / available_weight if ok else 0.0
            for weight, ok in zip(base_weights, available, strict=True)
        )
        score = sum(
            weight * value
            for weight, value, ok in zip(effective, values, available, strict=True)
            if ok
        )
        contributions = {
            name: (effective[index] * value if available[index] else 0.0)
            for index, (name, value) in enumerate(zip(names, values, strict=True))
        }
        return float(score), contributions, dict(zip(names, effective, strict=True))

    score = sum(weight * value for weight, value in zip(base_weights, values, strict=True))
    contributions = {
        name: weight * value
        for name, weight, value in zip(names, base_weights, values, strict=True)
    }
    return float(score), contributions, dict(zip(names, base_weights, strict=True))


def assess_cwe_risk(
    components: RiskComponents,
    policy: CweRiskPolicy,
) -> RiskAssessment:
    """Evaluate Eq. (28)-(29) under one explicit CWE policy."""
    score, contributions, weights_used = compute_risk_index(
        components,
        policy.weights,
        missing_policy=policy.missing_policy,
    )
    band = classify_risk_band(score, policy.thresholds)
    return RiskAssessment(
        cwe=policy.cwe,
        score=score,
        band=band,
        components=components,
        contributions=contributions,
        weights_used=weights_used,
        available_components={
            name: ok
            for name, ok in zip(
                ("probability", "severity", "exposure", "impact"),
                components.available(),
                strict=True,
            )
        },
        missing_policy=policy.missing_policy,
        policy=policy,
    )


class CweRiskScorer:
    """Evaluate findings against a registry of CWE-specific policies."""

    def __init__(
        self,
        policies: Mapping[str, CweRiskPolicy],
        *,
        default_policy: CweRiskPolicy | None = None,
    ) -> None:
        self.policies = dict(policies)
        self.default_policy = default_policy

    def assess(
        self,
        cwe: str,
        components: RiskComponents,
    ) -> RiskAssessment:
        """Assess one finding, falling back to ``default_policy`` if configured."""
        policy = self.policies.get(cwe)
        if policy is None:
            if self.default_policy is None:
                raise LookupError(f"no risk policy configured for {cwe!r}")
            policy = replace(self.default_policy, cwe=cwe)
        return assess_cwe_risk(components, policy)

    def assess_batch(
        self,
        items: Mapping[str, tuple[str, RiskComponents]],
    ) -> dict[str, RiskAssessment]:
        """Assess ``identifier -> (cwe, components)`` findings in one call."""
        output: dict[str, RiskAssessment] = {}
        for identifier, item in items.items():
            if not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str):
                raise TypeError("assess_batch values must be (cwe, RiskComponents) tuples")
            cwe, components = item
            output[identifier] = self.assess(cwe, components)
        return output

    @property
    def cwes(self) -> tuple[str, ...]:
        return tuple(sorted(self.policies))


def _optional(value: float) -> float | None:
    return float(value) if math.isfinite(float(value)) else None


__all__ = [
    "CweRiskPolicy",
    "CweRiskScorer",
    "RiskAssessment",
    "RiskComponents",
    "RiskThresholds",
    "RiskWeights",
    "assess_cwe_risk",
    "classify_risk_band",
    "compute_risk_index",
]
