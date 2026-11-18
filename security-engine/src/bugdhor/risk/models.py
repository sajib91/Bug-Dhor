"""Data contracts for the unified, explainable security risk engine.

The contracts deliberately separate three numbers that are easy to conflate:

* ``p_hat`` is the evidence-derived likelihood that a reported finding is real.
  Without a validated calibration artifact it is a heuristic support score.
* ``index`` is Eq. (28)'s linear prioritization index. It is never a probability.
* ``probability`` exists only when a calibration artifact validated on
  independent groups has been supplied.

Evidence is never imputed. Missing observations are reported and excluded from
the denominator. Correlated observations are collapsed into explicit dependency
groups before aggregation so that, for example, AST/CFG/DFG/taint views of the
same path are not counted as four independent votes.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EvidenceSource(StrEnum):
    """Canonical source categories consumed by the unified risk engine."""

    STATIC_ANALYSIS = "static_analysis"
    AST = "ast"
    CFG = "cfg"
    DFG = "dfg"
    TAINT = "taint"
    SAE_ACTIVATION = "sae_activation"
    COUNTERFACTUAL_INTERACTION = "counterfactual_interaction"
    CWE_METADATA = "cwe_metadata"
    MODEL_PREDICTION = "model_prediction"
    REPOSITORY_CONTEXT = "repository_context"
    EXPLOITABILITY = "exploitability"
    VERIFICATION = "verification"


class ClaimKind(StrEnum):
    """Epistemic status of one observation."""

    OBSERVATION = "observation"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"


class EvidencePolarity(StrEnum):
    """Direction in which one observation moves the risk estimate."""

    SUPPORTS = "supports"
    REFUTES = "refutes"
    NEUTRAL = "neutral"


_RUN_STATUSES = frozenset({"complete", "partial", "failed", "unavailable"})


@dataclass(frozen=True, slots=True)
class ReliabilityEvidence:
    """Measured metadata used to estimate an observation's reliability.

    Validation metrics take precedence over self-reported confidence. For a
    supporting observation, ``validation_precision`` is used; for a refuting
    observation, ``validation_specificity`` is used. If neither is available,
    reliability is ``reported_confidence * coverage`` for a completed run.
    A hypothesis without validation metrics has reliability zero. No numeric
    reliability is invented by this estimator.
    """

    validation_precision: float | None = None
    validation_specificity: float | None = None
    reported_confidence: float | None = None
    coverage: float | None = None
    run_status: str = "complete"
    basis: str = "caller_supplied"

    def __post_init__(self) -> None:
        for name in (
            "validation_precision",
            "validation_specificity",
            "reported_confidence",
            "coverage",
        ):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(value) or not 0.0 <= value <= 1.0):
                raise ValueError(f"{name} must be in [0, 1] or None")
        if self.run_status not in _RUN_STATUSES:
            raise ValueError(f"unsupported reliability run status: {self.run_status!r}")
        if not self.basis.strip():
            raise ValueError("reliability basis is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "validationPrecision": self.validation_precision,
            "validationSpecificity": self.validation_specificity,
            "reportedConfidence": self.reported_confidence,
            "coverage": self.coverage,
            "runStatus": self.run_status,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    """One normalized observation about a finding.

    ``value`` must already be in ``[0, 1]`` on a documented scale. Use the
    helpers in :mod:`bugdhor.risk.normalization` for source-specific scaling;
    the engine does not guess a scale from an unlabelled number.
    """

    source: EvidenceSource
    source_id: str
    value: float
    reliability: ReliabilityEvidence
    claim_kind: ClaimKind = ClaimKind.OBSERVATION
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS
    dependency_group: str = "unclassified"
    normalized_from: str = "caller_normalized"
    rationale: str = ""
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_id.strip():
            raise ValueError("evidence source_id is required")
        if not self.dependency_group.strip():
            raise ValueError("evidence dependency_group is required")
        if not self.normalized_from.strip():
            raise ValueError("evidence normalized_from is required")
        if not math.isfinite(self.value) or not 0.0 <= self.value <= 1.0:
            raise ValueError("evidence value must be finite and in [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "sourceId": self.source_id,
            "value": self.value,
            "claimKind": self.claim_kind.value,
            "polarity": self.polarity.value,
            "dependencyGroup": self.dependency_group,
            "normalizedFrom": self.normalized_from,
            "rationale": self.rationale,
            "limitations": list(self.limitations),
            "reliability": self.reliability.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class NormalizedEvidence(EvidenceObservation):
    """An observation with its explicitly estimated reliability attached."""

    reliability_value: float = 0.0
    reliability_method: str = "unavailable"

    def __post_init__(self) -> None:
        EvidenceObservation.__post_init__(self)
        if not math.isfinite(self.reliability_value) or not 0.0 <= self.reliability_value <= 1.0:
            raise ValueError("reliability_value must be finite and in [0, 1]")
        if not self.reliability_method.strip():
            raise ValueError("reliability_method is required")

    def to_dict(self) -> dict[str, Any]:
        # Call the base explicitly: a slotted dataclass recreates the class,
        # so a zero-argument super() closure can point at the old class object.
        payload = EvidenceObservation.to_dict(self)
        payload["reliabilityValue"] = self.reliability_value
        payload["reliabilityMethod"] = self.reliability_method
        return payload


@dataclass(frozen=True, slots=True)
class ExcludedEvidence:
    """An observation that was not allowed to contribute, with the reason."""

    source_id: str
    reason: str
    source: EvidenceSource | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceId": self.source_id,
            "source": self.source.value if self.source is not None else None,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Weights for ``R_index = a*p + b*S + c*E + d*I`` (Eq. 28).

    A ``basis`` and ``version`` are mandatory. A configuration that cannot say
    where its weights came from is rejected instead of being presented as an
    empirical result. The shipped baseline uses equal weights with the
    documented basis ``maximum_entropy_neutral_prior``; it remains heuristic.
    """

    p_hat: float
    severity: float
    exposure: float
    impact: float
    basis: str
    version: str

    def __post_init__(self) -> None:
        values = (self.p_hat, self.severity, self.exposure, self.impact)
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("risk weights must be finite and non-negative")
        if sum(values) <= 0:
            raise ValueError("at least one risk weight must be positive")
        if not self.basis.strip() or not self.version.strip():
            raise ValueError("risk weights require a documented basis and version")

    def normalized(self) -> tuple[float, float, float, float]:
        total = self.p_hat + self.severity + self.exposure + self.impact
        return (
            self.p_hat / total,
            self.severity / total,
            self.exposure / total,
            self.impact / total,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "p_hat": self.p_hat,
            "severity": self.severity,
            "exposure": self.exposure,
            "impact": self.impact,
            "basis": self.basis,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    """Ordered Eq. (29) thresholds with a documented provenance."""

    low: float
    medium: float
    high: float
    basis: str

    def __post_init__(self) -> None:
        values = (self.low, self.medium, self.high)
        if any(not math.isfinite(value) or not 0.0 < value <= 1.0 for value in values):
            raise ValueError("risk thresholds must lie in (0, 1]")
        if not self.low < self.medium < self.high:
            raise ValueError("risk thresholds must satisfy low < medium < high")
        if not self.basis.strip():
            raise ValueError("risk thresholds require a documented basis")

    def band(self, score: float | None) -> str:
        if score is None or not math.isfinite(score):
            return "unknown"
        if score >= self.high:
            return "critical"
        if score >= self.medium:
            return "high"
        if score >= self.low:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "low": self.low,
            "medium": self.medium,
            "high": self.high,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class CwePriorityProfile:
    """CWE-specific severity/exposure/impact evidence with its source.

    Values are normalized on documented scales. No CWE is assigned an implicit
    severity by the engine; a missing profile leaves the component unavailable.
    """

    cwe: str
    severity: float
    exposure: float
    impact: float
    basis: str
    threshold_overrides: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.cwe.strip():
            raise ValueError("CWE profile requires an identifier")
        for name, value in (
            ("severity", self.severity),
            ("exposure", self.exposure),
            ("impact", self.impact),
        ):
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"CWE {name} must be in [0, 1]")
        if not self.basis.strip():
            raise ValueError("CWE profile requires a documented basis")
        for key, value in self.threshold_overrides.items():
            if key not in {"low", "medium", "high"}:
                raise ValueError(f"unsupported threshold override: {key}")
            if not math.isfinite(value) or not 0.0 < value <= 1.0:
                raise ValueError("CWE threshold overrides must lie in (0, 1]")


@dataclass(frozen=True, slots=True)
class RiskConfig:
    """Complete deterministic configuration for one risk-engine invocation."""

    weights: RiskWeights
    thresholds: RiskThresholds
    cwe_profiles: Mapping[str, CwePriorityProfile] = field(default_factory=dict)
    dependency_groups: Mapping[str, str] = field(default_factory=dict)
    missing_policy: str = "renormalize"
    uncertainty_bands: tuple[float, float] = (1.0 / 3.0, 2.0 / 3.0)
    uncertainty_basis: str = "equal_width_ordinal_bands"
    priority_tie_breaker: str = "finding_id"
    name: str = "unified-risk-baseline"
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if self.priority_tie_breaker not in {"finding_id", "cwe", "source_id"}:
            raise ValueError("unsupported priority tie breaker")
        if not self.name.strip() or not self.version.strip():
            raise ValueError("risk configuration requires a name and version")
        if self.missing_policy not in {"renormalize", "unavailable"}:
            raise ValueError("missing_policy must be 'renormalize' or 'unavailable'")
        low, high = self.uncertainty_bands
        if not all(math.isfinite(value) and 0.0 < value < 1.0 for value in (low, high)):
            raise ValueError("uncertainty bands must lie in (0, 1)")
        if low >= high:
            raise ValueError("uncertainty bands must be increasing")
        if not self.uncertainty_basis.strip():
            raise ValueError("uncertainty bands require a documented basis")
        for source, group in self.dependency_groups.items():
            if not source.strip() or not group.strip():
                raise ValueError("dependency group mappings must be non-empty")

    def group_for(self, source: EvidenceSource) -> str:
        return self.dependency_groups.get(source.value, source.value)

    def config_hash(self) -> str:
        payload = {
            "name": self.name,
            "version": self.version,
            "weights": self.weights.to_dict(),
            "thresholds": self.thresholds.to_dict(),
            "cweProfiles": {
                key: {
                    "cwe": value.cwe,
                    "severity": value.severity,
                    "exposure": value.exposure,
                    "impact": value.impact,
                    "basis": value.basis,
                    "thresholdOverrides": dict(value.threshold_overrides),
                }
                for key, value in sorted(self.cwe_profiles.items())
            },
            "dependencyGroups": dict(sorted(self.dependency_groups.items())),
            "missingPolicy": self.missing_policy,
            "uncertaintyBands": list(self.uncertainty_bands),
            "uncertaintyBasis": self.uncertainty_basis,
            "priorityTieBreaker": self.priority_tie_breaker,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ComponentScores:
    """The four Eq. (28) inputs actually available for one finding."""

    p_hat: float | None
    severity: float | None
    exposure: float | None
    impact: float | None

    def available(self) -> Mapping[str, bool]:
        return {
            name: value is not None and math.isfinite(value)
            for name, value in (
                ("p_hat", self.p_hat),
                ("severity", self.severity),
                ("exposure", self.exposure),
                ("impact", self.impact),
            )
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "p_hat": self.p_hat,
            "severity": self.severity,
            "exposure": self.exposure,
            "impact": self.impact,
            "available": dict(self.available()),
        }


@dataclass(frozen=True, slots=True)
class GroupScore:
    """Aggregated evidence from one dependency group."""

    group: str
    support: float
    refutation: float
    reliability: float
    evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "support": self.support,
            "refutation": self.refutation,
            "reliability": self.reliability,
            "evidenceIds": list(self.evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class Uncertainty:
    """Explicit uncertainty in the heuristic estimate.

    This is not a confidence interval around a calibrated probability. It is a
    documented function of evidence coverage, source reliability, and
    support/refutation conflict. ``interval_*`` fields are populated only by a
    validated calibration evaluation, never by the heuristic engine.
    """

    value: float
    level: str
    coverage: float
    conflict: float
    basis: str
    interval_low: float | None = None
    interval_high: float | None = None
    interval_metric: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "level": self.level,
            "coverage": self.coverage,
            "conflict": self.conflict,
            "basis": self.basis,
            "intervalLow": self.interval_low,
            "intervalHigh": self.interval_high,
            "intervalMetric": self.interval_metric,
        }


@dataclass(frozen=True, slots=True)
class CalibrationSummary:
    """Validation metadata required before a probability may be emitted."""

    artifact_id: str
    method: str
    dataset_id: str
    split_hash: str
    config_hash: str
    status: str
    metrics: Mapping[str, float]
    metric_intervals: Mapping[str, tuple[float, float]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "method": self.method,
            "datasetId": self.dataset_id,
            "splitHash": self.split_hash,
            "configHash": self.config_hash,
            "status": self.status,
            "metrics": dict(self.metrics),
            "metricIntervals": {
                key: list(value) for key, value in sorted(self.metric_intervals.items())
            },
        }


@dataclass(frozen=True, slots=True)
class RiskResult:
    """Complete, auditable result for one finding."""

    finding_id: str
    cwe: str | None
    index: float | None
    band: str
    components: ComponentScores
    contributions: Mapping[str, float | None]
    group_scores: tuple[GroupScore, ...]
    interaction_adjustment: float
    uncertainty: Uncertainty
    normalized_evidence: tuple[NormalizedEvidence, ...]
    excluded_evidence: tuple[ExcludedEvidence, ...]
    explanation: tuple[str, ...]
    config_hash: str
    probability: float | None = None
    calibration: CalibrationSummary | None = None
    priority_rank: int | None = None

    @property
    def score_kind(self) -> str:
        return "heuristic_index"

    @property
    def probability_kind(self) -> str | None:
        return "calibrated_probability" if self.probability is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "cwe": self.cwe,
            "index": self.index,
            "scoreKind": self.score_kind,
            "band": self.band,
            "components": self.components.to_dict(),
            "contributions": dict(self.contributions),
            "interactionAdjustment": self.interaction_adjustment,
            "probability": self.probability,
            "probabilityKind": self.probability_kind,
            "calibration": self.calibration.to_dict() if self.calibration else None,
            "uncertainty": self.uncertainty.to_dict(),
            "groups": [group.to_dict() for group in self.group_scores],
            "evidence": [item.to_dict() for item in self.normalized_evidence],
            "excludedEvidence": [item.to_dict() for item in self.excluded_evidence],
            "explanation": list(self.explanation),
            "priorityRank": self.priority_rank,
            "configHash": self.config_hash,
        }


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """A ranked batch of findings with shared configuration provenance."""

    results: tuple[RiskResult, ...]
    config_hash: str
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [result.to_dict() for result in self.results],
            "configHash": self.config_hash,
            "warnings": list(self.warnings),
        }


def canonical_hash(payload: Mapping[str, Any]) -> str:
    """Return the deterministic SHA-256 of a canonical JSON payload."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=list)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_finite_unit(value: float, name: str) -> float:
    """Validate a finite value in ``[0, 1]``."""
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be finite and in [0, 1]")
    return float(value)


def as_tuple(values: Sequence[Any]) -> tuple[Any, ...]:
    """Return an immutable tuple without copying a stored mapping."""
    return tuple(values)


__all__ = [
    "CalibrationSummary",
    "CwePriorityProfile",
    "EvidenceObservation",
    "EvidencePolarity",
    "EvidenceSource",
    "ExcludedEvidence",
    "ClaimKind",
    "GroupScore",
    "NormalizedEvidence",
    "ReliabilityEvidence",
    "RiskAssessment",
    "RiskConfig",
    "RiskResult",
    "RiskThresholds",
    "RiskWeights",
    "Uncertainty",
    "canonical_hash",
    "validate_finite_unit",
]
