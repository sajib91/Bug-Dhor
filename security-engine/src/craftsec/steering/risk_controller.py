"""CWE-specific adaptive risk control for SAE steering decisions."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class StaticEvidence:
    """One explicitly classified static-analysis evidence item."""

    rule_id: str
    score: float
    polarity: str = "supports"
    cwe: str | None = None

    def __post_init__(self) -> None:
        if not self.rule_id.strip() or not math.isfinite(self.score) or self.score < 0:
            raise ValueError(
                "static evidence requires a non-empty rule and finite non-negative score"
            )
        if self.polarity not in {"supports", "refutes"}:
            raise ValueError("static evidence polarity must be supports or refutes")


@dataclass(frozen=True, slots=True)
class CweRiskPolicy:
    """All CWE-specific thresholds and weights used by the controller."""

    cwe: str
    priority_offset: float = 0.0
    feature_weight: float = 1.0
    interaction_weight: float = 1.0
    static_weight: float = 1.0
    heuristic_weight: float = 1.0
    feature_activation_threshold: float = 0.0
    interaction_threshold: float = 0.0
    static_evidence_threshold: float = 0.0
    steering_threshold: float = 0.0
    steering_base_strength: float = 0.0
    steering_scale: float = 1.0
    max_steering_strength: float = 10.0
    max_priority: float = 100.0
    priority_bands: Mapping[str, float] = field(
        default_factory=lambda: {"low": 0.0, "medium": 0.33, "high": 0.66}
    )

    context_multipliers: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.cwe.strip():
            raise ValueError("CWE policy requires a category")
        for name in (
            "priority_offset",
            "feature_weight",
            "interaction_weight",
            "static_weight",
            "heuristic_weight",
            "feature_activation_threshold",
            "interaction_threshold",
            "static_evidence_threshold",
            "steering_threshold",
            "steering_base_strength",
            "steering_scale",
            "max_steering_strength",
            "max_priority",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if self.max_priority == 0:
            raise ValueError("max_priority must be positive")
        if not self.priority_bands:
            raise ValueError("priority_bands must not be empty")
        if any(
            not label.strip() or not math.isfinite(threshold) or threshold < 0
            for label, threshold in self.priority_bands.items()
        ):
            raise ValueError("priority band thresholds must be finite and non-negative")
        if any(
            not key.strip() or not math.isfinite(multiplier) or multiplier < 0
            for key, multiplier in self.context_multipliers.items()
        ):
            raise ValueError("context multipliers must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class RiskAssessmentInput:
    """Measured evidence supplied for one source context."""

    cwe: str
    model_id: str
    model_version: str
    source_context: Mapping[str, str] = field(default_factory=dict)
    feature_activations: Mapping[int, float] = field(default_factory=dict)
    feature_importance: Mapping[int, float] = field(default_factory=dict)
    feature_interactions: Sequence[Any] = ()
    static_evidence: Sequence[StaticEvidence] = ()
    heuristic_risk: float | None = None

    def __post_init__(self) -> None:
        if not self.cwe.strip() or not self.model_id.strip() or not self.model_version.strip():
            raise ValueError("CWE, model ID, and model version are required")
        if self.heuristic_risk is not None and not math.isfinite(self.heuristic_risk):
            raise ValueError("heuristic_risk must be finite")
        if any(
            feature < 0 or not math.isfinite(value)
            for feature, value in self.feature_activations.items()
        ):
            raise ValueError("feature activations must be finite with non-negative indices")
        if any(
            feature < 0 or not math.isfinite(value) or value < 0
            for feature, value in self.feature_importance.items()
        ):
            raise ValueError("feature importance must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class CalibrationRequest:
    """Input contract for a model-specific calibrator."""

    model_id: str
    model_version: str
    cwe: str
    heuristic_priority: float
    source_context: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    """A probability only when produced by a declared calibration artifact."""

    probability: float
    calibrator_id: str
    method: str
    dataset_id: str

    def __post_init__(self) -> None:
        if not 0 <= self.probability <= 1:
            raise ValueError("calibrated probability must be in [0, 1]")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.calibrator_id, self.method, self.dataset_id)
        ):
            raise ValueError("calibration metadata is required")


class RiskCalibrator(Protocol):
    """Protocol for model- and version-specific calibration artifacts."""

    def calibrate(self, request: CalibrationRequest) -> CalibrationResult: ...


@dataclass(frozen=True, slots=True)
class RiskControllerDecision:
    """Risk and steering decision with explicit evidence availability."""

    cwe: str
    model_id: str
    model_version: str
    heuristic_priority: float
    risk_band: str
    calibrated_probability: float | None
    calibration: CalibrationResult | None
    steering_strength: float
    steering_enabled: bool
    context_multiplier: float
    feature_evidence_available: bool
    interaction_evidence_available: bool
    static_evidence_available: bool
    fallback_reasons: tuple[str, ...]
    component_scores: Mapping[str, float]
    policy: CweRiskPolicy

    @property
    def risk_interpretation(self) -> str:
        return (
            "calibrated_probability"
            if self.calibrated_probability is not None
            else "heuristic_risk; not a probability"
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["risk_interpretation"] = self.risk_interpretation
        return payload


class CweRiskController:
    """Prioritize CWE-specific risk and choose constrained steering strength."""

    def __init__(
        self,
        policies: Mapping[str, CweRiskPolicy],
        *,
        default_policy: CweRiskPolicy | None = None,
        calibrators: Mapping[tuple[str, str], RiskCalibrator] | None = None,
    ) -> None:
        self.policies = dict(policies)
        self.default_policy = default_policy
        self.calibrators = dict(calibrators or {})
        self.history: list[RiskControllerDecision] = []

    def assess(self, evidence: RiskAssessmentInput) -> RiskControllerDecision:
        policy = self.policies.get(evidence.cwe, self.default_policy)
        fallback_reasons: list[str] = []
        if policy is None:
            fallback_reasons.append("no CWE policy; risk controller fallback is disabled")
            return self._fallback(evidence, fallback_reasons)

        context_multiplier = self._context_multiplier(policy, evidence.source_context)
        feature_score = self._feature_score(evidence, policy)
        interaction_score = self._interaction_score(evidence.feature_interactions, policy)
        static_score = self._static_score(evidence.static_evidence, evidence.cwe, policy)
        heuristic_score = (
            evidence.heuristic_risk * policy.heuristic_weight
            if evidence.heuristic_risk is not None
            else 0.0
        )
        feature_evidence_available = self._has_feature_evidence(evidence, policy)
        if not feature_evidence_available:
            fallback_reasons.append(
                "SAE feature evidence unavailable or below threshold; steering is disabled"
            )
        if not evidence.feature_interactions:
            fallback_reasons.append("feature interaction evidence unavailable")
        if not evidence.static_evidence:
            fallback_reasons.append("static-analysis evidence unavailable")
        if evidence.heuristic_risk is None:
            fallback_reasons.append("heuristic risk unavailable")
        priority = self._bounded(
            (
                policy.priority_offset
                + policy.feature_weight * feature_score
                + policy.interaction_weight * interaction_score
                + policy.static_weight * static_score
                + heuristic_score
            )
            * context_multiplier,
            policy.max_priority,
        )
        band = self._band(priority, policy.priority_bands)
        calibration = self._calibrate(evidence, priority, fallback_reasons)
        strength = self._steering_strength(
            priority,
            context_multiplier,
            feature_evidence=feature_evidence_available,
            policy=policy,
        )
        decision = RiskControllerDecision(
            cwe=evidence.cwe,
            model_id=evidence.model_id,
            model_version=evidence.model_version,
            heuristic_priority=priority,
            risk_band=band,
            calibrated_probability=calibration.probability if calibration else None,
            calibration=calibration,
            steering_strength=strength,
            steering_enabled=strength > 0,
            context_multiplier=context_multiplier,
            feature_evidence_available=feature_evidence_available,
            interaction_evidence_available=bool(evidence.feature_interactions),
            static_evidence_available=bool(evidence.static_evidence),
            fallback_reasons=tuple(fallback_reasons),
            component_scores={
                "features": feature_score,
                "interactions": interaction_score,
                "static": static_score,
                "heuristic": heuristic_score,
            },
            policy=policy,
        )
        self.history.append(decision)
        return decision

    def save_history(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps([decision.to_dict() for decision in self.history], indent=2, default=list),
            encoding="utf-8",
        )
        return target

    def _feature_score(self, evidence: RiskAssessmentInput, policy: CweRiskPolicy) -> float:
        return sum(
            abs(value) * evidence.feature_importance.get(feature, 1.0)
            for feature, value in evidence.feature_activations.items()
            if abs(value) >= policy.feature_activation_threshold
        )

    @staticmethod
    def _has_feature_evidence(evidence: RiskAssessmentInput, policy: CweRiskPolicy) -> bool:
        return any(
            abs(value) >= policy.feature_activation_threshold
            for value in evidence.feature_activations.values()
        )

    @staticmethod
    def _interaction_score(interactions: Sequence[Any], policy: CweRiskPolicy) -> float:
        total = 0.0
        for interaction in interactions:
            contrast = _interaction_contrast(interaction)
            if contrast is not None and abs(contrast) >= policy.interaction_threshold:
                total += abs(contrast)
        return total

    @staticmethod
    def _static_score(
        evidence: Sequence[StaticEvidence], cwe: str, policy: CweRiskPolicy
    ) -> float:
        return sum(
            item.score * (1 if item.polarity == "supports" else -1)
            for item in evidence
            if item.cwe in {None, cwe} and item.score >= policy.static_evidence_threshold
        )

    @staticmethod
    def _context_multiplier(policy: CweRiskPolicy, context: Mapping[str, str]) -> float:
        multiplier = 1.0
        for key, value in context.items():
            multiplier *= policy.context_multipliers.get(f"{key}={value}", 1.0)
        return multiplier

    def _calibrate(
        self,
        evidence: RiskAssessmentInput,
        priority: float,
        fallback_reasons: list[str],
    ) -> CalibrationResult | None:
        calibrator = self.calibrators.get((evidence.model_id, evidence.model_version))
        if calibrator is None:
            fallback_reasons.append("model-specific calibration unavailable")
            return None
        try:
            return calibrator.calibrate(
                CalibrationRequest(
                    model_id=evidence.model_id,
                    model_version=evidence.model_version,
                    cwe=evidence.cwe,
                    heuristic_priority=priority,
                    source_context=evidence.source_context,
                )
            )
        except Exception as error:
            fallback_reasons.append(f"model-specific calibration failed: {error}")
            return None

    @staticmethod
    def _steering_strength(
        priority: float,
        multiplier: float,
        *,
        feature_evidence: bool,
        policy: CweRiskPolicy,
    ) -> float:
        if not feature_evidence or priority < policy.steering_threshold:
            return 0.0
        return min(
            policy.max_steering_strength,
            max(
                0.0,
                (policy.steering_base_strength + priority * policy.steering_scale)
                * multiplier,
            ),
        )

    @staticmethod
    def _bounded(value: float, maximum: float) -> float:
        return max(0.0, min(maximum, value))

    @staticmethod
    def _band(priority: float, bands: Mapping[str, float]) -> str:
        eligible = [
            (threshold, label) for label, threshold in bands.items() if threshold <= priority
        ]
        return max(eligible, default=(0.0, "unclassified"))[1]

    def _fallback(
        self, evidence: RiskAssessmentInput, reasons: Sequence[str]
    ) -> RiskControllerDecision:
        decision = RiskControllerDecision(
            cwe=evidence.cwe,
            model_id=evidence.model_id,
            model_version=evidence.model_version,
            heuristic_priority=0.0,
            risk_band="unavailable",
            calibrated_probability=None,
            calibration=None,
            steering_strength=0.0,
            steering_enabled=False,
            context_multiplier=1.0,
            feature_evidence_available=bool(evidence.feature_activations),
            interaction_evidence_available=bool(evidence.feature_interactions),
            static_evidence_available=bool(evidence.static_evidence),
            fallback_reasons=tuple(reasons),
            component_scores={},
            policy=self.default_policy
            or CweRiskPolicy(cwe=evidence.cwe, max_steering_strength=1.0),
        )
        self.history.append(decision)
        return decision


def _interaction_contrast(interaction: Any) -> float | None:
    if isinstance(interaction, Mapping):
        value = interaction.get("contrast")
        return float(value) if isinstance(value, (int, float)) and math.isfinite(value) else None
    estimate = getattr(interaction, "estimate", None)
    value = getattr(estimate, "contrast", None)
    return float(value) if isinstance(value, (int, float)) and math.isfinite(value) else None


__all__ = [
    "CalibrationRequest",
    "CalibrationResult",
    "CweRiskController",
    "CweRiskPolicy",
    "RiskAssessmentInput",
    "RiskCalibrator",
    "RiskControllerDecision",
    "StaticEvidence",
]
