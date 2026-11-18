"""Contracts for the transparent and adaptive security decision policy.

The policy is advisory by default. It emits a decision trace that names the
rules, observed conditions, configuration hash, and any action that was blocked
by capability or developer preference. It never applies a patch or changes a
workspace.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from bugdhor.risk.models import canonical_hash


class PolicyAction(StrEnum):
    INFORM_DEVELOPER = "inform_developer"
    DISPLAY_VULNERABILITY_WARNING = "display_vulnerability_warning"
    RECOMMEND_SECURE_CODING_PRACTICES = "recommend_secure_coding_practices"
    REQUEST_ADDITIONAL_ANALYSIS = "request_additional_analysis"
    PERFORM_COUNTERFACTUAL_ANALYSIS = "perform_counterfactual_analysis"
    APPLY_ACTIVATION_STEERING = "apply_activation_steering"
    GENERATE_SECURE_CODE_ALTERNATIVES = "generate_secure_code_alternatives"
    REQUEST_INDEPENDENT_VERIFICATION = "request_independent_verification"
    REJECT_UNSAFE_REPAIR_CANDIDATE = "reject_unsafe_repair_candidate"


class VerificationStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    NOT_RUN = "not_run"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    PASSED = "passed"


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """Declared capabilities, never inferred from a provider name."""

    supports_counterfactual: bool = False
    supports_activation_steering: bool = False
    activation_steering_pipeline: str = "none"
    supports_secure_code_generation: bool = False
    verification_available: bool = False

    def __post_init__(self) -> None:
        if self.activation_steering_pipeline not in {"none", "validated"}:
            raise ValueError("activation_steering_pipeline must be 'none' or 'validated'")
        if (
            self.activation_steering_pipeline == "validated"
            and not self.supports_activation_steering
        ):
            raise ValueError("a validated steering pipeline requires steering support")

    def to_dict(self) -> dict[str, Any]:
        return {
            "supportsCounterfactual": self.supports_counterfactual,
            "supportsActivationSteering": self.supports_activation_steering,
            "activationSteeringPipeline": self.activation_steering_pipeline,
            "supportsSecureCodeGeneration": self.supports_secure_code_generation,
            "verificationAvailable": self.verification_available,
        }


@dataclass(frozen=True, slots=True)
class DeveloperPreferences:
    """Configurable notification and enforcement boundaries."""

    notification_level: str = "detailed"
    allow_warnings: bool = True
    allow_practice_recommendations: bool = True
    allow_additional_analysis: bool = True
    allow_counterfactual_analysis: bool = False
    allow_activation_steering: bool = False
    allow_secure_code_generation: bool = True
    require_independent_verification: bool = True
    enforcement: str = "advisory"
    basis: str = "developer_configuration"

    def __post_init__(self) -> None:
        if self.notification_level not in {"off", "summary", "detailed"}:
            raise ValueError("notification_level must be off, summary, or detailed")
        if self.enforcement not in {"advisory", "blocking"}:
            raise ValueError("enforcement must be advisory or blocking")
        if not self.basis.strip():
            raise ValueError("developer preferences require a basis")

    def to_dict(self) -> dict[str, Any]:
        return {
            "notificationLevel": self.notification_level,
            "allowWarnings": self.allow_warnings,
            "allowPracticeRecommendations": self.allow_practice_recommendations,
            "allowAdditionalAnalysis": self.allow_additional_analysis,
            "allowCounterfactualAnalysis": self.allow_counterfactual_analysis,
            "allowActivationSteering": self.allow_activation_steering,
            "allowSecureCodeGeneration": self.allow_secure_code_generation,
            "requireIndependentVerification": self.require_independent_verification,
            "enforcement": self.enforcement,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Inputs available at decision time."""

    cwe: str | None
    risk_index: float | None
    risk_band: str
    evidence_strength: float | None
    uncertainty: float | None
    calibrated_probability: float | None
    sae_features: Mapping[int, float] = field(default_factory=dict)
    feature_interactions: tuple[Mapping[str, Any], ...] = ()
    model_capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    verification_status: VerificationStatus = VerificationStatus.NOT_APPLICABLE
    preferences: DeveloperPreferences | None = None
    candidate_available: bool = False
    candidate_rejection_reasons: tuple[str, ...] = ()
    score_kind: str = "heuristic_index"
    calibration_status: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("risk_index", self.risk_index),
            ("evidence_strength", self.evidence_strength),
            ("uncertainty", self.uncertainty),
            ("calibrated_probability", self.calibrated_probability),
        ):
            if value is not None and (not math.isfinite(value) or not 0.0 <= value <= 1.0):
                raise ValueError(f"{name} must be in [0, 1] or None")
        if any(not isinstance(item, Mapping) for item in self.feature_interactions):
            raise TypeError("feature_interactions must contain mappings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "riskIndex": self.risk_index,
            "riskBand": self.risk_band,
            "evidenceStrength": self.evidence_strength,
            "uncertainty": self.uncertainty,
            "calibratedProbability": self.calibrated_probability,
            "saeFeatures": {str(key): value for key, value in self.sae_features.items()},
            "featureInteractionCount": len(self.feature_interactions),
            "modelCapabilities": self.model_capabilities.to_dict(),
            "verificationStatus": self.verification_status.value,
            "preferences": self.preferences.to_dict() if self.preferences else None,
            "candidateAvailable": self.candidate_available,
            "candidateRejectionReasons": list(self.candidate_rejection_reasons),
            "scoreKind": self.score_kind,
            "calibrationStatus": self.calibration_status,
        }


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rule_id: str
    matched: bool
    actions: tuple[PolicyAction, ...]
    rationale: str
    observed: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "matched": self.matched,
            "actions": [action.value for action in self.actions],
            "rationale": self.rationale,
            "observed": dict(self.observed),
        }


@dataclass(frozen=True, slots=True)
class UtilityScore:
    action: PolicyAction
    benefit: float
    cost: float
    harm: float
    score: float
    allowed: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "benefit": self.benefit,
            "cost": self.cost,
            "harm": self.harm,
            "score": self.score,
            "allowed": self.allowed,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class DecisionTrace:
    decision_id: str
    mode: str
    config_hash: str
    rules: tuple[RuleEvaluation, ...]
    utility_scores: tuple[UtilityScore, ...]
    blocked_actions: tuple[str, ...]
    objective: str
    context: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decisionId": self.decision_id,
            "mode": self.mode,
            "configHash": self.config_hash,
            "rules": [rule.to_dict() for rule in self.rules],
            "utilityScores": [score.to_dict() for score in self.utility_scores],
            "blockedActions": list(self.blocked_actions),
            "objective": self.objective,
            "context": dict(self.context),
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    actions: tuple[PolicyAction, ...]
    primary_action: PolicyAction | None
    rationale: tuple[str, ...]
    trace: DecisionTrace
    baseline_actions: tuple[PolicyAction, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [action.value for action in self.actions],
            "primaryAction": self.primary_action.value if self.primary_action else None,
            "rationale": list(self.rationale),
            "trace": self.trace.to_dict(),
            "baselineActions": [action.value for action in self.baseline_actions],
        }


def context_hash(context: PolicyContext) -> str:
    """Hash the decision-relevant context for traceability."""
    return canonical_hash(context.to_dict())


__all__ = [
    "DecisionTrace",
    "DeveloperPreferences",
    "ModelCapabilities",
    "PolicyAction",
    "PolicyContext",
    "PolicyDecision",
    "RuleEvaluation",
    "UtilityScore",
    "VerificationStatus",
    "context_hash",
]
