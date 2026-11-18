"""Transparent, rule-based baseline for security decisions.

Every rule records the exact observed conditions that matched it. The baseline
is the reference policy: it does not learn, rank by utility, or claim optimal
behaviour. Its purpose is to make the default action set auditable and to give
the adaptive mode a candidate set whose provenance is visible.
"""

from __future__ import annotations

from bugdhor.decision.config import PolicyConfig
from bugdhor.decision.models import (
    PolicyAction,
    PolicyContext,
    RuleEvaluation,
    VerificationStatus,
)


def evaluate_rules(context: PolicyContext, config: PolicyConfig) -> tuple[RuleEvaluation, ...]:
    """Evaluate all baseline rules against one decision context."""
    threshold = config.thresholds
    risk = context.risk_index
    band = context.risk_band
    uncertainty = context.uncertainty
    prefs = context.preferences
    caps = context.model_capabilities

    high_risk = (
        (risk is not None and risk >= threshold.warning)
        or band in {"high", "critical"}
        or (
            context.calibrated_probability is not None
            and context.calibrated_probability >= threshold.warning
        )
    )
    strong_evidence = (
        context.evidence_strength is not None
        and context.evidence_strength >= threshold.warning
    )
    uncertain = (
        (uncertainty is not None and uncertainty >= threshold.uncertainty)
        or context.evidence_strength is None
        or risk is None
    )
    model_signal = bool(context.sae_features) or bool(context.feature_interactions)

    rules: list[RuleEvaluation] = [
        RuleEvaluation(
            rule_id="R01_INFORM_DEVELOPER",
            matched=prefs.notification_level != "off",
            actions=(PolicyAction.INFORM_DEVELOPER,),
            rationale=(
                "Notify the developer whenever notifications are enabled; "
                "this is the baseline transparency action."
            ),
            observed={"notificationLevel": prefs.notification_level},
        ),
        RuleEvaluation(
            rule_id="R02_DISPLAY_VULNERABILITY_WARNING",
            matched=high_risk and prefs.allow_warnings,
            actions=(PolicyAction.DISPLAY_VULNERABILITY_WARNING,),
            rationale=(
                "Display a warning when the risk index, band, or validated "
                "probability crosses the configured warning threshold."
            ),
            observed={
                "riskIndex": risk,
                "riskBand": band,
                "calibratedProbability": context.calibrated_probability,
                "warningThreshold": threshold.warning,
                "allowWarnings": prefs.allow_warnings,
            },
        ),
        RuleEvaluation(
            rule_id="R03_RECOMMEND_PRACTICES",
            matched=(high_risk or strong_evidence) and prefs.allow_practice_recommendations,
            actions=(PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES,),
            rationale=(
                "Recommend CWE-relevant secure coding practices when risk or "
                "evidence strength is material."
            ),
            observed={
                "cwe": context.cwe,
                "riskIndex": risk,
                "evidenceStrength": context.evidence_strength,
                "allowPracticeRecommendations": prefs.allow_practice_recommendations,
            },
        ),
        RuleEvaluation(
            rule_id="R04_REQUEST_ADDITIONAL_ANALYSIS",
            matched=uncertain and prefs.allow_additional_analysis,
            actions=(PolicyAction.REQUEST_ADDITIONAL_ANALYSIS,),
            rationale=(
                "Request more evidence when uncertainty is high or a required "
                "input is unavailable."
            ),
            observed={
                "uncertainty": uncertainty,
                "uncertaintyThreshold": threshold.uncertainty,
                "evidenceStrength": context.evidence_strength,
                "allowAdditionalAnalysis": prefs.allow_additional_analysis,
            },
        ),
        RuleEvaluation(
            rule_id="R05_COUNTERFACTUAL_ANALYSIS",
            matched=(
                model_signal
                and uncertain
                and caps.supports_counterfactual
                and prefs.allow_counterfactual_analysis
            ),
            actions=(PolicyAction.PERFORM_COUNTERFACTUAL_ANALYSIS,),
            rationale=(
                "Propose counterfactual analysis only when model evidence exists, "
                "uncertainty is material, and capability plus consent are present."
            ),
            observed={
                "saeFeatureCount": len(context.sae_features),
                "interactionCount": len(context.feature_interactions),
                "supportsCounterfactual": caps.supports_counterfactual,
                "allowCounterfactualAnalysis": prefs.allow_counterfactual_analysis,
            },
        ),
        RuleEvaluation(
            rule_id="R06_ACTIVATION_STEERING",
            matched=(
                model_signal
                and high_risk
                and caps.supports_activation_steering
                and caps.activation_steering_pipeline == "validated"
                and prefs.allow_activation_steering
            ),
            actions=(PolicyAction.APPLY_ACTIVATION_STEERING,),
            rationale=(
                "Activation steering is eligible only for a validated local pipeline "
                "with explicit developer consent; hosted assistants never satisfy "
                "this rule."
            ),
            observed={
                "supportsActivationSteering": caps.supports_activation_steering,
                "activationSteeringPipeline": caps.activation_steering_pipeline,
                "allowActivationSteering": prefs.allow_activation_steering,
            },
        ),
        RuleEvaluation(
            rule_id="R07_GENERATE_SECURE_ALTERNATIVES",
            matched=(
                high_risk
                and context.candidate_available
                and caps.supports_secure_code_generation
                and prefs.allow_secure_code_generation
            ),
            actions=(PolicyAction.GENERATE_SECURE_CODE_ALTERNATIVES,),
            rationale=(
                "Offer proposal-only secure alternatives when a candidate exists "
                "and generation is consented; applying any proposal still requires "
                "separate approval."
            ),
            observed={
                "candidateAvailable": context.candidate_available,
                "supportsSecureCodeGeneration": caps.supports_secure_code_generation,
                "allowSecureCodeGeneration": prefs.allow_secure_code_generation,
            },
        ),
        RuleEvaluation(
            rule_id="R08_REQUEST_INDEPENDENT_VERIFICATION",
            matched=(
                context.candidate_available
                and context.verification_status
                in {
                    VerificationStatus.NOT_RUN,
                    VerificationStatus.INCONCLUSIVE,
                    VerificationStatus.FAILED,
                }
                and (prefs.require_independent_verification or caps.verification_available)
            ),
            actions=(PolicyAction.REQUEST_INDEPENDENT_VERIFICATION,),
            rationale=(
                "Require independent verification before a candidate can be "
                "recommended; the generator cannot verify its own proposal."
            ),
            observed={
                "candidateAvailable": context.candidate_available,
                "verificationStatus": context.verification_status.value,
                "verificationAvailable": caps.verification_available,
                "requireIndependentVerification": prefs.require_independent_verification,
            },
        ),
        RuleEvaluation(
            rule_id="R09_REJECT_UNSAFE_CANDIDATE",
            matched=(
                bool(context.candidate_rejection_reasons)
                or context.verification_status is VerificationStatus.FAILED
                or (
                    context.candidate_available
                    and prefs.enforcement == "blocking"
                    and high_risk
                    and context.verification_status is not VerificationStatus.PASSED
                )
            ),
            actions=(PolicyAction.REJECT_UNSAFE_REPAIR_CANDIDATE,),
            rationale=(
                "Reject a candidate that was independently rejected, failed "
                "verification, or violates blocking enforcement without a passing "
                "verification."
            ),
            observed={
                "rejectionReasons": list(context.candidate_rejection_reasons),
                "verificationStatus": context.verification_status.value,
                "enforcement": prefs.enforcement,
            },
        ),
    ]
    return tuple(rules)


def actions_from_rules(rules: tuple[RuleEvaluation, ...]) -> tuple[PolicyAction, ...]:
    """Return the ordered, de-duplicated actions selected by matched rules."""
    selected: list[PolicyAction] = []
    for rule in rules:
        if not rule.matched:
            continue
        for action in rule.actions:
            if action not in selected:
                selected.append(action)
    return tuple(selected)


def baseline_actions(context: PolicyContext, config: PolicyConfig) -> tuple[PolicyAction, ...]:
    """Return the ordered, de-duplicated actions selected by the baseline."""
    return actions_from_rules(evaluate_rules(context, config))


__all__ = ["actions_from_rules", "baseline_actions", "evaluate_rules"]
