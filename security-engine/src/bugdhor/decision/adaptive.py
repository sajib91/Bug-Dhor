"""Preference-utility ranking for the adaptive decision mode.

This is a deterministic multi-attribute utility ranking, not reinforcement
learning and not an optimal decision procedure. Efficacy, cost, and harm terms
are supplied by a versioned developer-preference configuration; the context
only modulates their relative influence. The configured objective and the
utility terms are both recorded in the decision trace so that a reader can see
exactly what was optimized for and what was assumed.
"""

from __future__ import annotations

from bugdhor.decision.config import PolicyConfig
from bugdhor.decision.models import (
    PolicyAction,
    PolicyContext,
    UtilityScore,
    VerificationStatus,
)


def action_gate(
    action: PolicyAction,
    context: PolicyContext,
) -> tuple[bool, str]:
    """Return whether an action is permitted and the exact reason."""
    prefs = context.preferences
    caps = context.model_capabilities
    if action is PolicyAction.INFORM_DEVELOPER:
        if prefs.notification_level == "off":
            return False, "notifications_disabled"
        return True, "notifications_enabled"
    if action is PolicyAction.DISPLAY_VULNERABILITY_WARNING:
        if not prefs.allow_warnings:
            return False, "warnings_not_consented"
        return True, "warnings_consented"
    if action is PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES:
        if not prefs.allow_practice_recommendations:
            return False, "practice_recommendations_not_consented"
        return True, "practice_recommendations_consented"
    if action is PolicyAction.REQUEST_ADDITIONAL_ANALYSIS:
        if not prefs.allow_additional_analysis:
            return False, "additional_analysis_not_consented"
        return True, "additional_analysis_consented"
    if action is PolicyAction.PERFORM_COUNTERFACTUAL_ANALYSIS:
        if not caps.supports_counterfactual:
            return False, "counterfactual_capability_absent"
        if not prefs.allow_counterfactual_analysis:
            return False, "counterfactual_analysis_not_consented"
        return True, "counterfactual_capability_and_consent"
    if action is PolicyAction.APPLY_ACTIVATION_STEERING:
        if not caps.supports_activation_steering:
            return False, "steering_capability_absent"
        if caps.activation_steering_pipeline != "validated":
            return False, "steering_pipeline_not_validated"
        if not prefs.allow_activation_steering:
            return False, "activation_steering_not_consented"
        return True, "validated_local_steering"
    if action is PolicyAction.GENERATE_SECURE_CODE_ALTERNATIVES:
        if not context.candidate_available:
            return False, "no_repair_candidate_available"
        if not caps.supports_secure_code_generation:
            return False, "secure_generation_capability_absent"
        if not prefs.allow_secure_code_generation:
            return False, "secure_generation_not_consented"
        return True, "generation_capability_and_consent"
    if action is PolicyAction.REQUEST_INDEPENDENT_VERIFICATION:
        if not caps.verification_available and not prefs.require_independent_verification:
            return False, "verification_unavailable_and_not_required"
        if not caps.verification_available:
            return True, "verification_unavailable_request_surfaces_gap"
        return True, "verification_available"
    if action is PolicyAction.REJECT_UNSAFE_REPAIR_CANDIDATE:
        if (
            not context.candidate_rejection_reasons
            and context.verification_status is not VerificationStatus.FAILED
            and prefs.enforcement != "blocking"
        ):
            return False, "rejection_requires_blocking_mode_or_failed_verification"
        return True, "rejection_grounds_present"
    return False, "unknown_action"


def _modulators(context: PolicyContext) -> tuple[float, float, float]:
    """Return efficacy, cost, and harm multipliers derived from evidence."""
    risk = context.risk_index if context.risk_index is not None else 0.0
    evidence = context.evidence_strength if context.evidence_strength is not None else 0.0
    probability = (
        context.calibrated_probability if context.calibrated_probability is not None else 0.0
    )
    urgency = max(risk, probability)
    uncertainty = context.uncertainty if context.uncertainty is not None else 1.0
    efficacy_factor = 0.5 * urgency + 0.5 * evidence
    cost_factor = 1.0
    harm_factor = 0.5 + uncertainty
    return efficacy_factor, cost_factor, harm_factor


def adaptive_rank(
    context: PolicyContext,
    config: PolicyConfig,
    candidates: tuple[PolicyAction, ...],
) -> tuple[tuple[UtilityScore, ...], tuple[PolicyAction, ...], tuple[str, ...]]:
    """Rank candidate actions by the configured preference utility.

    Only permitted actions with a positive score are recommended. Every
    blocked action is recorded with its reason, including capability gaps for
    steering and counterfactual analysis.
    """
    efficacy_factor, cost_factor, harm_factor = _modulators(context)
    scores: list[UtilityScore] = []
    blocked: list[str] = []
    for action in candidates:
        allowed, reason = action_gate(action, context)
        benefit = config.utility.efficacy[action.value] * efficacy_factor
        cost = config.utility.cost[action.value] * cost_factor
        harm = config.utility.harm[action.value] * harm_factor
        score = benefit - cost - harm
        scores.append(
            UtilityScore(
                action=action,
                benefit=round(benefit, 6),
                cost=round(cost, 6),
                harm=round(harm, 6),
                score=round(score, 6),
                allowed=allowed,
                reason=reason,
            )
        )
        if not allowed:
            blocked.append(f"{action.value}: {reason}")

    ranked = tuple(
        item.action
        for item in sorted(scores, key=lambda value: value.score, reverse=True)
        if item.allowed and item.score > 0.0
    )
    return tuple(scores), ranked, tuple(blocked)


OBJECTIVE = (
    "preference_weighted_utility_ranking: maximize sum(efficacy*benefit_weight) "
    "- sum(cost*cost_weight) - sum(harm*harm_weight) over consented actions; "
    "deterministic, not learned, and not claimed to be optimal"
)


__all__ = ["OBJECTIVE", "action_gate", "adaptive_rank"]
