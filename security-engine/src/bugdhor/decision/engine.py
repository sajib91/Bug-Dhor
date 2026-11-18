"""Composition of the transparent baseline and adaptive decision policy."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from bugdhor.decision.adaptive import OBJECTIVE, action_gate, adaptive_rank
from bugdhor.decision.config import PolicyConfig
from bugdhor.decision.models import (
    DecisionTrace,
    DeveloperPreferences,
    ModelCapabilities,
    PolicyAction,
    PolicyContext,
    PolicyDecision,
    VerificationStatus,
    context_hash,
)
from bugdhor.decision.rules import actions_from_rules, evaluate_rules
from bugdhor.risk.models import RiskResult, canonical_hash

_RULE_OBJECTIVE = (
    "transparent_rule_baseline: ordered documented rules, no learned weights, "
    "no utility maximization, and no optimality claim"
)


class DecisionEngine:
    """Produce a traceable, advisory decision for one finding."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.config_hash = config.config_hash()

    def decide(self, context: PolicyContext) -> PolicyDecision:
        """Evaluate rules, then rank or pass through according to the mode."""
        resolved = replace(
            context,
            preferences=context.preferences or self.config.preferences,
        )
        rules = evaluate_rules(resolved, self.config)
        candidates = actions_from_rules(rules)

        gate_results = {action: action_gate(action, resolved) for action in PolicyAction}
        blocked = [
            f"{action.value}: {reason}"
            for action, (allowed, reason) in gate_results.items()
            if not allowed
        ]
        permitted_baseline = [action for action in candidates if gate_results[action][0]]

        utility_scores = ()
        if self.config.mode == "adaptive":
            utility_scores, actions, _ = adaptive_rank(resolved, self.config, candidates)
        else:
            actions = tuple(permitted_baseline)

        primary = actions[0] if actions else None
        rationale = tuple(rule.rationale for rule in rules if rule.matched)
        decision_id = canonical_hash(
            {
                "configHash": self.config_hash,
                "contextHash": context_hash(resolved),
                "mode": self.config.mode,
            }
        )
        trace = DecisionTrace(
            decision_id=decision_id,
            mode=self.config.mode,
            config_hash=self.config_hash,
            rules=rules,
            utility_scores=utility_scores,
            blocked_actions=tuple(sorted(set(blocked))),
            objective=OBJECTIVE if self.config.mode == "adaptive" else _RULE_OBJECTIVE,
            context=resolved.to_dict(),
        )
        return PolicyDecision(
            actions=actions,
            primary_action=primary,
            rationale=rationale,
            trace=trace,
            baseline_actions=tuple(permitted_baseline),
        )


def context_from_risk(
    result: RiskResult,
    *,
    capabilities: ModelCapabilities | None = None,
    preferences: DeveloperPreferences | None = None,
    candidate_available: bool = False,
    candidate_rejection_reasons: Sequence[str] = (),
    verification_status: VerificationStatus = VerificationStatus.NOT_APPLICABLE,
) -> PolicyContext:
    """Project a risk assessment into the policy's decision context.

    SAE and counterfactual observations are forwarded as descriptive evidence.
    Their epistemic status is preserved by the risk engine, and the policy's
    gates require explicit capability and consent before acting on them.
    """
    sae_features = {
        index: item.value
        for index, item in enumerate(
            item for item in result.normalized_evidence if item.source.value == "sae_activation"
        )
    }
    interactions = tuple(
        {
            "sourceId": item.source_id,
            "value": item.value,
            "polarity": item.polarity.value,
            "rationale": item.rationale,
        }
        for item in result.normalized_evidence
        if item.source.value == "counterfactual_interaction"
    )
    return PolicyContext(
        cwe=result.cwe,
        risk_index=result.index,
        risk_band=result.band,
        evidence_strength=result.uncertainty.coverage,
        uncertainty=result.uncertainty.value,
        calibrated_probability=result.probability,
        sae_features=sae_features,
        feature_interactions=interactions,
        model_capabilities=capabilities or ModelCapabilities(),
        verification_status=verification_status,
        preferences=preferences,
        candidate_available=candidate_available,
        candidate_rejection_reasons=tuple(candidate_rejection_reasons),
        score_kind=result.score_kind,
        calibration_status=result.calibration.status if result.calibration else None,
    )


__all__ = ["DecisionEngine", "context_from_risk"]
