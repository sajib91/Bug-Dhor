"""Contract tests for the advisory rule-baseline and adaptive decision policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugdhor.decision import (
    DecisionEngine,
    DeveloperPreferences,
    ModelCapabilities,
    PolicyAction,
    PolicyConfig,
    PolicyContext,
    VerificationStatus,
    context_from_risk,
)
from bugdhor.decision.config import UtilityConfig
from bugdhor.risk.config import default_risk_config
from bugdhor.risk.engine import FindingRiskInput, UnifiedRiskEngine
from bugdhor.risk.models import (
    EvidenceObservation,
    EvidencePolarity,
    EvidenceSource,
    ReliabilityEvidence,
)

CONFIG_PATH = (
    Path(__file__).resolve().parents[3] / "research" / "configs" / "risk" / "policy.json"
)


def make_config(
    mode: str = "rule_baseline",
    preferences: DeveloperPreferences | None = None,
) -> PolicyConfig:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    payload["mode"] = mode
    if preferences is not None:
        payload["preferences"] = {
            "notificationLevel": preferences.notification_level,
            "allowWarnings": preferences.allow_warnings,
            "allowPracticeRecommendations": preferences.allow_practice_recommendations,
            "allowAdditionalAnalysis": preferences.allow_additional_analysis,
            "allowCounterfactualAnalysis": preferences.allow_counterfactual_analysis,
            "allowActivationSteering": preferences.allow_activation_steering,
            "allowSecureCodeGeneration": preferences.allow_secure_code_generation,
            "requireIndependentVerification": preferences.require_independent_verification,
            "enforcement": preferences.enforcement,
            "basis": preferences.basis,
        }
    from bugdhor.decision import policy_config_from_mapping

    return policy_config_from_mapping(payload)


def context(
    *,
    preferences: DeveloperPreferences | None = None,
    capabilities: ModelCapabilities | None = None,
    risk_index: float | None = 0.9,
    risk_band: str = "critical",
    uncertainty: float | None = 0.2,
    evidence_strength: float | None = 0.8,
    **kwargs: object,
) -> PolicyContext:
    return PolicyContext(
        cwe="CWE-79",
        risk_index=risk_index,
        risk_band=risk_band,
        evidence_strength=evidence_strength,
        uncertainty=uncertainty,
        calibrated_probability=None,
        sae_features=kwargs.pop("sae_features", {}),
        feature_interactions=kwargs.pop("feature_interactions", ()),
        model_capabilities=capabilities or ModelCapabilities(),
        verification_status=kwargs.pop("verification_status", VerificationStatus.NOT_APPLICABLE),
        preferences=preferences,
        candidate_available=kwargs.pop("candidate_available", False),
        candidate_rejection_reasons=kwargs.pop("candidate_rejection_reasons", ()),
    )


def test_shipped_policy_config_is_loadable_and_documents_utility_basis() -> None:
    config = make_config()
    assert config.mode == "rule_baseline"
    assert config.utility.basis == "declared_developer_preferences_not_measured_effects"
    assert config.config_hash()
    assert set(config.utility.efficacy) == {action.value for action in PolicyAction}


def test_baseline_selects_inform_warning_and_practices_for_high_risk() -> None:
    decision = DecisionEngine(make_config()).decide(context())
    assert decision.trace.mode == "rule_baseline"
    assert PolicyAction.INFORM_DEVELOPER in decision.actions
    assert PolicyAction.DISPLAY_VULNERABILITY_WARNING in decision.actions
    assert PolicyAction.RECOMMEND_SECURE_CODING_PRACTICES in decision.actions
    assert decision.primary_action is PolicyAction.INFORM_DEVELOPER
    assert len(decision.trace.rules) == 9
    assert all(rule.observed for rule in decision.trace.rules)


def test_gates_record_blocked_actions_and_respect_notification_preferences() -> None:
    preferences = DeveloperPreferences(notification_level="off", allow_warnings=False)
    decision = DecisionEngine(make_config(preferences=preferences)).decide(context())
    assert PolicyAction.INFORM_DEVELOPER not in decision.actions
    assert PolicyAction.DISPLAY_VULNERABILITY_WARNING not in decision.actions
    assert "inform_developer: notifications_disabled" in decision.trace.blocked_actions
    assert "display_vulnerability_warning: warnings_not_consented" in decision.trace.blocked_actions


@pytest.mark.parametrize(
    ("capabilities", "preferences", "expected_reason"),
    [
        (ModelCapabilities(), DeveloperPreferences(), "counterfactual_capability_absent"),
        (
            ModelCapabilities(supports_counterfactual=True),
            DeveloperPreferences(),
            "counterfactual_analysis_not_consented",
        ),
    ],
)
def test_counterfactual_action_is_blocked_without_capability_and_consent(
    capabilities: ModelCapabilities, preferences: DeveloperPreferences, expected_reason: str
) -> None:
    decision = DecisionEngine(make_config(preferences=preferences)).decide(
        context(
            capabilities=capabilities,
            preferences=preferences,
            sae_features={0: 0.6},
            uncertainty=0.9,
        )
    )
    assert PolicyAction.PERFORM_COUNTERFACTUAL_ANALYSIS not in decision.actions
    assert any(
        reason.startswith("perform_counterfactual_analysis: " + expected_reason)
        for reason in decision.trace.blocked_actions
    )


def test_steering_requires_validated_local_pipeline_and_explicit_consent() -> None:
    capabilities = ModelCapabilities(
        supports_activation_steering=True,
        activation_steering_pipeline="none",
    )
    decision = DecisionEngine(make_config()).decide(
        context(capabilities=capabilities, sae_features={0: 0.9})
    )
    assert PolicyAction.APPLY_ACTIVATION_STEERING not in decision.actions
    assert any(
        "activation_steering: steering_pipeline_not_validated" in reason
        for reason in decision.trace.blocked_actions
    )

    validated = ModelCapabilities(
        supports_activation_steering=True,
        activation_steering_pipeline="validated",
    )
    consent = DeveloperPreferences(
        allow_activation_steering=True,
        allow_counterfactual_analysis=True,
    )
    allowed = DecisionEngine(make_config(preferences=consent)).decide(
        context(capabilities=validated, sae_features={0: 0.9}, uncertainty=0.9)
    )
    assert PolicyAction.APPLY_ACTIVATION_STEERING in allowed.actions
    assert not any(
        reason.startswith("apply_activation_steering: ")
        for reason in allowed.trace.blocked_actions
    )


def test_adaptive_mode_ranks_by_declared_utility_and_records_objective() -> None:
    capabilities = ModelCapabilities(supports_secure_code_generation=True)
    decision = DecisionEngine(make_config(mode="adaptive")).decide(
        context(capabilities=capabilities, candidate_available=True)
    )
    assert decision.trace.mode == "adaptive"
    assert "preference_weighted_utility_ranking" in decision.trace.objective
    assert "not learned" in decision.trace.objective
    assert "not claimed to be optimal" in decision.trace.objective
    assert len(decision.trace.utility_scores) >= 3
    assert all(score.allowed for score in decision.trace.utility_scores if score.score > 0)
    assert decision.actions == tuple(sorted(decision.actions, key=decision.actions.index))


def test_adaptive_ranking_drops_actions_with_non_positive_utility() -> None:
    config = make_config(mode="adaptive")
    utility = UtilityConfig(
        efficacy={action.value: 0.0 for action in PolicyAction},
        cost={action.value: 1.0 for action in PolicyAction},
        harm={action.value: 1.0 for action in PolicyAction},
        basis="synthetic_zero_benefit_utility",
    )
    from dataclasses import replace

    decision = DecisionEngine(replace(config, utility=utility)).decide(context())
    assert decision.actions == ()


def test_verification_and_rejection_are_enforced_before_recommendation() -> None:
    preferences = DeveloperPreferences(require_independent_verification=True)
    pending = DecisionEngine(make_config(preferences=preferences)).decide(
        context(
            capabilities=ModelCapabilities(supports_secure_code_generation=True),
            candidate_available=True,
            verification_status=VerificationStatus.NOT_RUN,
        )
    )
    assert PolicyAction.REQUEST_INDEPENDENT_VERIFICATION in pending.actions

    rejected = DecisionEngine(make_config(preferences=preferences)).decide(
        context(
            candidate_available=True,
            candidate_rejection_reasons=("functional_tests_failed",),
            verification_status=VerificationStatus.FAILED,
        )
    )
    assert PolicyAction.REJECT_UNSAFE_REPAIR_CANDIDATE in rejected.actions

    passed = DecisionEngine(make_config(preferences=preferences)).decide(
        context(
            candidate_available=True,
            verification_status=VerificationStatus.PASSED,
        )
    )
    assert PolicyAction.REQUEST_INDEPENDENT_VERIFICATION not in passed.actions


def test_trace_is_deterministic_and_changes_with_configuration() -> None:
    engine = DecisionEngine(make_config())
    first = engine.decide(context())
    second = engine.decide(context())
    assert first.trace.decision_id == second.trace.decision_id
    assert first.trace.decision_id == engine.decide(context()).trace.decision_id
    adaptive = DecisionEngine(make_config(mode="adaptive")).decide(context())
    assert adaptive.trace.decision_id != first.trace.decision_id
    assert first.trace.config_hash == engine.config_hash


def test_context_from_risk_preserves_epistemic_status() -> None:
    risk_result = UnifiedRiskEngine(default_risk_config()).assess(
        FindingRiskInput(
            finding_id="F-POLICY",
            cwe="CWE-79",
            observations=(
                EvidenceObservation(
                    source=EvidenceSource.SAE_ACTIVATION,
                    source_id="sae-3",
                    value=0.6,
                    reliability=ReliabilityEvidence(
                        validation_precision=0.8,
                        basis="synthetic_validation",
                    ),
                ),
                EvidenceObservation(
                    source=EvidenceSource.COUNTERFACTUAL_INTERACTION,
                    source_id="cf-3-4",
                    value=0.3,
                    polarity=EvidencePolarity.SUPPORTS,
                    reliability=ReliabilityEvidence(
                        validation_precision=0.7,
                        basis="synthetic_validation",
                    ),
                ),
            ),
        )
    )
    projected = context_from_risk(
        risk_result,
        capabilities=ModelCapabilities(supports_counterfactual=True),
        preferences=DeveloperPreferences(allow_counterfactual_analysis=True),
    )
    assert projected.sae_features == {0: 0.6}
    assert projected.feature_interactions[0]["sourceId"] == "cf-3-4"
    assert projected.risk_index == risk_result.index
    assert projected.risk_band == risk_result.band
    assert projected.score_kind == "heuristic_index"
    assert projected.calibrated_probability is None
