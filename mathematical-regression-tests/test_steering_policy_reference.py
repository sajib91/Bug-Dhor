"""Independent arithmetic checks for the risk controller and adaptive policy.

These tests rebuild the priority, band, strength, importance, direction, and
schedule formulas from their stated definitions.  They use hand-constructed
feature dictionaries and evidence so that the expected values are visible in
the test rather than produced by the module under test.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from bugdhor.counterfactual.higher_order import (
    HigherOrderInteractionEngine,
    generate_feature_subsets,
)
from bugdhor.counterfactual.pairwise import FeaturePair, PairwiseInteractionEngine
from bugdhor.sae.association import (
    FeatureAssociation,
    FeatureDictionary,
    FeatureDictionaryEntry,
    FeatureExperimentMetadata,
    FeatureStability,
)
from bugdhor.steering.adaptive import (
    AdaptiveSteeringConfig,
    AdaptiveSteeringContext,
    AdaptiveSteeringPolicy,
)
from bugdhor.steering.risk_controller import (
    CweRiskController,
    CweRiskPolicy,
    RiskAssessmentInput,
    StaticEvidence,
)


def _association(
    feature: int,
    *,
    difference: float | None,
    vulnerable_frequency: float | None,
    secure_frequency: float | None,
) -> FeatureAssociation:
    return FeatureAssociation(
        feature_index=feature,
        sample_count=4,
        vulnerable_count=2,
        secure_count=2,
        activation_frequency=0.5,
        vulnerable_activation_frequency=vulnerable_frequency,
        secure_activation_frequency=secure_frequency,
        vulnerable_mean_activation=None,
        secure_mean_activation=None,
        mean_activation_difference=difference,
        active_precision=0.5,
        active_recall=0.5,
        association_direction=(
            None
            if difference is None
            else ("positive" if difference > 0 else "negative")
        ),
    )


def _entry(
    feature: int,
    *,
    difference: float | None,
    vulnerable_frequency: float | None,
    secure_frequency: float | None,
    cwe: str = "CWE-89",
) -> FeatureDictionaryEntry:
    association = _association(
        feature,
        difference=difference,
        vulnerable_frequency=vulnerable_frequency,
        secure_frequency=secure_frequency,
    )
    selectivity = (
        None
        if vulnerable_frequency is None or secure_frequency is None
        else vulnerable_frequency - secure_frequency
    )
    return FeatureDictionaryEntry(
        feature_index=feature,
        association=association,
        cwe_associations={cwe: association},
        selectivity=selectivity,
        stability=FeatureStability({}, None, 0),
    )


def _dictionary(entries: tuple[FeatureDictionaryEntry, ...]) -> FeatureDictionary:
    return FeatureDictionary(
        metadata=FeatureExperimentMetadata(
            model_id="local/tiny",
            model_version="1",
            layer="transformer.h.0",
            sae_checkpoint="sae.pt",
            dataset_ids=("dataset",),
            experiment_id="policy-reference",
            activation_threshold=0.0,
        ),
        entries=entries,
    )


def _policy() -> AdaptiveSteeringPolicy:
    # Feature 0: selectivity +0.5, difference +0.5 -> association_reducing is -1.
    # Feature 1: selectivity -0.3, difference -0.2 -> association_reducing is +1.
    return AdaptiveSteeringPolicy(
        _dictionary(
            (
                _entry(
                    0,
                    difference=0.5,
                    vulnerable_frequency=0.8,
                    secure_frequency=0.3,
                ),
                _entry(
                    1,
                    difference=-0.2,
                    vulnerable_frequency=0.2,
                    secure_frequency=0.5,
                ),
            )
        ),
        config=AdaptiveSteeringConfig(
            max_features=2,
            base_strength=1.0,
            individual_weight=1.0,
            minimum_importance=0.1,
            direction_mode="association_reducing",
            context_multiplier=1.0,
            max_strength=10.0,
            enabled=False,
        ),
    )


def test_adaptive_selection_uses_absolute_selectivity_and_index_tiebreak() -> None:
    decision = _policy().plan()
    assert decision.selected_features == (0, 1)
    assert [item.score for item in decision.feature_importance] == pytest.approx([0.5, 0.3])
    assert [item.direction for item in decision.feature_importance] == pytest.approx([-1.0, 1.0])


def test_adaptive_individual_effects_apply_weight_score_and_direction() -> None:
    decision = _policy().plan()
    # individual = base_strength * individual_weight * |score| * direction
    assert decision.individual_effects == pytest.approx({0: -0.5, 1: 0.3})
    assert decision.context_adjustment == pytest.approx(1.0)
    assert decision.strengths == pytest.approx({0: -0.5, 1: 0.3})


def test_adaptive_context_multiplier_and_clamping_match_definition() -> None:
    policy = _policy()
    decision = policy.plan(
        AdaptiveSteeringContext(context_multiplier=4.0)
    )
    # base effects are -0.5 and +0.3; scale by 4 then clamp to +/-10.
    assert decision.strengths == pytest.approx({0: -2.0, 1: 1.2})
    assert decision.context_adjustment == pytest.approx(4.0)

    tight = AdaptiveSteeringPolicy(
        policy.feature_dictionary,
        config=AdaptiveSteeringConfig(
            max_features=2,
            base_strength=1.0,
            direction_mode="association_reducing",
            context_multiplier=100.0,
            max_strength=1.0,
            enabled=False,
        ),
    ).plan()
    assert tight.strengths == pytest.approx({0: -1.0, 1: 1.0})


def test_adaptive_direction_modes_and_missing_difference_are_explicit() -> None:
    positive = AdaptiveSteeringPolicy(
        _policy().feature_dictionary,
        config=AdaptiveSteeringConfig(max_features=2, direction_mode="positive"),
    ).plan()
    assert [item.direction for item in positive.feature_importance] == [1.0, 1.0]

    negative = AdaptiveSteeringPolicy(
        _policy().feature_dictionary,
        config=AdaptiveSteeringConfig(max_features=2, direction_mode="negative"),
    ).plan()
    assert [item.direction for item in negative.feature_importance] == [-1.0, -1.0]

    missing = AdaptiveSteeringPolicy(
        _dictionary(
            (
                _entry(
                    3,
                    difference=None,
                    vulnerable_frequency=None,
                    secure_frequency=None,
                ),
            )
        ),
        config=AdaptiveSteeringConfig(max_features=1),
    ).plan()
    # A one-class association has no measured direction; no sign is invented.
    assert missing.selected_features == ()
    assert missing.individual_effects == {}

    zero = AdaptiveSteeringPolicy(
        _dictionary(
            (
                _entry(
                    4,
                    difference=0.0,
                    vulnerable_frequency=0.5,
                    secure_frequency=0.5,
                ),
            )
        ),
        config=AdaptiveSteeringConfig(max_features=1),
    ).plan()
    # A measured zero difference also yields no direction: 1.0 * 0.0 * 0.0 = 0.0.
    assert zero.selected_features == (4,)
    assert [item.direction for item in zero.feature_importance] == [0.0]
    assert zero.individual_effects == {4: 0.0}
    assert zero.strengths == {4: 0.0}


def test_adaptive_cwe_specific_importance_uses_the_cwe_association() -> None:
    entry = _entry(
        5,
        difference=0.1,
        vulnerable_frequency=0.6,
        secure_frequency=0.4,
    )
    policy = AdaptiveSteeringPolicy(
        _dictionary((entry,)),
        config=AdaptiveSteeringConfig(max_features=1, cwe="CWE-89"),
    )
    decision = policy.plan(AdaptiveSteeringContext(cwe="CWE-89"))
    # CWE-specific selectivity is 0.6 - 0.4 = 0.2.
    assert decision.feature_importance[0].score == pytest.approx(0.2)
    assert decision.individual_effects[5] == pytest.approx(-0.2)


def test_adaptive_schedule_scales_by_observed_activation() -> None:
    decision = _policy().plan(
        AdaptiveSteeringContext(
            target_positions=(0, 1),
            feature_activations_by_position={
                0: {0: 2.0, 1: 0.0},
                1: {0: 1.0, 1: 3.0},
            },
        )
    )
    # activation_reference defaults to 1.0; scale is |observed| / 1.0.
    position_0, active_0, values_0 = decision.schedule[0]
    assert position_0 == 0
    assert active_0 == (0,)
    assert values_0 == pytest.approx((-1.0, 0.0))  # strength -0.5 * 2.0

    position_1, active_1, values_1 = decision.schedule[1]
    assert position_1 == 1
    assert active_1 == (0, 1)
    assert values_1 == pytest.approx((-0.5, 0.9))  # +0.3 * 3.0


def test_adaptive_pairwise_and_higher_order_contributions_are_allocated_by_order() -> None:
    dictionary = _dictionary(
        (
            _entry(0, difference=0.5, vulnerable_frequency=0.8, secure_frequency=0.3),
            _entry(1, difference=-0.2, vulnerable_frequency=0.2, secure_frequency=0.5),
            _entry(2, difference=0.1, vulnerable_frequency=0.6, secure_frequency=0.5),
        )
    )
    pairwise = PairwiseInteractionEngine(
        experiment_id="pair-reference",
        outcome_scale="logit",
    ).run(
        FeaturePair(0, 1),
        lambda interventions, _repetition: (
            interventions.get(0, 0.0) * interventions.get(1, 0.0)
        ),
    )
    higher = HigherOrderInteractionEngine(
        experiment_id="higher-reference",
        outcome_scale="logit",
        max_order=3,
    ).run(
        generate_feature_subsets((0, 1, 2), min_order=3, max_order=3),
        lambda interventions, _repetition: (
            interventions.get(0, 0.0)
            * interventions.get(1, 0.0)
            * interventions.get(2, 0.0)
        ),
    )
    config = AdaptiveSteeringConfig(
        max_features=3,
        base_strength=2.0,
        individual_weight=1.0,
        pairwise_weight=3.0,
        higher_order_weight=4.0,
        minimum_importance=0.0,
        direction_mode="association_reducing",
        context_multiplier=1.0,
        max_strength=100.0,
        enabled=False,
    )
    decision = AdaptiveSteeringPolicy(
        dictionary,
        pairwise_results=(pairwise,),
        higher_order_results=higher.results,
        config=config,
    ).plan()

    pair = decision.pairwise_interactions[0]
    assert pair.features == (0, 1)
    assert pair.weighted_contribution == pytest.approx(
        config.base_strength * config.pairwise_weight * pairwise.estimate.contrast
    )

    triple = decision.higher_order_interactions[0]
    assert triple.features == (0, 1, 2)
    assert triple.order == 3
    assert triple.weighted_contribution == pytest.approx(
        config.base_strength * config.higher_order_weight * higher.results[0].estimate.contrast
    )

    # Individual terms: base * |score| * direction.
    expected = {0: 2.0 * 0.5 * -1.0, 1: 2.0 * 0.3 * 1.0, 2: 2.0 * 0.1 * -1.0}
    per_pair = pair.weighted_contribution / 2
    for feature in pair.features:
        expected[feature] += per_pair
    per_triple = triple.weighted_contribution / 3
    for feature in triple.features:
        expected[feature] += per_triple
    assert decision.strengths == pytest.approx(expected)


def _risk_policy(**overrides) -> CweRiskPolicy:
    values = {
        "cwe": "CWE-89",
        "priority_offset": 0.1,
        "feature_weight": 1.0,
        "interaction_weight": 1.0,
        "static_weight": 1.0,
        "heuristic_weight": 1.0,
        "feature_activation_threshold": 0.5,
        "interaction_threshold": 0.3,
        "static_evidence_threshold": 0.1,
        "steering_threshold": 1.0,
        "steering_base_strength": 0.5,
        "steering_scale": 0.1,
        "max_steering_strength": 2.0,
        "max_priority": 100.0,
        "priority_bands": {"low": 0.0, "medium": 1.0, "high": 3.0},
        "context_multipliers": {"risk=high": 2.0},
    }
    values.update(overrides)
    return CweRiskPolicy(**values)


def _risk_controller() -> CweRiskController:
    return CweRiskController({"CWE-89": _risk_policy()})


def test_risk_priority_band_and_strength_match_the_stated_formula() -> None:
    controller = _risk_controller()
    evidence = RiskAssessmentInput(
        cwe="CWE-89",
        model_id="local/tiny",
        model_version="1",
        source_context={"risk": "high"},
        feature_activations={1: 2.0, 2: 0.1},
        feature_importance={1: 0.5},
        feature_interactions=({"contrast": 0.4}, {"contrast": 0.1}),
        static_evidence=(
            StaticEvidence("r1", 0.6, "supports", "CWE-89"),
            StaticEvidence("r2", 0.2, "refutes", "CWE-89"),
            StaticEvidence("r3", 0.9, "supports", "CWE-79"),
        ),
        heuristic_risk=0.5,
    )
    decision = controller.assess(evidence)

    # feature = 2.0 * 0.5 = 1.0; only interaction 0.4 exceeds the 0.3 threshold;
    # static = +0.6 - 0.2 (CWE-79 row is excluded); heuristic = 0.5.
    assert decision.component_scores == pytest.approx(
        {"features": 1.0, "interactions": 0.4, "static": 0.4, "heuristic": 0.5}
    )
    assert decision.context_multiplier == pytest.approx(2.0)
    # (0.1 + 1.0 + 0.4 + 0.4 + 0.5) * 2.0 = 4.8
    assert decision.heuristic_priority == pytest.approx(4.8)
    assert decision.risk_band == "high"
    # (0.5 + 4.8 * 0.1) * 2.0 = 1.96, below the 2.0 cap.
    assert decision.steering_strength == pytest.approx(1.96)
    assert decision.steering_enabled is True
    assert "model-specific calibration unavailable" in decision.fallback_reasons
    assert decision.calibrated_probability is None
    assert decision.risk_interpretation == "heuristic_risk; not a probability"


def test_risk_controller_priority_clamp_and_strength_cap() -> None:
    controller = CweRiskController(
        {
            "CWE-89": _risk_policy(
                max_priority=1.0,
                steering_base_strength=0.75,
                steering_scale=1.0,
                max_steering_strength=0.75,
            )
        }
    )
    decision = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-89",
            model_id="m",
            model_version="v",
            feature_activations={1: 10.0},
            feature_importance={1: 10.0},
            heuristic_risk=10.0,
        )
    )
    assert decision.heuristic_priority == pytest.approx(1.0)
    assert decision.risk_band == "medium"
    assert decision.steering_strength == pytest.approx(0.75)


def test_risk_controller_disables_steering_without_feature_evidence() -> None:
    controller = _risk_controller()
    decision = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-89",
            model_id="m",
            model_version="v",
            feature_activations={1: 0.1},
            heuristic_risk=5.0,
        )
    )
    assert decision.feature_evidence_available is False
    assert decision.steering_strength == 0.0
    assert decision.steering_enabled is False
    assert any("SAE feature evidence" in reason for reason in decision.fallback_reasons)


def test_risk_controller_accepts_direct_contrast_objects_and_missing_policy() -> None:
    direct = SimpleNamespace(contrast=0.8)
    controller = _risk_controller()
    decision = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-89",
            model_id="m",
            model_version="v",
            feature_interactions=(direct,),
        )
    )
    # A direct ``.contrast`` attribute is read without unwrapping an estimate.
    assert decision.component_scores["interactions"] == pytest.approx(0.8)

    unavailable = CweRiskController({}).assess(
        RiskAssessmentInput(cwe="CWE-999", model_id="m", model_version="v")
    )
    assert unavailable.risk_band == "unavailable"
    assert unavailable.heuristic_priority == 0.0
    assert unavailable.steering_enabled is False
    assert unavailable.fallback_reasons
