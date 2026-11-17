from __future__ import annotations

import numpy as np
import pytest
from mathematics.adaptive_steering import (
    AdaptiveSteeringConfig,
    FeatureImportance,
    allocate_feature_strengths,
    apply_adaptive_steering,
    build_position_schedule,
    plan_adaptive_steering,
    rank_feature_importance,
    resolve_direction,
)
from mathematics.sae_encoding import SAEParameters


def identity_sae(dim: int = 2) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_ranking_is_deterministic_with_ties():
    ranked = rank_feature_importance({5: 1.0, 2: 1.0, 9: 2.0}, direction_mode="positive")
    assert [item.feature_index for item in ranked] == [9, 2, 5]
    assert [item.score for item in ranked] == [2.0, 1.0, 1.0]
    limited = rank_feature_importance(
        {5: 1.0, 2: 1.0, 9: 2.0}, direction_mode="positive", max_features=2
    )
    assert [item.feature_index for item in limited] == [9, 2]


def test_direction_semantics():
    assert resolve_direction(None, "positive") == 1.0
    assert resolve_direction(None, "negative") == -1.0
    assert resolve_direction(0.5, "association_reducing") == -1.0
    assert resolve_direction(-0.5, "association_reducing") == 1.0
    assert resolve_direction(0.0, "association_reducing") == 1.0
    with pytest.raises(ValueError):
        resolve_direction(None, "association_reducing")


def test_individual_and_interaction_allocation():
    allocation = allocate_feature_strengths(
        {0: 1.0, 1: 2.0},
        mean_differences={0: 1.0, 1: -1.0},
        pairwise_contrasts={(0, 1): 2.0},
        config=AdaptiveSteeringConfig(max_features=2),
    )
    assert allocation.selected_features == (1, 0)
    assert allocation.individual_terms == {1: 2.0, 0: -1.0}
    assert allocation.per_feature_clipped[1] == pytest.approx(3.0)
    assert allocation.per_feature_clipped[0] == pytest.approx(0.0)
    assert allocation.strengths[1] == pytest.approx(3.0)
    assert allocation.interaction_terms[0].per_feature_contribution == pytest.approx(1.0)
    assert allocation.l2_norm == pytest.approx(3.0)


def test_context_and_per_feature_clipping():
    allocation = allocate_feature_strengths(
        {0: 1.0, 1: 2.0},
        mean_differences={0: 1.0, 1: -1.0},
        pairwise_contrasts={(0, 1): 2.0},
        config=AdaptiveSteeringConfig(max_features=2, context_multiplier=2.0, max_strength=5.0),
    )
    assert allocation.context_adjustment == 2.0
    assert allocation.per_feature_clipped[1] == pytest.approx(5.0)
    assert allocation.strengths[1] == pytest.approx(5.0)


def test_l2_budget_scales_all_strengths():
    allocation = allocate_feature_strengths(
        {0: 1.0, 1: 2.0},
        mean_differences={0: 1.0, 1: -1.0},
        pairwise_contrasts={(0, 1): 2.0},
        config=AdaptiveSteeringConfig(max_features=2, l2_budget=1.5),
    )
    strengths = np.asarray(list(allocation.strengths.values()))
    assert allocation.l2_norm == pytest.approx(3.0)
    assert allocation.l2_scale == pytest.approx(0.5)
    assert np.linalg.norm(strengths) == pytest.approx(1.5)
    assert allocation.strengths[1] == pytest.approx(1.5)


def test_position_schedule_uses_strict_activation_threshold():
    schedule = build_position_schedule(
        {0: 2.0, 1: -3.0},
        {
            0: {0: 1.0, 1: 0.0},
            1: {0: 0.0, 1: 2.0},
            2: {0: 0.5, 1: 0.5},
        },
        activation_threshold=0.5,
        activation_reference=1.0,
    )
    assert [item.position for item in schedule] == [0, 1, 2]
    assert schedule[0].active_features == (0,)
    np.testing.assert_allclose(schedule[0].strengths, [2.0])
    assert schedule[1].active_features == (1,)
    # 2.0 measured activation / 1.0 reference scales -3.0 to -6.0.
    np.testing.assert_allclose(schedule[1].strengths, [-6.0])
    assert schedule[2].active_features == ()


def test_apply_steering_uses_decoder_directions():
    plan = plan_adaptive_steering(
        [FeatureImportance(0, 1.0, 1.0), FeatureImportance(1, 1.0, -1.0)],
        config=AdaptiveSteeringConfig(max_features=2),
    )
    application = apply_adaptive_steering(
        np.asarray([[1.0, 2.0], [3.0, 4.0]]), identity_sae(), plan
    )
    np.testing.assert_allclose(application.modified, [[2.0, 1.0], [4.0, 3.0]])
    np.testing.assert_allclose(application.strength_vector, [1.0, -1.0])
    assert application.delta_l2_norm == pytest.approx(np.sqrt(2.0))
    assert application.changed_count == 4


def test_selected_feature_subset_and_empty_plan():
    plan = plan_adaptive_steering(
        [FeatureImportance(0, 1.0, 1.0), FeatureImportance(1, 2.0, -1.0)],
        config=AdaptiveSteeringConfig(max_features=2),
        selected_features=[0],
    )
    assert plan.selected_features == (0,)
    empty = plan_adaptive_steering({}, config=AdaptiveSteeringConfig())
    assert empty.selected_features == ()
    application = apply_adaptive_steering(np.zeros((1, 2)), identity_sae(), empty)
    np.testing.assert_allclose(application.modified, 0.0)
    assert application.changed_count == 0


def test_validation_errors():
    with pytest.raises(ValueError):
        AdaptiveSteeringConfig(max_order=1)
    with pytest.raises(ValueError):
        AdaptiveSteeringConfig(l2_budget=0.0)
    with pytest.raises(ValueError):
        rank_feature_importance(
            {0: 1.0}, mean_differences={}, direction_mode="association_reducing"
        )
    with pytest.raises(ValueError):
        rank_feature_importance({0: np.inf}, direction_mode="positive")
    with pytest.raises(ValueError):
        allocate_feature_strengths([FeatureImportance(0, 1.0, 1.0)], selected_features=[2])
    with pytest.raises(ValueError):
        build_position_schedule({0: 1.0}, {0: {0: 1.0}}, activation_reference=0.0)
