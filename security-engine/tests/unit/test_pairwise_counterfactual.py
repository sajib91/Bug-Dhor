from __future__ import annotations

import pytest

from craftsec.counterfactual import (
    FeaturePair,
    PairwiseCell,
    PairwiseInteractionEngine,
    estimate_interaction,
    rank_interactions,
    select_feature_pairs,
)


def test_pairwise_contrast_detects_non_additive_synthetic_effect() -> None:
    # Outcome = 1 + 2A + 3B + 5AB, so the interaction contrast is exactly 5.
    def runner(interventions: dict[int, float], _replicate: int) -> float:
        a = interventions.get(1, 0.0)
        b = interventions.get(2, 0.0)
        return 1.0 + 2.0 * a + 3.0 * b + 5.0 * a * b

    result = PairwiseInteractionEngine(
        experiment_id="synthetic",
        outcome_scale="risk_score",
        repetitions=3,
        seed=7,
    ).run(FeaturePair(1, 2), runner, feature_a_value=1.0, feature_b_value=1.0)

    assert result.estimate.contrast == pytest.approx(5.0)
    assert result.estimate.standard_error == pytest.approx(0.0)
    assert result.estimate.confidence_interval_95 == pytest.approx((5.0, 5.0))
    assert "not a significance test" in result.estimate.uncertainty_method


def test_pair_selection_and_ranking_are_deterministic() -> None:
    assert select_feature_pairs([3, 1, 2], max_pairs=2) == (
        FeaturePair(1, 2),
        FeaturePair(1, 3),
    )
    assert FeaturePair(4, 1).ordered == (1, 4)
    assert rank_interactions([], absolute=True) == ()


def test_uncertainty_is_not_reported_for_single_replicate_cells() -> None:
    cells = [
        # baseline, A, B, AB
        (0.0, 1.0, 1.0, 3.0),
    ]
    result = estimate_interaction(
        *[
            PairwiseCell(
                name=name,
                interventions={},
                outcomes=(value,),
            )
            for name, value in zip(("baseline", "a", "b", "ab"), cells[0], strict=True)
        ],
        outcome_scale="probability",
    )
    assert result.contrast == pytest.approx(1.0)
    assert result.standard_error is None
    assert result.confidence_interval_95 is None
