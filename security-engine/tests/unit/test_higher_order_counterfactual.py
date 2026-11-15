from __future__ import annotations

import pytest

from craftsec.counterfactual import (
    FeatureSubset,
    HigherOrderInteractionEngine,
    estimate_higher_order,
    generate_feature_subsets,
)


def test_three_way_factorial_contrast_detects_known_order_three_effect() -> None:
    # Outcome = 2 + A + 2B + 3C + 7ABC; the third-order contrast is 7.
    def runner(interventions: dict[int, float], _replicate: int) -> float:
        a = interventions.get(1, 0.0)
        b = interventions.get(2, 0.0)
        c = interventions.get(3, 0.0)
        return 2.0 + a + 2.0 * b + 3.0 * c + 7.0 * a * b * c

    experiment = HigherOrderInteractionEngine(
        experiment_id="synthetic-order-three",
        outcome_scale="risk_score",
        repetitions=3,
        max_order=3,
        seed=4,
    ).run((FeatureSubset((1, 2, 3)),), runner)

    result = experiment.results[0]
    assert result.estimate.contrast == pytest.approx(7.0)
    assert result.estimate.standard_error == pytest.approx(0.0)
    assert result.estimate.confidence_interval_95 == pytest.approx((7.0, 7.0))
    assert experiment.complexity.observed_cell_evaluations == 8 * 3


def test_subset_generation_sampling_and_budget_bound_work() -> None:
    subsets = generate_feature_subsets(
        [1, 2, 3, 4, 5],
        min_order=2,
        max_order=4,
        max_subsets=3,
        sampling_strategy="random",
        seed=9,
    )
    assert len(subsets) == 3
    assert subsets == generate_feature_subsets(
        [1, 2, 3, 4, 5],
        min_order=2,
        max_order=4,
        max_subsets=3,
        sampling_strategy="random",
        seed=9,
    )

    calls = 0

    def runner(_interventions: dict[int, float], _replicate: int) -> float:
        nonlocal calls
        calls += 1
        return 1.0

    experiment = HigherOrderInteractionEngine(
        experiment_id="budget",
        outcome_scale="score",
        repetitions=2,
        max_order=3,
    ).run((FeatureSubset((1, 2, 3)),), runner, budget=4)
    assert len(experiment.results) == 0
    assert calls == 4
    assert experiment.complexity.observed_cell_evaluations == 4


def test_single_pair_and_higher_order_results_can_be_ranked_together() -> None:
    def runner(interventions: dict[int, float], _replicate: int) -> float:
        return sum(interventions.values())

    engine = HigherOrderInteractionEngine(
        experiment_id="orders",
        outcome_scale="security_score",
        repetitions=1,
        max_order=3,
    )
    experiment = engine.run(
        (FeatureSubset((1,)), FeatureSubset((1, 2)), FeatureSubset((1, 2, 3))),
        runner,
    )
    assert [result.estimate.contrast for result in experiment.results] == [1.0, 0.0, 0.0]
    assert "no significance test" in experiment.results[-1].estimate.uncertainty_method


def test_missing_factorial_cell_is_rejected() -> None:
    with pytest.raises(ValueError, match="all factorial cells"):
        estimate_higher_order(
            FeatureSubset((1, 2)),
            {"baseline": (0.0,), "1": (1.0,), "2": (1.0,)},
            outcome_scale="score",
        )
