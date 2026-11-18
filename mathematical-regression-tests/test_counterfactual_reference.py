"""Independent checks of pairwise and higher-order factorial contrasts."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

import reference as ref
from bugdhor.counterfactual.higher_order import (
    FeatureSubset,
    estimate_higher_order,
    generate_feature_subsets,
)
from bugdhor.counterfactual.pairwise import (
    FeaturePair,
    PairwiseCell,
    PairwiseInteractionEngine,
    estimate_interaction,
    rank_interactions,
    select_feature_pairs,
)


def test_pairwise_contrast_and_independent_cell_se_match_reference() -> None:
    baseline = PairwiseCell("baseline", {}, (0.0, 1.0, 2.0))
    feature_a = PairwiseCell("feature_a", {0: 1.0}, (1.0, 2.0, 4.0))
    feature_b = PairwiseCell("feature_b", {1: 1.0}, (2.0, 2.0, 2.0))
    joint = PairwiseCell("joint", {0: 1.0, 1: 1.0}, (4.0, 5.0, 7.0))

    expected_contrast = (
        ref.mean(joint.outcomes)
        - ref.mean(feature_a.outcomes)
        - ref.mean(feature_b.outcomes)
        + ref.mean(baseline.outcomes)
    )
    expected_se = ref.independent_cell_standard_error(
        [joint.outcomes, feature_a.outcomes, feature_b.outcomes, baseline.outcomes]
    )
    estimate = estimate_interaction(
        baseline, feature_a, feature_b, joint, outcome_scale="logit"
    )
    assert estimate.contrast == pytest.approx(expected_contrast)
    assert estimate.standard_error == pytest.approx(expected_se)
    assert estimate.confidence_interval_95 == pytest.approx(
        (expected_contrast - 1.96 * expected_se, expected_contrast + 1.96 * expected_se)
    )
    assert "not a significance test" in estimate.uncertainty_method


def test_single_replicate_reports_unavailable_uncertainty() -> None:
    cell = lambda name, value: PairwiseCell(name, {}, (value,))
    estimate = estimate_interaction(
        cell("baseline", 0.0),
        cell("feature_a", 1.0),
        cell("feature_b", 2.0),
        cell("joint", 4.0),
        outcome_scale="probability",
    )
    assert estimate.contrast == pytest.approx(1.0)
    assert estimate.standard_error is None
    assert estimate.confidence_interval_95 is None


def test_higher_order_mobius_contrast_matches_reference() -> None:
    cells = {
        "baseline": (0.0, 1.0),
        "0": (1.0, 2.0),
        "1": (2.0, 3.0),
        "2": (4.0, 5.0),
        "0,1": (3.0, 4.0),
        "0,2": (3.0, 4.0),
        "1,2": (5.0, 6.0),
        "0,1,2": (2.0, 3.0),
    }
    subset = FeatureSubset((0, 1, 2))
    estimate = estimate_higher_order(subset, cells, outcome_scale="logit")

    expected = 0.0
    order = 3
    for cell in ref.powerset((0, 1, 2)):
        key = "baseline" if not cell else ",".join(str(feature) for feature in cell)
        sign = -1.0 if (order - len(cell)) % 2 else 1.0
        expected += sign * ref.mean(cells[key])
    expected_se = ref.independent_cell_standard_error(
        [cells["baseline"], cells["0"], cells["1"], cells["2"], cells["0,1"], cells["0,2"], cells["1,2"], cells["0,1,2"]]
    )
    assert estimate.contrast == pytest.approx(expected)
    assert estimate.order == 3
    assert estimate.standard_error == pytest.approx(expected_se)


def test_engine_replays_declared_factorial_contrast() -> None:
    responses = {
        frozenset(): 0.0,
        frozenset({0}): 1.0,
        frozenset({1}): 2.0,
        frozenset({0, 1}): 4.0,
    }
    engine = PairwiseInteractionEngine(
        experiment_id="pairwise-regression",
        outcome_scale="logit",
        repetitions=2,
        seed=7,
    )
    result = engine.run(
        FeaturePair(0, 1),
        lambda interventions, _repetition: responses[frozenset(interventions)],
    )
    expected = 4.0 - 1.0 - 2.0 + 0.0
    assert result.estimate.contrast == pytest.approx(expected)
    assert result.estimate.standard_error == pytest.approx(0.0)


def test_pair_selection_and_ranking_are_deterministic() -> None:
    pairs = select_feature_pairs([3, 1, 2, 1])
    assert [(pair.feature_a, pair.feature_b) for pair in pairs] == [(1, 2), (1, 3), (2, 3)]
    assert select_feature_pairs([3, 1, 2], max_pairs=2) == pairs[:2]
    with pytest.raises(ValueError):
        select_feature_pairs([1, 2], max_pairs=0)

    a = PairwiseCell("a", {}, (0.0,))
    b = PairwiseCell("b", {}, (1.0,))
    results = []
    for pair, contrast in ((FeaturePair(0, 1), -2.0), (FeaturePair(0, 2), 1.0)):
        joint = PairwiseCell("joint", {}, (contrast + 1.0,))
        results.append(
            type(
                "Result",
                (),
                {
                    "pair": pair,
                    "estimate": estimate_interaction(a, b, b, joint, outcome_scale="x"),
                },
            )()
        )
    assert [item.pair.ordered for item in rank_interactions(results)] == [(0, 1), (0, 2)]


def test_subset_generation_respects_orders_and_limit() -> None:
    subsets = generate_feature_subsets([1, 2, 3], min_order=2, max_order=2)
    assert [subset.features for subset in subsets] == [(1, 2), (1, 3), (2, 3)]
    assert len(generate_feature_subsets([1, 2, 3], min_order=1, max_order=3)) == 3 + 3 + 1
    limited = generate_feature_subsets([1, 2, 3, 4], min_order=1, max_order=2, max_subsets=5)
    assert len(limited) == 5
    with pytest.raises(ValueError):
        generate_feature_subsets([1], min_order=2, max_order=1)
