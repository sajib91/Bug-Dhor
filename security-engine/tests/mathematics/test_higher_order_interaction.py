from __future__ import annotations

import itertools

import numpy as np
import pytest
from mathematics.higher_order_interaction import (
    complexity_report,
    estimate_higher_order_interaction,
    generate_subsets,
    mobius_contrast,
    run_higher_order_experiment,
)
from mathematics.sae_encoding import SAEParameters


def power_set(features: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        combo
        for order in range(len(features) + 1)
        for combo in itertools.combinations(features, order)
    )


def boolean_polynomial(active: tuple[int, ...]) -> float:
    x = [1.0 if index in active else 0.0 for index in range(3)]
    return x[0] + x[1] + x[2] + x[0] * x[1] + x[0] * x[1] * x[2]


def polynomial_outcome(activations: np.ndarray) -> np.ndarray:
    h = np.asarray(activations, dtype=np.float64)
    return h[:, 0] + h[:, 1] + h[:, 2] + h[:, 0] * h[:, 1] + h[:, 0] * h[:, 1] * h[:, 2]


def identity_sae(dim: int = 3) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_mobius_contrast_recovers_the_triple_interaction():
    subset = (0, 1, 2)
    cells = {active: np.full(5, boolean_polynomial(active)) for active in power_set(subset)}
    assert mobius_contrast(cells, subset) == pytest.approx(1.0)
    estimate = estimate_higher_order_interaction(cells, subset)
    assert estimate.contrast == pytest.approx(1.0)
    assert estimate.order == 3
    assert estimate.count == 5
    assert estimate.standard_error == pytest.approx(0.0)


def test_all_factorial_cells_are_required():
    cells = {
        (): np.asarray([0.0]),
        (0,): np.asarray([1.0]),
        (1,): np.asarray([1.0]),
        (0, 1): np.asarray([3.0]),
    }
    with pytest.raises(ValueError):
        mobius_contrast(cells, (0, 1, 2))
    with pytest.raises(ValueError):
        estimate_higher_order_interaction(cells, (0, 2))


def test_paired_missing_units_are_dropped():
    cells = {
        (): np.asarray([0.0, 0.0, 0.0]),
        (0,): np.asarray([1.0, 1.0, 1.0]),
        (1,): np.asarray([1.0, 1.0, 1.0]),
        (0, 1): np.asarray([3.0, 3.0, np.nan]),
    }
    estimate = estimate_higher_order_interaction(cells, (0, 1))
    assert estimate.count == 2
    assert estimate.missing_count == 1
    assert estimate.contrast == pytest.approx(1.0)


def test_generate_subsets_exhaustive_and_reproducible():
    subsets = generate_subsets([3, 1, 2, 0], min_order=1, max_order=2)
    assert len(subsets) == 10
    assert subsets[0] == (0,)
    assert subsets[-1] == (2, 3)
    limited = generate_subsets([0, 1, 2, 3], min_order=1, max_order=2, max_subsets=5)
    assert limited == subsets[:5]
    first = generate_subsets(
        [0, 1, 2, 3], max_order=2, max_subsets=4, sampling_strategy="random", seed=9
    )
    second = generate_subsets(
        [0, 1, 2, 3], max_order=2, max_subsets=4, sampling_strategy="random", seed=9
    )
    assert first == second
    assert set(first) <= set(subsets)


def test_complexity_report_counts_cells():
    report = complexity_report(5, min_order=1, max_order=3)
    assert report.theoretical_subset_count == 25
    assert report.theoretical_cell_evaluations == 130
    assert "25 subsets" in report.summary
    with pytest.raises(ValueError):
        complexity_report(0)
    with pytest.raises(ValueError):
        complexity_report(3, min_order=2, max_order=1)


def test_run_higher_order_experiment_matches_analytic_polynomial():
    activations = np.zeros((2, 3))
    experiment = run_higher_order_experiment(
        activations, polynomial_outcome, identity_sae(), [(0, 1, 2)]
    )
    assert experiment.results[0].subset == (0, 1, 2)
    assert experiment.results[0].contrast == pytest.approx(1.0)
    assert len(experiment.cells) == 8
    assert experiment.intervention_value == 1.0
    assert experiment.ranked()[0].subset == (0, 1, 2)


def test_validation_errors():
    activations = np.zeros((1, 3))
    with pytest.raises(ValueError):
        run_higher_order_experiment(activations, polynomial_outcome, identity_sae(), [(0, 5)])
    with pytest.raises(ValueError):
        run_higher_order_experiment(activations, polynomial_outcome, identity_sae(), [])
    with pytest.raises(ValueError):
        run_higher_order_experiment(activations, polynomial_outcome, identity_sae(), [(1, 0)])
    with pytest.raises(ValueError):
        generate_subsets([0, 1], min_order=0, max_order=1)
    with pytest.raises(ValueError):
        generate_subsets([0, 1], sampling_strategy="bad")
    with pytest.raises(ValueError):
        generate_subsets([0, 1], max_subsets=0)
