"""Independent checks of the paired validation estimators."""

from __future__ import annotations

import math

import numpy as np
import pytest
import reference as ref
from bugdhor.counterfactual.validation import (
    BootstrapContrast,
    bootstrap_mean_interval,
    estimate_pairwise_contrast,
    factorial_unit_contrasts,
    interaction_on_scale,
    logit,
    sigmoid,
    stability_summary,
)


def _cells() -> dict[tuple[int, ...], list[float]]:
    return {
        (): [1.0, 2.0, 3.0],
        (0,): [2.0, 3.0, 4.0],
        (1,): [1.5, 2.5, 3.5],
        (0, 1): [3.0, 4.5, 6.0],
    }


def test_per_unit_factorial_contrast_is_the_paired_expression() -> None:
    cells = _cells()
    expected = np.array(
        [joint - a - b + base for joint, a, b, base in zip(cells[(0, 1)], cells[(0,)], cells[(1,)], cells[()])]
    )
    np.testing.assert_allclose(factorial_unit_contrasts(cells, (0, 1)), expected)


def test_pairwise_estimate_and_bootstrap_interval_match_reference() -> None:
    cells = _cells()
    units = np.asarray(cells[(0, 1)]) - np.asarray(cells[(0,)]) - np.asarray(cells[(1,)]) + np.asarray(cells[()])
    expected = ref.percentile_bootstrap_mean(units, confidence=0.95, n_boot=500, seed=11)
    result = estimate_pairwise_contrast(
        cells[()], cells[(0,)], cells[(1,)], cells[(0, 1)],
        confidence=0.95,
        n_boot=500,
        seed=11,
    )
    assert result.contrast == pytest.approx(expected[0])
    assert result.standard_error == pytest.approx(expected[1])
    assert result.confidence_low == pytest.approx(expected[2])
    assert result.confidence_high == pytest.approx(expected[3])
    assert result.n_units == 3


def test_bootstrap_reproducibility_and_single_observation_boundary() -> None:
    values = [0.1, -0.2, 0.4, 0.05]
    first = bootstrap_mean_interval(values, n_boot=300, seed=5)
    second = bootstrap_mean_interval(values, n_boot=300, seed=5)
    different = bootstrap_mean_interval(values, n_boot=300, seed=6)
    assert first == second
    assert first[2:] != different[2:]

    estimate, error, low, high = bootstrap_mean_interval([2.0], n_boot=100, seed=1)
    assert estimate == 2.0
    assert math.isnan(error) and math.isnan(low) and math.isnan(high)


def test_scale_transform_changes_the_contrast_but_not_the_equation() -> None:
    cells = {
        (): [0.2, 0.3],
        (0,): [0.5, 0.6],
        (1,): [0.4, 0.5],
        (0, 1): [0.8, 0.9],
    }
    probability_contrast = float(
        np.mean(factorial_unit_contrasts(cells, (0, 1)))
    )
    logit_contrast = interaction_on_scale(cells, (0, 1), logit)
    expected = float(
        np.mean(
            factorial_unit_contrasts(
                {key: logit(np.asarray(values)) for key, values in cells.items()},
                (0, 1),
            )
        )
    )
    assert logit_contrast == pytest.approx(expected)
    assert logit_contrast != pytest.approx(probability_contrast)


def test_sigmoid_logit_roundtrip_and_clipping() -> None:
    # Round-trip inside the unclipped region.  Extreme logits saturate to 0/1 and
    # are intentionally clipped, so they are checked separately below.
    values = np.array([-8.0, -1.0, 0.0, 1.0, 8.0])
    np.testing.assert_allclose(sigmoid(logit(sigmoid(values))), sigmoid(values))
    clipped = logit(np.array([0.0, 1.0]), epsilon=1e-6)
    assert np.all(np.isfinite(clipped))
    assert clipped[0] == pytest.approx(math.log(1e-6 / (1 - 1e-6)))
    assert clipped[1] == pytest.approx(math.log((1 - 1e-6) / 1e-6))
    with pytest.raises(ValueError):
        logit(np.array([-0.1, 0.5]))
    with pytest.raises(ValueError):
        logit(np.array([float("nan")]))


def test_stability_summary_uses_majority_sign_and_interval_overlap() -> None:
    results = {
        "a": BootstrapContrast(1.0, 0.1, 0.8, 1.2, 0.95, 10, 100, "m"),
        "b": BootstrapContrast(0.5, 0.1, 0.3, 0.7, 0.95, 10, 100, "m"),
        "c": BootstrapContrast(-0.5, 0.1, -0.7, -0.3, 0.95, 10, 100, "m"),
    }
    summary = stability_summary(results)
    assert summary.same_sign is False
    assert summary.sign_consistency == pytest.approx(2 / 3)
    assert summary.all_intervals_overlap is False
    assert summary.pooled_interval_low == pytest.approx(0.8)
    assert summary.pooled_interval_high == pytest.approx(-0.3)


def test_degenerate_stability_is_reported_not_invented() -> None:
    results = {
        "a": BootstrapContrast(0.0, 0.0, 0.0, 0.0, 0.95, 5, 10, "m"),
        "b": BootstrapContrast(0.0, 0.0, 0.0, 0.0, 0.95, 5, 10, "m"),
    }
    summary = stability_summary(results)
    assert summary.same_sign is True
    assert summary.sign_consistency == 1.0
    assert summary.all_intervals_overlap is True


def test_missing_or_misaligned_cells_are_rejected() -> None:
    with pytest.raises(KeyError):
        factorial_unit_contrasts({(): [1.0], (0,): [1.0], (1,): [1.0]}, (0, 1))
    with pytest.raises(ValueError, match="same number of units"):
        factorial_unit_contrasts(
            {(): [1.0, 2.0], (0,): [1.0], (1,): [1.0, 2.0], (0, 1): [1.0, 2.0]},
            (0, 1),
        )
    assert ref.factorial_contrast(
        {(): 1.0, (0,): 1.0, (1,): 1.0, (0, 1): 1.0}, (0, 1)
    ) == pytest.approx(0.0)
