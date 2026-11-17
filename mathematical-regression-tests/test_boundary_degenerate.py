"""Boundary and degenerate cases that must be reported rather than invented."""

from __future__ import annotations

import math

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from craftsec.counterfactual.higher_order import (
    FeatureSubset,
    estimate_higher_order,
    generate_feature_subsets,
)
from craftsec.counterfactual.pairwise import (
    PairwiseCell,
    estimate_interaction,
    select_feature_pairs,
)
from craftsec.counterfactual.validation import (
    BootstrapContrast,
    bootstrap_mean_interval,
    factorial_unit_contrasts,
    interaction_on_scale,
    logit,
    sigmoid,
    stability_summary,
)
from craftsec.evaluation.statistics import (
    benjamini_hochberg,
    bootstrap_ci,
    holm_bonferroni,
    paired_comparison,
    paired_t_test,
)
from craftsec.sae import SAEConfig, SparseAutoencoder
from craftsec.sae.association import (
    CodeSampleLabel,
    FeatureExperimentMetadata,
    FeatureSample,
    analyze_features,
)
from craftsec.sae.metrics import feature_statistics, validation_metrics
from craftsec.steering.engine import SteeringSpec

# --- SAE boundaries --------------------------------------------------------


def test_sae_rejects_bad_input_shapes_dtypes_and_values() -> None:
    sae = SparseAutoencoder(SAEConfig(input_dim=3, latent_dim=2))
    for bad in (
        torch.zeros(3),
        torch.zeros(1, 4),
        torch.zeros(1, 2, 3),
    ):
        with pytest.raises(ValueError, match="shape"):
            sae.encode(bad)
    with pytest.raises(ValueError, match="floating"):
        sae.encode(torch.zeros(1, 3, dtype=torch.int64))
    for value in (float("nan"), float("inf"), -float("inf")):
        with pytest.raises(ValueError, match="finite"):
            sae.encode(torch.tensor([[value, 0.0, 0.0]]))
    with pytest.raises(ValueError, match="shape"):
        sae.decode(torch.zeros(1, 3))
    with pytest.raises(ValueError, match="shape"):
        sae.decode(torch.zeros(2))


def test_all_dead_latents_and_zero_threshold() -> None:
    latents = torch.zeros(4, 3)
    stats = feature_statistics(latents, 0.0)
    assert stats.mean_l0 == 0.0
    assert stats.feature_utilization == (0.0, 0.0, 0.0)
    assert stats.dead_features == (0, 1, 2)
    assert stats.active_feature_count == 0

    exact_zero = feature_statistics(torch.tensor([[0.0]]), 0.0)
    # Strict comparison: 0 is not greater than 0.
    assert exact_zero.dead_features == (0,)


def test_relative_reconstruction_error_is_finite_for_zero_input() -> None:
    inputs = torch.zeros(2, 2)
    reconstructions = torch.ones(2, 2)
    metrics = validation_metrics(
        inputs, reconstructions, torch.zeros(2, 2), threshold=0.0
    )
    eps = torch.finfo(inputs.dtype).eps
    assert metrics.reconstruction_error == pytest.approx(1.0)
    assert metrics.relative_reconstruction_error == pytest.approx(float(1.0 / eps))
    assert math.isfinite(metrics.relative_reconstruction_error)


def test_feature_statistics_requires_a_matrix() -> None:
    with pytest.raises(ValueError, match="shape"):
        feature_statistics(torch.zeros(4), 0.0)
    with pytest.raises(ValueError, match="shape"):
        feature_statistics(torch.zeros(1, 2, 3), 0.0)


# --- factorial boundaries --------------------------------------------------


def test_factorial_contrasts_reject_empty_and_misaligned_cells() -> None:
    with pytest.raises(ValueError, match="at least one feature"):
        factorial_unit_contrasts({(): [1.0]}, ())
    with pytest.raises(ValueError, match="unique"):
        factorial_unit_contrasts({}, (0, 0))
    with pytest.raises(ValueError, match="same number of units"):
        factorial_unit_contrasts(
            {(): [1.0, 2.0], (0,): [1.0], (1,): [1.0, 2.0], (0, 1): [1.0, 2.0]},
            (0, 1),
        )
    with pytest.raises(ValueError, match="empty"):
        factorial_unit_contrasts({(): [], (0,): [], (1,): [], (0, 1): []}, (0, 1))
    with pytest.raises(KeyError, match="missing"):
        factorial_unit_contrasts({(): [1.0], (0,): [1.0]}, (0, 1))


def test_single_replicate_cell_has_no_uncertainty() -> None:
    cell = lambda name, value: PairwiseCell(name, {}, (value,))
    estimate = estimate_interaction(
        cell("baseline", 0.0),
        cell("a", 1.0),
        cell("b", 2.0),
        cell("joint", 4.0),
        outcome_scale="probability",
    )
    assert estimate.contrast == pytest.approx(1.0)
    assert estimate.standard_error is None
    assert estimate.confidence_interval_95 is None


def test_true_mobius_zero_interaction_and_empty_subsets() -> None:
    additive = {
        "baseline": (0.0, 1.0),
        "0": (1.0, 2.0),
        "1": (2.0, 3.0),
        "2": (4.0, 5.0),
        "0,1": (3.0, 4.0),
        "0,2": (5.0, 6.0),
        "1,2": (6.0, 7.0),
        "0,1,2": (7.0, 8.0),
    }
    estimate = estimate_higher_order(
        FeatureSubset((0, 1, 2)), additive, outcome_scale="logit"
    )
    # For a purely additive system the third-order contrast is zero.
    assert estimate.contrast == pytest.approx(0.0)

    with pytest.raises(ValueError):
        FeatureSubset(())
    with pytest.raises(ValueError, match="orders"):
        generate_feature_subsets([1], min_order=3, max_order=1)
    assert generate_feature_subsets([1, 2], min_order=3, max_order=3) == ()
    with pytest.raises(ValueError):
        select_feature_pairs([1, 2], max_pairs=-1)


# --- statistics boundaries -------------------------------------------------


def test_constant_and_empty_samples_report_degeneracy() -> None:
    constant = paired_t_test([2.0, 2.0, 2.0], [1.0, 1.0, 1.0])
    assert constant["p_value"] == 0.0
    assert constant["statistic"] == math.inf

    empty = paired_t_test([], [])
    assert empty["p_value"] is None
    assert empty["n"] == 0

    single = paired_t_test([1.0], [0.0])
    assert single["p_value"] is None
    assert single["reason"] == "insufficient_paired_observations"

    identical = paired_comparison([1.0, 1.0], [1.0, 1.0])
    assert identical.mean_difference == 0.0
    assert identical.paired_t_test["p_value"] is None


def test_bootstrap_single_observation_and_empty_clusters() -> None:
    estimate, error, low, high = bootstrap_mean_interval([3.0], n_boot=50, seed=1)
    assert estimate == 3.0
    assert math.isnan(error) and math.isnan(low) and math.isnan(high)

    empty = bootstrap_ci([], n_boot=10)
    assert empty.estimate is None
    assert empty.n == 0

    all_missing = bootstrap_ci(
        [1.0, float("nan")], cluster_ids=[None, None], n_boot=10
    )
    assert all_missing.estimate is None
    assert all_missing.n == 0


def test_multiple_comparison_with_no_valid_p_values_returns_none_rows() -> None:
    holm = holm_bonferroni([None, float("nan")])
    assert [row["adjusted_p_value"] for row in holm] == [None, None]
    assert [row["reject"] for row in holm] == [None, None]

    bh = benjamini_hochberg([])
    assert bh == []


# --- association boundaries ------------------------------------------------


def _metadata() -> FeatureExperimentMetadata:
    return FeatureExperimentMetadata(
        model_id="regression/model",
        model_version="1",
        layer="layer.0",
        sae_checkpoint="sae.pt",
        dataset_ids=("a",),
        experiment_id="boundary",
        activation_threshold=0.5,
    )


def test_single_class_association_has_no_contrast() -> None:
    samples = (
        FeatureSample(
            CodeSampleLabel("v1", True, "a", "boundary", "CWE-79"),
            torch.tensor([2.0, 0.0]),
        ),
        FeatureSample(
            CodeSampleLabel("v2", True, "a", "boundary", "CWE-79"),
            torch.tensor([2.0, 0.0]),
        ),
    )
    dictionary = analyze_features(samples, activation_threshold=0.5, metadata=_metadata())
    entry = dictionary.entries[0]
    assert entry.association.secure_mean_activation is None
    assert entry.association.mean_activation_difference is None
    assert entry.association.association_direction is None
    assert entry.selectivity is None
    assert entry.stability.sign_consistency is None
    assert entry.stability.datasets_with_both_classes == 0


def test_analysis_rejects_empty_samples_and_negative_threshold() -> None:
    with pytest.raises(ValueError, match="at least one"):
        analyze_features([], activation_threshold=0.5, metadata=_metadata())
    samples = (
        FeatureSample(
            CodeSampleLabel("v1", True, "a", "boundary", None),
            torch.tensor([2.0]),
        ),
    )
    with pytest.raises(ValueError, match="non-negative"):
        analyze_features(samples, activation_threshold=-0.1, metadata=_metadata())


# --- steering and scale boundaries ----------------------------------------


def test_steering_spec_rejects_empty_enabled_spec() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        SteeringSpec(feature_indices=(), enabled=True)
    # An empty, disabled spec is a valid no-op.
    assert SteeringSpec(feature_indices=()).enabled is False


def test_logit_rejects_out_of_range_and_non_finite_probabilities() -> None:
    for values in ([-0.1], [1.1], [float("nan")], [float("inf")]):
        with pytest.raises(ValueError):
            logit(np.asarray(values))
    assert sigmoid(np.asarray([-1000.0]))[0] == pytest.approx(0.0)
    assert sigmoid(np.asarray([1000.0]))[0] == pytest.approx(1.0)


def test_stability_with_one_group_is_trivially_consistent() -> None:
    summary = stability_summary(
        {"only": BootstrapContrast(0.5, 0.1, 0.4, 0.6, 0.95, 4, 100, "m")}
    )
    assert summary.same_sign is True
    assert summary.sign_consistency == 1.0
    assert summary.all_intervals_overlap is True


def test_interaction_on_scale_matches_manual_transform() -> None:
    cells = {(): [0.2], (0,): [0.5], (1,): [0.6], (0, 1): [0.9]}
    left = interaction_on_scale(cells, (0, 1), logit)
    transformed = {key: np.asarray(logit(values)) for key, values in cells.items()}
    right = float(factorial_unit_contrasts(transformed, (0, 1)).mean())
    assert left == pytest.approx(right)
