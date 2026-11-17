"""Independent checks of association, stability, transfer, and CWE ranking."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

import reference as ref
from craftsec.counterfactual.higher_order import preselect_features
from craftsec.counterfactual.pairwise import select_association_pairs
from craftsec.sae.association import (
    CodeSampleLabel,
    FeatureExperimentMetadata,
    FeatureSample,
    analyze_features,
)
from craftsec.sae.metrics import feature_statistics


def _metadata() -> FeatureExperimentMetadata:
    return FeatureExperimentMetadata(
        model_id="regression/model",
        model_version="1",
        layer="layer.0",
        sae_checkpoint="sae.pt",
        dataset_ids=("a", "b"),
        experiment_id="association-regression",
        activation_threshold=0.5,
    )


def _sample(sample_id, vulnerable, dataset, values, cwe=None):
    return FeatureSample(
        CodeSampleLabel(sample_id, vulnerable, dataset, "association-regression", cwe),
        torch.tensor(values, dtype=torch.float32),
    )


def test_association_statistics_match_reference() -> None:
    samples = (
        _sample("v1", True, "a", [2.0, 0.0]),
        _sample("v2", True, "a", [2.0, 0.0]),
        _sample("s1", False, "a", [0.0, 0.0]),
        _sample("s2", False, "a", [0.0, 0.0]),
    )
    dictionary = analyze_features(samples, activation_threshold=0.5, metadata=_metadata())
    entry = dictionary.entries[0]
    expected = ref.association_values([2.0, 2.0, 0.0, 0.0], [True, True, False, False], 0.5)
    assert entry.association.activation_frequency == pytest.approx(expected["activation_frequency"])
    assert entry.association.vulnerable_activation_frequency == pytest.approx(
        expected["vulnerable_activation_frequency"]
    )
    assert entry.association.secure_activation_frequency == pytest.approx(
        expected["secure_activation_frequency"]
    )
    assert entry.association.mean_activation_difference == pytest.approx(
        expected["mean_activation_difference"]
    )
    assert entry.association.active_precision == pytest.approx(expected["active_precision"])
    assert entry.association.active_recall == pytest.approx(expected["active_recall"])
    assert entry.association.association_direction == "vulnerable_higher"


def test_stability_uses_majority_sign_and_counts_two_class_datasets() -> None:
    samples = (
        _sample("a-v1", True, "a", [2.0, 0.0]),
        _sample("a-v2", True, "a", [2.0, 0.0]),
        _sample("a-s1", False, "a", [0.0, 0.0]),
        _sample("a-s2", False, "a", [0.0, 0.0]),
        _sample("b-v1", True, "b", [1.0, 0.0]),
        _sample("b-v2", True, "b", [1.0, 0.0]),
        _sample("b-s1", False, "b", [3.0, 0.0]),
        _sample("b-s2", False, "b", [3.0, 0.0]),
        _sample("c-v1", True, "c", [5.0, 0.0]),
        _sample("c-v2", True, "c", [5.0, 0.0]),
    )
    dictionary = analyze_features(
        samples, activation_threshold=0.5, metadata=_metadata(), cwes=[]
    )
    stability = dictionary.entries[0].stability
    assert dict(stability.dataset_differences) == pytest.approx(
        {"a": 2.0, "b": -2.0}
    )
    assert stability.sign_consistency == pytest.approx(0.5)
    # Dataset c has only vulnerable samples and is not a two-class dataset.
    assert stability.datasets_with_both_classes == 2


def test_cross_dataset_metrics_record_direction_transfer() -> None:
    samples = (
        _sample("a-v1", True, "a", [2.0, 2.0]),
        _sample("a-v2", True, "a", [2.0, 2.0]),
        _sample("a-s1", False, "a", [0.0, 0.0]),
        _sample("a-s2", False, "a", [0.0, 0.0]),
        _sample("b-v1", True, "b", [1.0, 2.0]),
        _sample("b-v2", True, "b", [1.0, 2.0]),
        _sample("b-s1", False, "b", [3.0, 0.0]),
        _sample("b-s2", False, "b", [3.0, 0.0]),
    )
    dictionary = analyze_features(samples, activation_threshold=0.5, metadata=_metadata())
    pairs = {
        (metric.train_dataset, metric.validation_dataset, metric.feature_index): metric
        for metric in dictionary.cross_dataset
    }
    feature0 = pairs[("a", "b", 0)]
    assert feature0.train_association_direction == "vulnerable_higher"
    assert feature0.validation_association_direction == "secure_higher"
    assert feature0.direction_agrees is False

    feature1 = pairs[("a", "b", 1)]
    assert feature1.train_association_direction == "vulnerable_higher"
    assert feature1.validation_association_direction == "vulnerable_higher"
    assert feature1.direction_agrees is True


def test_cwe_specific_ranking_uses_the_cwe_association() -> None:
    samples = (
        _sample("v89", True, "a", [0.0, 2.0, 0.0], "CWE-89"),
        _sample("s89", False, "a", [0.0, 0.0, 0.0], "CWE-89"),
        _sample("v79", True, "a", [2.0, 0.0, 0.0], "CWE-79"),
        _sample("s79", False, "a", [0.0, 0.0, 0.0], "CWE-79"),
    )
    dictionary = analyze_features(samples, activation_threshold=0.5, metadata=_metadata())
    overall = preselect_features(dictionary, max_features=1)
    cwe_specific = preselect_features(dictionary, max_features=1, cwe="CWE-89")
    assert overall == (0,)
    assert cwe_specific == (1,)

    pairs = select_association_pairs(dictionary, top_k=2, cwe="CWE-89")
    assert len(pairs) == 1
    assert pairs[0].cwe == "CWE-89"
    assert set(pairs[0].ordered) == {0, 1}


def test_feature_activation_threshold_matches_statistics() -> None:
    latents = torch.tensor([[0.5, 1.0], [2.0, 0.0]])
    stats = feature_statistics(latents, 1.0)
    # A value exactly at the threshold is inactive under the strict comparison.
    assert stats.mean_l0 == pytest.approx(0.5)
    assert stats.feature_utilization == pytest.approx((0.5, 0.0))
    assert stats.dead_features == (1,)
