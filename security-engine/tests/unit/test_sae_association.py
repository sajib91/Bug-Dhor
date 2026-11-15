from __future__ import annotations

from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from craftsec.sae import (  # noqa: E402
    CodeSampleLabel,
    FeatureExperimentMetadata,
    FeatureSample,
    analyze_features,
    samples_from_token_features,
)


def _sample(sample_id: str, vulnerable: bool, dataset: str, value: float, cwe: str | None):
    return FeatureSample(
        CodeSampleLabel(
            sample_id=sample_id,
            vulnerable=vulnerable,
            dataset_id=dataset,
            experiment_id="controlled-experiment",
            cwe=cwe,
        ),
        torch.tensor([value, 1.0 - value]),
    )


def test_association_reports_statistics_without_semantic_feature_labels(tmp_path: Path) -> None:
    samples = (
        _sample("v1", True, "dataset-a", 2.0, "CWE-89"),
        _sample("v2", True, "dataset-a", 3.0, "CWE-89"),
        _sample("s1", False, "dataset-a", 0.0, None),
        _sample("s2", False, "dataset-a", 0.0, None),
        _sample("v3", True, "dataset-b", 4.0, "CWE-89"),
        _sample("s3", False, "dataset-b", 0.0, None),
    )
    dictionary = analyze_features(
        samples,
        activation_threshold=0.5,
        metadata=FeatureExperimentMetadata(
            model_id="local/tiny",
            model_version="test",
            layer="layer.0",
            sae_checkpoint="sae-test.pt",
            dataset_ids=("dataset-a", "dataset-b"),
            experiment_id="controlled-experiment",
            activation_threshold=0.5,
        ),
    )

    first = dictionary.entries[0]
    assert first.association.mean_activation_difference == 3.0
    assert first.association.active_precision == 1.0
    assert first.association.active_recall == 1.0
    assert first.association.association_direction == "vulnerable_higher"
    assert first.cwe_associations["CWE-89"].vulnerable_count == 3
    assert first.stability.sign_consistency == 1.0
    assert dictionary.cross_dataset
    assert first.interpretation == "association_only; no causal or semantic claim"

    output = dictionary.save(tmp_path / "feature-dictionary.json")
    assert output.exists()
    assert "causal" in output.read_text(encoding="utf-8")


def test_token_feature_aggregation_preserves_labels_and_valid_tokens() -> None:
    labels = (
        CodeSampleLabel("v1", True, "dataset", "experiment", "CWE-89"),
        CodeSampleLabel("s1", False, "dataset", "experiment"),
    )
    features = torch.tensor(
        [
            [[1.0, 2.0], [3.0, 4.0], [99.0, 99.0]],
            [[0.0, 1.0], [2.0, 3.0], [99.0, 99.0]],
        ]
    )
    mask = torch.tensor([[1, 1, 0], [1, 1, 0]])

    samples = samples_from_token_features(labels, features, mask)

    assert samples[0].label.cwe == "CWE-89"
    assert torch.equal(samples[0].features, torch.tensor([2.0, 3.0]))
    assert torch.equal(samples[1].features, torch.tensor([1.0, 2.0]))
