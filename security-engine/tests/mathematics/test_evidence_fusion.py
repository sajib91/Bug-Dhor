from __future__ import annotations

import math

import numpy as np
import pytest
from mathematics.common import stable_sigmoid
from mathematics.evidence_fusion import (
    EvidenceMatrix,
    LogisticFusionHead,
    assemble_evidence_matrix,
    fit_logistic_fusion_head,
    masked_weighted_fusion,
    noisy_or_fusion,
)


def test_equation_24_assembly_preserves_columns_and_availability():
    evidence = assemble_evidence_matrix(
        {
            "neural": [0.8, 0.6, 0.2],
            "sae": [0.5, np.nan, 0.7],
            "static": [0.1, 0.2, 0.3],
        },
        availability={"static": [True, False, True]},
    )
    assert evidence.names == ("neural", "sae", "static")
    assert evidence.values.shape == (3, 3)
    assert evidence.available.tolist() == [
        [True, True, True],
        [True, False, False],
        [True, True, True],
    ]
    assert math.isnan(evidence.values[1, 1])
    assert math.isnan(evidence.values[1, 2])
    neural_values, neural_available = evidence.column("neural")
    np.testing.assert_allclose(neural_values, [0.8, 0.6, 0.2])
    assert neural_available.all()
    with pytest.raises(KeyError):
        evidence.column("dynamic")


def test_equation_24_rejects_unaligned_or_empty_evidence():
    with pytest.raises(ValueError):
        assemble_evidence_matrix({})
    with pytest.raises(ValueError):
        assemble_evidence_matrix({"a": [1.0, 2.0], "b": [1.0]})
    with pytest.raises(ValueError):
        assemble_evidence_matrix({"a": [1.0, 2.0]}, availability={"a": [True]})


def test_evidence_matrix_validation():
    with pytest.raises(ValueError):
        EvidenceMatrix(
            names=("a", "a"),
            values=np.zeros((1, 2)),
            available=np.ones((1, 2), dtype=bool),
        )
    with pytest.raises(ValueError):
        EvidenceMatrix(
            names=("a",),
            values=np.asarray([[np.nan]]),
            available=np.asarray([[True]]),
        )
    with pytest.raises(ValueError):
        EvidenceMatrix(
            names=("a", "b"),
            values=np.zeros((1, 2)),
            available=np.ones((1, 1), dtype=bool),
        )


def test_equation_26_masked_weighted_mean_never_imputes():
    evidence = np.asarray(
        [
            [0.8, 0.6, np.nan],
            [np.nan, np.nan, np.nan],
            [0.2, 0.4, 0.6],
        ]
    )
    result = masked_weighted_fusion(evidence, [0.5, 0.3, 0.2])
    assert result.scores[0] == pytest.approx((0.8 * 0.5 + 0.6 * 0.3) / 0.8)
    assert result.scores[0] == pytest.approx(0.725)
    assert math.isnan(result.scores[1])
    assert result.scores[2] == pytest.approx(0.2 * 0.5 + 0.4 * 0.3 + 0.6 * 0.2)
    assert result.effective_weight.tolist() == pytest.approx([0.8, 0.0, 1.0])
    assert result.missing_count == 4
    assert result.available.tolist() == [
        [True, True, False],
        [False, False, False],
        [True, True, True],
    ]


def test_equation_26_explicit_mask_can_only_remove_availability():
    evidence = np.asarray([[0.8, 0.6]])
    result = masked_weighted_fusion(
        evidence,
        [0.5, 0.5],
        availability=np.asarray([[True, False]]),
    )
    assert result.scores[0] == pytest.approx(0.8)
    assert result.effective_weight[0] == pytest.approx(0.5)
    assert result.missing_count == 1


def test_equation_26_missing_policies_and_validation():
    evidence = np.asarray([[0.8, np.nan]])
    with pytest.raises(ValueError, match="unavailable"):
        masked_weighted_fusion(evidence, [1.0, 1.0], on_missing="error")
    one_dimensional = masked_weighted_fusion(np.asarray([0.4, 0.6]), [0.5, 0.5])
    assert one_dimensional.scores.shape == (1,)
    assert one_dimensional.scores[0] == pytest.approx(0.5)
    with pytest.raises(ValueError):
        masked_weighted_fusion(evidence, [1.0])
    with pytest.raises(ValueError):
        masked_weighted_fusion(evidence, [1.0, -1.0])
    with pytest.raises(ValueError):
        masked_weighted_fusion(evidence, [0.0, 0.0])
    with pytest.raises(ValueError):
        masked_weighted_fusion(np.asarray([[1.2, 0.5]]), [1.0, 1.0])
    with pytest.raises(ValueError):
        masked_weighted_fusion(evidence, [1.0, 1.0], on_missing="drop")


def test_noisy_or_known_values_and_refutation_penalty():
    plain = noisy_or_fusion([0.8, 0.6, 0.4])
    assert plain.score == pytest.approx(1.0 - (0.2 * 0.4 * 0.6))
    assert plain.score == pytest.approx(0.952)
    assert plain.refutation_penalty == 0.0
    refuted = noisy_or_fusion([0.8, 0.6, 0.4], refutation_scores=[0.3])
    assert refuted.refutation_penalty == pytest.approx(0.3)
    assert refuted.score == pytest.approx(0.952 * 0.7)
    assert refuted.interpretation.startswith("Heuristic prioritization score")


def test_noisy_or_family_redundancy_and_caps():
    redundant = noisy_or_fusion(
        [0.8, 0.6],
        families=["program", "program"],
        redundancy_decay=0.5,
    )
    assert redundant.family_scores["program"] == pytest.approx(0.86)
    assert redundant.score == pytest.approx(0.86)
    mixed = noisy_or_fusion(
        [0.8, 0.6, 0.4],
        families=["program", "program", "llm"],
        redundancy_decay=0.5,
    )
    assert mixed.score == pytest.approx(1.0 - (1.0 - 0.86) * (1.0 - 0.4))
    capped = noisy_or_fusion(
        [0.8, 0.6, 0.4],
        families=["program", "program", "llm"],
        redundancy_decay=0.5,
        family_caps={"program": 0.5},
    )
    assert capped.family_scores["program"] == pytest.approx(0.5)
    assert capped.score == pytest.approx(1.0 - 0.5 * 0.6)


def test_noisy_or_validation():
    with pytest.raises(ValueError):
        noisy_or_fusion([np.nan, np.nan])
    with pytest.raises(ValueError):
        noisy_or_fusion([1.2])
    with pytest.raises(ValueError):
        noisy_or_fusion([0.5], redundancy_decay=1.5)
    with pytest.raises(ValueError):
        noisy_or_fusion([0.5], families=["a", "b"])
    with pytest.raises(ValueError):
        noisy_or_fusion([0.5, 0.5], weights=[1.0])
    with pytest.raises(ValueError):
        noisy_or_fusion([0.5], family_caps={"a": -1.0}, families=["a"])


def synthetic_fusion_data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(2026)
    features = rng.normal(size=(500, 3))
    logit = 1.4 * features[:, 0] - 1.1 * features[:, 1] + 0.4 * features[:, 2] + 0.2
    probability = stable_sigmoid(logit)
    labels = (rng.random(500) < probability).astype(np.int8)
    return features, labels


def test_equation_27_logistic_head_is_deterministic_and_learns():
    features, labels = synthetic_fusion_data()
    first = fit_logistic_fusion_head(features, labels, l2=1e-3, max_iterations=200)
    second = fit_logistic_fusion_head(features, labels, l2=1e-3, max_iterations=200)
    np.testing.assert_allclose(first.weights, second.weights)
    assert first.bias == pytest.approx(second.bias)
    assert first.converged
    assert first.weights[0] > 0
    assert first.weights[1] < 0
    assert first.final_loss < 0.6
    probabilities = first.predict_proba(features)
    assert probabilities.shape == (500,)
    assert np.all((probabilities > 0) & (probabilities < 1))
    accuracy = float(np.mean(first.predict(features) == labels))
    assert accuracy > 0.70
    assert first.binary_cross_entropy(features, labels) == pytest.approx(first.final_loss, rel=1e-6)
    assert 0.0 <= first.brier_score(features, labels) <= 0.25
    assert first.decision_function(features[0]).shape == (1,)


def test_logistic_head_known_values_and_validation():
    head = LogisticFusionHead(weights=np.asarray([1.0, -1.0]), bias=0.0)
    np.testing.assert_allclose(head.decision_function([1.0, 1.0]), [0.0])
    np.testing.assert_allclose(head.predict_proba([1.0, 1.0]), [0.5])
    assert head.predict([1.0, 1.0], threshold=0.5).tolist() == [True]
    assert head.binary_cross_entropy([[1.0, 1.0]], [0]) == pytest.approx(math.log(2.0))
    assert head.brier_score([[1.0, 1.0]], [1]) == pytest.approx(0.25)
    with pytest.raises(ValueError):
        head.predict([1.0, 1.0], threshold=1.0)
    with pytest.raises(ValueError):
        head.predict_proba([1.0, np.nan])
    with pytest.raises(ValueError):
        LogisticFusionHead(weights=np.asarray([np.nan]), bias=0.0)


def test_logistic_fit_validation_and_label_checks():
    features, labels = synthetic_fusion_data()
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features, labels[:-1])
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features, np.full(labels.shape, 2))
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features, labels, l2=-1.0)
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features, labels, max_iterations=0)
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features, labels, tolerance=0.0)
    with pytest.raises(ValueError):
        fit_logistic_fusion_head(features[0], labels[:2])
