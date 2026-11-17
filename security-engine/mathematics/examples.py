"""Reproducible small examples for every mathematical component.

Run with::

    cd security-engine
    .venv/bin/python -m mathematics.examples

The examples use deterministic synthetic tensors and exact analytic outcome
functions.  They exercise the real implementations; they do not contain
pre-computed scores or fabricated results.
"""

from __future__ import annotations

import json
import math
from typing import Any

import numpy as np

from mathematics.adaptive_steering import (
    AdaptiveSteeringConfig,
    apply_adaptive_steering,
    plan_adaptive_steering,
)
from mathematics.common import stable_sigmoid
from mathematics.counterfactual_estimation import estimate_counterfactual_outcomes
from mathematics.cwe_risk import (
    CweRiskPolicy,
    RiskComponents,
    RiskThresholds,
    RiskWeights,
    assess_cwe_risk,
)
from mathematics.evidence_fusion import (
    assemble_evidence_matrix,
    fit_logistic_fusion_head,
    masked_weighted_fusion,
    noisy_or_fusion,
)
from mathematics.feature_association import analyze_feature_associations
from mathematics.feature_measurement import measure_feature_activations
from mathematics.functional_preservation import (
    PredicateState,
    evaluate_preservation,
    functional_pass_rate,
)
from mathematics.higher_order_interaction import run_higher_order_experiment
from mathematics.pairwise_interaction import run_pairwise_experiment
from mathematics.sae_encoding import (
    SAEParameters,
    decode,
    encode,
    reconstruction_metrics,
    sae_loss,
)
from mathematics.single_feature_intervention import (
    FeatureIntervention,
    run_single_feature_experiment,
)
from mathematics.sparse_representation import l0_norm, to_sparse

SEED = 20240517


def build_demo_sae(input_dim: int = 6, latent_dim: int = 5) -> SAEParameters:
    """Build a deterministic, full-rank ReLU SAE for the examples."""
    rng = np.random.default_rng(SEED)
    encoder = rng.normal(0.0, 0.4, size=(latent_dim, input_dim))
    decoder = rng.normal(0.0, 0.4, size=(input_dim, latent_dim))
    # Make the decoder approximately a left inverse of the encoder.
    decoder = decoder + np.linalg.pinv(encoder)
    return SAEParameters(
        encoder_weight=encoder,
        encoder_bias=rng.normal(0.0, 0.05, size=latent_dim),
        decoder_weight=decoder,
        decoder_bias=rng.normal(0.0, 0.05, size=input_dim),
    )


def build_demo_activations(samples_per_group: int = 60) -> tuple[np.ndarray, np.ndarray]:
    """Create two measured activation groups with a reproducible shift."""
    rng = np.random.default_rng(SEED + 1)
    secure = rng.normal(0.0, 0.5, size=(samples_per_group, 6))
    vulnerable = rng.normal(0.0, 0.5, size=(samples_per_group, 6))
    vulnerable[:, 0] += 0.8
    vulnerable[:, 2] -= 0.4
    activations = np.vstack([secure, vulnerable])
    labels = np.concatenate(
        [np.zeros(samples_per_group, dtype=np.int8), np.ones(samples_per_group, dtype=np.int8)]
    )
    return activations, labels


def analytic_outcome(activations: np.ndarray) -> np.ndarray:
    """A nonlinear, deterministic outcome with a real pairwise interaction."""
    h = np.asarray(activations, dtype=np.float64)
    return h[:, 0] + 0.5 * h[:, 1] + 0.3 * np.tanh(h[:, 0] * h[:, 1])


def run_examples() -> dict[str, Any]:
    """Run every example and return the measured results."""
    parameters = build_demo_sae()
    activations, labels = build_demo_activations()
    latents = encode(activations, parameters)
    reconstruction = decode(latents, parameters)
    loss = sae_loss(activations, parameters, sparsity_coefficient=0.1)
    metrics = reconstruction_metrics(activations, parameters)
    sparse = to_sparse(latents, threshold=0.05)
    measurement = measure_feature_activations(latents, threshold=0.05)
    association = analyze_feature_associations(latents, labels, threshold=0.05)

    single = run_single_feature_experiment(
        activations,
        analytic_outcome,
        parameters,
        FeatureIntervention(0, "ablate"),
        seed=SEED,
    )
    pair = run_pairwise_experiment(
        activations,
        analytic_outcome,
        parameters,
        0,
        1,
        value_a=1.0,
        value_b=1.0,
        seed=SEED,
    )
    higher = run_higher_order_experiment(
        activations,
        analytic_outcome,
        parameters,
        [(0, 1, 2)],
        intervention_value=1.0,
        seed=SEED,
    )

    factual = analytic_outcome(activations)
    counterfactual = analytic_outcome(
        apply_adaptive_steering(
            activations,
            parameters,
            plan_adaptive_steering(
                {0: 1.0, 1: 0.8, 2: 0.6},
                mean_differences={
                    int(index): float(value)
                    for index, value in zip(
                        association.feature_indices,
                        association.mean_difference,
                        strict=True,
                    )
                },
                pairwise_contrasts={(0, 1): pair.estimate.contrast},
                higher_order_contrasts={
                    (0, 1, 2): higher.results[0].contrast,
                },
                config=AdaptiveSteeringConfig(
                    max_features=3,
                    l2_budget=2.0,
                    context_multiplier=1.0,
                ),
                activations_by_position={
                    0: {0: 0.5, 1: 0.2, 2: 1.5},
                    1: {0: 0.0, 1: 0.4, 2: 0.1},
                },
            ),
        ).modified,
    )
    counterfactual_estimate = estimate_counterfactual_outcomes(
        factual,
        counterfactual,
        outcome_scale="analytic_score",
        seed=SEED,
    )
    steering_plan = plan_adaptive_steering(
        {0: 1.0, 1: 0.8, 2: 0.6},
        mean_differences={
            int(index): float(value)
            for index, value in zip(
                association.feature_indices,
                association.mean_difference,
                strict=True,
            )
        },
        pairwise_contrasts={(0, 1): pair.estimate.contrast},
        higher_order_contrasts={(0, 1, 2): higher.results[0].contrast},
        config=AdaptiveSteeringConfig(max_features=3, l2_budget=2.0),
        activations_by_position={0: {0: 0.5, 1: 0.2, 2: 1.5}},
    )

    top = int(np.nanargmax(np.abs(association.mean_difference)))
    probability = float(
        stable_sigmoid(np.asarray(association.mean_difference[top], dtype=np.float64))
    )
    risk = assess_cwe_risk(
        RiskComponents(
            probability=probability,
            severity=0.8,
            exposure=0.6,
            impact=float(1.0 / (1.0 + math.exp(-abs(association.cohens_d[top])))),
        ),
        CweRiskPolicy(
            cwe="CWE-89",
            weights=RiskWeights(alpha=0.4, beta=0.2, gamma=0.2, delta=0.2),
            thresholds=RiskThresholds(low=0.25, medium=0.5, high=0.75),
        ),
    )

    rng = np.random.default_rng(SEED + 2)
    modality_scores = rng.uniform(0.0, 1.0, size=(200, 4))
    availability = np.ones_like(modality_scores, dtype=bool)
    availability[::17, 3] = False
    evidence = assemble_evidence_matrix(
        {
            "neural": modality_scores[:, 0],
            "sae": modality_scores[:, 1],
            "interaction": modality_scores[:, 2],
            "static": modality_scores[:, 3],
        },
        availability={
            "neural": availability[:, 0],
            "sae": availability[:, 1],
            "interaction": availability[:, 2],
            "static": availability[:, 3],
        },
    )
    masked = masked_weighted_fusion(
        evidence.values,
        np.asarray([0.4, 0.3, 0.2, 0.1]),
        availability=evidence.available,
    )
    noisy = noisy_or_fusion(
        [0.8, 0.6, 0.4],
        families=["program", "program", "llm"],
        redundancy_decay=0.7,
        refutation_scores=[0.3],
    )
    truth = (
        0.8 * modality_scores[:, 0]
        + 0.5 * modality_scores[:, 1]
        - 0.3 * modality_scores[:, 2]
        + 0.2 * modality_scores[:, 3]
        + 0.1 * rng.normal(size=200)
        > 0.55
    ).astype(np.int8)
    head = fit_logistic_fusion_head(modality_scores, truth, l2=1e-3)
    fused_probability = head.predict_proba(modality_scores.mean(axis=0))
    train_accuracy = float(np.mean(head.predict(modality_scores) == truth))

    functional_rate = functional_pass_rate([1, 2, 3.0, None], [1, 2, 3.0, 4])
    acceptance = evaluate_preservation(
        expected=[1, 2, 3.0],
        actual=[1, 2, 3.0],
        syntax=True,
        baseline_tests={"tests/test_api.py::test_ok": True},
        candidate_tests={"tests/test_api.py::test_ok": True},
        original_vulnerabilities={"CWE-89@a.py:10"},
        candidate_vulnerabilities=set(),
        targeted={"CWE-89@a.py:10"},
        scan_complete=True,
    )
    return {
        "sae": {
            "loss": loss.total,
            "reconstruction": loss.reconstruction,
            "sparsity": loss.sparsity,
            "r2": metrics.r2,
            "mean_l0": metrics.mean_l0,
            "reconstruction_norm": float(np.linalg.norm(reconstruction)),
            "support_entries": int((sparse.indices >= 0).sum()),
            "l0_per_sample": l0_norm(latents, threshold=0.05).tolist(),
        },
        "measurement": {
            "feature_indices": measurement.feature_indices.tolist(),
            "activation_frequency": measurement.activation_frequency.tolist(),
            "observed_count": measurement.observed_count.tolist(),
        },
        "association": {
            "mean_difference": association.mean_difference.tolist(),
            "cohens_d": association.cohens_d.tolist(),
            "q_value": association.q_value.tolist(),
        },
        "single_feature": {
            "effect": single.effect.estimate,
            "standard_error": single.effect.standard_error,
            "count": single.effect.count,
        },
        "pairwise": {
            "contrast": pair.estimate.contrast,
            "standard_error": pair.estimate.standard_error,
            "paired": pair.estimate.paired,
        },
        "higher_order": {
            "subset": list(higher.results[0].subset),
            "contrast": higher.results[0].contrast,
            "standard_error": higher.results[0].standard_error,
        },
        "counterfactual": {
            "delta": counterfactual_estimate.delta,
            "standard_error": counterfactual_estimate.standard_error,
            "count": counterfactual_estimate.count,
        },
        "steering": {
            "selected": list(steering_plan.selected_features),
            "strengths": {str(key): value for key, value in steering_plan.strengths.items()},
            "l2_norm": steering_plan.allocation.l2_norm,
            "l2_scale": steering_plan.allocation.l2_scale,
            "schedule": [
                {
                    "position": item.position,
                    "active_features": list(item.active_features),
                    "strengths": list(item.strengths),
                }
                for item in steering_plan.schedule
            ],
        },
        "risk": {
            "score": risk.score,
            "band": risk.band,
            "is_probability": risk.is_probability,
            "missing_count": risk.missing_count,
        },
        "fusion": {
            "masked_scores_head": masked.scores[:3].tolist(),
            "masked_missing": masked.missing_count,
            "noisy_or_score": noisy.score,
            "logistic_probability": float(fused_probability[0]),
            "train_accuracy": train_accuracy,
        },
        "preservation": {
            "functional_pass_rate": functional_rate.pass_rate,
            "functional_state": functional_rate.state.value,
            "acceptance_state": acceptance.state.value,
            "accepted": acceptance.accepted,
            "inconclusive_count": acceptance.inconclusive_count,
            "targeted_state": acceptance.predicates["V_security"].value,
            "hoare_absent_is_not_pass": PredicateState.INCONCLUSIVE.value,
        },
    }


def main() -> None:
    """Print the examples as deterministic JSON."""
    print(json.dumps(run_examples(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
