from __future__ import annotations

import torch

from bugdhor.counterfactual.higher_order import (
    HigherOrderInteractionEngine,
    generate_feature_subsets,
)
from bugdhor.counterfactual.pairwise import FeaturePair, PairwiseInteractionEngine
from bugdhor.sae.association import (
    CodeSampleLabel,
    FeatureExperimentMetadata,
    FeatureSample,
    analyze_features,
)
from bugdhor.steering import (
    AdaptiveSteeringConfig,
    AdaptiveSteeringContext,
    AdaptiveSteeringPolicy,
)


def _dictionary():
    labels = [
        CodeSampleLabel("v1", True, "dataset", "experiment", "CWE-89"),
        CodeSampleLabel("v2", True, "dataset", "experiment", "CWE-89"),
        CodeSampleLabel("s1", False, "dataset", "experiment", "CWE-89"),
        CodeSampleLabel("s2", False, "dataset", "experiment", "CWE-89"),
    ]
    samples = tuple(
        FeatureSample(label, features)
        for label, features in zip(
            labels,
            (
                torch.tensor([2.0, 0.1]),
                torch.tensor([2.0, 0.2]),
                torch.tensor([0.0, 0.1]),
                torch.tensor([0.0, 0.2]),
            ),
            strict=True,
        )
    )
    return analyze_features(
        samples,
        metadata=FeatureExperimentMetadata(
            model_id="local/tiny",
            model_version="test",
            layer="transformer.h.0",
            sae_checkpoint="sae.pt",
            dataset_ids=("dataset",),
            experiment_id="experiment",
            activation_threshold=0.0,
        ),
    )


def test_policy_exposes_individual_pairwise_higher_order_and_context_terms() -> None:
    pairwise = PairwiseInteractionEngine(
        experiment_id="pair",
        outcome_scale="risk_score",
        model_id="local/tiny",
        layer="transformer.h.0",
    ).run(
        FeaturePair(0, 1),
        lambda interventions, _repetition: (
            interventions.get(0, 0.0) * interventions.get(1, 0.0)
        ),
    )
    higher = HigherOrderInteractionEngine(
        experiment_id="higher",
        outcome_scale="risk_score",
        max_order=3,
    ).run(
        generate_feature_subsets((0, 1), min_order=2, max_order=2),
        lambda interventions, _repetition: (
            interventions.get(0, 0.0) * interventions.get(1, 0.0)
        ),
    )
    policy = AdaptiveSteeringPolicy(
        _dictionary(),
        pairwise_results=(pairwise,),
        higher_order_results=higher.results,
        config=AdaptiveSteeringConfig(
            max_features=2,
            cwe="CWE-89",
            minimum_importance=0.01,
            enabled=False,
            context_multiplier=2.0,
        ),
    )

    decision = policy.plan(
        AdaptiveSteeringContext(
            cwe="CWE-89",
            feature_activations_by_position={0: {0: 2.0}, 1: {0: 0.0, 1: 2.0}},
        )
    )

    assert decision.selected_features == (0,)
    assert decision.feature_importance[0].source == "selectivity"
    assert decision.individual_effects
    assert decision.pairwise_interactions == ()
    assert decision.higher_order_interactions == ()
    assert decision.context_adjustment == 2.0
    assert decision.schedule[0][0] == 0
    assert decision.spec.enabled is False


def test_policy_persists_explicit_position_schedule_and_interactions() -> None:
    pairwise = PairwiseInteractionEngine(
        experiment_id="pair",
        outcome_scale="risk_score",
    ).run(
        FeaturePair(0, 1),
        lambda interventions, _repetition: sum(interventions.values()),
    )
    policy = AdaptiveSteeringPolicy(
        _dictionary(),
        pairwise_results=(pairwise,),
        config=AdaptiveSteeringConfig(max_features=2, direction_mode="positive"),
    )
    decision = policy.plan(
        AdaptiveSteeringContext(
            target_positions=(2,),
            feature_activations_by_position={2: {0: 1.0, 1: 1.0}},
        )
    )

    assert decision.selected_features == (0, 1)
    assert len(decision.pairwise_interactions) == 1
    assert decision.schedule[0][0] == 2
    assert decision.spec.position_strengths is not None
    assert set(decision.spec.position_strengths) == {2}
