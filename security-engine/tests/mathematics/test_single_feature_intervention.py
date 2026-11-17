from __future__ import annotations

import numpy as np
import pytest
from mathematics.sae_encoding import SAEParameters
from mathematics.single_feature_intervention import (
    FeatureIntervention,
    apply_decoder_intervention,
    apply_latent_intervention,
    apply_multi_feature_decoder_intervention,
    estimate_paired_effect,
    run_single_feature_experiment,
    sweep_intervention_values,
)


def identity_sae(dim: int = 2) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_ablation_effect_is_exact():
    activations = np.asarray([[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]])
    experiment = run_single_feature_experiment(
        activations,
        lambda h: h[:, 0] + 2.0 * h[:, 1],
        identity_sae(),
        FeatureIntervention(0, "ablate"),
    )
    np.testing.assert_allclose(experiment.factual_outcomes, [5.0, 11.0, 17.0])
    np.testing.assert_allclose(experiment.interventional_outcomes, [4.0, 8.0, 12.0])
    assert experiment.effect.estimate == pytest.approx(-3.0)
    assert experiment.effect.standard_error == pytest.approx(2.0 / np.sqrt(3.0))
    assert experiment.effect.count == 3
    assert experiment.application.changed_count == 3


def test_clamp_and_add_modes():
    latents = np.asarray([[1.0, 2.0], [3.0, 4.0]])
    clamp = apply_latent_intervention(latents, FeatureIntervention(1, "clamp", 10.0))
    np.testing.assert_allclose(clamp.modified[:, 1], [10.0, 10.0])
    np.testing.assert_allclose(clamp.delta, [8.0, 6.0])
    add = apply_latent_intervention(latents, FeatureIntervention(1, "add", -1.0))
    np.testing.assert_allclose(add.modified[:, 1], [1.0, 3.0])


def test_missing_latents_are_left_unchanged():
    latents = np.asarray([[np.nan, 2.0], [3.0, 4.0]])
    application = apply_latent_intervention(latents, FeatureIntervention(0, "ablate"))
    assert application.missing_count == 1
    assert application.changed_count == 1
    assert np.isnan(application.modified[0, 0])
    np.testing.assert_allclose(application.modified[1, 0], 0.0)


def test_decoder_and_multi_feature_directions():
    parameters = identity_sae()
    activations = np.asarray([[1.0, 2.0], [3.0, 4.0]])
    latents = activations.copy()
    single = apply_decoder_intervention(
        activations, latents, parameters, FeatureIntervention(0, "clamp", 5.0)
    )
    np.testing.assert_allclose(single.modified, [[5.0, 2.0], [5.0, 4.0]])
    multi = apply_multi_feature_decoder_intervention(
        activations,
        latents,
        parameters,
        [FeatureIntervention(0, "clamp", 5.0), FeatureIntervention(1, "ablate")],
    )
    np.testing.assert_allclose(multi.modified, [[5.0, 0.0], [5.0, 0.0]])
    assert multi.feature_index == -1


def test_estimate_paired_effect_drops_missing_pairs():
    estimate = estimate_paired_effect([1.0, np.nan, 3.0], [2.0, 4.0, 6.0])
    assert estimate.count == 2
    assert estimate.missing_count == 1
    assert estimate.estimate == pytest.approx(2.0)
    assert estimate.standardized_effect == pytest.approx(2.0 / np.sqrt(2.0))


def test_sweep_is_deterministic_and_dose_ordered():
    activations = np.asarray([[1.0, 2.0], [3.0, 4.0]])
    results = sweep_intervention_values(
        activations,
        lambda h: h[:, 0] + h[:, 1],
        identity_sae(),
        0,
        [0.0, 1.0, 2.0],
    )
    effects = [item.effect.estimate for item in results]
    assert effects == sorted(effects)
    assert effects[0] == pytest.approx(-2.0)


def test_validation_errors():
    parameters = identity_sae()
    with pytest.raises(ValueError):
        FeatureIntervention(0, "ablate", 1.0)
    with pytest.raises(ValueError):
        FeatureIntervention(0, "clamp", np.nan)
    with pytest.raises(ValueError):
        apply_decoder_intervention(
            np.zeros((1, 2)), np.zeros((1, 2)), parameters, FeatureIntervention(3)
        )
    with pytest.raises(ValueError):
        apply_multi_feature_decoder_intervention(
            np.zeros((1, 2)),
            np.zeros((1, 2)),
            parameters,
            [FeatureIntervention(0), FeatureIntervention(0)],
        )
    with pytest.raises(ValueError):
        estimate_paired_effect([1.0], [1.0, 2.0])
    with pytest.raises(ValueError):
        sweep_intervention_values(np.zeros((1, 2)), lambda h: h[:, 0], parameters, 0, [1.0])
