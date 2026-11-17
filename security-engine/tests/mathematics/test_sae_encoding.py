from __future__ import annotations

import numpy as np
import pytest
from mathematics.common import resolve_rng
from mathematics.sae_encoding import (
    SAEParameters,
    decode,
    encode,
    forward,
    normalize_decoder_columns,
    reconstruction_metrics,
    sae_loss,
)


def identity_sae(dim: int = 2) -> SAEParameters:
    return SAEParameters(
        encoder_weight=np.eye(dim),
        encoder_bias=np.zeros(dim),
        decoder_weight=np.eye(dim),
        decoder_bias=np.zeros(dim),
    )


def test_encode_decode_equations():
    parameters = identity_sae()
    activations = np.asarray([[1.0, -2.0], [0.0, 3.0]])
    latents = encode(activations, parameters)
    expected = np.asarray([[1.0, 0.0], [0.0, 3.0]])
    np.testing.assert_allclose(latents, expected)
    np.testing.assert_allclose(decode(latents, parameters), expected)
    encoded, reconstructed = forward(activations, parameters)
    np.testing.assert_allclose(encoded, expected)
    np.testing.assert_allclose(reconstructed, expected)


def test_encode_threshold_is_post_hoc():
    parameters = identity_sae()
    activations = np.asarray([[0.5, -0.5, 0.0]])
    parameters = SAEParameters(
        encoder_weight=np.eye(3),
        encoder_bias=np.zeros(3),
        decoder_weight=np.eye(3),
        decoder_bias=np.zeros(3),
    )
    np.testing.assert_allclose(encode(activations, parameters, threshold=0.51), 0.0)
    np.testing.assert_allclose(
        encode(activations, parameters, threshold=0.5),
        np.asarray([[0.5, 0.0, 0.0]]),
    )
    with pytest.raises(ValueError):
        encode(activations, parameters, threshold=-1.0)


def test_sae_loss_paper_formula_is_exact():
    parameters = SAEParameters(
        encoder_weight=np.asarray([[1.0, 0.0]]),
        encoder_bias=np.asarray([0.0]),
        decoder_weight=np.asarray([[0.0], [0.0]]),
        decoder_bias=np.zeros(2),
    )
    activations = np.asarray([[1.0, 2.0]])
    loss = sae_loss(activations, parameters, sparsity_coefficient=0.5)
    assert loss.reconstruction == pytest.approx(1.0 + 4.0)
    assert loss.sparsity == pytest.approx(1.0)
    assert loss.total == pytest.approx(5.0 + 0.5)


def test_sae_loss_elementwise_missing_mask():
    parameters = identity_sae()
    activations = np.asarray([[1.0, np.nan]])
    reconstruction = np.asarray([[1.0, 9.0]])
    latents = np.asarray([[1.0, 0.0]])
    observed = np.asarray([[True, False]])
    loss = sae_loss(
        activations,
        parameters,
        sparsity_coefficient=0.0,
        latents=latents,
        reconstruction=reconstruction,
        observed=observed,
        reduction="elementwise",
    )
    assert loss.reconstruction == 0.0
    with pytest.raises(ValueError):
        sae_loss(
            activations,
            parameters,
            sparsity_coefficient=0.0,
            latents=latents,
            reconstruction=reconstruction,
            observed=observed,
            reduction="paper",
        )


def test_reconstruction_metrics_and_dead_features():
    parameters = identity_sae()
    activations = np.asarray([[1.0, 2.0], [3.0, 4.0]])
    metrics = reconstruction_metrics(activations, parameters)
    assert metrics.r2 == pytest.approx(1.0)
    assert metrics.mean_l0 == pytest.approx(2.0)
    assert metrics.dead_features == ()

    sparse_parameters = SAEParameters(
        encoder_weight=np.asarray([[1.0, 0.0], [-1.0, 0.0]]),
        encoder_bias=np.zeros(2),
        decoder_weight=np.asarray([[1.0, 0.0], [0.0, 0.0]]),
        decoder_bias=np.zeros(2),
    )
    metrics = reconstruction_metrics(
        np.asarray([[1.0, 0.0]]), sparse_parameters, active_threshold=0.0
    )
    assert metrics.dead_feature_fraction == pytest.approx(0.5)
    assert metrics.dead_features == (1,)


def test_degenerate_r2_is_nan():
    parameters = identity_sae()
    metrics = reconstruction_metrics(np.asarray([[1.0, 1.0]]), parameters)
    assert np.isnan(metrics.r2)


def test_parameter_validation_and_normalization():
    with pytest.raises(ValueError):
        SAEParameters(
            encoder_weight=np.eye(2),
            encoder_bias=np.zeros(2),
            decoder_weight=np.eye(3),
            decoder_bias=np.zeros(2),
        )
    parameters = SAEParameters(
        encoder_weight=np.eye(2),
        encoder_bias=np.zeros(2),
        decoder_weight=np.asarray([[3.0, 0.0], [4.0, 0.0]]),
        decoder_bias=np.zeros(2),
    )
    normalized = normalize_decoder_columns(parameters)
    np.testing.assert_allclose(np.linalg.norm(normalized.decoder_weight, axis=0), [1.0, 0.0])
    with pytest.raises(ValueError):
        SAEParameters(
            encoder_weight=np.asarray([[np.nan, 0.0]]),
            encoder_bias=np.zeros(1),
            decoder_weight=np.zeros((2, 1)),
            decoder_bias=np.zeros(2),
        )


def test_torch_tensors_are_accepted_detached():
    torch = pytest.importorskip("torch")
    parameters = identity_sae()
    activations = torch.tensor([[1.0, -2.0]], dtype=torch.float64)
    np.testing.assert_allclose(encode(activations, parameters), [[1.0, 0.0]])
    generator = torch.Generator().manual_seed(0)
    tensor = torch.rand((3, 2), generator=generator, dtype=torch.float64)
    array = resolve_rng(0).normal(size=(3, 2))
    assert tensor.shape == array.shape
