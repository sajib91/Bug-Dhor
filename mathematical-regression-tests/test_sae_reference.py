"""Independent checks of SAE encoding, loss, and sparse statistics."""

from __future__ import annotations

import numpy as np
import pytest

torch = pytest.importorskip("torch")

import reference as ref
from bugdhor.sae import SAEConfig, SparseAutoencoder
from bugdhor.sae.metrics import feature_statistics, validation_metrics


def _identity_sae() -> SparseAutoencoder:
    sae = SparseAutoencoder(SAEConfig(input_dim=2, latent_dim=2, sparsity_coefficient=0.5))
    with torch.no_grad():
        sae.encoder.weight.copy_(torch.eye(2))
        sae.encoder.bias.zero_()
        sae.decoder.weight.copy_(torch.eye(2))
        sae.decoder.bias.zero_()
    return sae


def test_encode_decode_and_loss_match_numpy_reference() -> None:
    sae = SparseAutoencoder(SAEConfig(input_dim=3, latent_dim=4, sparsity_coefficient=0.25))
    with torch.no_grad():
        sae.encoder.weight.copy_(torch.tensor(np.arange(12, dtype=np.float32).reshape(4, 3) / 10))
        sae.encoder.bias.copy_(torch.tensor([0.1, -0.2, 0.0, 0.3]))
        sae.decoder.weight.copy_(torch.tensor(np.arange(12, dtype=np.float32).reshape(3, 4) / 7))
        sae.decoder.bias.copy_(torch.tensor([0.01, 0.02, 0.03]))

    activations = torch.tensor([[1.0, -2.0, 0.5], [0.0, 0.3, 0.7]])
    weight_e = sae.encoder.weight.detach().numpy()
    bias_e = sae.encoder.bias.detach().numpy()
    weight_d = sae.decoder.weight.detach().numpy()
    bias_d = sae.decoder.bias.detach().numpy()
    x = activations.numpy()

    expected_latents = ref.sae_encode(x, weight_e, bias_e)
    expected_reconstruction = ref.sae_decode(expected_latents, weight_d, bias_d)
    with torch.no_grad():
        output = sae(activations)
        latents = output.latents.numpy()
        reconstruction = output.reconstruction.numpy()

    np.testing.assert_allclose(latents, expected_latents, rtol=1e-6, atol=1e-6)
    np.testing.assert_allclose(reconstruction, expected_reconstruction, rtol=1e-6, atol=1e-6)

    expected_total, expected_mse, expected_l1 = ref.sae_loss(
        x, weight_e, bias_e, weight_d, bias_d, sae.config.sparsity_coefficient
    )
    with torch.no_grad():
        total, mse, l1 = sae.loss(activations)
    assert float(total) == pytest.approx(expected_total, rel=1e-6)
    assert float(mse) == pytest.approx(expected_mse, rel=1e-6)
    assert float(l1) == pytest.approx(expected_l1, rel=1e-6)


def test_feature_activation_threshold_is_strictly_greater_than() -> None:
    sae = _identity_sae()
    activations = torch.tensor([[1.0, 2.0]])
    threshold = 1.0

    expected = ref.threshold_latents(activations.numpy(), threshold)
    actual = sae.feature_activations(activations, threshold=threshold).numpy()
    np.testing.assert_allclose(actual, expected)
    # A value exactly at the threshold is removed, not retained.
    assert actual[0, 0] == 0.0 and actual[0, 1] == 2.0

    no_threshold = sae.feature_activations(activations).numpy()
    np.testing.assert_allclose(no_threshold, activations.numpy())


def test_sparse_statistics_match_reference_and_agree_with_thresholding() -> None:
    latents = torch.tensor([
        [1.0, 0.0, -2.0],
        [0.5, 4.0, 0.0],
        [1.0, 1.0, 1.0],
    ])
    threshold = 1.0
    expected_l0, expected_utilization, expected_dead = ref.feature_statistics(
        latents.numpy(), threshold
    )
    stats = feature_statistics(latents, threshold)
    assert stats.mean_l0 == pytest.approx(expected_l0)
    np.testing.assert_allclose(stats.feature_utilization, expected_utilization)
    assert stats.dead_features == expected_dead

    thresholded = torch.tensor(ref.threshold_latents(latents.numpy(), threshold))
    assert feature_statistics(thresholded, threshold).mean_l0 == pytest.approx(
        stats.mean_l0
    )


def test_validation_metrics_match_reference() -> None:
    inputs = torch.tensor([[1.0, 2.0], [3.0, 4.0]])
    reconstructions = torch.tensor([[1.0, 1.0], [2.0, 4.0]])
    latents = torch.tensor([[1.0, 0.0], [0.0, 2.0]])
    metrics = validation_metrics(inputs, reconstructions, latents, threshold=0.5)

    assert metrics.reconstruction_error == pytest.approx(
        float(np.mean((reconstructions.numpy() - inputs.numpy()) ** 2))
    )
    assert metrics.relative_reconstruction_error == pytest.approx(
        ref.relative_reconstruction_error(inputs.numpy(), reconstructions.numpy())
    )
    expected_l0, _, expected_dead = ref.feature_statistics(latents.numpy(), 0.5)
    assert metrics.mean_l0 == pytest.approx(expected_l0)
    assert metrics.dead_features == expected_dead


def test_encoder_rejects_non_finite_and_wrong_shape() -> None:
    sae = _identity_sae()
    with pytest.raises(ValueError, match="shape"):
        sae.encode(torch.zeros(3))
    with pytest.raises(ValueError, match="finite"):
        sae.encode(torch.tensor([[float("nan"), 1.0]]))
