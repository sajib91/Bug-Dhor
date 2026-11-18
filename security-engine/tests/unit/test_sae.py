from __future__ import annotations

from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from bugdhor.sae import (  # noqa: E402
    SAEConfig,
    SAETrainer,
    SparseAutoencoder,
    load_checkpoint,
    save_checkpoint,
)


def _data() -> torch.Tensor:
    return torch.linspace(-1, 1, steps=240).reshape(60, 4)


def test_sae_forward_loss_and_feature_extraction_are_real_tensors() -> None:
    config = SAEConfig(input_dim=4, latent_dim=7, sparsity_coefficient=0.01)
    model = SparseAutoencoder(config)
    values = _data()[:8]

    output = model(values)
    total, reconstruction, sparsity = model.loss(values)
    features = model.feature_activations(values, threshold=config.l0_threshold)

    assert output.latents.shape == (8, 7)
    assert output.reconstruction.shape == values.shape
    assert total.item() >= reconstruction.item()
    assert sparsity.item() >= 0
    assert features.shape == (8, 7)
    assert not features.requires_grad


def test_training_tracks_reconstruction_sparsity_and_convergence() -> None:
    config = SAEConfig(
        input_dim=4,
        latent_dim=8,
        sparsity_coefficient=0.001,
        batch_size=10,
        epochs=3,
        validation_fraction=0.2,
        seed=42,
    )
    model = SparseAutoencoder(config)
    result = SAETrainer(config).fit(model, _data())

    assert result.config_hash == config.config_hash
    assert len(result.epochs) == 3
    assert result.validation is not None
    assert result.validation.reconstruction_error >= 0
    assert result.validation.mean_l0 >= 0
    assert len(result.validation.feature_utilization) == 8
    assert result.epochs[0].train_mean_l0 >= 0
    assert len(result.epochs[0].train_feature_utilization) == 8
    assert isinstance(result.epochs[0].train_dead_features, tuple)
    assert result.epochs[1].convergence_delta is not None


def test_checkpoint_round_trip_preserves_weights_and_config(tmp_path: Path) -> None:
    config = SAEConfig(input_dim=4, latent_dim=6, seed=7)
    model = SparseAutoencoder(config)
    path = save_checkpoint(tmp_path / "sae.pt", model)

    loaded, training = load_checkpoint(path, config=config)

    assert training is None
    assert loaded.config == config
    for expected, actual in zip(model.parameters(), loaded.parameters(), strict=True):
        assert torch.equal(expected, actual)


def test_checkpoint_rejects_incompatible_configuration(tmp_path: Path) -> None:
    config = SAEConfig(input_dim=4, latent_dim=6)
    path = save_checkpoint(tmp_path / "sae.pt", SparseAutoencoder(config))

    with pytest.raises(Exception, match="incompatible"):
        load_checkpoint(path, config=SAEConfig(input_dim=4, latent_dim=7))
