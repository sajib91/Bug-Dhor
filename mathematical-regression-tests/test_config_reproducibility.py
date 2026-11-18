"""Configuration hashing, checkpoint round-trip, and seeded reproducibility.

Reproducibility is a mathematical requirement here: an experiment is only
reproducible if the same declared configuration yields the same hash and the
same seed yields the same parameters.  These checks use only public API.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from bugdhor.experiments.config import (
    ExperimentConfig,
    canonical_json,
    sha256_text,
)
from bugdhor.sae import SAEConfig, SparseAutoencoder
from bugdhor.sae.checkpoint import load_checkpoint, save_checkpoint
from bugdhor.sae.errors import (
    SAECheckpointError,
    SAEConfigurationError,
)
from bugdhor.sae.training import SAETrainer


def _config(**overrides) -> SAEConfig:
    values = {
        "input_dim": 4,
        "latent_dim": 6,
        "sparsity_coefficient": 0.01,
        "batch_size": 4,
        "learning_rate": 0.01,
        "epochs": 2,
        "validation_fraction": 0.0,
        "l0_threshold": 1e-6,
        "seed": 17,
    }
    values.update(overrides)
    return SAEConfig(**values)


def test_sae_config_hash_is_canonical_and_sensitive_to_every_field() -> None:
    base = _config()
    assert base.config_hash == _config().config_hash
    # The hash is a SHA-256 over canonically ordered JSON.
    canonical = json.dumps(base.to_dict(), sort_keys=True, separators=(",", ":"))
    assert base.config_hash == sha256_text(canonical)

    for field_name, alternate in (
        ("input_dim", 5),
        ("latent_dim", 7),
        ("sparsity_coefficient", 0.02),
        ("batch_size", 8),
        ("learning_rate", 0.02),
        ("epochs", 3),
        ("validation_fraction", 0.5),
        ("l0_threshold", 1e-5),
        ("seed", 18),
    ):
        assert _config(**{field_name: alternate}).config_hash != base.config_hash


def test_invalid_sae_configuration_is_rejected() -> None:
    for overrides in (
        {"input_dim": 0},
        {"latent_dim": 0},
        {"sparsity_coefficient": -1.0},
        {"batch_size": 0},
        {"epochs": 0},
        {"learning_rate": 0.0},
        {"validation_fraction": 1.0},
        {"validation_fraction": -0.1},
        {"l0_threshold": -1.0},
    ):
        with pytest.raises(SAEConfigurationError):
            _config(**overrides)


def test_checkpoint_round_trip_preserves_weights_and_hash(tmp_path: Path) -> None:
    config = _config()
    model = SparseAutoencoder(config)
    path = save_checkpoint(tmp_path / "sae.pt", model)
    payload = torch.load(path, map_location="cpu", weights_only=False)
    assert payload["config_hash"] == config.config_hash
    assert payload["config"] == config.to_dict()

    restored, training = load_checkpoint(path, config=config)
    assert training is None
    assert restored.config.config_hash == config.config_hash
    for name, tensor in model.state_dict().items():
        assert torch.equal(restored.state_dict()[name], tensor)


def test_checkpoint_rejects_incompatible_or_corrupted_payload(tmp_path: Path) -> None:
    config = _config()
    path = save_checkpoint(tmp_path / "sae.pt", SparseAutoencoder(config))

    with pytest.raises(SAECheckpointError):
        load_checkpoint(path, config=_config(seed=99))

    payload = torch.load(path, map_location="cpu", weights_only=False)
    payload["config_hash"] = "0" * 64
    corrupt = tmp_path / "corrupt.pt"
    torch.save(payload, corrupt)
    with pytest.raises(SAECheckpointError, match="hash"):
        load_checkpoint(corrupt)

    garbage = tmp_path / "garbage.pt"
    garbage.write_bytes(b"not a torch checkpoint")
    with pytest.raises(SAECheckpointError):
        load_checkpoint(garbage)


def test_training_is_deterministic_for_a_fixed_seed() -> None:
    activations = torch.linspace(-1.0, 1.0, steps=32).reshape(8, 4)

    def trained(seed: int):
        # The trainer seeds global RNG state; construct the model afterwards so
        # parameter initialisation is part of the seeded stream.
        trainer = SAETrainer(_config(seed=seed))
        model = SparseAutoencoder(_config(seed=seed))
        return model, trainer.fit(model, activations)

    first, first_result = trained(3)
    second, second_result = trained(3)
    different, different_result = trained(4)

    for name, tensor in first.state_dict().items():
        assert torch.equal(second.state_dict()[name], tensor)
    assert any(
        not torch.equal(first.state_dict()[name], different.state_dict()[name])
        for name in first.state_dict()
    )

    assert [epoch.train_loss for epoch in first_result.epochs] == [
        epoch.train_loss for epoch in second_result.epochs
    ]
    assert first_result.config_hash == second_result.config_hash
    assert [epoch.train_loss for epoch in first_result.epochs] != [
        epoch.train_loss for epoch in different_result.epochs
    ]
    assert different_result.config_hash != first_result.config_hash


def test_experiment_config_hash_is_canonical_and_tag_order_insensitive() -> None:
    def make(tags, parameters=None):
        return ExperimentConfig(
            experiment_id="exp-1",
            name="Pairwise validation",
            group="E4",
            dataset={"name": "synthetic", "version": 1},
            split={"seed": 7, "fraction": 0.5},
            model={"id": "tiny", "revision": "abc"},
            parameters=parameters or {"topK": 3, "nBoot": 2000},
            seed=11,
            tools={"python": "3.11"},
            tags=tags,
        )

    base = make(["b", "a"])
    assert base.config_hash() == make(["a", "b"]).config_hash()
    assert base.config_hash() == sha256_text(
        canonical_json(
            {
                "experimentId": "exp-1",
                "name": "Pairwise validation",
                "group": "E4",
                "dataset": {"name": "synthetic", "version": 1},
                "split": {"seed": 7, "fraction": 0.5},
                "model": {"id": "tiny", "revision": "abc"},
                "parameters": {"topK": 3, "nBoot": 2000},
                "seed": 11,
                "tools": {"python": "3.11"},
                "tags": ["a", "b"],
            }
        )
    )
    assert base.config_hash() != make(["a", "b"], {"topK": 4}).config_hash()
    assert base.to_dict()["configHash"] == base.config_hash()
    assert base.validate() == []


def test_experiment_config_validation_reports_missing_fields() -> None:
    config = ExperimentConfig(
        experiment_id="",
        name="",
        group="not-a-group",
        dataset={},
        split={},
        model={},
    )
    errors = config.validate()
    assert "unknown_experiment_group:not-a-group" in errors
    assert "missing_experiment_id" in errors
    assert "missing_name" in errors
