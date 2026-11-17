"""Independent checks of decoder-direction steering arithmetic."""

from __future__ import annotations

import numpy as np
import pytest

torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")

import reference as ref
from craftsec.models.config import GenerationConfig
from craftsec.sae import SAEConfig, SparseAutoencoder
from craftsec.steering.engine import (
    ActivationSteeringEngine,
    SteeringSpec,
)


class TinyTokenizer:
    name_or_path = "regression-tokenizer"
    version = "1"

    def __call__(self, text, **_kwargs):
        tokens = text.split() or ["<pad>"]
        ids = [1 + (hash(token) % 8) for token in tokens]
        return {
            "input_ids": torch.tensor([ids], dtype=torch.long),
            "attention_mask": torch.ones((1, len(ids)), dtype=torch.long),
        }

    def decode(self, ids, **_kwargs):
        return " ".join(str(int(value)) for value in ids.tolist())


class TinyAdapter:
    def __init__(self) -> None:
        self._torch = torch
        self.model_id = "regression/tiny"
        self.model_version = "1"
        self.device = "cpu"
        self.supports_activations = True
        self.tokenizer = TinyTokenizer()
        self.model = transformers.GPT2LMHeadModel(
            transformers.GPT2Config(
                vocab_size=16,
                n_positions=16,
                n_ctx=16,
                n_embd=2,
                n_layer=1,
                n_head=1,
                bos_token_id=0,
                eos_token_id=0,
            )
        )


def _engine(max_delta_norm: float = 2.0) -> ActivationSteeringEngine:
    sae = SparseAutoencoder(SAEConfig(input_dim=2, latent_dim=2))
    with torch.no_grad():
        sae.decoder.weight.zero_()
        sae.decoder.weight[0, 0] = 3.0
        sae.decoder.weight[1, 1] = 4.0
    return ActivationSteeringEngine(
        TinyAdapter(),
        sae,
        layer="transformer.h.0",
        sae_checkpoint="regression.pt",
        experiment_id="steering-regression",
        seed=3,
    )


def test_directions_and_clamped_delta_match_reference() -> None:
    engine = _engine()
    decoder = engine.sae.decoder.weight.detach().numpy()
    directions = engine._directions((0, 1), (1.0, 1.0)).numpy()
    np.testing.assert_allclose(
        directions, ref.decoder_directions(decoder, (0, 1), (1.0, 1.0))
    )
    # ``_directions`` returns the unclamped per-feature rows; the hook clamps the
    # summed delta.  The reference clamps the same sum.
    unclamped = directions.sum(axis=0)
    clamped = ref.clamped_delta(decoder, (0, 1), (1.0, 1.0), max_norm=2.0)
    assert np.linalg.norm(unclamped) == pytest.approx(5.0)
    assert np.linalg.norm(clamped) == pytest.approx(2.0)
    np.testing.assert_allclose(unclamped * (2.0 / 5.0), clamped)


def test_run_applies_clamped_delta_and_uses_one_decoding_path() -> None:
    engine = _engine()
    result = engine.run(
        "token",
        SteeringSpec(
            feature_indices=(0, 1),
            strengths=(1.0, 1.0),
            target_positions=(0,),
            enabled=True,
            max_delta_norm=2.0,
        ),
        generation=GenerationConfig(max_new_tokens=1),
    )
    assert result.metadata.generation_kwargs["use_cache"] is False
    assert result.validation.max_delta_norm == pytest.approx(2.0)
    assert result.activation_deltas == pytest.approx((2.0,))
    assert engine.adapter.model.transformer.h[0]._forward_hooks == {}


def test_steering_spec_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError):
        SteeringSpec(feature_indices=(0, 0), enabled=True)
    with pytest.raises(ValueError):
        SteeringSpec(feature_indices=(0,), strengths=(1.0, 2.0))
    with pytest.raises(ValueError):
        SteeringSpec(feature_indices=(0,), max_delta_norm=0.0)
    with pytest.raises(ValueError):
        SteeringSpec(feature_indices=(0,), target_positions=())


def test_positions_filter_out_of_range_indices() -> None:
    assert ActivationSteeringEngine._positions(None, 3) == (0, 1, 2)
    assert ActivationSteeringEngine._positions((0, 5, 2), 3) == (0, 2)
    assert ActivationSteeringEngine._positions((1, 2), 3) == (1, 2)
