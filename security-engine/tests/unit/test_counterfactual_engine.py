from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")

from craftsec.counterfactual import (  # noqa: E402
    CounterfactualEngine,
    CounterfactualSpec,
    RiskOutcome,
)
from craftsec.models.config import GenerationConfig  # noqa: E402
from craftsec.models.errors import ModelCompatibilityError  # noqa: E402
from craftsec.sae import SAEConfig, SparseAutoencoder  # noqa: E402


class TinyTokenizer:
    name_or_path = "local-counterfactual-tokenizer"

    def __init__(self) -> None:
        self.vocabulary = {"<pad>": 0}

    def __call__(self, texts, **_kwargs):
        if isinstance(texts, str):
            texts = [texts]
        rows = []
        offsets = []
        for text in texts:
            row = []
            row_offsets = []
            for token in text.split():
                start = text.index(token, row_offsets[-1][1] if row_offsets else 0)
                end = start + len(token)
                self.vocabulary.setdefault(token, len(self.vocabulary))
                row.append(self.vocabulary[token])
                row_offsets.append((start, end))
            rows.append(row)
            offsets.append(row_offsets)
        width = max(len(row) for row in rows)
        return {
            "input_ids": torch.tensor([row + [0] * (width - len(row)) for row in rows]),
            "attention_mask": torch.tensor(
                [[1] * len(row) + [0] * (width - len(row)) for row in rows]
            ),
            "offset_mapping": torch.tensor(
                [row + [(0, 0)] * (width - len(row)) for row in offsets]
            ),
        }

    def convert_ids_to_tokens(self, ids):
        reverse = {value: key for key, value in self.vocabulary.items()}
        return [reverse[value] for value in ids]

    def decode(self, ids, **_kwargs):
        reverse = {value: key for key, value in self.vocabulary.items()}
        return " ".join(reverse.get(value, f"<token-{value}>") for value in ids.tolist())


class TinyAdapter:
    def __init__(self) -> None:
        self._torch = torch
        self.model_id = "local/tiny-gpt2"
        self.model_version = "test"
        self.device = "cpu"
        self.supports_activations = True
        self.tokenizer = TinyTokenizer()
        self.model = transformers.GPT2LMHeadModel(
            transformers.GPT2Config(
                vocab_size=32,
                n_positions=32,
                n_ctx=32,
                n_embd=8,
                n_layer=1,
                n_head=2,
                bos_token_id=0,
                eos_token_id=0,
            )
        )


def test_counterfactual_preserves_settings_and_separates_output_from_truth() -> None:
    adapter = TinyAdapter()
    sae = SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=4, seed=3))
    engine = CounterfactualEngine(
        adapter,
        sae,
        layer="transformer.h.0",
        sae_checkpoint="sae-test.pt",
        experiment_id="counterfactual-test",
        seed=11,
    )

    result = engine.run(
        "def safe(): return 1",
        CounterfactualSpec(feature_index=0, mode="ablate", target_positions=(0,)),
        generation=GenerationConfig(max_new_tokens=1),
        risk_evaluator=lambda text: RiskOutcome(
            predicted_vulnerable="eval" in text,
            risk_score=0.2,
        ),
        true_vulnerable=False,
    )

    assert result.metadata.generation_kwargs["max_new_tokens"] == 1
    assert result.metadata.generation_kwargs["use_cache"] is False
    assert result.metadata.seed == 11
    # The recorded post-intervention values are re-encoded measurements, not the
    # requested ablation target, so they are not assumed to be exactly zero.
    assert result.activation.feature_delta == pytest.approx(
        result.activation.intervention_mean - result.activation.baseline_mean
    )
    assert all(value == value for value in result.activation.intervention_values)
    assert result.comparison.baseline_risk.true_vulnerable is False
    assert result.comparison.intervention_risk.true_vulnerable is False
    assert result.comparison.true_vulnerability_status_unchanged
    assert result.causal_interpretation.startswith("Controlled output comparison")
    assert adapter.model.transformer.h[0]._forward_hooks == {}


def test_modify_requires_value_and_invalid_feature_is_rejected() -> None:
    with pytest.raises(ValueError):
        CounterfactualSpec(feature_index=0, mode="modify")
    engine = CounterfactualEngine(
        TinyAdapter(),
        SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2)),
        layer="transformer.h.0",
        sae_checkpoint="sae.pt",
        experiment_id="test",
    )
    with pytest.raises(ValueError, match="feature_index"):
        engine.run("x", CounterfactualSpec(feature_index=2, mode="ablate"))


def test_invalid_layer_and_incompatible_sae_are_rejected() -> None:
    with pytest.raises(ModelCompatibilityError, match="intervention layer"):
        CounterfactualEngine(
            TinyAdapter(),
            SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2)),
            layer="transformer.h.99",
            sae_checkpoint="sae.pt",
            experiment_id="test",
        )
    with pytest.raises(ModelCompatibilityError, match="hidden size"):
        CounterfactualEngine(
            TinyAdapter(),
            SparseAutoencoder(SAEConfig(input_dim=7, latent_dim=2)),
            layer="transformer.h.0",
            sae_checkpoint="sae.pt",
            experiment_id="test",
        )
