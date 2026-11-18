from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")

from bugdhor.models.config import GenerationConfig  # noqa: E402
from bugdhor.models.errors import ModelCompatibilityError  # noqa: E402
from bugdhor.sae import SAEConfig, SparseAutoencoder  # noqa: E402
from bugdhor.steering import (  # noqa: E402
    ActivationSteeringEngine,
    FunctionalConstraintEvaluator,
    FunctionalConstraints,
    FunctionalEvidence,
    SteeringSpec,
)


class TinyTokenizer:
    name_or_path = "local-steering-tokenizer"
    version = "test-tokenizer"

    def __init__(self) -> None:
        self.vocabulary = {"<pad>": 0}

    def __call__(self, text, **_kwargs):
        tokens = text.split()
        for token in tokens:
            self.vocabulary.setdefault(token, len(self.vocabulary))
        return {
            "input_ids": torch.tensor(
                [[self.vocabulary[token] for token in tokens]], dtype=torch.long
            ),
            "attention_mask": torch.ones((1, len(tokens)), dtype=torch.long),
        }

    def decode(self, ids, **_kwargs):
        reverse = {value: key for key, value in self.vocabulary.items()}
        return " ".join(reverse.get(value, "<unknown>") for value in ids.tolist())


class TinyAdapter:
    def __init__(self) -> None:
        self._torch = torch
        self.model_id = "local/tiny-gpt2"
        self.model_version = "test-model"
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


def test_steering_uses_decoder_direction_and_restores_hooks() -> None:
    adapter = TinyAdapter()
    sae = SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2))
    with torch.no_grad():
        sae.decoder.weight.zero_()
        sae.decoder.weight[0, 0] = 1.0
    engine = ActivationSteeringEngine(
        adapter,
        sae,
        layer="transformer.h.0",
        sae_checkpoint="sae-test.pt",
        experiment_id="steering-test",
    )

    result = engine.run(
        "safe code",
        SteeringSpec(
            feature_indices=(0,),
            strengths=(2.0,),
            target_positions=(0,),
            enabled=True,
            max_delta_norm=1.5,
        ),
        generation=GenerationConfig(max_new_tokens=1),
    )

    assert result.comparison.steered is not None
    assert result.metadata.enabled is True
    assert result.metadata.tokenizer_version == "test-tokenizer"
    assert result.validation.finite is True
    assert result.validation.shape_valid is True
    assert result.validation.max_delta_norm == 1.5
    assert result.activation_deltas
    assert adapter.model.transformer.h[0]._forward_hooks == {}


def test_steering_is_disabled_by_default_without_running_an_intervention() -> None:
    adapter = TinyAdapter()
    engine = ActivationSteeringEngine(
        adapter,
        SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2)),
        layer="transformer.h.0",
        sae_checkpoint="sae.pt",
        experiment_id="disabled-test",
    )

    result = engine.run(
        "safe code",
        SteeringSpec(feature_indices=(0,)),
        generation=GenerationConfig(max_new_tokens=1),
    )

    assert result.comparison.steered is None
    assert result.comparison.output_changed is None
    assert result.validation.enabled is False
    assert result.validation.original_restored is True
    assert adapter.model.transformer.h[0]._forward_hooks == {}


def test_steering_rejects_unsupported_layers() -> None:
    with pytest.raises(ModelCompatibilityError, match="compatible Transformer layer"):
        ActivationSteeringEngine(
            TinyAdapter(),
            SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2)),
            layer="unsupported.layer",
            sae_checkpoint="sae.pt",
            experiment_id="invalid-test",
        )


def test_steering_rejects_functionally_regressive_candidate() -> None:
    class EvidenceEvaluator:
        def evaluate(self, candidate, baseline, baseline_generation_seconds):
            return FunctionalEvidence(
                syntax_valid=True,
                functional_regression=1.0,
                security_improvement=1.0,
            )

    adapter = TinyAdapter()
    engine = ActivationSteeringEngine(
        adapter,
        SparseAutoencoder(SAEConfig(input_dim=8, latent_dim=2)),
        layer="transformer.h.0",
        sae_checkpoint="sae.pt",
        experiment_id="functional-rejection-test",
    )
    result = engine.run(
        "safe code",
        SteeringSpec(feature_indices=(0,), enabled=True),
        generation=GenerationConfig(max_new_tokens=1),
        functional_evaluator=FunctionalConstraintEvaluator(
            FunctionalConstraints(max_functional_regression=0.0),
            evidence_evaluator=EvidenceEvaluator(),
        ),
    )

    assert result.comparison.steered is None
    assert result.comparison.rejected_candidate is not None
    assert result.functional_evaluation is not None
    assert result.functional_evaluation.accepted is False
    assert result.metadata.functional_tradeoff == {
        "security_improvement": 1.0,
        "functional_regression": 1.0,
        "generation_overhead": None,
    }
