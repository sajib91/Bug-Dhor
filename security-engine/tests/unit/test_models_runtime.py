from __future__ import annotations

from pathlib import Path

import pytest

from craftsec.models import (
    SUPPORTED_MODELS,
    DevicePreference,
    GenerationConfig,
    InferenceEngine,
    ModelConfig,
    ModelManager,
)
from craftsec.models.activations import (
    ActivationCollector,
    ActivationStore,
    FunctionSpan,
    LayerDiscovery,
)
from craftsec.models.adapter import InferenceResult
from craftsec.models.errors import ModelCompatibilityError, ModelInferenceError
from craftsec.models.huggingface import resolve_device


class FakeAdapter:
    model_id = "fake/model"
    model_version = "v1"
    device = "cpu"
    supports_activations = True

    def generate(self, prompt, *, generation_kwargs, capture_activations=False):
        return InferenceResult(
            text=prompt,
            prompt_tokens=2,
            generated_tokens=1,
        )

    def unload(self):
        self.unloaded = True


class TinyTokenizer:
    name_or_path = "local-tiny-tokenizer"

    def __init__(self) -> None:
        self.vocabulary = {"<pad>": 0}

    def __call__(self, texts, **_kwargs):
        import torch

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


def test_supported_models_document_exact_checkpoints_and_licenses() -> None:
    assert SUPPORTED_MODELS["deepseek-coder-6.7b-instruct"].model_id == (
        "deepseek-ai/deepseek-coder-6.7b-instruct"
    )
    assert SUPPORTED_MODELS["qwen2.5-coder-7b-instruct"].license_name == "Apache-2.0"
    assert SUPPORTED_MODELS["llama-3.1-8b-instruct"].gated


def test_unknown_model_is_rejected_before_loading() -> None:
    with pytest.raises(ModelCompatibilityError, match="unsupported"):
        _ = ModelConfig(model="unknown/model").spec


def test_manager_and_inference_use_mocked_adapter_without_weights() -> None:
    manager = ModelManager(adapter_factory=lambda _config: FakeAdapter())
    manager.load(ModelConfig(model="qwen2.5-coder-7b-instruct", device=DevicePreference.CPU))

    result = InferenceEngine(manager).generate("hello", capture_activations=True)

    assert result.text == "hello"
    assert manager.loaded is not None
    manager.unload()
    assert manager.loaded is None


def test_inference_requires_loaded_model() -> None:
    with pytest.raises(ModelInferenceError, match="No model is loaded"):
        InferenceEngine(ModelManager()).generate("hello")


def test_generation_config_is_bounded_and_omits_sampling_when_disabled() -> None:
    assert GenerationConfig(do_sample=False).to_generation_kwargs() == {
        "max_new_tokens": 256,
        "do_sample": False,
    }
    with pytest.raises(ValueError):
        GenerationConfig(max_new_tokens=0)


def test_device_resolution_does_not_hide_explicit_cuda_failure() -> None:
    class Torch:
        class cuda:
            @staticmethod
            def is_available() -> bool:
                return False

    assert resolve_device("auto", Torch()) == "cpu"
    with pytest.raises(Exception, match="CUDA"):
        resolve_device("cuda", Torch())


def test_real_tiny_transformer_collects_token_and_function_activations(
    tmp_path: Path,
) -> None:
    pytest.importorskip("torch")
    transformers = pytest.importorskip("transformers")
    config = transformers.GPT2Config(
        vocab_size=32,
        n_positions=32,
        n_ctx=32,
        n_embd=8,
        n_layer=2,
        n_head=2,
    )
    model = transformers.GPT2LMHeadModel(config)
    tokenizer = TinyTokenizer()
    collector = ActivationCollector(
        model,
        tokenizer,
        model_id="local/tiny-gpt2",
        model_version="test",
        tokenizer_version="test-tokenizer",
        layer_indices=(0, 1),
    )

    prompts = ("def safe(): return 1", "def unsafe(): eval(x)")
    batches = collector.collect(
        prompts,
        batch_size=2,
        functions=(
            (FunctionSpan("safe", 0, len(prompts[0])),),
            (FunctionSpan("unsafe", 0, len(prompts[1])),),
        ),
    )

    assert LayerDiscovery.discover(model) == ("transformer.h.0", "transformer.h.1")
    batch = batches[0]
    assert batch.metadata.hidden_size == 8
    assert batch.metadata.model_version == "test"
    assert batch.metadata.tokenizer_version == "test-tokenizer"
    assert tuple(batch.activations) == ("transformer.h.0", "transformer.h.1")
    assert all(not value.requires_grad for value in batch.activations.values())
    assert all(value.device.type == "cpu" for value in batch.activations.values())
    assert len(batch.function_activations[0][0].token_indices) == 4
    assert batch.function_activations[1][0].values["transformer.h.0"].shape == (8,)

    stored = ActivationStore(tmp_path).save("tiny", batch)
    loaded = ActivationStore(tmp_path).load("tiny")
    assert stored.exists()
    assert loaded["metadata"].model_id == "local/tiny-gpt2"
    assert loaded["activations"]["transformer.h.0"].shape == (2, 4, 8)
    assert model.transformer.h[0]._forward_hooks == {}
