"""Lazy Hugging Face Transformers adapter for local model execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from bugdhor.models.activations import ActivationBatch, ActivationCollector, FunctionSpan
from bugdhor.models.adapter import Activation, InferenceResult
from bugdhor.models.config import ModelConfig
from bugdhor.models.errors import (
    ModelCompatibilityError,
    ModelDependencyError,
    ModelInferenceError,
    ModelLoadError,
)


def _imports() -> tuple[Any, Any, Any]:
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as error:
        raise ModelDependencyError(
            "Install the optional ML dependencies with `pip install -e '.[ml]'`."
        ) from error
    return torch, AutoModelForCausalLM, AutoTokenizer


def resolve_device(preference: str, torch: Any) -> str:
    """Resolve CPU or CUDA without silently falling back from an explicit CUDA request."""
    if preference == "cpu":
        return "cpu"
    if preference == "cuda":
        if not torch.cuda.is_available():
            raise ModelCompatibilityError("CUDA was requested but is not available")
        return "cuda"
    return "cuda" if torch.cuda.is_available() else "cpu"


def _dtype(torch: Any, value: str) -> Any:
    if value == "auto":
        return "auto"
    return getattr(torch, value)


class HuggingFaceAdapter:
    """Transformers adapter with tokenizer ownership and hidden-state capture."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        torch, model_class, tokenizer_class = _imports()
        self._torch = torch
        self.model_id = config.spec.model_id
        self.device = resolve_device(config.device.value, torch)
        kwargs = {
            "revision": config.revision,
            "local_files_only": config.local_files_only,
            "trust_remote_code": config.trust_remote_code,
        }
        if kwargs["revision"] is None:
            del kwargs["revision"]
        if self.device == "cuda" and config.torch_dtype == "auto":
            kwargs["torch_dtype"] = "auto"
        elif config.torch_dtype != "auto":
            kwargs["torch_dtype"] = _dtype(torch, config.torch_dtype)
        try:
            self.tokenizer = tokenizer_class.from_pretrained(config.source, **kwargs)
            self.model = model_class.from_pretrained(config.source, **kwargs).to(self.device)
            self.model.eval()
        except Exception as error:
            raise ModelLoadError(
                f"Unable to load local model {config.source!r}; "
                "weights are never downloaded automatically."
            ) from error
        self.model_version = (
            config.revision
            or getattr(self.model.config, "_commit_hash", None)
            or config.spec.revision
            or "main"
        )
        self._tokenizer_version = (
            config.revision
            or getattr(self.tokenizer, "init_kwargs", {}).get("revision")
            or "main"
        )
        self.supports_activations = bool(config.spec.supports_hidden_states)
        self._activation_collector: ActivationCollector | None = None

    def generate(
        self,
        prompt: str,
        *,
        generation_kwargs: Mapping[str, Any],
        capture_activations: bool = False,
    ) -> InferenceResult:
        if not prompt.strip():
            raise ValueError("prompt must not be empty")
        if capture_activations and not self.supports_activations:
            raise ModelCompatibilityError(f"{self.model_id} does not expose activations")
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt")
            inputs = {key: value.to(self.device) for key, value in inputs.items()}
            kwargs = dict(generation_kwargs)
            kwargs["return_dict_in_generate"] = True
            kwargs["output_hidden_states"] = capture_activations
            with self._torch.inference_mode():
                output = self.model.generate(**inputs, **kwargs)
            sequences = output.sequences
            prompt_tokens = int(inputs["input_ids"].shape[-1])
            generated = sequences[:, prompt_tokens:]
            text = self.tokenizer.decode(generated[0], skip_special_tokens=True)
            activations = self._extract_activations(output) if capture_activations else ()
            return InferenceResult(
                text=text,
                prompt_tokens=prompt_tokens,
                generated_tokens=int(generated.shape[-1]),
                activations=activations,
            )
        except ModelCompatibilityError:
            raise
        except Exception as error:
            raise ModelInferenceError(f"Inference failed for {self.model_id!r}") from error

    def collect_activations(
        self,
        prompts: Sequence[str],
        *,
        batch_size: int = 1,
        layer_names: Sequence[str] | None = None,
        layer_indices: Sequence[int] | None = None,
        functions: Sequence[Sequence[FunctionSpan]] | None = None,
    ) -> tuple[ActivationBatch, ...]:
        """Run real forward passes and collect selected layer activations."""
        if not self.supports_activations:
            raise ModelCompatibilityError(f"{self.model_id} does not expose activations")
        try:
            collector = ActivationCollector(
                self.model,
                self.tokenizer,
                model_id=self.model_id,
                model_version=self.model_version,
                tokenizer_id=str(getattr(self.tokenizer, "name_or_path", self.model_id)),
                tokenizer_version=self._tokenizer_version,
                device=self.device,
                layer_names=layer_names,
                layer_indices=layer_indices,
            )
            self._activation_collector = collector
            return collector.collect(prompts, batch_size=batch_size, functions=functions)
        except ModelCompatibilityError:
            raise
        except Exception as error:
            raise ModelInferenceError(
                f"Activation collection failed for {self.model_id!r}"
            ) from error

    @staticmethod
    def _extract_activations(output: Any) -> tuple[Activation, ...]:
        hidden = getattr(output, "hidden_states", None)
        if hidden is None or (isinstance(hidden, (tuple, list)) and not hidden):
            return ()
        last_step = hidden[-1] if isinstance(hidden, (tuple, list)) else hidden
        if not isinstance(last_step, (tuple, list)):
            return (Activation(layer="last_hidden_state", values=last_step),)
        return tuple(
            Activation(layer=f"layer.{index}", values=value)
            for index, value in enumerate(last_step)
        )

    def unload(self) -> None:
        self._activation_collector = None
        del self.model
        del self.tokenizer
        if self.device == "cuda":
            self._torch.cuda.empty_cache()


__all__ = ["HuggingFaceAdapter", "resolve_device"]

