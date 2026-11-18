"""Adapter contracts shared by model backends."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from bugdhor.models.activations import ActivationBatch, FunctionSpan


@dataclass(frozen=True, slots=True)
class Activation:
    """A captured internal activation for one layer."""

    layer: str
    values: Any


@dataclass(frozen=True, slots=True)
class InferenceResult:
    """Generated text plus optional model internals."""

    text: str
    prompt_tokens: int
    generated_tokens: int
    activations: tuple[Activation, ...] = ()


class ModelAdapter(Protocol):
    """Minimal backend contract used by the manager and inference engine."""

    model_id: str
    model_version: str
    device: str
    supports_activations: bool

    def generate(
        self,
        prompt: str,
        *,
        generation_kwargs: Mapping[str, Any],
        capture_activations: bool = False,
    ) -> InferenceResult: ...

    def unload(self) -> None: ...

    def collect_activations(
        self,
        prompts: Sequence[str],
        *,
        batch_size: int = 1,
        layer_names: Sequence[str] | None = None,
        layer_indices: Sequence[int] | None = None,
        functions: Sequence[Sequence[FunctionSpan]] | None = None,
    ) -> tuple[ActivationBatch, ...]: ...


def validate_adapter(adapter: ModelAdapter) -> None:
    """Validate the stable metadata required from an adapter."""
    for field in ("model_id", "model_version", "device"):
        if not str(getattr(adapter, field, "")).strip():
            raise ValueError(f"model adapter must declare {field}")
    if not isinstance(getattr(adapter, "supports_activations", None), bool):
        raise ValueError("model adapter must declare supports_activations")


__all__ = ["Activation", "InferenceResult", "ModelAdapter", "validate_adapter"]

