"""Inference facade that enforces lifecycle and generation policy."""

from __future__ import annotations

from bugdhor.models.adapter import InferenceResult
from bugdhor.models.config import GenerationConfig
from bugdhor.models.errors import ModelInferenceError
from bugdhor.models.manager import ModelManager


class InferenceEngine:
    """Run bounded inference against the manager's currently loaded model."""

    def __init__(self, manager: ModelManager) -> None:
        self.manager = manager

    def generate(
        self,
        prompt: str,
        *,
        generation: GenerationConfig | None = None,
        capture_activations: bool = False,
    ) -> InferenceResult:
        adapter = self.manager.adapter
        if adapter is None:
            raise ModelInferenceError("No model is loaded")
        settings = generation or GenerationConfig()
        return adapter.generate(
            prompt,
            generation_kwargs=settings.to_generation_kwargs(),
            capture_activations=capture_activations,
        )


__all__ = ["InferenceEngine"]

