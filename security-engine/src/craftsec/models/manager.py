"""Lifecycle manager for one local model at a time."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from craftsec.models.adapter import ModelAdapter, validate_adapter
from craftsec.models.config import ModelConfig
from craftsec.models.huggingface import HuggingFaceAdapter


@dataclass(frozen=True, slots=True)
class LoadedModel:
    """Stable runtime metadata for the active adapter."""

    model_id: str
    model_version: str
    device: str
    supports_activations: bool


class ModelManager:
    """Load, expose, and unload a single configured adapter."""

    def __init__(
        self,
        *,
        adapter_factory: Callable[[ModelConfig], ModelAdapter] = HuggingFaceAdapter,
    ) -> None:
        self._adapter_factory = adapter_factory
        self._adapter: ModelAdapter | None = None

    @property
    def adapter(self) -> ModelAdapter | None:
        return self._adapter

    @property
    def loaded(self) -> LoadedModel | None:
        if self._adapter is None:
            return None
        return LoadedModel(
            model_id=self._adapter.model_id,
            model_version=self._adapter.model_version,
            device=self._adapter.device,
            supports_activations=self._adapter.supports_activations,
        )

    def load(self, config: ModelConfig) -> LoadedModel:
        if self._adapter is not None:
            self.unload()
        adapter = self._adapter_factory(config)
        validate_adapter(adapter)
        self._adapter = adapter
        loaded = self.loaded
        assert loaded is not None
        return loaded

    def unload(self) -> None:
        if self._adapter is not None:
            self._adapter.unload()
            self._adapter = None


__all__ = ["LoadedModel", "ModelManager"]

