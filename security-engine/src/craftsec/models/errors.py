"""Errors raised by the local Hugging Face model runtime."""

from __future__ import annotations


class ModelRuntimeError(RuntimeError):
    """Base class for expected model-runtime failures."""


class ModelDependencyError(ModelRuntimeError):
    """The optional ML dependencies are not installed."""


class ModelCompatibilityError(ModelRuntimeError):
    """A model or tokenizer is not compatible with the requested runtime."""


class ModelLoadError(ModelRuntimeError):
    """A configured model could not be loaded."""


class ModelInferenceError(ModelRuntimeError):
    """Inference failed after a model was loaded."""

