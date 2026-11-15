"""CRAFT-Sec local Hugging Face model runtime.

The runtime is lazy: importing this package never imports PyTorch, Transformers,
or downloads model weights. Loading is local-files-only by default.
"""

from craftsec.models.activations import (
    ActivationBatch,
    ActivationCollector,
    ActivationMetadata,
    ActivationStore,
    FunctionActivation,
    FunctionSpan,
    LayerDiscovery,
)
from craftsec.models.adapter import Activation, InferenceResult, ModelAdapter
from craftsec.models.config import (
    SUPPORTED_MODELS,
    DevicePreference,
    GenerationConfig,
    ModelConfig,
    ModelSpec,
)
from craftsec.models.errors import (
    ModelCompatibilityError,
    ModelDependencyError,
    ModelInferenceError,
    ModelLoadError,
    ModelRuntimeError,
)
from craftsec.models.huggingface import HuggingFaceAdapter, resolve_device
from craftsec.models.inference import InferenceEngine
from craftsec.models.manager import LoadedModel, ModelManager

__all__ = [
    "SUPPORTED_MODELS",
    "Activation",
    "ActivationBatch",
    "ActivationCollector",
    "ActivationMetadata",
    "ActivationStore",
    "DevicePreference",
    "GenerationConfig",
    "HuggingFaceAdapter",
    "InferenceEngine",
    "InferenceResult",
    "FunctionActivation",
    "FunctionSpan",
    "LayerDiscovery",
    "LoadedModel",
    "ModelAdapter",
    "ModelCompatibilityError",
    "ModelConfig",
    "ModelDependencyError",
    "ModelInferenceError",
    "ModelLoadError",
    "ModelManager",
    "ModelRuntimeError",
    "ModelSpec",
    "resolve_device",
]
