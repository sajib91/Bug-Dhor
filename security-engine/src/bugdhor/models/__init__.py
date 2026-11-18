"""Bug Dhor local Hugging Face model runtime.

The runtime is lazy: importing this package never imports PyTorch, Transformers,
or downloads model weights. Loading is local-files-only by default.
"""

from bugdhor.models.activations import (
    ActivationBatch,
    ActivationCollector,
    ActivationMetadata,
    ActivationStore,
    FunctionActivation,
    FunctionSpan,
    LayerDiscovery,
)
from bugdhor.models.adapter import Activation, InferenceResult, ModelAdapter
from bugdhor.models.config import (
    SUPPORTED_MODELS,
    DevicePreference,
    GenerationConfig,
    ModelConfig,
    ModelSpec,
)
from bugdhor.models.errors import (
    ModelCompatibilityError,
    ModelDependencyError,
    ModelInferenceError,
    ModelLoadError,
    ModelRuntimeError,
)
from bugdhor.models.huggingface import HuggingFaceAdapter, resolve_device
from bugdhor.models.inference import InferenceEngine
from bugdhor.models.manager import LoadedModel, ModelManager

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
