"""Configuration and registry for supported local Hugging Face models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from bugdhor.models.errors import ModelCompatibilityError


class DevicePreference(StrEnum):
    """Device selection policy."""

    AUTO = "auto"
    CPU = "cpu"
    CUDA = "cuda"


@dataclass(frozen=True, slots=True)
class GenerationConfig:
    """Bounded generation parameters passed to ``transformers.generate``."""

    max_new_tokens: int = 256
    temperature: float = 0.2
    top_p: float = 0.95
    do_sample: bool = False

    def __post_init__(self) -> None:
        if self.max_new_tokens < 1:
            raise ValueError("max_new_tokens must be positive")
        if self.temperature < 0:
            raise ValueError("temperature must be non-negative")
        if not 0 < self.top_p <= 1:
            raise ValueError("top_p must be in (0, 1]")

    def to_generation_kwargs(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
        }
        if self.do_sample:
            values.update(temperature=self.temperature, top_p=self.top_p)
        return values


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """Compatibility and licensing metadata for a supported checkpoint."""

    name: str
    model_id: str
    family: str
    revision: str | None
    license_name: str
    license_url: str
    gated: bool
    supports_hidden_states: bool = True
    limitations: tuple[str, ...] = ()


SUPPORTED_MODELS: dict[str, ModelSpec] = {
    "llama-3.1-8b-instruct": ModelSpec(
        name="Llama 3.1 8B Instruct",
        model_id="meta-llama/Llama-3.1-8B-Instruct",
        family="llama",
        revision=None,
        license_name="Llama 3.1 Community License",
        license_url="https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct",
        gated=True,
        limitations=("The checkpoint is gated and requires an accepted Hugging Face license.",),
    ),
    "qwen2.5-coder-7b-instruct": ModelSpec(
        name="Qwen2.5-Coder 7B Instruct",
        model_id="Qwen/Qwen2.5-Coder-7B-Instruct",
        family="qwen2",
        revision=None,
        license_name="Apache-2.0",
        license_url="https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct",
        gated=False,
        limitations=("Long-context use depends on available host memory.",),
    ),
    "deepseek-coder-6.7b-instruct": ModelSpec(
        name="DeepSeek-Coder 6.7B Instruct",
        model_id="deepseek-ai/deepseek-coder-6.7b-instruct",
        family="deepseek",
        revision=None,
        license_name="DeepSeek Model License",
        license_url="https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct",
        gated=False,
        limitations=(
            "This integration selects the 6.7B instruct checkpoint; other DeepSeek-Coder "
            "variants are not implicitly interchangeable.",
        ),
    ),
}


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Runtime configuration; no setting in this class downloads weights."""

    model: str
    device: DevicePreference = DevicePreference.AUTO
    model_path: str | None = None
    revision: str | None = None
    local_files_only: bool = True
    torch_dtype: str = "auto"
    trust_remote_code: bool = False
    generation: GenerationConfig = field(default_factory=GenerationConfig)

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError("model must not be empty")
        if self.torch_dtype not in {"auto", "float32", "float16", "bfloat16"}:
            raise ValueError("torch_dtype must be auto, float32, float16, or bfloat16")

    @property
    def spec(self) -> ModelSpec:
        if self.model in SUPPORTED_MODELS:
            return SUPPORTED_MODELS[self.model]
        for spec in SUPPORTED_MODELS.values():
            if self.model == spec.model_id:
                return spec
        raise ModelCompatibilityError(
            f"unsupported Bug Dhor model {self.model!r}; "
            f"choose one of {', '.join(sorted(SUPPORTED_MODELS))}"
        )

    @property
    def source(self) -> str:
        return self.model_path or self.spec.model_id

