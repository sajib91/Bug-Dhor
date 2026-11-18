"""Genuine SAE decoder-direction steering for compatible local Transformers models."""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from typing import Any

import torch

from bugdhor.models.activations import LayerDiscovery
from bugdhor.models.adapter import InferenceResult
from bugdhor.models.config import GenerationConfig
from bugdhor.models.errors import ModelCompatibilityError, ModelInferenceError
from bugdhor.sae.model import SparseAutoencoder
from bugdhor.steering.functional import (
    FunctionalConstraintEvaluator,
    FunctionalEvaluation,
)


@dataclass(frozen=True, slots=True)
class SteeringSpec:
    """A requested SAE feature intervention.

    ``strengths`` are additive coefficients in the SAE decoder-direction basis.
    Positive and negative values are both valid and are never interpreted as
    semantic or causal guarantees.
    """

    feature_indices: tuple[int, ...]
    strengths: tuple[float, ...] | None = None
    target_positions: tuple[int, ...] | None = None
    position_strengths: Mapping[int, tuple[float, ...]] | None = None
    enabled: bool = False
    max_delta_norm: float = 10.0

    def __post_init__(self) -> None:
        if not self.feature_indices and self.enabled:
            raise ValueError("feature_indices must not be empty")
        if len(set(self.feature_indices)) != len(self.feature_indices):
            raise ValueError("feature_indices must be unique")
        if any(index < 0 for index in self.feature_indices):
            raise ValueError("feature_indices must be non-negative")
        if self.strengths is not None and len(self.strengths) != len(self.feature_indices):
            raise ValueError("strengths must have one value per feature index")
        if self.strengths is not None and any(not math.isfinite(value) for value in self.strengths):
            raise ValueError("strengths must contain finite values")
        if self.target_positions is not None:
            if not self.target_positions:
                raise ValueError("target_positions must not be empty")
            if len(set(self.target_positions)) != len(self.target_positions):
                raise ValueError("target_positions must be unique")
            if any(position < 0 for position in self.target_positions):
                raise ValueError("target_positions must be non-negative")
        if self.position_strengths is not None:
            for position, strengths in self.position_strengths.items():
                if position < 0 or len(strengths) != len(self.feature_indices):
                    raise ValueError(
                        "position_strengths must map positions to one strength per feature"
                    )
                if any(not math.isfinite(value) for value in strengths):
                    raise ValueError("position_strengths must contain finite values")
        if not math.isfinite(self.max_delta_norm) or self.max_delta_norm <= 0:
            raise ValueError("max_delta_norm must be finite and positive")

    def resolved_strengths(self) -> tuple[float, ...]:
        return self.strengths or tuple(1.0 for _ in self.feature_indices)

    def strengths_for_position(self, position: int) -> tuple[float, ...]:
        if self.position_strengths is None:
            return self.resolved_strengths()
        return self.position_strengths.get(position, self.resolved_strengths())


@dataclass(frozen=True, slots=True)
class SteeringValidation:
    """Measured safety and shape checks for one steering run."""

    enabled: bool
    layer: str
    compatible: bool
    finite: bool
    shape_valid: bool
    max_delta_norm: float
    original_restored: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SteeringMetadata:
    """Complete reproducibility metadata for an intervention."""

    experiment_id: str
    model_id: str
    model_version: str
    tokenizer_id: str
    tokenizer_version: str
    layer: str
    sae_checkpoint: str
    feature_indices: tuple[int, ...]
    strengths: tuple[float, ...]
    target_positions: tuple[int, ...] | None
    position_strengths: Mapping[int, tuple[float, ...]] | None
    max_delta_norm: float
    enabled: bool
    prompt_hash: str
    generation_kwargs: Mapping[str, Any]
    seed: int
    functional_constraints: Mapping[str, Any] | None = None
    functional_tradeoff: Mapping[str, float | None] | None = None


@dataclass(frozen=True, slots=True)
class SteeringComparison:
    """Original and steered generation comparison."""

    baseline: InferenceResult
    steered: InferenceResult | None
    output_changed: bool | None
    rejected_candidate: InferenceResult | None = None


@dataclass(frozen=True, slots=True)
class SteeringResult:
    """Steering output, validation, and provenance."""

    metadata: SteeringMetadata
    comparison: SteeringComparison
    validation: SteeringValidation
    functional_evaluation: FunctionalEvaluation | None = None
    activation_deltas: tuple[float, ...] = ()
    limitations: tuple[str, ...] = (
        "Steering changes model activations and output behavior; it does not establish "
        "a change in true vulnerability status.",
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActivationSteeringEngine:
    """Apply actual SAE decoder directions to supported local Transformer layers."""

    def __init__(
        self,
        adapter: Any,
        sae: SparseAutoencoder,
        *,
        layer: str,
        sae_checkpoint: str,
        experiment_id: str,
        seed: int = 0,
    ) -> None:
        if not getattr(adapter, "supports_activations", False):
            raise ModelCompatibilityError("activation steering requires activation support")
        if not hasattr(adapter, "model") or not hasattr(adapter, "tokenizer"):
            raise ModelCompatibilityError(
                "activation steering requires a local Transformers adapter"
            )
        discovered = LayerDiscovery.discover(adapter.model)
        if layer not in discovered:
            raise ModelCompatibilityError(
                f"steering layer {layer!r} is not a compatible Transformer layer"
            )
        self.adapter = adapter
        self.sae = sae.to(adapter.device)
        self.sae.eval()
        self.layer = layer
        self.sae_checkpoint = sae_checkpoint
        self.experiment_id = experiment_id
        self.seed = seed
        self._validate_decoder()

    def run(
        self,
        prompt: str,
        spec: SteeringSpec,
        *,
        generation: GenerationConfig | None = None,
        functional_evaluator: FunctionalConstraintEvaluator | None = None,
    ) -> SteeringResult:
        """Generate baseline and, only when explicitly enabled, steered output."""

        self._seed()
        generation_config = generation or GenerationConfig()
        generation_kwargs = dict(generation_config.to_generation_kwargs())
        # Baseline and steered conditions must share one decoding path.  With a
        # KV cache a forward hook can fire only on the prefill pass, so the two
        # conditions would not be comparable.  Disable it for both.
        generation_kwargs["use_cache"] = False
        baseline = self._generate(prompt, generation_kwargs)
        tokenizer_id = str(getattr(self.adapter.tokenizer, "name_or_path", self.adapter.model_id))
        tokenizer_version = self._tokenizer_version()
        metadata = SteeringMetadata(
            experiment_id=self.experiment_id,
            model_id=self.adapter.model_id,
            model_version=self.adapter.model_version,
            tokenizer_id=tokenizer_id,
            tokenizer_version=tokenizer_version,
            layer=self.layer,
            sae_checkpoint=self.sae_checkpoint,
            feature_indices=spec.feature_indices,
            strengths=spec.resolved_strengths(),
            target_positions=spec.target_positions,
            position_strengths=spec.position_strengths,
            max_delta_norm=spec.max_delta_norm,
            enabled=spec.enabled,
            prompt_hash=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            generation_kwargs=generation_kwargs,
            seed=self.seed,
            functional_constraints=(
                None
                if functional_evaluator is None
                else asdict(functional_evaluator.constraints)
            ),
        )
        if not spec.enabled:
            return SteeringResult(
                metadata=metadata,
                comparison=SteeringComparison(baseline, None, None),
                validation=SteeringValidation(
                    enabled=False,
                    layer=self.layer,
                    compatible=True,
                    finite=True,
                    shape_valid=True,
                    max_delta_norm=0.0,
                    original_restored=True,
                ),
            )

        deltas: list[float] = []
        validation_state = {
            "finite": True,
            "shape_valid": True,
            "max_delta_norm": 0.0,
        }
        try:
            steered_kwargs = dict(generation_kwargs)
            with self._steering_hook(spec, validation_state, deltas):
                steered = self._generate(prompt, steered_kwargs)
        except ModelCompatibilityError:
            raise
        except ModelInferenceError:
            raise
        except Exception as error:
            raise ModelInferenceError("SAE activation steering failed") from error
        validation = SteeringValidation(
            enabled=True,
            layer=self.layer,
            compatible=True,
            finite=bool(validation_state["finite"]),
            shape_valid=bool(validation_state["shape_valid"]),
            max_delta_norm=float(validation_state["max_delta_norm"]),
            original_restored=True,
            error=None,
        )
        if not validation.finite or not validation.shape_valid:
            raise ModelInferenceError("SAE steering produced invalid activation values")
        functional_evaluation = (
            None
            if functional_evaluator is None
            else functional_evaluator.evaluate(
                steered.text,
                baseline=baseline.text,
            )
        )
        if functional_evaluation is not None:
            metadata = replace(
                metadata,
                functional_tradeoff=functional_evaluation.tradeoff,
            )
        accepted_steered = (
            steered if functional_evaluation is None or functional_evaluation.accepted else None
        )
        return SteeringResult(
            metadata=metadata,
            comparison=SteeringComparison(
                baseline,
                accepted_steered,
                baseline.text != steered.text,
                rejected_candidate=(
                    steered
                    if functional_evaluation is not None and not functional_evaluation.accepted
                    else None
                ),
            ),
            validation=validation,
            activation_deltas=tuple(deltas),
            functional_evaluation=functional_evaluation,
        )

    @contextmanager
    def _steering_hook(
        self,
        spec: SteeringSpec,
        validation_state: dict[str, float | bool],
        deltas: list[float],
    ) -> Iterator[None]:
        modules = dict(self.adapter.model.named_modules())
        module = modules.get(self.layer)
        if module is None:
            raise ModelCompatibilityError(f"steering layer {self.layer!r} was not found")
        def intervene(_module: Any, _inputs: Any, output: Any) -> Any:
            hidden = output[0] if isinstance(output, (tuple, list)) else output
            if not hasattr(hidden, "ndim") or hidden.ndim != 3:
                validation_state["shape_valid"] = False
                raise ModelCompatibilityError(
                    f"steering layer {self.layer!r} did not emit [batch, tokens, hidden]"
                )
            if hidden.shape[-1] != self.sae.config.input_dim:
                validation_state["shape_valid"] = False
                raise ModelCompatibilityError("SAE input dimension does not match layer width")
            positions = self._positions(spec.target_positions, int(hidden.shape[1]))
            if not positions:
                return output
            modified = hidden.clone()
            for position in positions:
                directions = self._directions(
                    spec.feature_indices, spec.strengths_for_position(position)
                )
                delta = directions.to(device=hidden.device, dtype=hidden.dtype).sum(dim=0)
                norm = float(torch.linalg.vector_norm(delta).detach().cpu().item())
                if not math.isfinite(norm):
                    validation_state["finite"] = False
                    raise ModelInferenceError("SAE steering direction is numerically unstable")
                if norm > spec.max_delta_norm:
                    delta = delta * (spec.max_delta_norm / norm)
                    norm = spec.max_delta_norm
                modified[:, position, :] = modified[:, position, :] + delta
                validation_state["max_delta_norm"] = max(
                    float(validation_state["max_delta_norm"]), norm
                )
                deltas.append(norm)
            if not torch.isfinite(modified).all():
                validation_state["finite"] = False
                raise ModelInferenceError("SAE steering produced non-finite activations")
            if isinstance(output, tuple):
                return (modified, *output[1:])
            if isinstance(output, list):
                return [modified, *output[1:]]
            return modified

        handle = module.register_forward_hook(intervene)
        try:
            yield
        finally:
            handle.remove()

    def _directions(
        self, feature_indices: Sequence[int], strengths: Sequence[float]
    ) -> torch.Tensor:
        with torch.inference_mode():
            directions = self.sae.decoder.weight[:, list(feature_indices)].T.detach()
            return directions * torch.tensor(
                strengths, device=directions.device, dtype=directions.dtype
            ).unsqueeze(1)

    def _validate_decoder(self) -> None:
        decoder = self.sae.decoder.weight
        if decoder.ndim != 2 or decoder.shape != (
            self.sae.config.input_dim,
            self.sae.config.latent_dim,
        ):
            raise ModelCompatibilityError("SAE decoder dimensions are incompatible")
        if not torch.isfinite(decoder).all():
            raise ModelCompatibilityError("SAE decoder contains non-finite steering directions")

    def _generate(self, prompt: str, generation_kwargs: Mapping[str, Any]) -> InferenceResult:
        try:
            encoded = self.adapter.tokenizer(prompt, return_tensors="pt")
            model_inputs = {
                key: value.to(self.adapter.device)
                for key, value in encoded.items()
                if key != "offset_mapping" and hasattr(value, "to")
            }
            kwargs = dict(generation_kwargs)
            kwargs["return_dict_in_generate"] = True
            with self.adapter._torch.inference_mode():
                output = self.adapter.model.generate(**model_inputs, **kwargs)
            prompt_tokens = int(model_inputs["input_ids"].shape[-1])
            generated = output.sequences[:, prompt_tokens:]
            return InferenceResult(
                text=self.adapter.tokenizer.decode(generated[0], skip_special_tokens=True),
                prompt_tokens=prompt_tokens,
                generated_tokens=int(generated.shape[-1]),
            )
        except ModelCompatibilityError:
            raise
        except Exception as error:
            raise ModelInferenceError("Steered model inference failed") from error

    @staticmethod
    def _positions(positions: Sequence[int] | None, sequence_length: int) -> tuple[int, ...]:
        if positions is None:
            return tuple(range(sequence_length))
        if any(position >= sequence_length for position in positions):
            return tuple(position for position in positions if position < sequence_length)
        return tuple(positions)

    def _tokenizer_version(self) -> str:
        version = getattr(self.adapter.tokenizer, "version", None)
        if version is not None:
            return str(version)
        try:
            import transformers

            return str(transformers.__version__)
        except ImportError:
            return "unknown"

    def _seed(self) -> None:
        random.seed(self.seed)
        torch.manual_seed(self.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.seed)


__all__ = [
    "ActivationSteeringEngine",
    "SteeringComparison",
    "SteeringMetadata",
    "SteeringResult",
    "SteeringSpec",
    "SteeringValidation",
]
