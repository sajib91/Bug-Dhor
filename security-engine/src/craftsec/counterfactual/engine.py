"""Controlled SAE feature interventions for model-output comparisons."""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any

import torch

from craftsec.models.activations import ActivationCollector
from craftsec.models.adapter import InferenceResult
from craftsec.models.config import GenerationConfig
from craftsec.models.errors import ModelCompatibilityError, ModelInferenceError
from craftsec.sae.model import SparseAutoencoder


@dataclass(frozen=True, slots=True)
class CounterfactualSpec:
    """One single-feature intervention."""

    feature_index: int
    mode: str
    value: float | None = None
    target_positions: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        if self.feature_index < 0:
            raise ValueError("feature_index must be non-negative")
        if self.mode not in {"ablate", "modify"}:
            raise ValueError("mode must be 'ablate' or 'modify'")
        if self.mode == "modify" and self.value is None:
            raise ValueError("modify interventions require a target value")
        if self.target_positions is not None and any(
            position < 0 for position in self.target_positions
        ):
            raise ValueError("target_positions must be non-negative")

    @property
    def target_value(self) -> float:
        return 0.0 if self.mode == "ablate" else float(self.value)


@dataclass(frozen=True, slots=True)
class RiskOutcome:
    """Optional model-output risk measurement and independent ground truth."""

    predicted_vulnerable: bool | None = None
    risk_score: float | None = None
    security_metrics: Mapping[str, float] = field(default_factory=dict)
    true_vulnerable: bool | None = None


@dataclass(frozen=True, slots=True)
class CounterfactualMetadata:
    """Reproducibility and provenance metadata for an intervention run."""

    experiment_id: str
    model_id: str
    model_version: str
    layer: str
    sae_checkpoint: str
    prompt_hash: str
    generation_kwargs: Mapping[str, Any]
    seed: int
    feature_index: int
    intervention_mode: str
    target_value: float
    target_positions: tuple[int, ...] | None


@dataclass(frozen=True, slots=True)
class ActivationMeasurement:
    """Baseline and post-intervention feature values."""

    baseline_values: tuple[float, ...]
    intervention_values: tuple[float, ...]
    baseline_mean: float
    intervention_mean: float
    feature_delta: float


@dataclass(frozen=True, slots=True)
class CounterfactualComparison:
    """Before/after output and risk comparison."""

    baseline: InferenceResult
    intervention: InferenceResult
    baseline_risk: RiskOutcome
    intervention_risk: RiskOutcome
    output_changed: bool
    predicted_vulnerability_changed: bool | None
    true_vulnerability_status_unchanged: bool | None


@dataclass(frozen=True, slots=True)
class CounterfactualResult:
    """Complete single-feature counterfactual experiment record."""

    metadata: CounterfactualMetadata
    activation: ActivationMeasurement
    comparison: CounterfactualComparison
    causal_interpretation: str = (
        "Controlled output comparison recorded; causal influence is not established."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


RiskEvaluator = Callable[[str], RiskOutcome]


class CounterfactualEngine:
    """Run reproducible single-feature ablation or modification experiments."""

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
            raise ModelCompatibilityError("counterfactuals require a compatible activation adapter")
        if not hasattr(adapter, "model") or not hasattr(adapter, "tokenizer"):
            raise ModelCompatibilityError("counterfactuals require a local Transformers adapter")
        self.adapter = adapter
        self.sae = sae
        self.layer = layer
        self.sae_checkpoint = sae_checkpoint
        self.experiment_id = experiment_id
        self.seed = seed
        self.sae.to(adapter.device)

    def run(
        self,
        prompt: str,
        spec: CounterfactualSpec,
        *,
        generation: GenerationConfig | None = None,
        risk_evaluator: RiskEvaluator | None = None,
        true_vulnerable: bool | None = None,
    ) -> CounterfactualResult:
        self._seed()
        generation_config = generation or GenerationConfig()
        generation_kwargs = generation_config.to_generation_kwargs()
        baseline_activation = self._measure_activation(prompt, spec.feature_index)
        if baseline_activation.shape[-1] != self.sae.config.input_dim:
            raise ModelCompatibilityError("SAE input dimension does not match model layer width")
        baseline_latent = self.sae.feature_activations(
            baseline_activation.reshape(-1, baseline_activation.shape[-1])
        ).reshape(baseline_activation.shape[0], baseline_activation.shape[1], -1)
        self._validate_feature(spec.feature_index, baseline_latent.shape[-1])
        target_positions = self._positions(spec.target_positions, baseline_latent.shape[1])
        baseline_values = baseline_latent[0, target_positions, spec.feature_index]
        baseline = self._generate(prompt, generation_kwargs)
        baseline_risk = self._evaluate(baseline.text, risk_evaluator, true_vulnerable)

        with self._intervention_hook(
            spec,
            target_positions,
            sequence_length=baseline_activation.shape[1],
        ):
            intervention = self._generate(prompt, generation_kwargs)
        intervention_risk = self._evaluate(intervention.text, risk_evaluator, true_vulnerable)
        intervention_values = torch.full_like(
            baseline_values,
            spec.target_value,
        )
        measurement = ActivationMeasurement(
            baseline_values=tuple(float(value) for value in baseline_values.cpu()),
            intervention_values=tuple(float(value) for value in intervention_values.cpu()),
            baseline_mean=float(baseline_values.mean().item()),
            intervention_mean=float(intervention_values.mean().item()),
            feature_delta=float((intervention_values - baseline_values).mean().item()),
        )
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        metadata = CounterfactualMetadata(
            experiment_id=self.experiment_id,
            model_id=self.adapter.model_id,
            model_version=self.adapter.model_version,
            layer=self.layer,
            sae_checkpoint=self.sae_checkpoint,
            prompt_hash=prompt_hash,
            generation_kwargs=generation_kwargs,
            seed=self.seed,
            feature_index=spec.feature_index,
            intervention_mode=spec.mode,
            target_value=spec.target_value,
            target_positions=spec.target_positions,
        )
        predicted_changed = None
        if (
            baseline_risk.predicted_vulnerable is not None
            and intervention_risk.predicted_vulnerable is not None
        ):
            predicted_changed = (
                baseline_risk.predicted_vulnerable != intervention_risk.predicted_vulnerable
            )
        return CounterfactualResult(
            metadata=metadata,
            activation=measurement,
            comparison=CounterfactualComparison(
                baseline=baseline,
                intervention=intervention,
                baseline_risk=baseline_risk,
                intervention_risk=intervention_risk,
                output_changed=baseline.text != intervention.text,
                predicted_vulnerability_changed=predicted_changed,
                true_vulnerability_status_unchanged=(
                    None
                    if baseline_risk.true_vulnerable is None
                    or intervention_risk.true_vulnerable is None
                    else baseline_risk.true_vulnerable == intervention_risk.true_vulnerable
                ),
            ),
        )

    def _measure_activation(self, prompt: str, feature_index: int) -> torch.Tensor:
        collector = ActivationCollector(
            self.adapter.model,
            self.adapter.tokenizer,
            model_id=self.adapter.model_id,
            model_version=self.adapter.model_version,
            tokenizer_id=str(
                getattr(self.adapter.tokenizer, "name_or_path", self.adapter.model_id)
            ),
            device=self.adapter.device,
            layer_names=(self.layer,),
        )
        batches = collector.collect((prompt,), batch_size=1)
        activation = batches[0].activations[self.layer]
        self._validate_feature(feature_index, self.sae.config.latent_dim)
        return activation

    @contextmanager
    def _intervention_hook(
        self,
        spec: CounterfactualSpec,
        target_positions: tuple[int, ...],
        *,
        sequence_length: int,
    ):
        modules = dict(self.adapter.model.named_modules())
        module = modules.get(self.layer)
        if module is None:
            raise ModelCompatibilityError(f"intervention layer {self.layer!r} was not found")
        def intervene(_module: Any, _inputs: Any, output: Any) -> Any:
            hidden = output[0] if isinstance(output, (tuple, list)) else output
            if not hasattr(hidden, "ndim") or hidden.ndim != 3:
                raise ModelCompatibilityError(
                    f"intervention layer {self.layer!r} did not emit [batch, tokens, hidden]"
                )
            positions = tuple(
                position
                for position in target_positions
                if hidden.shape[1] == sequence_length and position < hidden.shape[1]
            )
            if not positions:
                return output
            decoder_direction = self.sae.decoder.weight[:, spec.feature_index].detach().to(
                hidden.device, hidden.dtype
            )
            baseline_latent = self.sae.feature_activations(
                hidden.reshape(-1, hidden.shape[-1])
            ).reshape(hidden.shape[0], hidden.shape[1], -1)
            delta = (
                spec.target_value - baseline_latent[:, positions, spec.feature_index]
            ).unsqueeze(-1) * decoder_direction
            modified = hidden.clone()
            modified[:, positions, :] = modified[:, positions, :] + delta
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

    def _generate(self, prompt: str, generation_kwargs: Mapping[str, Any]) -> InferenceResult:
        try:
            encoded = self.adapter.tokenizer(prompt, return_tensors="pt")
            model_inputs = {
                key: value.to(self.adapter.device)
                for key, value in encoded.items()
                if key != "offset_mapping"
                if hasattr(value, "to")
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
            raise ModelInferenceError("Counterfactual model inference failed") from error

    @staticmethod
    def _evaluate(
        text: str,
        evaluator: RiskEvaluator | None,
        true_vulnerable: bool | None,
    ) -> RiskOutcome:
        if evaluator is None:
            return RiskOutcome(true_vulnerable=true_vulnerable)
        measured = evaluator(text)
        return RiskOutcome(
            predicted_vulnerable=measured.predicted_vulnerable,
            risk_score=measured.risk_score,
            security_metrics=measured.security_metrics,
            true_vulnerable=true_vulnerable,
        )

    @staticmethod
    def _positions(positions: Sequence[int] | None, sequence_length: int) -> tuple[int, ...]:
        selected = tuple(positions) if positions is not None else tuple(range(sequence_length))
        if not selected or any(position >= sequence_length for position in selected):
            raise ValueError("target positions must overlap the baseline token sequence")
        return selected

    @staticmethod
    def _validate_feature(feature_index: int, feature_count: int) -> None:
        if feature_index >= feature_count:
            raise ValueError("feature_index is outside the available feature dimension")

    def _seed(self) -> None:
        random.seed(self.seed)
        torch.manual_seed(self.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.seed)


__all__ = [
    "ActivationMeasurement",
    "CounterfactualComparison",
    "CounterfactualEngine",
    "CounterfactualMetadata",
    "CounterfactualResult",
    "CounterfactualSpec",
    "RiskOutcome",
]
