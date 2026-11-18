"""Hook-based activation collection for compatible Transformers models."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bugdhor.models.errors import ModelCompatibilityError, ModelInferenceError

_LAYER_NAME_RE = re.compile(r"(?:^|\.)(?:layers|h|block|blocks|layer)\.(\d+)$")


@dataclass(frozen=True, slots=True)
class FunctionSpan:
    """Character span identifying a source function in one prompt."""

    name: str
    start_char: int
    end_char: int

    def __post_init__(self) -> None:
        if not self.name.strip() or self.start_char < 0 or self.end_char < self.start_char:
            raise ValueError("function spans require a name and valid character offsets")


@dataclass(frozen=True, slots=True)
class ActivationMetadata:
    """Provenance and shape metadata attached to every activation batch."""

    model_id: str
    model_version: str
    tokenizer_id: str
    tokenizer_version: str
    layer_names: tuple[str, ...]
    hidden_size: int
    dtype: str
    device: str
    batch_size: int


@dataclass(frozen=True, slots=True)
class FunctionActivation:
    """Mean activation over the tokens overlapping one function span."""

    function: FunctionSpan
    token_indices: tuple[int, ...]
    values: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ActivationBatch:
    """Token-aligned, detached activation tensors for one collection batch."""

    input_ids: Any
    attention_mask: Any
    tokens: tuple[tuple[str, ...], ...]
    offsets: tuple[tuple[tuple[int, int], ...], ...]
    activations: Mapping[str, Any]
    metadata: ActivationMetadata
    function_activations: tuple[tuple[FunctionActivation, ...], ...] = ()


class LayerDiscovery:
    """Discover hookable Transformer blocks without assuming one architecture."""

    @staticmethod
    def discover(model: Any) -> tuple[str, ...]:
        candidates: list[tuple[int, str]] = []
        for name, module in model.named_modules():
            match = _LAYER_NAME_RE.search(name)
            if match and name and hasattr(module, "register_forward_hook"):
                candidates.append((int(match.group(1)), name))
        if not candidates:
            raise ModelCompatibilityError(
                "No compatible Transformer layers were discovered for activation hooks"
            )
        return tuple(name for _, name in sorted(candidates))

    @staticmethod
    def select(
        discovered: Sequence[str],
        *,
        layer_names: Sequence[str] | None = None,
        layer_indices: Sequence[int] | None = None,
    ) -> tuple[str, ...]:
        if layer_names is not None and layer_indices is not None:
            raise ValueError("configure layer_names or layer_indices, not both")
        if layer_names is not None:
            selected = tuple(layer_names)
            unknown = set(selected) - set(discovered)
            if unknown:
                raise ModelCompatibilityError(
                    f"Requested activation layers were not found: {', '.join(sorted(unknown))}"
                )
            return selected
        if layer_indices is not None:
            try:
                return tuple(discovered[index] for index in layer_indices)
            except IndexError as error:
                raise ModelCompatibilityError(
                    "Requested activation layer index is out of range"
                ) from error
        return tuple(discovered)


class ActivationCollector:
    """Collect real forward activations with exception-safe hook cleanup."""

    def __init__(
        self,
        model: Any,
        tokenizer: Any,
        *,
        model_id: str,
        model_version: str,
        tokenizer_id: str | None = None,
        tokenizer_version: str | None = None,
        layer_names: Sequence[str] | None = None,
        layer_indices: Sequence[int] | None = None,
        device: str = "cpu",
        max_length: int | None = None,
    ) -> None:
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        discovered = LayerDiscovery.discover(model)
        self.layer_names = LayerDiscovery.select(
            discovered, layer_names=layer_names, layer_indices=layer_indices
        )
        self.model_id = model_id
        self.model_version = model_version
        self.tokenizer_id = tokenizer_id or str(
            getattr(tokenizer, "name_or_path", "local-tokenizer")
        )
        self.tokenizer_version = tokenizer_version or self._library_version()
        self.max_length = max_length

    @staticmethod
    def _library_version() -> str:
        try:
            import transformers

            return str(transformers.__version__)
        except ImportError:
            return "unknown"

    @contextmanager
    def _hooks(self, captured: dict[str, Any]) -> Iterator[None]:
        handles = []
        modules = dict(self.model.named_modules())
        try:
            for name in self.layer_names:
                module = modules[name]

                def capture(_module: Any, _inputs: Any, output: Any, *, layer: str = name) -> None:
                    value = output[0] if isinstance(output, (tuple, list)) else output
                    if not hasattr(value, "detach") or value.ndim != 3:
                        raise ModelCompatibilityError(
                            f"Layer {layer!r} did not emit [batch, tokens, hidden] activations"
                        )
                    captured[layer] = value.detach().to("cpu").clone()

                handles.append(module.register_forward_hook(capture))
            yield
        finally:
            for handle in handles:
                handle.remove()

    def collect(
        self,
        prompts: Sequence[str],
        *,
        batch_size: int = 1,
        functions: Sequence[Sequence[FunctionSpan]] | None = None,
    ) -> tuple[ActivationBatch, ...]:
        if not prompts:
            return ()
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if functions is not None and len(functions) != len(prompts):
            raise ValueError("functions must contain one span sequence per prompt")
        results = []
        for start in range(0, len(prompts), batch_size):
            batch_prompts = prompts[start : start + batch_size]
            batch_functions = functions[start : start + batch_size] if functions else None
            results.append(self._collect_batch(batch_prompts, batch_functions))
        return tuple(results)

    def _collect_batch(
        self,
        prompts: Sequence[str],
        functions: Sequence[Sequence[FunctionSpan]] | None,
    ) -> ActivationBatch:
        if any(not prompt for prompt in prompts):
            raise ValueError("prompts must not contain empty strings")
        kwargs: dict[str, Any] = {
            "return_tensors": "pt",
            "padding": True,
            "return_offsets_mapping": True,
        }
        if self.max_length is not None:
            kwargs.update(truncation=True, max_length=self.max_length)
        try:
            encoded = self.tokenizer(prompts, **kwargs)
            offsets = encoded.pop("offset_mapping")
            model_inputs = {
                key: value.to(self.device) for key, value in encoded.items() if hasattr(value, "to")
            }
            captured: dict[str, Any] = {}
            with self._hooks(captured):
                import torch

                self.model.eval()
                with torch.inference_mode():
                    self.model(**model_inputs)
            input_ids = model_inputs["input_ids"].detach().to("cpu").clone()
            attention_mask = model_inputs["attention_mask"].detach().to("cpu").clone()
            sequence_length = int(input_ids.shape[1])
            hidden_size = self._validate_shapes(captured, len(prompts), sequence_length)
            token_strings = tuple(
                tuple(self.tokenizer.convert_ids_to_tokens(row.tolist())) for row in input_ids
            )
            raw_offsets = offsets.tolist() if hasattr(offsets, "tolist") else offsets
            normalized_offsets = tuple(
                tuple((int(pair[0]), int(pair[1])) for pair in row) for row in raw_offsets
            )
            metadata = ActivationMetadata(
                model_id=self.model_id,
                model_version=self.model_version,
                tokenizer_id=self.tokenizer_id,
                tokenizer_version=self.tokenizer_version,
                layer_names=self.layer_names,
                hidden_size=hidden_size,
                dtype=str(next(iter(captured.values())).dtype),
                device=self.device,
                batch_size=len(prompts),
            )
            function_values = ()
            if functions is not None:
                function_values = tuple(
                    tuple(
                        self._aggregate(
                            item,
                            normalized_offsets[index],
                            captured,
                            batch_index=index,
                        )
                        for item in spans
                    )
                    for index, spans in enumerate(functions)
                )
            return ActivationBatch(
                input_ids=input_ids,
                attention_mask=attention_mask,
                tokens=token_strings,
                offsets=normalized_offsets,
                activations=captured,
                metadata=metadata,
                function_activations=function_values,
            )
        except (ModelCompatibilityError, ValueError):
            raise
        except Exception as error:
            raise ModelInferenceError("Activation collection failed") from error

    def _validate_shapes(self, captured: Mapping[str, Any], batch: int, sequence: int) -> int:
        if set(captured) != set(self.layer_names):
            missing = set(self.layer_names) - set(captured)
            raise ModelCompatibilityError(
                f"Activation hooks did not capture layers: {sorted(missing)}"
            )
        dimensions = {tuple(value.shape) for value in captured.values()}
        if any(shape[0] != batch or shape[1] != sequence for shape in dimensions):
            raise ModelCompatibilityError(
                "Captured activation shape does not match tokenized inputs"
            )
        hidden_sizes = {shape[2] for shape in dimensions}
        if len(hidden_sizes) != 1:
            raise ModelCompatibilityError("Selected layers have inconsistent hidden dimensions")
        return hidden_sizes.pop()

    def _aggregate(
        self,
        function: FunctionSpan,
        offsets: Sequence[tuple[int, int]],
        activations: Mapping[str, Any],
        *,
        batch_index: int,
    ) -> FunctionActivation:
        indices = tuple(
            index
            for index, (start, end) in enumerate(offsets)
            if end > function.start_char and start < function.end_char
        )
        if not indices:
            raise ValueError(f"Function {function.name!r} does not overlap any code token")
        values = {
            layer: tensor[batch_index, list(indices), :].mean(dim=0)
            for layer, tensor in activations.items()
        }
        return FunctionActivation(function=function, token_indices=indices, values=values)


class ActivationStore:
    """Persist activation tensors and JSON metadata without detaching provenance."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, batch: ActivationBatch) -> Path:
        if not name or Path(name).name != name:
            raise ValueError("activation name must be a simple file name")
        import torch

        path = self.root / f"{name}.pt"
        payload = {
            "input_ids": batch.input_ids,
            "attention_mask": batch.attention_mask,
            "tokens": batch.tokens,
            "offsets": batch.offsets,
            "activations": dict(batch.activations),
            "metadata": batch.metadata,
            "function_activations": batch.function_activations,
        }
        torch.save(payload, path)
        (self.root / f"{name}.json").write_text(
            json.dumps(
                batch.metadata.__dict__
                if hasattr(batch.metadata, "__dict__")
                else {
                    field: getattr(batch.metadata, field)
                    for field in batch.metadata.__dataclass_fields__
                },
                default=list,
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def load(self, name: str) -> dict[str, Any]:
        import torch

        return torch.load(self.root / f"{name}.pt", map_location="cpu", weights_only=False)


__all__ = [
    "ActivationBatch",
    "ActivationCollector",
    "ActivationMetadata",
    "ActivationStore",
    "FunctionActivation",
    "FunctionSpan",
    "LayerDiscovery",
]
