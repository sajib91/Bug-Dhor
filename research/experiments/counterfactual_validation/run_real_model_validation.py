"""Real-model validation of Bug Dhor counterfactual interaction analysis.

Design
------
Model checkpoints
    ``Qwen/Qwen2.5-Coder-0.5B`` (base) and
    ``Qwen/Qwen2.5-Coder-0.5B-Instruct``.

Outcome ``Y``
    For each code prompt, ``Y`` is the next-token log-odds of the label pair
    ``A`` (unsafe) versus ``B`` (safe) under the fixed instruction template
    defined in :mod:`bugdhor.counterfactual.validation_corpus`.  ``Y`` is a
    declared model readout, not a vulnerability label or ground truth.

Intervention states
    For a residual-stream layer, an SAE is trained on real activations.  For a
    selected feature ``f`` with measured latent ``a_f(x)`` and decoder direction
    ``d_f``, state ``1`` ablates the feature at the final token position::

        h'(x) = h(x) - a_f(x) * d_f

    State ``0`` leaves the activation unchanged.  The joint state subtracts all
    declared directions simultaneously.  This is a controlled activation
    intervention, not an external manipulation of the code.

Contrasts
    Pairwise: ``Y(1,1) - Y(1,0) - Y(0,1) + Y(0,0)``.
    Higher order: ``sum_{T subset S} (-1)^(|S|-|T|) Y(T)``.

Uncertainty
    Paired percentile bootstrap over prompts (experimental units).  No p-values
    or significance claims are produced.

Run from the repository root::

    .venv/bin/python research/experiments/counterfactual_validation/run_real_model_validation.py
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import torch
from bugdhor.counterfactual.validation import (
    BootstrapContrast,
    bootstrap_mean_interval,
    estimate_higher_order_contrast,
    estimate_pairwise_contrast,
    factorial_unit_contrasts,
    stability_summary,
)
from bugdhor.counterfactual.validation_corpus import (
    ValidationSample,
    build_validation_corpus,
    decode_label_tokens,
    split_roles,
)
from bugdhor.sae.checkpoint import save_checkpoint
from bugdhor.sae.config import SAEConfig
from bugdhor.sae.model import SparseAutoencoder
from bugdhor.sae.training import SAETrainer
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = Path(__file__).resolve().parent / "results"
ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"

CHECKPOINTS: dict[str, str] = {
    "base": "Qwen/Qwen2.5-Coder-0.5B",
    "instruct": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
}

DEFAULT_LAYERS = "4,10,16,21"


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    return value


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:  # noqa: BLE001 - provenance must not abort the run
        return None


def _snapshot(repo: str) -> Path:
    """Resolve an already-downloaded snapshot without requiring every repo file."""
    from huggingface_hub import constants, snapshot_download

    folder = "models--" + repo.replace("/", "--")
    snapshots = Path(constants.HF_HUB_CACHE) / folder / "snapshots"
    if snapshots.is_dir():
        for candidate in sorted(snapshots.iterdir()):
            if (candidate / "config.json").is_file() and (
                candidate / "model.safetensors"
            ).is_file():
                return candidate
    return Path(
        snapshot_download(
            repo,
            local_files_only=True,
            allow_patterns=["*.json", "*.safetensors", "*.txt", "*.model"],
        )
    )


def _discover_layers(model: Any) -> list[tuple[int, str]]:
    import re

    pattern = re.compile(r"(?:^|\.)(?:layers|h|block|blocks|layer)\.(\d+)$")
    found: list[tuple[int, str]] = []
    for name, module in model.named_modules():
        match = pattern.search(name)
        if match and name and hasattr(module, "register_forward_hook"):
            found.append((int(match.group(1)), name))
    if not found:
        raise RuntimeError("no hookable transformer layers were discovered")
    return sorted(found)


def _parse_layers(text: str, available: list[tuple[int, str]]) -> list[tuple[int, str]]:
    requested = [int(item) for item in text.split(",") if item.strip()]
    by_index = dict(available)
    missing = [index for index in requested if index not in by_index]
    if missing:
        raise ValueError(f"requested layers are not available: {missing}")
    return [(index, by_index[index]) for index in requested]


@dataclass
class LayerRuntime:
    model: Any
    tokenizer: Any
    layer_module: Any
    layer_index: int
    layer_name: str
    token_a: int
    token_b: int
    device: str = "cpu"

    def __post_init__(self) -> None:
        self._inputs: dict[str, Any] | None = None
        self._prompt_count = 0

    def encode(self, prompts: list[str]) -> None:
        encoded = self.tokenizer(
            prompts,
            padding=True,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        self._inputs = {key: value.to(self.device) for key, value in encoded.items()}
        self._prompt_count = len(prompts)

    def _forward(
        self,
        delta: np.ndarray | None,
        *,
        capture_all: bool,
    ) -> tuple[np.ndarray, np.ndarray | None, np.ndarray]:
        if self._inputs is None:
            raise RuntimeError("encode() must be called before a forward pass")
        captured: dict[str, Any] = {}

        def hook(_module: Any, _inputs: Any, output: Any) -> Any:
            hidden = output[0] if isinstance(output, (tuple, list)) else output
            if delta is not None:
                addition = torch.as_tensor(
                    delta, dtype=hidden.dtype, device=hidden.device
                )
                hidden[:, -1, :] = hidden[:, -1, :] + addition
            captured["last"] = hidden[:, -1, :].detach().float().cpu().clone()
            if capture_all:
                mask = self._inputs["attention_mask"].bool()
                captured["all"] = hidden[mask].detach().float().cpu().clone()
            return None

        handle = self.layer_module.register_forward_hook(hook)
        try:
            with torch.inference_mode():
                try:
                    output = self.model(
                        **self._inputs,
                        use_cache=False,
                        logits_to_keep=1,
                    )
                    last_logits = output.logits[:, -1, :]
                except TypeError:
                    output = self.model(**self._inputs, use_cache=False)
                    last_logits = output.logits[:, -1, :]
        finally:
            handle.remove()
        outcome = (
            (last_logits[:, self.token_a] - last_logits[:, self.token_b])
            .float()
            .cpu()
            .numpy()
        )
        return outcome, captured.get("all"), captured["last"].numpy()

    def outcome(self, delta: np.ndarray | None = None) -> np.ndarray:
        outcome, _, _ = self._forward(delta, capture_all=False)
        return outcome

    def training_activations(self) -> np.ndarray:
        _, activations, _ = self._forward(None, capture_all=True)
        assert activations is not None
        return activations

    def last_token_activations(self) -> np.ndarray:
        _, _, last = self._forward(None, capture_all=False)
        return last


def _load_model(repo: str) -> tuple[Any, Any, Path, dict[str, Any]]:
    path = _snapshot(repo)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"
    model = AutoModelForCausalLM.from_pretrained(
        path,
        local_files_only=True,
        dtype=torch.float32,
    )
    model.eval()
    model.to("cpu")
    metadata = {
        "repo": repo,
        "local_path": str(path),
        "hidden_size": int(model.config.hidden_size),
        "num_hidden_layers": int(model.config.num_hidden_layers),
        "dtype": "float32",
        "device": "cpu",
    }
    return model, tokenizer, path, metadata


def _train_sae(
    activations: np.ndarray,
    *,
    hidden_size: int,
    latent_multiplier: int,
    epochs: int,
    sparsity: float,
    seed: int,
    artifact_path: Path,
) -> tuple[SparseAutoencoder, dict[str, Any]]:
    config = SAEConfig(
        input_dim=hidden_size,
        latent_dim=hidden_size * latent_multiplier,
        sparsity_coefficient=sparsity,
        batch_size=128,
        learning_rate=1e-3,
        epochs=epochs,
        validation_fraction=0.1,
        seed=seed,
    )
    model = SparseAutoencoder(config)
    trainer = SAETrainer(config)
    tensor = (
        activations
        if isinstance(activations, torch.Tensor)
        else torch.from_numpy(activations)
    ).float()
    training = trainer.fit(model, tensor)
    save_checkpoint(artifact_path, model, training=training)
    validation = training.validation
    summary = {
        "config": config.to_dict(),
        "config_hash": config.config_hash,
        "activation_vectors": int(activations.shape[0]),
        "reconstruction_error": None
        if validation is None
        else validation.reconstruction_error,
        "relative_reconstruction_error": (
            None if validation is None else validation.relative_reconstruction_error
        ),
        "mean_l0": None if validation is None else validation.mean_l0,
        "dead_features": (
            None if validation is None else len(validation.dead_features)
        ),
        "checkpoint": str(artifact_path),
    }
    return model, summary


def _delta_for(
    latents: np.ndarray,
    decoder_weight: np.ndarray,
    feature_indices: list[int],
) -> np.ndarray:
    columns = decoder_weight[:, feature_indices]
    magnitudes = latents[:, feature_indices]
    return -(magnitudes @ columns.T)


def _pooled_contrast(
    unit_arrays: list[np.ndarray],
    *,
    seed: int,
    label: str,
) -> BootstrapContrast:
    pooled = np.concatenate([np.asarray(array).reshape(-1) for array in unit_arrays])
    estimate, error, low, high = bootstrap_mean_interval(
        pooled, confidence=0.95, n_boot=2000, seed=seed
    )
    return BootstrapContrast(
        contrast=estimate,
        standard_error=error,
        confidence_low=low,
        confidence_high=high,
        confidence=0.95,
        n_units=int(pooled.size),
        n_boot=2000,
        method=label,
    )


def _sign_consistency(values: np.ndarray) -> float:
    nonzero = values[values != 0.0]
    if nonzero.size == 0:
        return 1.0
    positive = float(np.mean(nonzero > 0.0))
    return max(positive, 1.0 - positive)


def _jackknife_range(values: np.ndarray) -> tuple[float, float] | tuple[None, None]:
    if values.size < 2:
        return None, None
    means = [float(np.delete(values, index).mean()) for index in range(values.size)]
    return min(means), max(means)


def _cwe_map(samples: tuple[ValidationSample, ...]) -> dict[str, list[int]]:
    mapping: dict[str, list[int]] = {}
    for index, sample in enumerate(samples):
        mapping.setdefault(sample.cwe, []).append(index)
    return mapping


def run_config(
    *,
    checkpoint: str,
    runtime: LayerRuntime,
    evaluation: tuple[ValidationSample, ...],
    training: tuple[ValidationSample, ...],
    top_k: int,
    latent_multiplier: int,
    epochs: int,
    sparsity: float,
    seed: int,
    n_boot: int,
    direction_fraction: float,
    artifact_dir: Path,
) -> dict[str, Any]:
    started = time.time()
    eval_prompts = [sample.prompt for sample in evaluation]
    train_prompts = [sample.prompt for sample in training]

    runtime.encode(eval_prompts)
    baseline = runtime.outcome()
    last_hidden = runtime.last_token_activations()

    runtime.encode(train_prompts)
    train_activations = runtime.training_activations()

    hidden_size = int(last_hidden.shape[1])
    sae_path = artifact_dir / f"{checkpoint}_layer{runtime.layer_index}.pt"
    sae, sae_summary = _train_sae(
        train_activations,
        hidden_size=hidden_size,
        latent_multiplier=latent_multiplier,
        epochs=epochs,
        sparsity=sparsity,
        seed=seed,
        artifact_path=sae_path,
    )

    latents = sae.feature_activations(
        torch.from_numpy(last_hidden).float(),
        threshold=sae.config.l0_threshold,
    ).numpy()
    decoder_weight = sae.decoder.weight.detach().cpu().numpy()
    decoder_norm = np.linalg.norm(decoder_weight, axis=0)
    mean_activation = latents.mean(axis=0)
    max_activation = latents.max(axis=0)
    n_units_active = (latents > sae.config.l0_threshold).sum(axis=0)

    order = np.argsort(-mean_activation)
    selected: list[int] = []
    for feature in order:
        if len(selected) >= top_k:
            break
        if mean_activation[feature] <= 0.0:
            continue
        if decoder_norm[feature] <= 1e-8:
            continue
        selected.append(int(feature))
    if len(selected) < 3:
        raise RuntimeError(
            f"only {len(selected)} usable features were selected at layer "
            f"{runtime.layer_index}"
        )

    residual_norm = float(np.median(np.linalg.norm(last_hidden, axis=1)))
    step = direction_fraction * residual_norm
    unit_directions = decoder_weight / np.maximum(decoder_norm, 1e-12)

    def steering_delta(features: list[int]) -> np.ndarray:
        direction = unit_directions[:, features].sum(axis=1)
        row = step * direction
        return np.repeat(row[None, :], len(eval_prompts), axis=0)

    runtime.encode(eval_prompts)
    cells: dict[tuple[int, ...], np.ndarray] = {(): baseline}
    for feature in selected:
        cells[(feature,)] = runtime.outcome(steering_delta([feature]))
    for left in range(len(selected)):
        for right in range(left + 1, len(selected)):
            pair = sorted((selected[left], selected[right]))
            cells[tuple(pair)] = runtime.outcome(steering_delta(pair))
    triple = tuple(sorted(selected[:3]))
    cells[triple] = runtime.outcome(steering_delta(list(triple)))

    # Natural measured-activation ablation is a separate, weaker intervention.
    # It is used for single-feature ablation reporting and for one pairwise
    # ablation sensitivity check, not for the primary factorial contrasts.
    ablation_first, ablation_second = sorted(selected[:2])
    ablation_pair = (ablation_first, ablation_second)
    ablation_cells: dict[tuple[int, ...], np.ndarray] = {(): baseline}
    for feature in selected:
        ablation_cells[(feature,)] = runtime.outcome(
            _delta_for(latents, decoder_weight, [feature])
        )
    ablation_cells[ablation_pair] = runtime.outcome(
        _delta_for(latents, decoder_weight, list(ablation_pair))
    )
    ablation_result = estimate_pairwise_contrast(
        baseline,
        ablation_cells[(ablation_first,)],
        ablation_cells[(ablation_second,)],
        ablation_cells[ablation_pair],
        confidence=0.95,
        n_boot=n_boot,
        seed=seed,
    )
    ablation_unit = factorial_unit_contrasts(
        {
            (): baseline,
            (0,): ablation_cells[(ablation_first,)],
            (1,): ablation_cells[(ablation_second,)],
            (0, 1): ablation_cells[ablation_pair],
        },
        (0, 1),
    )

    cwe_indices = _cwe_map(evaluation)
    pairwise_records: list[dict[str, Any]] = []
    pooled_units: list[np.ndarray] = []

    for left in range(len(selected)):
        for right in range(left + 1, len(selected)):
            first, second = sorted((selected[left], selected[right]))
            pair_key = (first, second)
            single_first = cells[(first,)]
            single_second = cells[(second,)]
            joint = cells[pair_key]
            result = estimate_pairwise_contrast(
                baseline,
                single_first,
                single_second,
                joint,
                confidence=0.95,
                n_boot=n_boot,
                seed=seed,
            )
            unit_contrast = factorial_unit_contrasts(
                {
                    (): baseline,
                    (0,): single_first,
                    (1,): single_second,
                    (0, 1): joint,
                },
                (0, 1),
            )
            pooled_units.append(unit_contrast)
            per_cwe: dict[str, BootstrapContrast] = {}
            for cwe, indices in cwe_indices.items():
                index = np.asarray(indices)
                per_cwe[cwe] = estimate_pairwise_contrast(
                    baseline[index],
                    single_first[index],
                    single_second[index],
                    joint[index],
                    confidence=0.95,
                    n_boot=max(500, n_boot // 2),
                    seed=seed,
                )
            cwe_summary = stability_summary(per_cwe)
            low, high = _jackknife_range(unit_contrast)
            single_effect = float(np.mean(np.abs(single_first - baseline)))
            pairwise_records.append(
                {
                    "features": [first, second],
                    "contrast": result.contrast,
                    "standard_error": result.standard_error,
                    "confidence_low": result.confidence_low,
                    "confidence_high": result.confidence_high,
                    "n_units": result.n_units,
                    "unit_sign_consistency": _sign_consistency(unit_contrast),
                    "jackknife_low": low,
                    "jackknife_high": high,
                    "mean_abs_single_feature_outcome_change": single_effect,
                    "per_cwe": {
                        cwe: {
                            "contrast": item.contrast,
                            "confidence_low": item.confidence_low,
                            "confidence_high": item.confidence_high,
                            "n_units": item.n_units,
                        }
                        for cwe, item in per_cwe.items()
                    },
                    "cwe_same_sign": cwe_summary.same_sign,
                    "cwe_sign_consistency": cwe_summary.sign_consistency,
                    "cwe_all_intervals_overlap": cwe_summary.all_intervals_overlap,
                }
            )

    triple_result = estimate_higher_order_contrast(
        cells, triple, confidence=0.95, n_boot=n_boot, seed=seed
    )
    triple_unit = factorial_unit_contrasts(cells, triple)
    triple_low, triple_high = _jackknife_range(triple_unit)
    triple_cwe: dict[str, BootstrapContrast] = {}
    for cwe, indices in cwe_indices.items():
        index = np.asarray(indices)
        subset = {key: value[index] for key, value in cells.items()}
        triple_cwe[cwe] = estimate_higher_order_contrast(
            subset,
            triple,
            confidence=0.95,
            n_boot=max(500, n_boot // 2),
            seed=seed,
        )
    triple_cwe_summary = stability_summary(triple_cwe)

    pairwise_contrasts = np.asarray([record["contrast"] for record in pairwise_records])
    pooled = _pooled_contrast(
        pooled_units,
        seed=seed,
        label="pooled per-unit pairwise contrasts; percentile bootstrap over units",
    )
    cwe_pooled: dict[str, BootstrapContrast] = {}
    for cwe, indices in cwe_indices.items():
        index = np.asarray(indices)
        cwe_units = [
            factorial_unit_contrasts(
                {
                    (): baseline[index],
                    (0,): cells[(record["features"][0],)][index],
                    (1,): cells[(record["features"][1],)][index],
                    (0, 1): cells[tuple(record["features"])][index],
                },
                (0, 1),
            )
            for record in pairwise_records
        ]
        cwe_pooled[cwe] = _pooled_contrast(
            cwe_units,
            seed=seed,
            label="pooled per-unit pairwise contrasts within CWE",
        )
    cwe_pooled_summary = stability_summary(cwe_pooled)

    selected_decoder = decoder_weight[:, selected]
    primary_single_effects = {
        feature: float(np.mean(np.abs(cells[(feature,)] - baseline)))
        for feature in selected
    }
    ablation_single_effects = {
        feature: {
            "mean_abs_outcome_change": float(
                np.mean(np.abs(ablation_cells[(feature,)] - baseline))
            ),
            "mean_latent_activation": float(np.mean(latents[:, feature])),
        }
        for feature in selected
    }
    record = {
        "checkpoint": checkpoint,
        "layer_index": runtime.layer_index,
        "layer_name": runtime.layer_name,
        "runtime_seconds": time.time() - started,
        "intervention": {
            "primary": (
                "add a fixed step along the normalized SAE decoder direction; "
                "state 1 = h + step * d_f/||d_f||, state 0 = h"
            ),
            "direction_fraction_of_median_residual_norm": direction_fraction,
            "direction_step": step,
            "median_residual_norm": residual_norm,
            "ablation": (
                "sensitivity check: state 1 = h - a_f(x) * d_f, the natural "
                "measured-activation ablation"
            ),
        },
        "sae": sae_summary,
        "selected_features": [
            {
                "feature": feature,
                "mean_activation": float(mean_activation[feature]),
                "max_activation": float(max_activation[feature]),
                "n_units_active": int(n_units_active[feature]),
                "decoder_norm": float(decoder_norm[feature]),
            }
            for feature in selected
        ],
        "cells": {str(key): value.tolist() for key, value in cells.items()},
        "single_feature_effects": {
            "primary_direction": {
                str(feature): value for feature, value in primary_single_effects.items()
            },
            "natural_ablation": {
                str(feature): value
                for feature, value in ablation_single_effects.items()
            },
        },
        "ablation_pairwise": {
            "features": [ablation_first, ablation_second],
            "contrast": ablation_result.contrast,
            "standard_error": ablation_result.standard_error,
            "confidence_low": ablation_result.confidence_low,
            "confidence_high": ablation_result.confidence_high,
            "unit_sign_consistency": _sign_consistency(ablation_unit),
        },
        "pairwise": pairwise_records,
        "triple": {
            "features": list(triple),
            "contrast": triple_result.contrast,
            "standard_error": triple_result.standard_error,
            "confidence_low": triple_result.confidence_low,
            "confidence_high": triple_result.confidence_high,
            "unit_sign_consistency": _sign_consistency(triple_unit),
            "jackknife_low": triple_low,
            "jackknife_high": triple_high,
            "per_cwe": {
                cwe: {
                    "contrast": item.contrast,
                    "confidence_low": item.confidence_low,
                    "confidence_high": item.confidence_high,
                    "n_units": item.n_units,
                }
                for cwe, item in triple_cwe.items()
            },
            "cwe_same_sign": triple_cwe_summary.same_sign,
            "cwe_sign_consistency": triple_cwe_summary.sign_consistency,
            "cwe_all_intervals_overlap": triple_cwe_summary.all_intervals_overlap,
        },
        "layer_pooled": {
            "mean_pairwise_contrast": float(np.mean(pairwise_contrasts)),
            "median_pairwise_contrast": float(np.median(pairwise_contrasts)),
            "fraction_positive": float(np.mean(pairwise_contrasts > 0.0)),
            "pooled_pairwise": {
                "contrast": pooled.contrast,
                "standard_error": pooled.standard_error,
                "confidence_low": pooled.confidence_low,
                "confidence_high": pooled.confidence_high,
                "n_units": pooled.n_units,
            },
            "cwe_pooled": {
                cwe: {
                    "contrast": item.contrast,
                    "confidence_low": item.confidence_low,
                    "confidence_high": item.confidence_high,
                }
                for cwe, item in cwe_pooled.items()
            },
            "cwe_same_sign": cwe_pooled_summary.same_sign,
            "cwe_sign_consistency": cwe_pooled_summary.sign_consistency,
            "cwe_all_intervals_overlap": cwe_pooled_summary.all_intervals_overlap,
        },
        "_selected_decoder": selected_decoder,
        "_pooled_result": pooled,
    }
    return record


def _checkpoint_stability(
    configs: list[dict[str, Any]],
    decoder_registry: dict[tuple[str, int], np.ndarray],
) -> dict[str, Any]:
    by_layer: dict[int, dict[str, dict[str, Any]]] = {}
    for config in configs:
        by_layer.setdefault(config["layer_index"], {})[config["checkpoint"]] = config

    layers: list[dict[str, Any]] = []
    matching_cosines: list[float] = []
    for layer_index, entries in sorted(by_layer.items()):
        if "base" not in entries or "instruct" not in entries:
            continue
        base = entries["base"]
        instruct = entries["instruct"]
        base_pooled = base["_pooled_result"]
        instruct_pooled = instruct["_pooled_result"]
        summary = stability_summary({"base": base_pooled, "instruct": instruct_pooled})
        base_vectors = decoder_registry[("base", layer_index)]
        instruct_vectors = decoder_registry[("instruct", layer_index)]
        base_norm = base_vectors / np.maximum(
            np.linalg.norm(base_vectors, axis=0, keepdims=True), 1e-12
        )
        instruct_norm = instruct_vectors / np.maximum(
            np.linalg.norm(instruct_vectors, axis=0, keepdims=True), 1e-12
        )
        cosine = base_norm.T @ instruct_norm
        best = cosine.max(axis=1)
        matching_cosines.extend(float(value) for value in best)
        layers.append(
            {
                "layer_index": layer_index,
                "base_pooled_contrast": base_pooled.contrast,
                "instruct_pooled_contrast": instruct_pooled.contrast,
                "same_sign": summary.same_sign,
                "all_intervals_overlap": summary.all_intervals_overlap,
                "base_triple_contrast": base["triple"]["contrast"],
                "instruct_triple_contrast": instruct["triple"]["contrast"],
                "selected_feature_best_decoder_cosine": best.tolist(),
            }
        )

    if not layers:
        return {"available": False}

    same_sign_count = sum(layer["same_sign"] for layer in layers)
    overlap_count = sum(layer["all_intervals_overlap"] for layer in layers)
    triple_sign_agreement = sum(
        np.sign(layer["base_triple_contrast"])
        == np.sign(layer["instruct_triple_contrast"])
        for layer in layers
    )
    return {
        "available": True,
        "layers": layers,
        "layer_count": len(layers),
        "same_sign_layers": same_sign_count,
        "interval_overlap_layers": overlap_count,
        "triple_sign_agreement_layers": triple_sign_agreement,
        "mean_selected_feature_best_decoder_cosine": (
            float(np.mean(matching_cosines)) if matching_cosines else None
        ),
        "note": (
            "Independently trained SAEs do not guarantee feature identity across "
            "checkpoints.  The contrast comparison is therefore population-level, "
            "and the decoder-cosine values quantify how weak that identification is."
        ),
    }


def _layer_stability(configs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for config in configs:
        grouped.setdefault(config["checkpoint"], []).append(config)
    result: dict[str, Any] = {}
    for checkpoint, entries in grouped.items():
        entries = sorted(entries, key=lambda item: item["layer_index"])
        pooled = {
            f"layer_{entry['layer_index']}": entry["_pooled_result"]
            for entry in entries
        }
        summary = stability_summary(pooled)
        result[checkpoint] = {
            "layers": [
                {
                    "layer_index": entry["layer_index"],
                    "pooled_contrast": entry["_pooled_result"].contrast,
                    "confidence_low": entry["_pooled_result"].confidence_low,
                    "confidence_high": entry["_pooled_result"].confidence_high,
                    "mean_pairwise_contrast": entry["layer_pooled"][
                        "mean_pairwise_contrast"
                    ],
                    "fraction_positive": entry["layer_pooled"]["fraction_positive"],
                    "triple_contrast": entry["triple"]["contrast"],
                }
                for entry in entries
            ],
            "same_sign": summary.same_sign,
            "sign_consistency": summary.sign_consistency,
            "all_intervals_overlap": summary.all_intervals_overlap,
        }
    return result


def _strip_private(configs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in config.items() if not key.startswith("_")}
        for config in configs
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layers", default=DEFAULT_LAYERS)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--eval-variants", type=int, default=2)
    parser.add_argument("--train-variants", type=int, default=4)
    parser.add_argument("--sae-epochs", type=int, default=8)
    parser.add_argument("--sparsity", type=float, default=0.01)
    parser.add_argument("--latent-multiplier", type=int, default=2)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--n-boot", type=int, default=2000)
    parser.add_argument("--direction-fraction", type=float, default=0.25)
    parser.add_argument("--checkpoints", default="base,instruct")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", default="real_model_validation.json")
    args = parser.parse_args()

    if args.smoke:
        args.layers = "0"
        args.top_k = 3
        args.eval_variants = 1
        args.train_variants = 1
        args.sae_epochs = 1
        args.n_boot = 200

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    corpus = build_validation_corpus(
        eval_variants=args.eval_variants,
        train_variants=args.train_variants,
    )
    evaluation, training = split_roles(corpus)
    print(
        f"corpus: {len(evaluation)} evaluation units, {len(training)} training prompts",
        flush=True,
    )

    requested_checkpoints = [item.strip() for item in args.checkpoints.split(",")]
    payload: dict[str, Any] = {
        "experiment": "real_model_counterfactual_validation",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "estimand": {
            "outcome": (
                "Y(prompt) = logit(token A) - logit(token B) at the final "
                "non-padding position, where A/B are the declared label tokens."
            ),
            "intervention": (
                "State 1 ablates feature f by subtracting a_f(x) * d_f from the "
                "residual-stream output of the selected layer at the final token; "
                "state 0 leaves it unchanged; joint states subtract all declared "
                "directions simultaneously."
            ),
            "pairwise": "Y(1,1) - Y(1,0) - Y(0,1) + Y(0,0)",
            "higher_order": "sum_{T subset S} (-1)^(|S|-|T|) Y(T)",
        },
        "provenance": {
            "git_commit": _git_commit(),
            "python": sys.version,
            "torch": torch.__version__,
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "corpus": {
            "n_eval": len(evaluation),
            "n_train": len(training),
            "categories": sorted({sample.cwe for sample in corpus}),
            "samples": [
                {
                    "sample_id": sample.sample_id,
                    "cwe": sample.cwe,
                    "label": sample.label,
                    "role": sample.role,
                    "variant": sample.variant,
                }
                for sample in corpus
            ],
            "note": (
                "Labels describe the generating pattern only; they are not "
                "validated vulnerability ground truth and are not used by the "
                "interaction estimator."
            ),
        },
        "checkpoints": {},
        "configs": [],
        "stability": {},
    }

    decoder_registry: dict[tuple[str, int], np.ndarray] = {}
    all_configs: list[dict[str, Any]] = []

    for checkpoint_name in requested_checkpoints:
        if checkpoint_name not in CHECKPOINTS:
            raise ValueError(f"unknown checkpoint {checkpoint_name!r}")
        repo = CHECKPOINTS[checkpoint_name]
        print(f"\n=== loading {checkpoint_name}: {repo} ===", flush=True)
        try:
            model, tokenizer, _path, metadata = _load_model(repo)
        except Exception as error:  # noqa: BLE001 - record unavailable checkpoint
            payload["checkpoints"][checkpoint_name] = {
                "status": "unavailable",
                "reason": repr(error),
            }
            print(f"unavailable: {error}", flush=True)
            continue

        token_a, token_b, first_text, second_text = decode_label_tokens(tokenizer)
        available_layers = _discover_layers(model)
        selected_layers = _parse_layers(args.layers, available_layers)
        payload["checkpoints"][checkpoint_name] = {
            "status": "ok",
            **metadata,
            "label_tokens": {
                "first_token_id": token_a,
                "second_token_id": token_b,
                "first_text": first_text,
                "second_text": second_text,
            },
            "selected_layers": [index for index, _ in selected_layers],
        }

        for layer_index, layer_name in selected_layers:
            print(
                f"--- {checkpoint_name} layer {layer_index} ({layer_name}) ---",
                flush=True,
            )
            modules = dict(model.named_modules())
            runtime = LayerRuntime(
                model=model,
                tokenizer=tokenizer,
                layer_module=modules[layer_name],
                layer_index=layer_index,
                layer_name=layer_name,
                token_a=token_a,
                token_b=token_b,
            )
            try:
                record = run_config(
                    checkpoint=checkpoint_name,
                    runtime=runtime,
                    evaluation=evaluation,
                    training=training,
                    top_k=args.top_k,
                    latent_multiplier=args.latent_multiplier,
                    epochs=args.sae_epochs,
                    sparsity=args.sparsity,
                    seed=args.seed + layer_index,
                    n_boot=args.n_boot,
                    direction_fraction=args.direction_fraction,
                    artifact_dir=ARTIFACT_DIR,
                )
            except Exception as error:  # noqa: BLE001 - record failed layer config
                record = {
                    "checkpoint": checkpoint_name,
                    "layer_index": layer_index,
                    "layer_name": layer_name,
                    "status": "error",
                    "error": repr(error),
                    "traceback": traceback.format_exc(),
                }
                print(f"layer failed: {error}", flush=True)
            else:
                decoder_registry[(checkpoint_name, layer_index)] = record.pop(
                    "_selected_decoder"
                )
                print(
                    f"completed in {record['runtime_seconds']:.1f}s; "
                    f"pooled mean pairwise contrast "
                    f"{record['layer_pooled']['pooled_pairwise']['contrast']:+.4f}",
                    flush=True,
                )
            all_configs.append(record)

        del model
        gc.collect()

    payload["configs"] = _strip_private(all_configs)
    completed = [config for config in all_configs if config.get("status") != "error"]
    payload["stability"] = {
        "across_cwe": [
            {
                "checkpoint": config["checkpoint"],
                "layer_index": config["layer_index"],
                "cwe_same_sign": config["layer_pooled"]["cwe_same_sign"],
                "cwe_sign_consistency": config["layer_pooled"]["cwe_sign_consistency"],
                "cwe_all_intervals_overlap": config["layer_pooled"][
                    "cwe_all_intervals_overlap"
                ],
            }
            for config in completed
        ],
        "across_layers": _layer_stability(completed) if completed else {},
        "across_checkpoints": _checkpoint_stability(
            [config for config in completed if "_pooled_result" in config],
            decoder_registry,
        )
        if completed
        else {},
    }

    output = OUT_DIR / args.output
    output.write_text(json.dumps(_jsonable(payload), indent=2) + "\n")
    print(f"\nwrote {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
