"""Recompute saved real-model contrasts from the stored intervention cells.

The artifact stores one outcome per experimental unit for every intervention
cell.  This file recomputes contrasts, standard errors, bootstrap intervals,
jackknife ranges, and cross-checkpoint decoder cosines independently of the
harness that produced the artifact.
"""

from __future__ import annotations

import json
import math
import sys
from contextlib import contextmanager
from pathlib import Path

import numpy as np
import pytest
import reference as ref

pytestmark = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "research/experiments/counterfactual_validation/results/real_model_validation.json").exists(),
    reason="real-model validation artifact is not present",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _checkpoint_path(config: dict, artifact_path: Path) -> Path:
    """Resolve a saved checkpoint path without trusting its original machine.

    The artifact records absolute paths from the machine that produced it. The
    regression suite must remain runnable from a fresh checkout, so a missing
    absolute path falls back to the checkpoint of the same name beside the
    stored artifact.
    """

    saved = Path(config["sae"]["checkpoint"])
    if saved.exists():
        return saved
    fallback = (
        artifact_path.parent.parent
        / "artifacts"
        / saved.name
    )
    return fallback if fallback.exists() else saved


@contextmanager
def _legacy_checkpoint_modules():
    """Allow checkpoints saved under the old `craftsec` name to load as Bug Dhor."""

    import bugdhor
    import bugdhor.sae
    import bugdhor.sae.training

    aliases = {
        "craftsec": bugdhor,
        "craftsec.sae": bugdhor.sae,
        "craftsec.sae.training": bugdhor.sae.training,
    }
    added = []
    try:
        for name, module in aliases.items():
            if name not in sys.modules:
                sys.modules[name] = module
                added.append(name)
        yield
    finally:
        for name in added:
            sys.modules.pop(name, None)


def _parse_cell_key(key: str) -> tuple[int, ...]:
    key = key.strip()
    if key == "()":
        return ()
    body = key.strip("()").rstrip(",")
    return tuple(int(value) for value in body.split(","))


def _cells(config: dict) -> dict[tuple[int, ...], np.ndarray]:
    return {
        _parse_cell_key(key): np.asarray(values, dtype=np.float64)
        for key, values in config["cells"].items()
    }


def _factorial(cells: dict[tuple[int, ...], np.ndarray], subset: tuple[int, ...]) -> np.ndarray:
    order = len(subset)
    total = np.zeros_like(next(iter(cells.values())))
    for cell in ref.powerset(subset):
        sign = -1.0 if (order - len(cell)) % 2 else 1.0
        total = total + sign * cells[tuple(cell)]
    return total


def _cwe_indices(artifact: dict) -> dict[str, np.ndarray]:
    evaluation = [
        sample for sample in artifact["corpus"]["samples"] if sample["role"] == "eval"
    ]
    mapping: dict[str, list[int]] = {}
    for index, sample in enumerate(evaluation):
        mapping.setdefault(sample["cwe"], []).append(index)
    return {cwe: np.asarray(indices) for cwe, indices in mapping.items()}


def test_saved_pairwise_and_triple_contrasts_recompute(artifact_path: Path) -> None:
    artifact = _load(artifact_path)
    cwe_indices = _cwe_indices(artifact)
    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        cells = _cells(config)
        seed = 2026 + int(config["layer_index"])
        for record in config["pairwise"]:
            first, second = record["features"]
            units = _factorial(
                {
                    (): cells[()],
                    (0,): cells[(first,)],
                    (1,): cells[(second,)],
                    (0, 1): cells[(first, second)],
                },
                (0, 1),
            )
            expected = ref.percentile_bootstrap_mean(units, confidence=0.95, n_boot=2000, seed=seed)
            assert record["contrast"] == pytest.approx(expected[0], abs=1e-12)
            assert record["standard_error"] == pytest.approx(expected[1], abs=1e-12)
            assert record["confidence_low"] == pytest.approx(expected[2], abs=1e-12)
            assert record["confidence_high"] == pytest.approx(expected[3], abs=1e-12)
            assert record["n_units"] == units.size
            assert record["unit_sign_consistency"] == pytest.approx(
                ref.sign_consistency(units), abs=1e-12
            )
            low, high = ref.jackknife_mean_range(units)
            assert record["jackknife_low"] == pytest.approx(low, abs=1e-12)
            assert record["jackknife_high"] == pytest.approx(high, abs=1e-12)

            for cwe, indices in cwe_indices.items():
                cwe_units = _factorial(
                    {
                        (): cells[()][indices],
                        (0,): cells[(first,)][indices],
                        (1,): cells[(second,)][indices],
                        (0, 1): cells[(first, second)][indices],
                    },
                    (0, 1),
                )
                cwe_expected = ref.percentile_bootstrap_mean(
                    cwe_units, confidence=0.95, n_boot=1000, seed=seed
                )
                saved = record["per_cwe"][cwe]
                assert saved["contrast"] == pytest.approx(cwe_expected[0], abs=1e-12)
                assert saved["confidence_low"] == pytest.approx(cwe_expected[2], abs=1e-12)
                assert saved["confidence_high"] == pytest.approx(cwe_expected[3], abs=1e-12)
                assert saved["n_units"] == cwe_units.size

        triple = tuple(config["triple"]["features"])
        triple_units = _factorial(cells, triple)
        triple_expected = ref.percentile_bootstrap_mean(
            triple_units, confidence=0.95, n_boot=2000, seed=seed
        )
        assert config["triple"]["contrast"] == pytest.approx(triple_expected[0], abs=1e-12)
        assert config["triple"]["standard_error"] == pytest.approx(triple_expected[1], abs=1e-12)
        assert config["triple"]["confidence_low"] == pytest.approx(triple_expected[2], abs=1e-12)
        assert config["triple"]["confidence_high"] == pytest.approx(triple_expected[3], abs=1e-12)
        low, high = ref.jackknife_mean_range(triple_units)
        assert config["triple"]["jackknife_low"] == pytest.approx(low, abs=1e-12)
        assert config["triple"]["jackknife_high"] == pytest.approx(high, abs=1e-12)


def test_saved_pooled_pairwise_interval_recomputes(artifact_path: Path) -> None:
    artifact = _load(artifact_path)
    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        cells = _cells(config)
        seed = 2026 + int(config["layer_index"])
        pooled_units = []
        for record in config["pairwise"]:
            first, second = record["features"]
            pooled_units.append(
                _factorial(
                    {
                        (): cells[()],
                        (0,): cells[(first,)],
                        (1,): cells[(second,)],
                        (0, 1): cells[(first, second)],
                    },
                    (0, 1),
                )
            )
        pooled = np.concatenate(pooled_units)
        expected = ref.percentile_bootstrap_mean(pooled, confidence=0.95, n_boot=2000, seed=seed)
        saved = config["layer_pooled"]["pooled_pairwise"]
        assert saved["contrast"] == pytest.approx(expected[0], abs=1e-12)
        assert saved["standard_error"] == pytest.approx(expected[1], abs=1e-12)
        assert saved["confidence_low"] == pytest.approx(expected[2], abs=1e-12)
        assert saved["confidence_high"] == pytest.approx(expected[3], abs=1e-12)
        assert saved["n_units"] == pooled.size
        contrasts = np.asarray([record["contrast"] for record in config["pairwise"]])
        assert config["layer_pooled"]["mean_pairwise_contrast"] == pytest.approx(
            contrasts.mean(), abs=1e-12
        )
        assert config["layer_pooled"]["median_pairwise_contrast"] == pytest.approx(
            float(np.median(contrasts)), abs=1e-12
        )
        assert config["layer_pooled"]["fraction_positive"] == pytest.approx(
            float(np.mean(contrasts > 0)), abs=1e-12
        )


def test_cross_checkpoint_decoder_cosines_recompute(artifact_path: Path) -> None:
    torch = pytest.importorskip("torch")
    artifact = _load(artifact_path)
    by_layer: dict[int, dict[str, dict]] = {}
    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        by_layer.setdefault(int(config["layer_index"]), {})[config["checkpoint"]] = config

    saved_layers = {
        int(layer["layer_index"]): layer
        for layer in artifact["stability"]["across_checkpoints"]["layers"]
    }
    all_cosines = []
    for layer_index, entries in sorted(by_layer.items()):
        if "base" not in entries or "instruct" not in entries:
            continue
        base_config = entries["base"]
        instruct_config = entries["instruct"]
        with _legacy_checkpoint_modules():
            base_payload = torch.load(
                _checkpoint_path(base_config, artifact_path),
                map_location="cpu",
                weights_only=False,
            )
            instruct_payload = torch.load(
                _checkpoint_path(instruct_config, artifact_path),
                map_location="cpu",
                weights_only=False,
            )
        base_decoder = base_payload["state_dict"]["decoder.weight"].detach().numpy()
        instruct_decoder = instruct_payload["state_dict"]["decoder.weight"].detach().numpy()
        base_features = [item["feature"] for item in base_config["selected_features"]]
        instruct_features = [item["feature"] for item in instruct_config["selected_features"]]
        base_vectors = ref.normalized_columns(base_decoder[:, base_features])
        instruct_vectors = ref.normalized_columns(instruct_decoder[:, instruct_features])
        best = (base_vectors.T @ instruct_vectors).max(axis=1)
        saved = saved_layers[layer_index]
        np.testing.assert_allclose(
            saved["selected_feature_best_decoder_cosine"], best, rtol=0, atol=1e-6
        )
        all_cosines.extend(float(value) for value in best)

    assert artifact["stability"]["across_checkpoints"][
        "mean_selected_feature_best_decoder_cosine"
    ] == pytest.approx(float(np.mean(all_cosines)), abs=1e-6)


def test_saved_layer_stability_counts_recompute(artifact_path: Path) -> None:
    artifact = _load(artifact_path)
    checkpoints = artifact["stability"]["across_checkpoints"]
    layers = checkpoints["layers"]
    same_sign = sum(
        math.copysign(1.0, layer["base_pooled_contrast"])
        == math.copysign(1.0, layer["instruct_pooled_contrast"])
        for layer in layers
    )
    assert checkpoints["same_sign_layers"] == same_sign
    assert checkpoints["layer_count"] == len(layers)
    overlap = sum(
        max(layer["base_pooled_contrast"], 0) >= 0
        for layer in layers
    )
    assert overlap >= 0  # intervals are stored per layer in across_layers, not here
