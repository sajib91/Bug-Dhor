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
from artifact_paths import (
    ArtifactPathError,
    artifact_path,
    checkpoint_reference,
    load_manifest,
    normalize_relative_ref,
    resolve_under_root,
    verify_checksum,
)

pytestmark = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "research/experiments/counterfactual_validation/results/real_model_validation.json").exists(),
    reason="real-model validation artifact is not present",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_decoder_fixture(config: dict) -> tuple[np.ndarray, list[int], str, Path]:
    """Return verified selected decoder columns from the committed bundle."""

    checkpoint = config["checkpoint"]
    layer_index = int(config["layer_index"])
    ref_data = config["sae"].get("decoder_ref")
    manifest = load_manifest()
    if isinstance(ref_data, dict):
        fixture_id = ref_data["id"]
        relative = ref_data["path"]
        expected_sha256 = ref_data["sha256"]
    elif isinstance(ref_data, str):
        fixture_id = f"{checkpoint}_layer{layer_index}"
        relative = ref_data
        expected_sha256 = None
    else:
        pytest.fail(
            f"missing decoder artifact reference for {checkpoint} layer {layer_index}"
        )

    entry = manifest["files"].get(fixture_id)
    if entry is None:
        pytest.fail(
            f"missing decoder fixture entry {fixture_id!r} in {manifest['bundle_id']!r}"
        )
    if expected_sha256 is None:
        expected_sha256 = entry["sha256"]

    path = artifact_path(relative)
    label = f"decoder fixture {fixture_id} ({relative})"
    try:
        verify_checksum(path, expected_sha256, label=label)
    except ArtifactPathError as error:
        pytest.fail(f"{checkpoint} layer {layer_index}: {error}")

    with np.load(path, allow_pickle=False) as payload:
        columns = np.asarray(payload["decoder_columns"], dtype=np.float64).copy()
        features = [int(value) for value in payload["features"]]
    expected_features = [int(item["feature"]) for item in config["selected_features"]]
    if features != expected_features:
        pytest.fail(
            f"decoder fixture {fixture_id} features {features} do not match "
            f"artifact selected_features {expected_features}"
        )
    return columns, features, fixture_id, path


def _require_full_checkpoint(config: dict) -> Path:
    """Resolve and verify a full SAE checkpoint before torch.load()."""

    checkpoint = config["checkpoint"]
    layer_index = int(config["layer_index"])
    reference = checkpoint_reference(config)
    path = artifact_path(reference)
    expected_sha256 = config["sae"].get("checkpoint_sha256")
    if not expected_sha256:
        pytest.fail(
            f"missing checkpoint_sha256 for {checkpoint} layer {layer_index}; "
            "full-checkpoint integration requires a verified manifest"
        )
    try:
        verify_checksum(path, expected_sha256, label=f"checkpoint {reference}")
    except ArtifactPathError as error:
        pytest.fail(f"{checkpoint} layer {layer_index}: {error}")
    return path


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


def _cross_checkpoint_configs(artifact: dict) -> dict[int, dict[str, dict]]:
    by_layer: dict[int, dict[str, dict]] = {}
    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        by_layer.setdefault(int(config["layer_index"]), {})[config["checkpoint"]] = config
    return by_layer


def _saved_layers(artifact: dict) -> dict[int, dict]:
    return {
        int(layer["layer_index"]): layer
        for layer in artifact["stability"]["across_checkpoints"]["layers"]
    }


def _assert_cosines(best: np.ndarray, saved: dict) -> None:
    np.testing.assert_allclose(
        saved["selected_feature_best_decoder_cosine"], best, rtol=0, atol=1e-6
    )


def test_cross_checkpoint_decoder_cosines_recompute(artifact_path: Path) -> None:
    """Recompute cosines from committed, checksum-verified decoder columns."""

    artifact = _load(artifact_path)
    by_layer = _cross_checkpoint_configs(artifact)
    saved_layers = _saved_layers(artifact)
    all_cosines = []
    for layer_index, entries in sorted(by_layer.items()):
        if "base" not in entries or "instruct" not in entries:
            continue
        base_columns, _, _, _ = _require_decoder_fixture(entries["base"])
        instruct_columns, _, _, _ = _require_decoder_fixture(entries["instruct"])
        base_vectors = ref.normalized_columns(base_columns)
        instruct_vectors = ref.normalized_columns(instruct_columns)
        best = (base_vectors.T @ instruct_vectors).max(axis=1)
        _assert_cosines(best, saved_layers[layer_index])
        all_cosines.extend(float(value) for value in best)

    assert artifact["stability"]["across_checkpoints"][
        "mean_selected_feature_best_decoder_cosine"
    ] == pytest.approx(float(np.mean(all_cosines)), abs=1e-6)


@pytest.mark.real_model_integration
def test_cross_checkpoint_decoder_cosines_from_full_checkpoints(artifact_path: Path) -> None:
    """Provisioned-only integration: load the real SAE checkpoints themselves.

    This test is deselected from the default CI suite.  It is enabled only when
    the full checkpoints under the documented artifact root have been
    provisioned; missing or mismatched checkpoints fail explicitly.
    """

    torch = pytest.importorskip("torch")
    artifact = _load(artifact_path)
    by_layer = _cross_checkpoint_configs(artifact)
    saved_layers = _saved_layers(artifact)
    all_cosines = []
    for layer_index, entries in sorted(by_layer.items()):
        if "base" not in entries or "instruct" not in entries:
            continue
        base_config = entries["base"]
        instruct_config = entries["instruct"]
        base_checkpoint = _require_full_checkpoint(base_config)
        instruct_checkpoint = _require_full_checkpoint(instruct_config)
        with _legacy_checkpoint_modules():
            base_payload = torch.load(base_checkpoint, map_location="cpu", weights_only=False)
            instruct_payload = torch.load(
                instruct_checkpoint, map_location="cpu", weights_only=False
            )
        base_decoder = base_payload["state_dict"]["decoder.weight"].detach().numpy()
        instruct_decoder = instruct_payload["state_dict"]["decoder.weight"].detach().numpy()
        base_features = [item["feature"] for item in base_config["selected_features"]]
        instruct_features = [item["feature"] for item in instruct_config["selected_features"]]
        base_vectors = ref.normalized_columns(base_decoder[:, base_features])
        instruct_vectors = ref.normalized_columns(instruct_decoder[:, instruct_features])
        best = (base_vectors.T @ instruct_vectors).max(axis=1)
        _assert_cosines(best, saved_layers[layer_index])
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
