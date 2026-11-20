"""Portable artifact reference and integrity checks for the regression suite."""

from __future__ import annotations

import json

import pytest

from artifact_paths import (
    ArtifactPathError,
    ARTIFACT_ROOT,
    artifact_path,
    checkpoint_reference,
    load_manifest,
    normalize_relative_ref,
    resolve_under_root,
    sha256_file,
    verify_checksum,
)
from test_artifact_recomputation import _require_full_checkpoint


def test_relative_checkpoint_resolution_stays_inside_root() -> None:
    resolved = artifact_path("decoder_fixtures/v1/base_layer4.npz")
    assert resolved.is_file()
    assert resolved.is_relative_to(ARTIFACT_ROOT.resolve())


def test_missing_checkpoint_reports_reference() -> None:
    config = {
        "checkpoint": "base",
        "layer_index": 99,
        "sae": {
            "checkpoint": "artifacts/missing_layer99.pt",
            "checkpoint_sha256": "0" * 64,
        },
    }
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _require_full_checkpoint(config)
    message = str(excinfo.value)
    assert "base layer 99" in message
    assert "artifacts/missing_layer99.pt" in message


@pytest.mark.parametrize("reference", ["../secret.pt", "artifacts/../../secret.pt", "/etc/passwd"])
def test_invalid_artifact_root_traversal_is_rejected(reference: str) -> None:
    with pytest.raises(ArtifactPathError):
        resolve_under_root(ARTIFACT_ROOT, reference)


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("artifacts/base_layer4.pt", "artifacts/base_layer4.pt"),
        ("artifacts\\base_layer4.pt", "artifacts/base_layer4.pt"),
    ],
)
def test_cross_platform_relative_paths(reference: str, expected: str) -> None:
    assert normalize_relative_ref(reference) == expected


@pytest.mark.parametrize("reference", ["C:\\Users\\dev\\model.pt", "\\\\server\\share\\model.pt"])
def test_windows_absolute_paths_are_rejected(reference: str) -> None:
    with pytest.raises(ArtifactPathError):
        normalize_relative_ref(reference)


def test_checksum_mismatch_is_reported() -> None:
    path = artifact_path("decoder_fixtures/v1/base_layer4.npz")
    with pytest.raises(ArtifactPathError) as excinfo:
        verify_checksum(path, "0" * 64, label="decoder fixture test")
    assert "checksum mismatch" in str(excinfo.value)


def test_legacy_absolute_checkpoint_schema_is_compatibly_resolved() -> None:
    config = {
        "sae": {
            "checkpoint": "/Users/developer/Downloads/CRAFT-Sec/research/"
            "experiments/counterfactual_validation/artifacts/base_layer4.pt"
        }
    }
    assert checkpoint_reference(config) == "artifacts/base_layer4.pt"


def test_committed_fixture_manifest_checksums_are_valid() -> None:
    manifest = load_manifest()
    for fixture_id, entry in manifest["files"].items():
        path = artifact_path(entry["path"])
        assert path.is_file(), fixture_id
        assert sha256_file(path) == entry["sha256"], fixture_id
        artifact = json.loads(
            (ARTIFACT_ROOT / "results" / "real_model_validation.json").read_text(
                encoding="utf-8"
            )
        )
        matches = [
            config
            for config in artifact["configs"]
            if f"{config['checkpoint']}_layer{config['layer_index']}" == fixture_id
        ]
        assert len(matches) == 1, fixture_id
        assert matches[0]["sae"]["decoder_ref"]["sha256"] == entry["sha256"]
