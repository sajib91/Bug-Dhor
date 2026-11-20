"""Build the committed decoder-column fixture bundle from real SAE checkpoints.

Run from the repository root after the full SAE checkpoints have been
provisioned under ``research/experiments/counterfactual_validation/artifacts``::

    .venv/bin/python research/experiments/counterfactual_validation/build_decoder_fixtures.py

The script does not train or invent values.  It extracts only the selected
decoder columns that the mathematical regression test needs, verifies the
source checkpoint SHA-256, and writes a versioned manifest.
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path

import numpy as np
import torch

from artifact_paths import (
    ARTIFACT_ROOT,
    FIXTURE_BUNDLE_ID,
    MANIFEST_PATH,
    artifact_path,
    checkpoint_reference,
    sha256_file,
    verify_checksum,
)

ARTIFACT_JSON = ARTIFACT_ROOT / "results" / "real_model_validation.json"


@contextmanager
def _legacy_modules():
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


def main() -> int:
    artifact = json.loads(ARTIFACT_JSON.read_text(encoding="utf-8"))
    fixtures = {}
    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        checkpoint = config["checkpoint"]
        layer_index = int(config["layer_index"])
        fixture_id = f"{checkpoint}_layer{layer_index}"
        features = [int(item["feature"]) for item in config["selected_features"]]
        sae = config["sae"]
        source_ref = checkpoint_reference(config)
        source_path = artifact_path(source_ref)
        source_sha256 = sae["checkpoint_sha256"]
        verify_checksum(source_path, source_sha256, label=f"source {fixture_id}")

        with _legacy_modules():
            payload = torch.load(source_path, map_location="cpu", weights_only=False)
        decoder = payload["state_dict"]["decoder.weight"].detach().cpu().numpy()
        if max(features) >= decoder.shape[1]:
            raise SystemExit(f"{fixture_id}: feature index outside decoder")
        columns = np.ascontiguousarray(decoder[:, features], dtype=np.float32)

        rel = f"decoder_fixtures/v1/{fixture_id}.npz"
        out_path = artifact_path(rel)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez(
            out_path,
            decoder_columns=columns,
            features=np.asarray(features, dtype=np.int64),
            checkpoint=np.asarray(checkpoint),
            layer_index=np.asarray(layer_index, dtype=np.int64),
            source_checkpoint=np.asarray(source_ref),
            source_sha256=np.asarray(source_sha256),
        )
        fixtures[fixture_id] = {
            "path": rel,
            "sha256": sha256_file(out_path),
            "source_checkpoint": source_ref,
            "source_sha256": source_sha256,
            "checkpoint": checkpoint,
            "layer": layer_index,
            "features": features,
        }
        print(f"{fixture_id}: {rel} sha256={fixtures[fixture_id]['sha256']}")

    manifest = {
        "schema_version": 1,
        "bundle_id": FIXTURE_BUNDLE_ID,
        "artifact_root": "research/experiments/counterfactual_validation",
        "description": (
            "Selected decoder columns extracted from the real SAE checkpoints "
            "used by real_model_validation.json. Not a re-trained or synthetic "
            "model artifact."
        ),
        "files": dict(sorted(fixtures.items())),
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    for config in artifact["configs"]:
        if config.get("status") == "error":
            continue
        fixture_id = f"{config['checkpoint']}_layer{config['layer_index']}"
        config["sae"]["decoder_ref"]["sha256"] = manifest["files"][fixture_id]["sha256"]
    ARTIFACT_JSON.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {MANIFEST_PATH}")
    print(f"updated {ARTIFACT_JSON} decoder_ref checksums")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
