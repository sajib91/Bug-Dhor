"""Portable references for counterfactual-validation artifacts.

All paths recorded in ``real_model_validation.json`` are POSIX-style and
relative to :data:`ARTIFACT_ROOT`.  This module is the single place that turns
those references into filesystem paths, and it refuses to resolve outside the
documented root.

The committed ``decoder_fixtures/v1`` bundle contains the selected decoder
columns extracted from the original SAE checkpoints.  It lets the mathematical
regression suite recompute the saved cosine values on any OS without shipping
~100 MiB of full checkpoints.  Full checkpoints remain supported by an
explicitly provisioned integration test.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

ARTIFACT_ROOT = Path(__file__).resolve().parent
FIXTURE_BUNDLE_ID = "counterfactual-decoder-cosines-v1"
MANIFEST_PATH = ARTIFACT_ROOT / "decoder_fixtures" / "v1" / "manifest.json"


class ArtifactPathError(ValueError):
    """Raised when an artifact reference is unsafe, missing, or unverifiable."""


def normalize_relative_ref(value: str | Path) -> str:
    """Normalize an artifact reference to a safe POSIX relative string."""

    text = str(value).replace("\\", "/").strip()
    if not text:
        raise ArtifactPathError("empty artifact reference")
    if text.startswith("/") or text.startswith("//"):
        raise ArtifactPathError(f"absolute artifact reference is not allowed: {text!r}")
    if len(text) >= 2 and text[1] == ":":
        raise ArtifactPathError(f"drive-qualified artifact reference is not allowed: {text!r}")

    pure = PurePosixPath(text)
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ArtifactPathError(f"unsafe artifact reference {text!r}: '.'/'..' segments are not allowed")
    return pure.as_posix()


def resolve_under_root(root: Path, reference: str | Path) -> Path:
    """Resolve *reference* under *root* and enforce containment."""

    relative = normalize_relative_ref(reference)
    base = root.resolve()
    candidate = (base / relative).resolve()
    if not candidate.is_relative_to(base):
        raise ArtifactPathError(f"artifact reference escapes root: {relative!r}")
    return candidate


def artifact_path(reference: str | Path) -> Path:
    """Resolve a repository-document-root-relative artifact reference."""

    return resolve_under_root(ARTIFACT_ROOT, reference)


def legacy_checkpoint_reference(saved: str | Path) -> str:
    """Map an old absolute checkpoint path to a safe relative reference.

    Old JSON stored absolute developer paths.  Only the basename is honored,
    and it must still resolve inside ``artifacts/`` and match the manifest
    checksum before use.
    """

    text = str(saved).replace("\\", "/")
    name = PurePosixPath(text).name
    if not name or name in {".", ".."} or not name.endswith(".pt"):
        raise ArtifactPathError(f"invalid legacy checkpoint reference: {saved!r}")
    return normalize_relative_ref(Path("artifacts") / name)


def checkpoint_reference(config: dict) -> str:
    """Return the safe relative checkpoint reference for a config.

    New artifacts store a relative reference.  Legacy artifacts stored an
    absolute developer path; only its basename is honored, and the resulting
    reference must still resolve inside ``artifacts/``.
    """

    sae = config.get("sae") or {}
    saved = sae.get("checkpoint")
    if not saved:
        raise ArtifactPathError("config has no sae.checkpoint reference")
    text = str(saved).replace("\\", "/")
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
        return legacy_checkpoint_reference(text)
    return normalize_relative_ref(text)


def sha256_file(path: Path) -> str:
    """Stream a SHA-256 digest for *path*."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected_sha256: str, *, label: str) -> None:
    """Fail clearly when *path* is missing or its digest does not match."""

    if not path.is_file():
        raise ArtifactPathError(f"missing {label}: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ArtifactPathError(
            f"checksum mismatch for {label}: {path}\n"
            f"  expected: {expected_sha256}\n"
            f"  actual:   {actual}"
        )


def load_manifest() -> dict:
    """Load and validate the committed decoder-fixture manifest."""

    if not MANIFEST_PATH.is_file():
        raise ArtifactPathError(f"missing fixture manifest: {MANIFEST_PATH}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ArtifactPathError(
            f"unsupported fixture manifest schema: {manifest.get('schema_version')!r}"
        )
    if manifest.get("bundle_id") != FIXTURE_BUNDLE_ID:
        raise ArtifactPathError(f"unexpected fixture bundle id: {manifest.get('bundle_id')!r}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ArtifactPathError("fixture manifest has no files")
    return manifest


def decoder_fixture_entry(checkpoint: str, layer_index: int) -> tuple[str, dict]:
    """Return ``(id, entry)`` for one checkpoint/layer fixture."""

    fixture_id = f"{checkpoint}_layer{layer_index}"
    manifest = load_manifest()
    entry = manifest["files"].get(fixture_id)
    if entry is None:
        raise ArtifactPathError(f"missing decoder fixture entry: {fixture_id}")
    return fixture_id, entry
