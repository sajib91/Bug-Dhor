"""Privacy-preserving result persistence.

Persisted artifacts contain metadata and hashes only by default. Source code,
prompts, patches, and tool output are never written unless an operator
explicitly opts into full-payload persistence (which is still redacted).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from bugdhor.core.redaction import redact_mapping

_SAFE_KEYS = frozenset(
    {
        "operation",
        "status",
        "apiVersion",
        "requestId",
        "jobId",
        "findingId",
        "repairId",
        "workflowId",
        "cwe",
        "stage",
        "name",
        "reasonCode",
        "classification",
        "verdict",
        "analysisAvailable",
        "verified",
        "requiresApproval",
        "executed",
        "syntaxValid",
        "framework",
        "passed",
        "failed",
        "errors",
        "skipped",
        "total",
        "passRate",
        "durationSeconds",
        "size",
        "createdAt",
        "updatedAt",
        "recordedAt",
        "timestamp",
        "backedn",
        "backend",
        "_kind",
        "language_id",
        "parsed_ok",
    }
)
_HASH_SUFFIXES = ("sha256", "hash")


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sanitize_for_persistence(payload: Any, *, full_payloads: bool = False) -> Any:
    """Reduce a response payload to metadata and hashes."""
    if isinstance(payload, Mapping):
        result: dict[str, Any] = {}
        for key, value in payload.items():
            name = str(key)
            lowered = name.lower()
            if name in _SAFE_KEYS or lowered.endswith(_HASH_SUFFIXES):
                if isinstance(value, (str, int, float, bool)) or value is None:
                    result[name] = value
                else:
                    result[name] = sanitize_for_persistence(value, full_payloads=full_payloads)
            elif lowered in {
                "sourcetext",
                "sourcecode",
                "originalcode",
                "repairedcode",
                "patchedsource",
                "text",
                "prompt",
            } and isinstance(value, str):
                result[f"{name}Sha256"] = _hash_text(value)
            elif isinstance(value, (dict, list, tuple)):
                nested = sanitize_for_persistence(value, full_payloads=full_payloads)
                if nested not in (None, {}, []):
                    result[name] = nested
        return result
    if isinstance(payload, (list, tuple)):
        values = [sanitize_for_persistence(item, full_payloads=full_payloads) for item in payload]
        return [item for item in values if item not in (None, {}, [])]
    if isinstance(payload, str):
        if full_payloads:
            return redact_mapping(payload)
        return None
    if isinstance(payload, (int, float, bool)) or payload is None:
        return payload
    return None


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass


def prune_artifacts(directory: Path, *, retention_days: int) -> None:
    """Delete persisted artifacts older than the configured retention window."""
    if retention_days <= 0:
        return
    cutoff = time.time() - retention_days * 86_400
    try:
        for entry in directory.iterdir():
            if not entry.is_file():
                continue
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
            except OSError:
                continue
    except OSError:
        return


def write_json_private(path: Path, payload: Any, *, retention_days: int = 0) -> None:
    """Atomically write JSON with 0700 directories and a 0600 file."""
    _ensure_private_directory(path.parent)
    prune_artifacts(path.parent, retention_days=retention_days)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


__all__ = ["prune_artifacts", "sanitize_for_persistence", "write_json_private"]
