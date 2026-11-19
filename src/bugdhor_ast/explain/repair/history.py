"""Explicit apply and revert workflow with bounded patch history.

Applying or reverting requires an explicit approval object whose confirmation
must equal the reviewed patch identifier. File content is verified before any
write, and revert refuses to overwrite a file that changed after apply.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .patch import (
    Patch,
    PatchApprovalError,
    PatchFreshness,
    PatchFreshnessResult,
    PatchStaleError,
    check_patch_freshness,
    extract_span_text,
    read_source_file,
    replace_span_text,
    sha256_text,
    source_size,
)

HISTORY_SCHEMA_VERSION = "1.0"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_ENTRY_KEYS = frozenset(
    {
        "entry_id",
        "patch_id",
        "finding_id",
        "file",
        "applied_at",
        "backup_code",
        "backup_size",
        "backup_sha256",
        "applied_code",
        "applied_size",
        "applied_sha256",
        "reverted_at",
    }
)
_HISTORY_KEYS = frozenset({"schema_version", "entries"})


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


def _as_str(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} must not be empty")
    return value


def _as_optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _as_str(value, label, allow_empty=False)


def _as_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _as_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.match(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class PatchApproval:
    """Explicit developer approval for one patch identifier."""

    approved: bool
    confirmation: str
    actor: str = "developer"

    def validate(self, patch_id: str) -> None:
        """Raise unless this approval matches the reviewed patch."""

        if self.approved is not True:
            raise PatchApprovalError(
                "Explicit approval is required before any source write."
            )
        if self.confirmation != patch_id:
            raise PatchApprovalError(
                "Approval confirmation must equal the reviewed patch_id."
            )
        _as_str(self.actor, "approval.actor")


@dataclass(frozen=True)
class PatchHistoryEntry:
    """Exact source snapshots needed to verify and revert one apply."""

    entry_id: str
    patch_id: str
    finding_id: str
    file: str
    applied_at: str
    backup_code: str
    backup_size: int
    backup_sha256: str
    applied_code: str
    applied_size: int
    applied_sha256: str
    reverted_at: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "entry_id",
            "patch_id",
            "finding_id",
            "file",
            "applied_at",
            "backup_code",
            "applied_code",
        ):
            _as_str(getattr(self, name), f"history_entry.{name}")
        _as_int(self.backup_size, "history_entry.backup_size")
        _as_int(self.applied_size, "history_entry.applied_size")
        _as_digest(self.backup_sha256, "history_entry.backup_sha256")
        _as_digest(self.applied_sha256, "history_entry.applied_sha256")
        _as_optional_str(self.reverted_at, "history_entry.reverted_at")
        if source_size(self.backup_code) != self.backup_size:
            raise ValueError("history_entry.backup_size does not match backup_code")
        if sha256_text(self.backup_code) != self.backup_sha256:
            raise ValueError("history_entry.backup_sha256 does not match backup_code")
        if source_size(self.applied_code) != self.applied_size:
            raise ValueError("history_entry.applied_size does not match applied_code")
        if sha256_text(self.applied_code) != self.applied_sha256:
            raise ValueError("history_entry.applied_sha256 does not match applied_code")

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "patch_id": self.patch_id,
            "finding_id": self.finding_id,
            "file": self.file,
            "applied_at": self.applied_at,
            "backup_code": self.backup_code,
            "backup_size": self.backup_size,
            "backup_sha256": self.backup_sha256,
            "applied_code": self.applied_code,
            "applied_size": self.applied_size,
            "applied_sha256": self.applied_sha256,
            "reverted_at": self.reverted_at,
        }

    @classmethod
    def from_dict(cls, value: Any) -> PatchHistoryEntry:
        value = _as_mapping(value, "history entry")
        if set(value) != _ENTRY_KEYS:
            raise ValueError("history entry has invalid keys")
        return cls(**dict(value))


@dataclass
class PatchHistory:
    """In-memory history of applied patches for one workflow session."""

    entries: list[PatchHistoryEntry] = field(default_factory=list)

    def add(self, entry: PatchHistoryEntry) -> None:
        """Append an entry, rejecting duplicate entry identifiers."""

        if any(item.entry_id == entry.entry_id for item in self.entries):
            raise ValueError(f"Duplicate history entry: {entry.entry_id}")
        self.entries.append(entry)

    def get(self, entry_id: str) -> PatchHistoryEntry | None:
        return next(
            (item for item in self.entries if item.entry_id == entry_id),
            None,
        )

    def find_by_patch(self, patch_id: str) -> tuple[PatchHistoryEntry, ...]:
        return tuple(item for item in self.entries if item.patch_id == patch_id)

    def mark_reverted(self, entry_id: str, timestamp: str) -> PatchHistoryEntry:
        """Mark an entry as reverted and return the updated entry."""

        for index, entry in enumerate(self.entries):
            if entry.entry_id != entry_id:
                continue
            if entry.reverted_at is not None:
                raise PatchStaleError(f"History entry is already reverted: {entry_id}")
            updated = replace(entry, reverted_at=timestamp)
            self.entries[index] = updated
            return updated
        raise ValueError(f"Unknown history entry: {entry_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "entries": [item.to_dict() for item in self.entries],
        }

    @classmethod
    def from_dict(cls, value: Any) -> PatchHistory:
        value = _as_mapping(value, "patch history")
        if set(value) != _HISTORY_KEYS:
            raise ValueError("patch history has invalid keys")
        if value["schema_version"] != HISTORY_SCHEMA_VERSION:
            raise ValueError(
                f"patch history.schema_version must be {HISTORY_SCHEMA_VERSION}"
            )
        if not isinstance(value["entries"], (list, tuple)):
            raise TypeError("patch history.entries must be a list")
        history = cls()
        for item in value["entries"]:
            history.add(PatchHistoryEntry.from_dict(item))
        return history


@dataclass(frozen=True)
class PatchApplyResult:
    """Result of an approved apply operation."""

    patch_id: str
    file: str
    entry: PatchHistoryEntry
    freshness: PatchFreshnessResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "file": self.file,
            "entry": self.entry.to_dict(),
            "freshness": self.freshness.to_dict(),
        }


@dataclass(frozen=True)
class PatchRevertResult:
    """Result of an approved revert operation."""

    entry_id: str
    patch_id: str
    file: str
    restored_size: int
    restored_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "patch_id": self.patch_id,
            "file": self.file,
            "restored_size": self.restored_size,
            "restored_sha256": self.restored_sha256,
        }


def _next_entry_id(history: PatchHistory, patch_id: str) -> str:
    return f"history:{len(history.entries) + 1}:{patch_id.replace(':', '-')}"


def apply_patch(
    patch: Patch,
    approval: PatchApproval,
    *,
    history: PatchHistory,
) -> PatchApplyResult:
    """Apply a fresh patch after explicit approval and record exact history."""

    approval.validate(patch.patch_id)
    backup_code = read_source_file(patch.file)
    freshness = check_patch_freshness(patch, backup_code)
    if freshness.status is not PatchFreshness.FRESH:
        raise PatchStaleError(
            f"Patch is not fresh: {freshness.reason}"
        )

    modified = backup_code
    ordered = sorted(
        patch.edits,
        key=lambda item: (item.start_line, item.start_column),
        reverse=True,
    )
    for edit in ordered:
        if extract_span_text(modified, edit) != edit.original_code:
            raise PatchStaleError(
                "A patch edit no longer matches the source during application."
            )
        modified = replace_span_text(modified, edit, edit.proposed_code)

    path = Path(patch.file)
    path.write_bytes(modified.encode("utf-8"))

    entry = PatchHistoryEntry(
        entry_id=_next_entry_id(history, patch.patch_id),
        patch_id=patch.patch_id,
        finding_id=patch.finding_id,
        file=patch.file,
        applied_at=_utc_now(),
        backup_code=backup_code,
        backup_size=source_size(backup_code),
        backup_sha256=sha256_text(backup_code),
        applied_code=modified,
        applied_size=source_size(modified),
        applied_sha256=sha256_text(modified),
    )
    history.add(entry)
    return PatchApplyResult(
        patch_id=patch.patch_id,
        file=patch.file,
        entry=entry,
        freshness=freshness,
    )


def revert_patch(
    entry: PatchHistoryEntry,
    approval: PatchApproval,
    *,
    history: PatchHistory,
) -> PatchRevertResult:
    """Restore the exact pre-apply bytes for one recorded patch."""

    approval.validate(entry.patch_id)
    if entry.reverted_at is not None:
        raise PatchStaleError(f"History entry is already reverted: {entry.entry_id}")
    current_code = read_source_file(entry.file)
    current_size = source_size(current_code)
    current_hash = sha256_text(current_code)
    if current_size != entry.applied_size or current_hash != entry.applied_sha256:
        raise PatchStaleError(
            "The file changed after apply; revert refused to overwrite it."
        )
    if source_size(entry.backup_code) != entry.backup_size:
        raise PatchStaleError("Stored backup size does not match backup content.")
    if sha256_text(entry.backup_code) != entry.backup_sha256:
        raise PatchStaleError("Stored backup hash does not match backup content.")

    Path(entry.file).write_bytes(entry.backup_code.encode("utf-8"))
    updated = history.mark_reverted(entry.entry_id, _utc_now())
    return PatchRevertResult(
        entry_id=updated.entry_id,
        patch_id=updated.patch_id,
        file=updated.file,
        restored_size=entry.backup_size,
        restored_sha256=entry.backup_sha256,
    )


__all__ = [
    "HISTORY_SCHEMA_VERSION",
    "PatchApplyResult",
    "PatchApproval",
    "PatchHistory",
    "PatchHistoryEntry",
    "PatchRevertResult",
    "apply_patch",
    "revert_patch",
]
