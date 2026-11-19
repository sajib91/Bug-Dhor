"""Minimal patch previews, unified diffs, and freshness checks.

This module never modifies files. It creates reviewable patch objects and
checks that the file still matches the source bytes and span used to build the
patch. Applying and reverting are implemented separately in :mod:`.history`.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .recommendation import RepairRecommendation, RepairStatus

PATCH_SCHEMA_VERSION = "1.0"

_PATCH_KEYS = frozenset(
    {
        "schema_version",
        "patch_id",
        "finding_id",
        "rule_id",
        "strategy",
        "file",
        "source_size",
        "source_sha256",
        "edits",
        "unified_diff",
        "requires_approval",
    }
)
_EDIT_KEYS = frozenset(
    {
        "file",
        "language",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "original_code",
        "proposed_code",
    }
)
_OVERLAP_KEYS = frozenset(
    {
        "left_patch_id",
        "right_patch_id",
        "file",
        "left_span",
        "right_span",
    }
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PatchError(Exception):
    """Base class for patch model errors."""


class PatchValidationError(PatchError):
    """Raised when a patch or its inputs are invalid."""


class PatchStaleError(PatchError):
    """Raised when source content no longer matches a patch."""


class PatchConflictError(PatchError):
    """Raised when patches target overlapping source spans."""


class PatchApprovalError(PatchError):
    """Raised when explicit approval is absent."""


class PatchFreshness(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


def _check_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    keys = set(value)
    expected_set = set(expected)
    missing = sorted(expected_set - keys)
    unknown = sorted(keys - expected_set)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ValueError(f"{label} has invalid keys ({', '.join(details)})")


def _as_str(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} must not be empty")
    return value


def _as_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def sha256_text(text: str) -> str:
    """Return the SHA-256 of the UTF-8 bytes represented by ``text``."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def source_size(text: str) -> int:
    """Return the byte length of ``text`` as UTF-8."""

    return len(text.encode("utf-8"))


def read_source_file(file: str | Path) -> str:
    """Read a UTF-8 source file as text without translating newlines."""

    path = Path(file)
    if not path.is_file():
        raise PatchValidationError(f"Source file does not exist: {path}")
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PatchValidationError(
            f"Source file is not valid UTF-8: {path}"
        ) from error


def _line_offsets(source_code: str) -> list[int]:
    offsets = [0]
    for line in source_code.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line.encode("utf-8")))
    return offsets


def _byte_bounds(source_code: str, edit: PatchEdit) -> tuple[int, int]:
    offsets = _line_offsets(source_code)
    line_count = len(offsets) - 1
    if edit.start_line < 1 or edit.end_line > line_count:
        raise PatchStaleError("Patch span is outside the current source lines.")
    if edit.end_line < edit.start_line:
        raise PatchStaleError("Patch span has an invalid line order.")
    if edit.start_column < 1 or edit.end_column < edit.start_column:
        raise PatchStaleError("Patch span has an invalid column order.")

    raw = source_code.encode("utf-8")
    start = offsets[edit.start_line - 1] + edit.start_column - 1
    end = offsets[edit.end_line - 1] + edit.end_column - 1
    if start < 0 or end > len(raw) or start > end:
        raise PatchStaleError("Patch span is outside the current source bytes.")
    return start, end


def _decode_span(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PatchStaleError("Patch span is not valid UTF-8.") from error


def extract_span_text(source_code: str, edit: PatchEdit) -> str:
    """Return the exact source text covered by a patch edit."""

    start, end = _byte_bounds(source_code, edit)
    return _decode_span(source_code.encode("utf-8")[start:end])


def _match_newlines(text: str, source_code: str) -> str:
    if "\r\n" in source_code:
        return text.replace("\r\n", "\n").replace("\n", "\r\n")
    if "\r" in source_code and "\n" not in source_code:
        return text.replace("\r\n", "\n").replace("\n", "\r")
    return text


def replace_span_text(
    source_code: str, edit: PatchEdit, replacement: str
) -> str:
    """Return source text with one edit span replaced."""

    start, end = _byte_bounds(source_code, edit)
    raw = source_code.encode("utf-8")
    new_bytes = _match_newlines(replacement, source_code).encode("utf-8")
    return (raw[:start] + new_bytes + raw[end:]).decode("utf-8")


@dataclass(frozen=True)
class PatchEdit:
    """One exact source replacement with one-based coordinates."""

    file: str
    language: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    original_code: str
    proposed_code: str

    def __post_init__(self) -> None:
        _as_str(self.file, "edit.file", allow_empty=True)
        _as_str(self.language, "edit.language")
        for name in (
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        ):
            _as_int(getattr(self, name), f"edit.{name}", minimum=1)
        _as_str(self.original_code, "edit.original_code")
        _as_str(self.proposed_code, "edit.proposed_code")
        if self.original_code == self.proposed_code:
            raise ValueError("edit.original_code and edit.proposed_code must differ")

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "original_code": self.original_code,
            "proposed_code": self.proposed_code,
        }

    @classmethod
    def from_dict(cls, value: Any) -> PatchEdit:
        value = _as_mapping(value, "patch edit")
        _check_keys(value, _EDIT_KEYS, "patch edit")
        return cls(**dict(value))


@dataclass(frozen=True)
class Patch:
    """A reviewable patch bound to exact source bytes."""

    patch_id: str
    finding_id: str
    rule_id: str
    strategy: str
    file: str
    source_size: int
    source_sha256: str
    edits: tuple[PatchEdit, ...]
    unified_diff: str
    requires_approval: bool = True

    def __post_init__(self) -> None:
        for name in ("patch_id", "finding_id", "rule_id", "strategy", "file"):
            _as_str(getattr(self, name), f"patch.{name}")
        _as_int(self.source_size, "patch.source_size")
        if not isinstance(self.source_sha256, str) or not _SHA256_PATTERN.match(
            self.source_sha256
        ):
            raise ValueError("patch.source_sha256 must be a lowercase SHA-256 digest")
        if not self.edits:
            raise ValueError("patch.edits must not be empty")
        for edit in self.edits:
            if not isinstance(edit, PatchEdit):
                raise TypeError("patch.edits must contain PatchEdit values")
            if edit.file != self.file:
                raise ValueError("every patch edit must target patch.file")
        _as_str(self.unified_diff, "patch.unified_diff")
        if not isinstance(self.requires_approval, bool):
            raise TypeError("patch.requires_approval must be a boolean")
        if self.requires_approval is not True:
            raise ValueError("patch.requires_approval must always be true")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PATCH_SCHEMA_VERSION,
            "patch_id": self.patch_id,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "strategy": self.strategy,
            "file": self.file,
            "source_size": self.source_size,
            "source_sha256": self.source_sha256,
            "edits": [edit.to_dict() for edit in self.edits],
            "unified_diff": self.unified_diff,
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, value: Any) -> Patch:
        value = _as_mapping(value, "patch")
        validate_patch(value)
        return cls(
            patch_id=value["patch_id"],
            finding_id=value["finding_id"],
            rule_id=value["rule_id"],
            strategy=value["strategy"],
            file=value["file"],
            source_size=value["source_size"],
            source_sha256=value["source_sha256"],
            edits=tuple(PatchEdit.from_dict(item) for item in value["edits"]),
            unified_diff=value["unified_diff"],
            requires_approval=value["requires_approval"],
        )


def validate_patch(value: Any) -> None:
    """Validate a serialized patch and raise on errors."""

    value = _as_mapping(value, "patch")
    _check_keys(value, _PATCH_KEYS, "patch")
    if value["schema_version"] != PATCH_SCHEMA_VERSION:
        raise ValueError(f"patch.schema_version must be {PATCH_SCHEMA_VERSION}")
    for name in ("patch_id", "finding_id", "rule_id", "strategy", "file"):
        _as_str(value[name], f"patch.{name}")
    _as_int(value["source_size"], "patch.source_size")
    if not isinstance(value["source_sha256"], str) or not _SHA256_PATTERN.match(
        value["source_sha256"]
    ):
        raise ValueError("patch.source_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(value["edits"], (list, tuple)) or not value["edits"]:
        raise ValueError("patch.edits must be a non-empty list")
    for index, item in enumerate(value["edits"]):
        edit = PatchEdit.from_dict(item)
        if edit.file != value["file"]:
            raise ValueError("every patch edit must target patch.file")
    _as_str(value["unified_diff"], "patch.unified_diff")
    if not isinstance(value["requires_approval"], bool):
        raise TypeError("patch.requires_approval must be a boolean")
    if value["requires_approval"] is not True:
        raise ValueError("patch.requires_approval must always be true")


def _build_diff(file: str, original: str, modified: str) -> str:
    lines = list(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile=f"a/{file}",
            tofile=f"b/{file}",
            n=3,
            lineterm="",
        )
    )
    return "\n".join(lines)


def _patch_id(payload: Mapping[str, Any]) -> str:
    import json

    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return f"patch:{hashlib.sha256(encoded).hexdigest()[:12]}"


def build_patch(
    recommendation: RepairRecommendation,
    source_code: str = "",
    *,
    file: str | None = None,
) -> Patch:
    """Build a patch for a ready recommendation without changing any file."""

    if recommendation.status is not RepairStatus.READY:
        raise PatchValidationError(
            "Only ready repair recommendations can produce patches."
        )
    target_file = file or recommendation.target.file
    if not target_file or target_file == "<source>":
        raise PatchValidationError(
            "A concrete file path is required to build an applicable patch."
        )
    if not isinstance(source_code, str):
        raise TypeError("source_code must be a string")
    if not source_code:
        source_code = read_source_file(target_file)

    edit = PatchEdit(
        file=target_file,
        language=recommendation.target.language,
        start_line=recommendation.target.start_line,
        start_column=recommendation.target.start_column,
        end_line=recommendation.target.end_line,
        end_column=recommendation.target.end_column,
        original_code=recommendation.original_code or "",
        proposed_code=recommendation.proposed_code or "",
    )
    actual_original = extract_span_text(source_code, edit)
    if actual_original != edit.original_code:
        raise PatchStaleError(
            "The recommendation no longer matches the supplied source span."
        )
    modified = replace_span_text(source_code, edit, edit.proposed_code)
    diff = _build_diff(target_file, source_code, modified)
    if not diff:
        raise PatchValidationError("The recommendation produced no source diff.")

    digest = sha256_text(source_code)
    identity = {
        "file": target_file,
        "source_sha256": digest,
        "source_size": source_size(source_code),
        "edits": [edit.to_dict()],
        "unified_diff": diff,
    }
    return Patch(
        patch_id=_patch_id(identity),
        finding_id=recommendation.finding_id,
        rule_id=recommendation.rule_id,
        strategy=recommendation.strategy,
        file=target_file,
        source_size=identity["source_size"],
        source_sha256=digest,
        edits=(edit,),
        unified_diff=diff,
        requires_approval=True,
    )


@dataclass(frozen=True)
class PatchFreshnessResult:
    """Result of checking a patch against current source bytes."""

    status: PatchFreshness
    reason: str
    current_size: int | None = None
    current_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "current_size": self.current_size,
            "current_sha256": self.current_sha256,
        }


def check_patch_freshness(
    patch: Patch, source_code: str | None = None
) -> PatchFreshnessResult:
    """Check file identity, byte hash, and exact edited span."""

    if source_code is None:
        try:
            source_code = read_source_file(patch.file)
        except PatchValidationError as error:
            return PatchFreshnessResult(
                status=PatchFreshness.UNAVAILABLE,
                reason=str(error),
            )
    current_size = source_size(source_code)
    current_hash = sha256_text(source_code)
    if current_size != patch.source_size or current_hash != patch.source_sha256:
        return PatchFreshnessResult(
            status=PatchFreshness.STALE,
            reason="The current source bytes differ from the patch source.",
            current_size=current_size,
            current_sha256=current_hash,
        )
    for edit in patch.edits:
        try:
            actual = extract_span_text(source_code, edit)
        except PatchStaleError as error:
            return PatchFreshnessResult(
                status=PatchFreshness.STALE,
                reason=str(error),
                current_size=current_size,
                current_sha256=current_hash,
            )
        if actual != edit.original_code:
            return PatchFreshnessResult(
                status=PatchFreshness.STALE,
                reason="The current source span differs from the patch span.",
                current_size=current_size,
                current_sha256=current_hash,
            )
    return PatchFreshnessResult(
        status=PatchFreshness.FRESH,
        reason="Source bytes and exact edited span match the patch.",
        current_size=current_size,
        current_sha256=current_hash,
    )


@dataclass(frozen=True)
class PatchOverlap:
    """Two patches that target overlapping one-based spans."""

    left_patch_id: str
    right_patch_id: str
    file: str
    left_span: tuple[int, int, int, int]
    right_span: tuple[int, int, int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_patch_id": self.left_patch_id,
            "right_patch_id": self.right_patch_id,
            "file": self.file,
            "left_span": list(self.left_span),
            "right_span": list(self.right_span),
        }


def _spans_overlap(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> bool:
    left_start = (left[0], left[1])
    left_end = (left[2], left[3])
    right_start = (right[0], right[1])
    right_end = (right[2], right[3])
    return left_start < right_end and right_start < left_end


def find_overlaps(patches: Iterable[Patch]) -> tuple[PatchOverlap, ...]:
    """Return all overlapping patch pairs without modifying anything."""

    values = list(patches)
    overlaps: list[PatchOverlap] = []
    for left_index, left in enumerate(values):
        for right in values[left_index + 1 :]:
            for left_edit in left.edits:
                for right_edit in right.edits:
                    if left_edit.file != right_edit.file:
                        continue
                    left_span = (
                        left_edit.start_line,
                        left_edit.start_column,
                        left_edit.end_line,
                        left_edit.end_column,
                    )
                    right_span = (
                        right_edit.start_line,
                        right_edit.start_column,
                        right_edit.end_line,
                        right_edit.end_column,
                    )
                    if _spans_overlap(left_span, right_span):
                        overlaps.append(
                            PatchOverlap(
                                left_patch_id=left.patch_id,
                                right_patch_id=right.patch_id,
                                file=left_edit.file,
                                left_span=left_span,
                                right_span=right_span,
                            )
                        )
    return tuple(overlaps)


def validate_patch_set(patches: Iterable[Patch]) -> None:
    """Raise when any two patches target overlapping source spans."""

    overlaps = find_overlaps(patches)
    if overlaps:
        raise PatchConflictError(
            "Overlapping patches were detected: "
            + ", ".join(
                f"{item.left_patch_id} vs {item.right_patch_id}"
                for item in overlaps
            )
        )


__all__ = [
    "PATCH_SCHEMA_VERSION",
    "Patch",
    "PatchApprovalError",
    "PatchConflictError",
    "PatchEdit",
    "PatchError",
    "PatchFreshness",
    "PatchFreshnessResult",
    "PatchOverlap",
    "PatchStaleError",
    "PatchValidationError",
    "build_patch",
    "check_patch_freshness",
    "extract_span_text",
    "find_overlaps",
    "read_source_file",
    "replace_span_text",
    "sha256_text",
    "source_size",
    "validate_patch",
    "validate_patch_set",
]
