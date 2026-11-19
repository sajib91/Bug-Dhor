"""Canonical path and patch handling for all engine file operations.

This module is the single boundary for patch validation and temporary patch
application. Absolute paths, traversal segments, Windows drive paths, and
symbolic links are rejected before any file is created or written. Every
candidate patch is applied only inside a freshly created temporary directory;
the caller's workspace is never modified by validation or verification.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath

from bugdhor.core.errors import SecurityAppError, ValidationAppError

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class UnsafePatchPathError(ValueError):
    """Raised when a patch targets a path outside its approved temporary root."""


def reject_absolute_file_path(value: str, field: str = "filePath") -> str:
    """Reject absolute or drive-qualified paths at the API boundary."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationAppError(f"{field} must be a non-empty string.")
    if "\x00" in value:
        raise ValidationAppError(f"{field} must not contain NUL bytes.")
    text = value.strip()
    if (
        PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or _DRIVE_RE.match(text)
    ):
        raise ValidationAppError(f"{field} must be relative to workspaceRoot.")
    parts = text.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValidationAppError(
            f"{field} must be a canonical relative path without traversal segments."
        )
    return "/".join(parts)


def canonical_relative_path(root: Path, value: str, *, must_exist: bool = False) -> Path:
    """Return a canonical relative path contained in ``root``.

    Existing symlink components are rejected even when they resolve back inside
    the root, because a snapshot may otherwise be redirected by a later change.
    """
    relative = Path(reject_absolute_file_path(value))
    resolved_root = root.resolve()
    candidate = (resolved_root / relative).resolve(strict=False)
    if candidate != resolved_root and not candidate.is_relative_to(resolved_root):
        raise SecurityAppError(
            "The requested path is outside the workspace root.",
            code="E_PATH_OUTSIDE_WORKSPACE",
        )
    if must_exist and not candidate.exists():
        raise ValidationAppError("The requested file does not exist.")
    current = resolved_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SecurityAppError(
                "Symbolic links are not allowed in validated paths.",
                code="E_PATH_OUTSIDE_WORKSPACE",
            )
    return relative


def normalize_patch(raw: str) -> str | None:
    """Extract a unified diff and normalize line endings."""
    if not isinstance(raw, str):
        return None
    text = raw.replace("\r\n", "\n").strip()
    fenced = re.fullmatch(r"```(?:diff)?\s*\n(.*?)\n```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    if "--- " not in text or "+++ " not in text or "@@ " not in text:
        return None
    lines = text.splitlines()
    start = next((idx for idx, line in enumerate(lines) if line.startswith("--- ")), None)
    if start is None or not any(line.startswith("+++ ") for line in lines[start:]):
        return None
    normalized = lines[start:]
    # Validate every target before the patch can be used by any caller.
    try:
        patch_paths("\n".join(normalized) + "\n")
    except UnsafePatchPathError:
        return None
    return "\n".join(normalized) + "\n"


def patch_paths(patch: str) -> tuple[str, ...]:
    """Return canonical, validated relative paths touched by ``patch``."""
    paths: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("+++ "):
            continue
        value = line[4:].split("\t", 1)[0].split(" ", 1)[0]
        value = value.removeprefix("b/")
        if value == "/dev/null":
            continue
        paths.append(str(reject_absolute_file_path(value, "patch target")))
    return tuple(dict.fromkeys(paths))


def validate_patch_scope(patch: str, allowed: Sequence[str] | set[str] | str) -> tuple[str, ...]:
    """Validate that a patch touches only the explicitly allowed relative paths."""
    touched = patch_paths(patch)
    expected = {allowed} if isinstance(allowed, str) else set(allowed)
    if not touched or len(touched) > len(expected) or not set(touched).issubset(expected):
        raise UnsafePatchPathError("patch touches an unexpected file or no file")
    return touched


def apply_patch_to_sources(sources: Mapping[str, str], patch: str) -> dict[str, str]:
    """Apply a unified diff to an in-memory mapping without touching disk."""
    touched = validate_patch_scope(patch, set(sources))
    result = dict(sources)
    lines = patch.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            index += 1
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            raise ValueError("malformed unified diff headers")
        path = str(
            reject_absolute_file_path(
                lines[index + 1][4:].split("\t", 1)[0].split(" ", 1)[0].removeprefix("b/"),
                "patch target",
            )
        )
        if path == "/dev/null":
            raise UnsafePatchPathError("file creation patches are not supported")
        if path not in touched:
            raise UnsafePatchPathError("patch target was not validated")
        original = result[path].splitlines()
        output: list[str] = []
        cursor = 0
        index += 2
        while index < len(lines) and lines[index].startswith("@@ "):
            match = _HUNK_RE.match(lines[index])
            if match is None:
                raise ValueError("malformed patch hunk")
            start = int(match.group(1)) - 1
            if start < 0:
                raise ValueError("invalid patch hunk start")
            output.extend(original[cursor:start])
            cursor = start
            index += 1
            while index < len(lines) and not lines[index].startswith(("@@ ", "--- ")):
                line = lines[index]
                if line.startswith(" "):
                    if cursor >= len(original) or original[cursor] != line[1:]:
                        raise ValueError("patch context does not match source")
                    output.append(original[cursor])
                    cursor += 1
                elif line.startswith("-"):
                    if cursor >= len(original) or original[cursor] != line[1:]:
                        raise ValueError("patch deletion does not match source")
                    cursor += 1
                elif line.startswith("+"):
                    output.append(line[1:])
                elif line != "\\ No newline at end of file":
                    raise ValueError("malformed patch line")
                index += 1
        output.extend(original[cursor:])
        result[path] = "\n".join(output) + ("\n" if output else "")
    return result


def apply_patch_in_temp(
    root: Path,
    relative_path: str,
    source_text: str,
    patch: str,
    *,
    repository_sources: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Write a source and its repository context into a temp tree, then patch it.

    All filesystem writes happen under a newly created temporary directory.
    Paths are validated before the first write, and the resulting tree is
    rechecked for containment before patched sources are returned.
    """
    canonical = canonical_relative_path(root, relative_path)
    sources: dict[str, str] = {str(canonical): source_text}
    for item in (repository_sources or {}).items():
        candidate = canonical_relative_path(root, str(item[0]))
        sources[str(candidate)] = str(item[1])
    validate_patch_scope(patch, set(sources))

    with tempfile.TemporaryDirectory(prefix="bugdhor-safe-patch-") as directory:
        temp_root = Path(directory).resolve()
        for relative, text in sources.items():
            destination = temp_root / relative
            if not destination.resolve().is_relative_to(temp_root):
                raise UnsafePatchPathError("patch target escapes the temporary root")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
        patched = apply_patch_to_sources(sources, patch)
        for relative in patched:
            destination = temp_root / relative
            if destination.is_symlink() or not destination.resolve().is_relative_to(temp_root):
                raise UnsafePatchPathError("patched file escapes the temporary root")
        return patched


def validate_patch_tree(root: Path, touched: Sequence[str]) -> bool:
    """Validate syntax for patched files after containment checks."""
    import ast

    from bugdhor.program_analysis.analysis import analyze_source

    for relative in touched:
        path = canonical_relative_path(root, str(relative), must_exist=True)
        full = root / path
        if full.is_symlink():
            return False
        try:
            text = full.read_text(encoding="utf-8")
        except OSError:
            return False
        if full.suffix == ".py":
            try:
                ast.parse(text)
            except SyntaxError:
                return False
        elif full.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                parsed = analyze_source(text, path=full, language_id="javascript")
            except (OSError, RuntimeError, TypeError, ValueError):
                return False
            if getattr(parsed.parsed, "has_syntax_errors", False):
                return False
    return True


def validate_patched_source(source: str, path: str) -> bool:
    """Validate syntax for a patched source without touching the filesystem."""
    import ast

    if path.endswith(".py"):
        try:
            ast.parse(source)
        except SyntaxError:
            return False
        return True
    if path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        from bugdhor.program_analysis.analysis import analyze_source

        try:
            parsed = analyze_source(source, path=path, language_id="javascript")
        except (OSError, RuntimeError, TypeError, ValueError):
            return False
        return not getattr(parsed.parsed, "has_syntax_errors", False)
    return True


def read_patch_tree(root: Path, relative: str) -> str:
    """Read one contained, non-symlink file from a temporary patch tree."""
    path = canonical_relative_path(root, relative, must_exist=True)
    full = root / path
    if full.is_symlink():
        raise UnsafePatchPathError("symbolic links are not allowed in patch trees")
    return full.read_text(encoding="utf-8")


__all__ = [
    "UnsafePatchPathError",
    "apply_patch_in_temp",
    "apply_patch_to_sources",
    "canonical_relative_path",
    "normalize_patch",
    "patch_paths",
    "read_patch_tree",
    "reject_absolute_file_path",
    "validate_patch_scope",
    "validate_patch_tree",
    "validate_patched_source",
]
