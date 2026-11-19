"""Central redaction helpers for errors, logs, and persisted artifacts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MAX_REDACTED_LENGTH = 2_000

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|credential)(\s*[:=]\s*)([^\s,;'\"}]+)"
    ),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)(Authorization\s*[:=]\s*)([^\s,;]+)"),
)
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "credentials",
        "hf_token",
        "password",
        "passwd",
        "secret",
        "token",
    }
)


def redact_text(value: Any, *, limit: int = MAX_REDACTED_LENGTH) -> str:
    """Return a bounded string with common secret values replaced."""
    if value is None:
        return ""
    text = str(value)
    text = "".join(char if char >= " " or char == "\n" else " " for char in text)
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    if len(text) > limit:
        return text[:limit] + "...[TRUNCATED]"
    return text


def redact_mapping(value: Any) -> Any:
    """Recursively redact secret-bearing mapping keys."""
    if isinstance(value, Mapping):
        return {
            key: "[REDACTED]" if str(key).lower() in _SENSITIVE_KEYS else redact_mapping(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_mapping(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


__all__ = ["redact_mapping", "redact_text"]
