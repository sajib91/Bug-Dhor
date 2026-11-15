"""CWE extraction and conservative, evidence-backed rule mappings.

Tool output is the primary source of CWE evidence. A fallback mapping is used
only when a tool supplies a stable rule identifier and no CWE metadata. Unknown
rules remain unmapped rather than being assigned a plausible-looking weakness.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_CWE_RE = re.compile(r"(?i)\bcwe[\s_:/#-]*0*([1-9][0-9]*)\b")
_DIGITS_RE = re.compile(r"^0*([1-9][0-9]*)$")

# Bandit test ID -> CWE. Only stable, documented rule-to-weakness pairs are
# included. Ambiguous tests are intentionally absent so that ``cwe`` stays
# ``None`` instead of being guessed.
BANDIT_CWE_MAP: dict[str, str] = {
    "B101": "CWE-703",
    "B102": "CWE-94",
    "B103": "CWE-732",
    "B104": "CWE-605",
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-377",
    "B110": "CWE-703",
    "B112": "CWE-703",
    "B201": "CWE-94",
    "B202": "CWE-1336",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-95",
    "B308": "CWE-79",
    "B310": "CWE-918",
    "B311": "CWE-330",
    "B312": "CWE-319",
    "B313": "CWE-611",
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-319",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B325": "CWE-377",
    "B401": "CWE-502",
    "B402": "CWE-319",
    "B403": "CWE-502",
    "B404": "CWE-78",
    "B405": "CWE-611",
    "B406": "CWE-611",
    "B407": "CWE-611",
    "B408": "CWE-611",
    "B409": "CWE-611",
    "B410": "CWE-611",
    "B411": "CWE-502",
    "B412": "CWE-20",
    "B413": "CWE-327",
    "B501": "CWE-295",
    "B502": "CWE-327",
    "B503": "CWE-327",
    "B504": "CWE-327",
    "B505": "CWE-326",
    "B506": "CWE-502",
    "B507": "CWE-295",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-78",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B613": "CWE-506",
    "B701": "CWE-79",
    "B702": "CWE-79",
    "B703": "CWE-79",
}


def normalize_cwe(value: Any) -> str | None:
    """Return one canonical ``CWE-<n>`` identifier, or ``None``."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        match = _CWE_RE.search(text) or _DIGITS_RE.match(text)
        if match is None:
            return None
        number = int(match.group(1))
        return f"CWE-{number}" if number > 0 else None
    return None


def extract_cwes(value: Any) -> tuple[str, ...]:
    """Extract every CWE identifier from a scalar or nested collection.

    Tool metadata frequently stores CWE values as a list of strings such as
    ``["CWE-79: Improper Neutralization..."]`` or as integer identifiers. The
    order of first appearance is retained and duplicates are removed.
    """
    found: list[str] = []

    def visit(item: Any) -> None:
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                visit(child)
            return
        if isinstance(item, dict):
            for key in ("cwe", "cwes", "id"):
                if key in item:
                    visit(item[key])
            return
        normalized = normalize_cwe(item)
        if normalized is not None and normalized not in found:
            found.append(normalized)

    visit(value)
    return tuple(found)


def bandit_cwes(test_id: str | None, *metadata: Any) -> tuple[str, ...]:
    """Prefer explicit Bandit CWE metadata, then the curated rule map."""
    explicit = extract_cwes(metadata)
    if explicit:
        return explicit
    if test_id:
        mapped = BANDIT_CWE_MAP.get(test_id.upper())
        if mapped:
            return (mapped,)
    return ()


def merge_cwes(*groups: Iterable[str]) -> tuple[str, ...]:
    """Union CWE groups while preserving first-seen order."""
    merged: list[str] = []
    for group in groups:
        for value in group:
            if value not in merged:
                merged.append(value)
    return tuple(merged)
