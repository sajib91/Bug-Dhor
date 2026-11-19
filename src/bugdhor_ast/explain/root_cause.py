"""Deterministic root-cause localization from existing analysis evidence.

Every strategy returns a status of ``determined``, ``heuristic``, or ``unknown``.
A root cause is never inferred from rule names alone, and taint origins are
reported as analysis-model origins rather than runtime causal proof.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .evidence import (
    _ast_evidence,
    _finding_location,
    _format_point,
    _matching_taint,
    _start_point,
)
from .schema import (
    EvidenceRecord,
    EvidenceStatus,
    ExplanationLocation,
    FindingExplanation,
    RootCause,
    RootCauseStatus,
)

_UNDEFINED_RULES = frozenset({"PY001", "JS001", "JAVA001"})
_DANGEROUS_RULES = frozenset(
    {
        "PY009",
        "PY010",
        "JS009",
        "JS010",
        "JAVA009",
        "JAVA010",
    }
)
_UNUSED_RULES = frozenset(
    {
        "PY002",
        "PY005",
        "PY006",
        "JS002",
        "JS005",
        "JS006",
        "JAVA002",
        "JAVA005",
        "JAVA006",
    }
)
_NULL_ACCESS_RULES = frozenset({"PY007", "JS007", "JAVA007"})
_NAME_PATTERN = re.compile(r"'([^']+)'|\"([^\"]+)\"")


@dataclass(frozen=True)
class RootCauseAnalysis:
    """Root-cause result plus any evidence created while locating it."""

    analysis_kind: str
    root_cause: RootCause
    evidence: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_kind": self.analysis_kind,
            "root_cause": self.root_cause.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "limitations": list(self.limitations),
        }


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("analysis payloads must be mappings")
    return dict(value)


def _span(
    location: ExplanationLocation,
) -> tuple[tuple[int, int], tuple[int, int]]:
    return (
        (location.start_line, location.start_column),
        (location.end_line, location.end_column),
    )


def _location_from_mapping(value: Mapping[str, Any]) -> ExplanationLocation | None:
    if not value:
        return None
    line = value.get("line", value.get("start_line", 0))
    column = value.get("column", value.get("start_column", 0))
    end_line = value.get("end_line", line)
    end_column = value.get("end_column", column)
    return ExplanationLocation(
        file=str(value.get("file", "<source>")),
        start_line=int(line or 0),
        start_column=int(column or 0),
        end_line=int(end_line or line or 0),
        end_column=int(end_column or column or 0),
    )


def _mentioned_name(message: Any) -> str | None:
    if not isinstance(message, str):
        return None
    for match in _NAME_PATTERN.finditer(message):
        return match.group(1) or match.group(2)
    return None


def _base_refs(
    explanation: FindingExplanation | None,
    kinds: set[str],
    *,
    limit: int = 4,
) -> tuple[str, ...]:
    if explanation is None:
        return ()
    matches = [
        record.id
        for record in explanation.evidence.all_records()
        if record.kind in kinds
    ]
    return tuple(matches[:limit])


def _unsupported(
    location: ExplanationLocation,
    refs: tuple[str, ...],
    rule_id: str,
) -> RootCauseAnalysis:
    return RootCauseAnalysis(
        analysis_kind="unsupported",
        root_cause=RootCause(
            status=RootCauseStatus.UNKNOWN,
            location=None,
            rationale=(
                f"No deterministic root-cause strategy is available for {rule_id}."
            ),
            evidence_refs=refs,
        ),
        limitations=(
            f"Root cause for {rule_id} was not localized; no inference was made.",
        ),
    )


def _syntax_error(
    analysis: Mapping[str, Any],
    location: ExplanationLocation,
    refs: tuple[str, ...],
) -> RootCauseAnalysis:
    errors = [
        item
        for item in analysis.get("syntax_errors", [])
        if isinstance(item, Mapping)
        and _start_point(item) == (location.start_line, location.start_column)
    ]
    if not errors:
        return RootCauseAnalysis(
            analysis_kind="syntax_error",
            root_cause=RootCause(
                status=RootCauseStatus.UNKNOWN,
                location=None,
                rationale="No syntax-error AST item was available at the finding span.",
                evidence_refs=refs,
            ),
            limitations=("Syntax-error evidence was unavailable.",),
        )
    error = errors[0]
    record = EvidenceRecord(
        id="root-cause:syntax-error",
        status=EvidenceStatus.OBSERVED,
        kind="root_cause_syntax_error",
        summary=f"Syntax error: {error.get('message', 'unknown')}",
        value=dict(error),
    )
    return RootCauseAnalysis(
        analysis_kind="syntax_error",
        root_cause=RootCause(
            status=RootCauseStatus.DETERMINED,
            location=location,
            rationale=(
                "The parser reported a syntax error at the finding span; this "
                "is the direct trigger for AST001."
            ),
            evidence_refs=refs + (record.id,),
        ),
        evidence=(record,),
    )


def _undefined_reference(
    finding: Mapping[str, Any],
    analysis: Mapping[str, Any],
    location: ExplanationLocation,
    refs: tuple[str, ...],
) -> RootCauseAnalysis:
    matches = [
        item
        for item in analysis.get("unresolved_references", [])
        if isinstance(item, Mapping)
        and _start_point(item.get("location", {}))
        == (location.start_line, location.start_column)
    ]
    name = _mentioned_name(finding.get("message")) or (
        matches[0].get("name") if matches else None
    )
    if matches:
        matched = matches[0]
        cause_location = _location_from_mapping(matched.get("location", {})) or location
        record = EvidenceRecord(
            id="root-cause:unresolved-reference",
            status=EvidenceStatus.DERIVED,
            kind="root_cause_unresolved_reference",
            summary=f"Unresolved reference {matched.get('name', name or 'unknown')}",
            value={
                "name": matched.get("name"),
                "scope_id": matched.get("scope_id"),
                "kind": matched.get("kind"),
                "statement_id": matched.get("statement_id"),
                "location": matched.get("location"),
            },
        )
        return RootCauseAnalysis(
            analysis_kind="undefined_reference",
            root_cause=RootCause(
                status=RootCauseStatus.DETERMINED,
                location=cause_location,
                rationale=(
                    "Scope analysis found no visible declaration for the "
                    "referenced identifier at this location."
                ),
                evidence_refs=refs + (record.id,),
            ),
            evidence=(record,),
            limitations=(
                (
                    "Resolution is syntax-scoped and does not model dynamic "
                    "globals or runtime imports."
                ),
            ),
        )

    if name:
        return RootCauseAnalysis(
            analysis_kind="undefined_reference",
            root_cause=RootCause(
                status=RootCauseStatus.HEURISTIC,
                location=location,
                rationale=(
                    f"The rule reports undefined use of {name}, but no "
                    "unresolved-reference record was supplied."
                ),
                evidence_refs=refs,
            ),
            limitations=(
                (
                    "Scope evidence was unavailable; the use site is a heuristic "
                    "root-cause location."
                ),
            ),
        )
    return RootCauseAnalysis(
        analysis_kind="undefined_reference",
        root_cause=RootCause(
            status=RootCauseStatus.UNKNOWN,
            location=None,
            rationale="Neither scope evidence nor an identifier name was available.",
            evidence_refs=refs,
        ),
    )


def _dangerous_call(
    analysis: Mapping[str, Any],
    location: ExplanationLocation,
    refs: tuple[str, ...],
) -> RootCauseAnalysis:
    records = [
        record
        for record in _ast_evidence(analysis, _span(location))
        if record.kind == "ast_function_calls"
    ]
    if not records:
        return RootCauseAnalysis(
            analysis_kind="dangerous_call",
            root_cause=RootCause(
                status=RootCauseStatus.UNKNOWN,
                location=None,
                rationale="No AST call node was available at the finding span.",
                evidence_refs=refs,
            ),
            limitations=("Call-site evidence was unavailable.",),
        )
    call = records[0]
    value = call.value if isinstance(call.value, Mapping) else {}
    cause_location = _location_from_mapping(value) or location
    name = str(value.get("name", "unknown call"))
    record = EvidenceRecord(
        id="root-cause:dangerous-call",
        status=EvidenceStatus.OBSERVED,
        kind="root_cause_dangerous_call",
        summary=f"Dangerous call {name}",
        value=dict(value),
    )
    return RootCauseAnalysis(
        analysis_kind="dangerous_call",
        root_cause=RootCause(
            status=RootCauseStatus.DETERMINED,
            location=cause_location,
            rationale=(
                f"The finding is directly triggered by the call to {name}. "
                "This identifies the call site, not exploitability."
            ),
            evidence_refs=refs + (record.id,),
        ),
        evidence=(record,),
    )


def _unused_declaration(
    finding: Mapping[str, Any],
    analysis: Mapping[str, Any],
    location: ExplanationLocation,
    refs: tuple[str, ...],
) -> RootCauseAnalysis:
    name = _mentioned_name(finding.get("message"))
    symbols = [
        item
        for item in analysis.get("symbols", [])
        if isinstance(item, Mapping) and (name is None or item.get("name") == name)
    ]
    if not symbols:
        status = RootCauseStatus.HEURISTIC if name else RootCauseStatus.UNKNOWN
        return RootCauseAnalysis(
            analysis_kind="unused_declaration",
            root_cause=RootCause(
                status=status,
                location=location if name else None,
                rationale=(
                    f"The rule reports unused {name or 'name'}, but no symbol "
                    "record was supplied."
                ),
                evidence_refs=refs,
            ),
            limitations=("Symbol evidence was unavailable.",),
        )

    symbol = symbols[0]
    cause_location = _location_from_mapping(symbol.get("declaration", {})) or location
    record = EvidenceRecord(
        id="root-cause:unused-declaration",
        status=EvidenceStatus.DERIVED,
        kind="root_cause_unused_declaration",
        summary=f"Declaration of {symbol.get('name', name)}",
        value={
            "symbol_id": symbol.get("id"),
            "name": symbol.get("name"),
            "scope_id": symbol.get("scope_id"),
            "reference_count": len(symbol.get("references", [])),
        },
    )
    return RootCauseAnalysis(
        analysis_kind="unused_declaration",
        root_cause=RootCause(
            status=RootCauseStatus.DETERMINED,
            location=cause_location,
            rationale=(
                "The finding concerns the declaration site of this symbol; "
                "no broader cause is inferred."
            ),
            evidence_refs=refs + (record.id,),
        ),
        evidence=(record,),
    )


def _null_access(
    location: ExplanationLocation,
    refs: tuple[str, ...],
) -> RootCauseAnalysis:
    return RootCauseAnalysis(
        analysis_kind="null_access",
        root_cause=RootCause(
            status=RootCauseStatus.HEURISTIC,
            location=location,
            rationale=(
                "The dereference site is the nearest available root-cause "
                "location; guard absence is not path-feasibility evidence."
            ),
            evidence_refs=refs,
        ),
        limitations=(
            (
                "Null/zero-value analysis is conservative and does not prove "
                "runtime feasibility."
            ),
        ),
    )


def _taint_origin(
    finding: Mapping[str, Any],
    analysis: Mapping[str, Any],
    location: ExplanationLocation,
    refs: tuple[str, ...],
    explanation: FindingExplanation | None,
) -> RootCauseAnalysis:
    raw, _, limitations = _matching_taint(analysis, finding, _span(location))
    if raw is None:
        return RootCauseAnalysis(
            analysis_kind="taint_origin",
            root_cause=RootCause(
                status=RootCauseStatus.UNKNOWN,
                location=None,
                rationale="No raw taint finding was available for this diagnostic.",
                evidence_refs=refs,
            ),
            limitations=tuple(limitations),
        )

    source_location = _location_from_mapping(raw.get("source_location", {}))
    sink_location = _location_from_mapping(raw.get("sink_location", {})) or location
    record = EvidenceRecord(
        id="root-cause:taint-origin",
        status=EvidenceStatus.DERIVED,
        kind="root_cause_taint_origin",
        summary=(
            f"Taint origin {raw.get('source_name', 'unknown')} at "
            f"{_format_point(_start_point(raw.get('source_location', {})))}"
        ),
        value={
            "source_rule": raw.get("source_rule"),
            "source_name": raw.get("source_name"),
            "source_location": raw.get("source_location"),
            "sink_rule": raw.get("sink_rule"),
            "sink_name": raw.get("sink_name"),
            "sink_location": raw.get("sink_location"),
            "path_length": len(raw.get("path", [])),
        },
        refs=_base_refs(
            explanation,
            {"taint_source_sink", "taint_path", "ast_function_calls"},
        ),
    )
    return RootCauseAnalysis(
        analysis_kind="taint_origin",
        root_cause=RootCause(
            status=RootCauseStatus.HEURISTIC,
            location=source_location,
            rationale=(
                f"Taint propagation starts at {raw.get('source_name', 'unknown')} "
                f"and reaches {raw.get('sink_name', 'unknown')} at "
                f"{_format_point(_start_point(sink_location.to_dict()))}. "
                "The path is syntax-level and does not establish runtime feasibility."
            ),
            evidence_refs=refs + (record.id,),
        ),
        evidence=(record,),
        limitations=_deduplicate(
            tuple(limitations)
            + (
                (
                    "Taint root cause is an analysis-model origin, not proof of "
                    "exploitability."
                ),
            )
        ),
    )


def _deduplicate(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if isinstance(value, str)))


def analyze_root_cause(
    finding: Any,
    analysis: Any = None,
    *,
    explanation: FindingExplanation | None = None,
) -> RootCauseAnalysis:
    """Locate a root cause using only supplied evidence."""

    finding_dict = _as_dict(finding)
    analysis_dict = _as_dict(analysis)
    location = _finding_location(finding_dict)
    rule_id = str(finding_dict.get("rule_id", "")).upper()
    refs = _base_refs(
        explanation,
        {"finding", "ast_function_calls", "unresolved_reference", "taint_source_sink"},
    )

    if rule_id == "AST001":
        return _syntax_error(analysis_dict, location, refs)
    if rule_id.endswith("-TAINT001"):
        return _taint_origin(finding_dict, analysis_dict, location, refs, explanation)
    if rule_id in _UNDEFINED_RULES:
        return _undefined_reference(finding_dict, analysis_dict, location, refs)
    if rule_id in _DANGEROUS_RULES:
        return _dangerous_call(analysis_dict, location, refs)
    if rule_id in _UNUSED_RULES:
        return _unused_declaration(finding_dict, analysis_dict, location, refs)
    if rule_id in _NULL_ACCESS_RULES:
        return _null_access(location, refs)
    return _unsupported(location, refs, rule_id)
