"""Stable schemas for explainable Bug-Dhor findings.

All coordinates in this schema remain one-based, matching the existing
``bugdhor_ast`` engine. VS Code adapters are responsible for converting them
to zero-based ranges.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

EXPLANATION_SCHEMA_VERSION = "1.0"

_CWE_PATTERN = re.compile(r"^CWE-\d+$")

_EXPLANATION_KEYS = frozenset(
    {
        "schema_version",
        "finding_id",
        "rule_id",
        "severity",
        "language",
        "category",
        "cwe",
        "location",
        "root_cause",
        "trigger",
        "evidence",
        "source_to_sink_path",
        "confidence",
        "limitations",
        "suggested_remediation",
        "verification_requirements",
    }
)
_LOCATION_KEYS = frozenset(
    {
        "file",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    }
)
_EVIDENCE_KEYS = frozenset(
    {
        "observed",
        "derived",
        "heuristic",
        "unavailable",
    }
)
_EVIDENCE_RECORD_KEYS = frozenset(
    {
        "id",
        "status",
        "kind",
        "summary",
        "value",
        "refs",
    }
)
_CWE_KEYS = frozenset(
    {
        "id",
        "confidence",
        "rationale",
        "evidence_refs",
    }
)
_ROOT_CAUSE_KEYS = frozenset(
    {
        "status",
        "location",
        "rationale",
        "evidence_refs",
    }
)
_CONFIDENCE_KEYS = frozenset({"value", "basis"})


class EvidenceStatus(str, Enum):
    """Provenance of a single evidence record."""

    OBSERVED = "observed"
    DERIVED = "derived"
    HEURISTIC = "heuristic"
    UNAVAILABLE = "unavailable"


class ConfidenceLevel(str, Enum):
    """Normalized confidence values used in explanations."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RootCauseStatus(str, Enum):
    """How strongly a root cause is supported by evidence."""

    DETERMINED = "determined"
    HEURISTIC = "heuristic"
    UNKNOWN = "unknown"


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


def _check_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
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


def _as_str(value: Any, label: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} must not be empty")
    return value


def _as_str_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_as_str(item, f"{label}[{index}]", allow_empty=False))
    return tuple(result)


def _as_enum(value: Any, enum_type: type[Enum], label: str) -> Enum:
    try:
        return enum_type(value)
    except ValueError as error:
        allowed = ", ".join(item.value for item in enum_type)
        raise ValueError(f"{label} must be one of: {allowed}") from error


@dataclass(frozen=True)
class ExplanationLocation:
    """One-based source span copied from existing engine output."""

    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        _as_str(self.file, "location.file")
        for name in (
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"location.{name} must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ExplanationLocation:
        value = _as_mapping(value, "location")
        _check_keys(value, _LOCATION_KEYS, "location")
        return cls(
            file=value["file"],
            start_line=value["start_line"],
            start_column=value["start_column"],
            end_line=value["end_line"],
            end_column=value["end_column"],
        )


@dataclass(frozen=True)
class EvidenceRecord:
    """A single observed, derived, heuristic, or unavailable evidence item."""

    id: str
    status: EvidenceStatus
    kind: str
    summary: str
    value: Any = None
    refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "id", _as_str(self.id, "evidence.id", allow_empty=False)
        )
        object.__setattr__(
            self,
            "status",
            _as_enum(self.status, EvidenceStatus, "evidence.status"),
        )
        object.__setattr__(
            self, "kind", _as_str(self.kind, "evidence.kind", allow_empty=False)
        )
        object.__setattr__(
            self,
            "summary",
            _as_str(self.summary, "evidence.summary", allow_empty=False),
        )
        object.__setattr__(self, "refs", _as_str_list(self.refs, "evidence.refs"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "kind": self.kind,
            "summary": self.summary,
            "value": self.value,
            "refs": list(self.refs),
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceRecord:
        value = _as_mapping(value, "evidence record")
        _check_keys(value, _EVIDENCE_RECORD_KEYS, "evidence record")
        return cls(
            id=value["id"],
            status=value["status"],
            kind=value["kind"],
            summary=value["summary"],
            value=value["value"],
            refs=value["refs"],
        )


@dataclass(frozen=True)
class EvidenceCollection:
    """Evidence grouped by provenance."""

    observed: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    derived: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    heuristic: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    unavailable: tuple[EvidenceRecord, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed": [item.to_dict() for item in self.observed],
            "derived": [item.to_dict() for item in self.derived],
            "heuristic": [item.to_dict() for item in self.heuristic],
            "unavailable": [item.to_dict() for item in self.unavailable],
        }

    def all_records(self) -> tuple[EvidenceRecord, ...]:
        return self.observed + self.derived + self.heuristic + self.unavailable

    def add(self, record: EvidenceRecord) -> EvidenceCollection:
        field_name = record.status.value
        records = getattr(self, field_name) + (record,)
        return EvidenceCollection(
            observed=records if field_name == "observed" else self.observed,
            derived=records if field_name == "derived" else self.derived,
            heuristic=records if field_name == "heuristic" else self.heuristic,
            unavailable=(
                records if field_name == "unavailable" else self.unavailable
            ),
        )

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceCollection:
        value = _as_mapping(value, "evidence")
        _check_keys(value, _EVIDENCE_KEYS, "evidence")
        parsed: dict[str, tuple[EvidenceRecord, ...]] = {}
        for name in _EVIDENCE_KEYS:
            items = value[name]
            if not isinstance(items, (list, tuple)):
                raise TypeError(f"evidence.{name} must be a list")
            parsed[name] = tuple(
                EvidenceRecord.from_dict(item) for item in items
            )
        return cls(**parsed)


@dataclass(frozen=True)
class CweMapping:
    """A defensible CWE mapping with rationale and confidence."""

    id: str
    confidence: ConfidenceLevel
    rationale: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CWE_PATTERN.match(self.id):
            raise ValueError("cwe.id must look like CWE-123")
        object.__setattr__(
            self,
            "confidence",
            _as_enum(self.confidence, ConfidenceLevel, "cwe.confidence"),
        )
        object.__setattr__(
            self,
            "rationale",
            _as_str(self.rationale, "cwe.rationale", allow_empty=False),
        )
        object.__setattr__(
            self, "evidence_refs", _as_str_list(self.evidence_refs, "cwe.evidence_refs")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Any) -> CweMapping:
        value = _as_mapping(value, "cwe mapping")
        _check_keys(value, _CWE_KEYS, "cwe mapping")
        return cls(
            id=value["id"],
            confidence=value["confidence"],
            rationale=value["rationale"],
            evidence_refs=value["evidence_refs"],
        )


@dataclass(frozen=True)
class RootCause:
    """Root-cause localization result, possibly unknown."""

    status: RootCauseStatus
    location: ExplanationLocation | None
    rationale: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "status",
            _as_enum(self.status, RootCauseStatus, "root_cause.status"),
        )
        object.__setattr__(
            self,
            "rationale",
            _as_str(self.rationale, "root_cause.rationale", allow_empty=False),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _as_str_list(self.evidence_refs, "root_cause.evidence_refs"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "location": None if self.location is None else self.location.to_dict(),
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Any) -> RootCause:
        value = _as_mapping(value, "root_cause")
        _check_keys(value, _ROOT_CAUSE_KEYS, "root_cause")
        location = value["location"]
        return cls(
            status=value["status"],
            location=None if location is None else ExplanationLocation.from_dict(location),
            rationale=value["rationale"],
            evidence_refs=value["evidence_refs"],
        )


@dataclass(frozen=True)
class ConfidenceAssessment:
    """Confidence value plus the basis for that value."""

    value: ConfidenceLevel
    basis: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _as_enum(self.value, ConfidenceLevel, "confidence.value"),
        )
        object.__setattr__(
            self,
            "basis",
            _as_str(self.basis, "confidence.basis", allow_empty=False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value.value, "basis": self.basis}

    @classmethod
    def from_dict(cls, value: Any) -> ConfidenceAssessment:
        value = _as_mapping(value, "confidence")
        _check_keys(value, _CONFIDENCE_KEYS, "confidence")
        return cls(value=value["value"], basis=value["basis"])


@dataclass(frozen=True)
class FindingExplanation:
    """Stable v1 explanation for one existing Bug-Dhor finding."""

    finding_id: str
    rule_id: str
    severity: str
    language: str
    category: str | None
    cwe: tuple[CweMapping, ...]
    location: ExplanationLocation
    root_cause: RootCause
    trigger: Any
    evidence: EvidenceCollection
    source_to_sink_path: tuple[Any, ...]
    confidence: ConfidenceAssessment
    limitations: tuple[str, ...]
    suggested_remediation: str | None
    verification_requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("finding_id", "rule_id", "severity", "language"):
            _as_str(getattr(self, name), f"explanation.{name}", allow_empty=False)
        if self.category is not None:
            _as_str(self.category, "explanation.category", allow_empty=False)
        object.__setattr__(
            self,
            "limitations",
            _as_str_list(self.limitations, "explanation.limitations"),
        )
        object.__setattr__(
            self,
            "verification_requirements",
            _as_str_list(
                self.verification_requirements,
                "explanation.verification_requirements",
            ),
        )
        object.__setattr__(
            self,
            "source_to_sink_path",
            tuple(self.source_to_sink_path),
        )
        if self.suggested_remediation is not None:
            _as_str(
                self.suggested_remediation,
                "explanation.suggested_remediation",
                allow_empty=False,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EXPLANATION_SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "language": self.language,
            "category": self.category,
            "cwe": [item.to_dict() for item in self.cwe],
            "location": self.location.to_dict(),
            "root_cause": self.root_cause.to_dict(),
            "trigger": self.trigger,
            "evidence": self.evidence.to_dict(),
            "source_to_sink_path": list(self.source_to_sink_path),
            "confidence": self.confidence.to_dict(),
            "limitations": list(self.limitations),
            "suggested_remediation": self.suggested_remediation,
            "verification_requirements": list(self.verification_requirements),
        }

    @classmethod
    def from_dict(cls, value: Any) -> FindingExplanation:
        value = _as_mapping(value, "explanation")
        validate_explanation(value)
        return cls(
            finding_id=value["finding_id"],
            rule_id=value["rule_id"],
            severity=value["severity"],
            language=value["language"],
            category=value["category"],
            cwe=tuple(CweMapping.from_dict(item) for item in value["cwe"]),
            location=ExplanationLocation.from_dict(value["location"]),
            root_cause=RootCause.from_dict(value["root_cause"]),
            trigger=value["trigger"],
            evidence=EvidenceCollection.from_dict(value["evidence"]),
            source_to_sink_path=tuple(value["source_to_sink_path"]),
            confidence=ConfidenceAssessment.from_dict(value["confidence"]),
            limitations=value["limitations"],
            suggested_remediation=value["suggested_remediation"],
            verification_requirements=value["verification_requirements"],
        )


def validate_explanation(value: Any) -> None:
    """Validate a serialized v1 explanation and raise ``ValueError`` on error."""

    value = _as_mapping(value, "explanation")
    _check_keys(value, _EXPLANATION_KEYS, "explanation")
    if value["schema_version"] != EXPLANATION_SCHEMA_VERSION:
        raise ValueError(
            f"explanation.schema_version must be {EXPLANATION_SCHEMA_VERSION}"
        )
    for name in ("finding_id", "rule_id", "severity", "language"):
        _as_str(value[name], f"explanation.{name}", allow_empty=False)
    if value["category"] is not None:
        _as_str(value["category"], "explanation.category", allow_empty=False)

    if not isinstance(value["cwe"], (list, tuple)):
        raise TypeError("explanation.cwe must be a list")
    for index, item in enumerate(value["cwe"]):
        CweMapping.from_dict(item)

    ExplanationLocation.from_dict(value["location"])
    RootCause.from_dict(value["root_cause"])
    EvidenceCollection.from_dict(value["evidence"])
    if not isinstance(value["source_to_sink_path"], (list, tuple)):
        raise TypeError("explanation.source_to_sink_path must be a list")
    for index, item in enumerate(value["source_to_sink_path"]):
        if not isinstance(item, Mapping):
            raise TypeError(
                f"explanation.source_to_sink_path[{index}] must be a mapping"
            )
    ConfidenceAssessment.from_dict(value["confidence"])
    _as_str_list(value["limitations"], "explanation.limitations")
    _as_str_list(
        value["verification_requirements"],
        "explanation.verification_requirements",
    )
    if value["suggested_remediation"] is not None:
        _as_str(
            value["suggested_remediation"],
            "explanation.suggested_remediation",
            allow_empty=False,
        )
