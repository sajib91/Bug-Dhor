"""Stable schema for deterministic repair recommendations.

Recommendations never authorize a source change by themselves. Every valid
recommendation sets ``requires_approval`` to true so a later patch workflow
must show the exact diff and obtain explicit developer confirmation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..schema import ConfidenceLevel

REPAIR_SCHEMA_VERSION = "1.0"

_RECOMMENDATION_KEYS = frozenset(
    {
        "schema_version",
        "finding_id",
        "rule_id",
        "strategy",
        "status",
        "original_code",
        "proposed_code",
        "target",
        "explanation",
        "security_rationale",
        "functional_considerations",
        "confidence",
        "required_tests",
        "known_limitations",
        "requires_approval",
    }
)
_TARGET_KEYS = frozenset(
    {
        "file",
        "language",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    }
)


class RepairStatus(str, Enum):
    """Whether a recommendation can advance to patch preview."""

    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    UNSUPPORTED = "unsupported"


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


def _as_optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _as_str(value, label, allow_empty=False)


def _as_str_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_as_str(item, f"{label}[{index}]"))
    return tuple(result)


def _as_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class RepairTarget:
    """One-based target span copied from an existing finding."""

    file: str
    language: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        _as_str(self.file, "target.file", allow_empty=True)
        _as_str(self.language, "target.language")
        for name in (
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        ):
            _as_int(getattr(self, name), f"target.{name}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_dict(cls, value: Any) -> RepairTarget:
        value = _as_mapping(value, "target")
        _check_keys(value, _TARGET_KEYS, "target")
        return cls(
            file=value["file"],
            language=value["language"],
            start_line=value["start_line"],
            start_column=value["start_column"],
            end_line=value["end_line"],
            end_column=value["end_column"],
        )


@dataclass(frozen=True)
class RepairRecommendation:
    """A deterministic, reviewable repair proposal for one finding."""

    finding_id: str
    rule_id: str
    strategy: str
    status: RepairStatus
    original_code: str | None
    proposed_code: str | None
    target: RepairTarget
    explanation: str
    security_rationale: str
    functional_considerations: str
    confidence: ConfidenceLevel
    required_tests: tuple[str, ...] = field(default_factory=tuple)
    known_limitations: tuple[str, ...] = field(default_factory=tuple)
    requires_approval: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", RepairStatus(self.status)
        )
        object.__setattr__(
            self, "confidence", ConfidenceLevel(self.confidence)
        )
        for name in (
            "finding_id",
            "rule_id",
            "strategy",
            "explanation",
            "security_rationale",
            "functional_considerations",
        ):
            _as_str(getattr(self, name), f"recommendation.{name}")
        _as_optional_str(self.original_code, "recommendation.original_code")
        _as_optional_str(self.proposed_code, "recommendation.proposed_code")
        object.__setattr__(
            self,
            "required_tests",
            _as_str_list(self.required_tests, "recommendation.required_tests"),
        )
        object.__setattr__(
            self,
            "known_limitations",
            _as_str_list(
                self.known_limitations, "recommendation.known_limitations"
            ),
        )
        if not isinstance(self.requires_approval, bool):
            raise TypeError("recommendation.requires_approval must be a boolean")
        if self.requires_approval is not True:
            raise ValueError("recommendation.requires_approval must always be true")
        if self.status is RepairStatus.READY:
            if not self.original_code or not self.proposed_code:
                raise ValueError("ready recommendations require original and proposed code")
            if self.original_code == self.proposed_code:
                raise ValueError("ready recommendations must change the source")
            if not self.required_tests:
                raise ValueError("ready recommendations require at least one test")
        if self.status is RepairStatus.UNSUPPORTED and self.proposed_code is not None:
            raise ValueError("unsupported recommendations must not propose code")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "strategy": self.strategy,
            "status": self.status.value,
            "original_code": self.original_code,
            "proposed_code": self.proposed_code,
            "target": self.target.to_dict(),
            "explanation": self.explanation,
            "security_rationale": self.security_rationale,
            "functional_considerations": self.functional_considerations,
            "confidence": self.confidence.value,
            "required_tests": list(self.required_tests),
            "known_limitations": list(self.known_limitations),
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, value: Any) -> RepairRecommendation:
        value = _as_mapping(value, "recommendation")
        validate_recommendation(value)
        return cls(
            finding_id=value["finding_id"],
            rule_id=value["rule_id"],
            strategy=value["strategy"],
            status=RepairStatus(value["status"]),
            original_code=value["original_code"],
            proposed_code=value["proposed_code"],
            target=RepairTarget.from_dict(value["target"]),
            explanation=value["explanation"],
            security_rationale=value["security_rationale"],
            functional_considerations=value["functional_considerations"],
            confidence=ConfidenceLevel(value["confidence"]),
            required_tests=value["required_tests"],
            known_limitations=value["known_limitations"],
            requires_approval=value["requires_approval"],
        )


def validate_recommendation(value: Any) -> None:
    """Validate a serialized repair recommendation and raise on errors."""

    value = _as_mapping(value, "recommendation")
    _check_keys(value, _RECOMMENDATION_KEYS, "recommendation")
    if value["schema_version"] != REPAIR_SCHEMA_VERSION:
        raise ValueError(
            f"recommendation.schema_version must be {REPAIR_SCHEMA_VERSION}"
        )
    for name in (
        "finding_id",
        "rule_id",
        "strategy",
        "explanation",
        "security_rationale",
        "functional_considerations",
    ):
        _as_str(value[name], f"recommendation.{name}")
    _as_optional_str(value["original_code"], "recommendation.original_code")
    _as_optional_str(value["proposed_code"], "recommendation.proposed_code")
    status = RepairStatus(value["status"])
    ConfidenceLevel(value["confidence"])
    RepairTarget.from_dict(value["target"])
    _as_str_list(value["required_tests"], "recommendation.required_tests")
    _as_str_list(value["known_limitations"], "recommendation.known_limitations")
    if not isinstance(value["requires_approval"], bool):
        raise TypeError("recommendation.requires_approval must be a boolean")
    if value["requires_approval"] is not True:
        raise ValueError("recommendation.requires_approval must always be true")
    if status is RepairStatus.READY:
        if not value["original_code"] or not value["proposed_code"]:
            raise ValueError(
                "ready recommendations require original and proposed code"
            )
        if value["original_code"] == value["proposed_code"]:
            raise ValueError("ready recommendations must change the source")
        if not value["required_tests"]:
            raise ValueError("ready recommendations require at least one test")
    if status is RepairStatus.UNSUPPORTED and value["proposed_code"] is not None:
        raise ValueError("unsupported recommendations must not propose code")


__all__ = [
    "REPAIR_SCHEMA_VERSION",
    "RepairRecommendation",
    "RepairStatus",
    "RepairTarget",
    "validate_recommendation",
]
