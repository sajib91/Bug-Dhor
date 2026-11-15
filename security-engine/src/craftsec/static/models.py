"""Immutable models for static-analyzer execution and normalization.

The models keep three things separate that must never be conflated:

* whether a tool was available at all;
* whether the process completed and its output parsed; and
* the normalized findings produced by that output.

A missing tool or failed invocation is therefore represented explicitly and can
never be mistaken for a successful empty scan.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp accepted by the shared contracts."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ToolName(StrEnum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    CODEQL = "codeql"
    JOERN = "joern"


class AvailabilityStatus(StrEnum):
    """Why a tool can or cannot be executed."""

    AVAILABLE = "available"
    MISSING = "missing"
    UNSUPPORTED = "unsupported"
    NOT_CONFIGURED = "not_configured"
    LICENSE_NOT_ACCEPTED = "license_not_accepted"
    LAUNCH_FAILED = "launch_failed"


class ScanStatus(StrEnum):
    """The explicit outcome of one tool scan or one combined run."""

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(value: str) -> int:
    """Return the ordered rank of a normalized severity."""
    return _SEVERITY_ORDER.get(value, 0)


def max_severity(*values: str) -> str:
    """Return the highest normalized severity, defaulting to ``info``."""
    return max(values, key=severity_rank, default="info")


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A zero-based source range.

    Tool-native coordinates are normalized before construction. Lines and
    columns are zero-based so the values can be handed directly to the VS Code
    diagnostics contract.
    """

    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("SourceLocation.path must not be empty")
        values = (self.start_line, self.start_column, self.end_line, self.end_column)
        if any(not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("SourceLocation coordinates must be non-negative integers")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("SourceLocation end must not precede start")

    @property
    def start(self) -> tuple[int, int]:
        return (self.start_line, self.start_column)

    @property
    def end(self) -> tuple[int, int]:
        return (self.end_line, self.end_column)

    def overlaps(self, other: SourceLocation) -> bool:
        return self.path == other.path and self.start <= other.end and other.start <= self.end

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": {"line": self.start_line, "column": self.start_column},
            "end": {"line": self.end_line, "column": self.end_column},
        }


@dataclass(frozen=True, slots=True)
class RelatedFinding:
    """One original finding preserved inside a deduplicated cluster."""

    finding_id: str
    tool: str
    rule_id: str
    cwe: str | None = None
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "tool": self.tool,
            "ruleId": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class StaticFinding:
    """One normalized finding from one static analyzer."""

    finding_id: str
    tool: str
    rule_id: str
    message: str
    severity: str
    location: SourceLocation
    cwes: tuple[str, ...] = ()
    rule_name: str | None = None
    fingerprint: str | None = None
    evidence: str | None = None
    tool_version: str | None = None
    config_hash: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)
    related: tuple[RelatedFinding, ...] = ()
    generated_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if not self.finding_id or not self.rule_id or not self.message:
            raise ValueError("finding_id, rule_id, and message must be non-empty")
        if self.severity not in _SEVERITY_ORDER:
            raise ValueError(f"unsupported severity: {self.severity!r}")
        if self.cwes:
            for cwe in self.cwes:
                if not cwe.startswith("CWE-") or not cwe[4:].isdigit():
                    raise ValueError(f"invalid CWE identifier: {cwe!r}")

    @property
    def cwe(self) -> str | None:
        return self.cwes[0] if self.cwes else None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Every original rule identifier, primary first."""
        return tuple(dict.fromkeys([self.rule_id, *(item.rule_id for item in self.related)]))

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([self.tool, *(item.tool for item in self.related)]))

    def merged_with(self, others: tuple[RelatedFinding, ...]) -> StaticFinding:
        return replace(self, related=others)

    def to_dict(self) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "producer": self.tool,
            "producerVersion": self.tool_version or "unknown",
            "generatedAt": self.generated_at,
            "source": "static",
        }
        if self.config_hash:
            provenance["configHash"] = self.config_hash
        return {
            "findingId": self.finding_id,
            "tool": self.tool,
            "tools": list(self.tools),
            "toolVersion": self.tool_version,
            "configHash": self.config_hash,
            "ruleId": self.rule_id,
            "ruleIds": list(self.rule_ids),
            "ruleName": self.rule_name,
            "message": self.message,
            "severity": self.severity,
            "cwe": self.cwe,
            "cwes": list(self.cwes),
            "filePath": self.location.path,
            "location": self.location.to_dict(),
            "fingerprint": self.fingerprint,
            "evidence": self.evidence,
            "related": [item.to_dict() for item in self.related],
            "provenance": provenance,
        }


@dataclass(frozen=True, slots=True)
class ToolExecution:
    """Captured process metadata for one analyzer invocation."""

    argv: tuple[str, ...]
    return_code: int | None
    duration_seconds: float
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    launch_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "returnCode": self.return_code,
            "durationSeconds": round(self.duration_seconds, 3),
            "timedOut": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdoutTruncated": self.stdout_truncated,
            "stderrTruncated": self.stderr_truncated,
            "launchError": self.launch_error,
        }


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    """Detection result for one configured tool."""

    tool: str
    status: AvailabilityStatus
    executable: str | None
    version: str | None = None
    reason_code: str | None = None
    detail: str | None = None
    configuration: Mapping[str, Any] = field(default_factory=dict)
    config_hash: str | None = None
    warnings: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        return self.status is AvailabilityStatus.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "available": self.available,
            "status": self.status.value,
            "executable": self.executable,
            "version": self.version,
            "reasonCode": self.reason_code,
            "detail": self.detail,
            "configuration": dict(self.configuration),
            "configHash": self.config_hash,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class ToolScanResult:
    """One analyzer's explicit outcome, findings, and execution record."""

    tool: str
    status: ScanStatus
    availability: ToolAvailability
    version: str | None
    configuration: Mapping[str, Any]
    config_hash: str
    findings: tuple[StaticFinding, ...] = ()
    execution: ToolExecution | None = None
    reason_code: str | None = None
    detail: str | None = None
    warnings: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status in {ScanStatus.OK, ScanStatus.PARTIAL}

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "succeeded": self.succeeded,
            "version": self.version,
            "configuration": dict(self.configuration),
            "configHash": self.config_hash,
            "reasonCode": self.reason_code,
            "detail": self.detail,
            "warnings": list(self.warnings),
            "findingCount": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "execution": self.execution.to_dict() if self.execution else None,
        }


@dataclass(frozen=True, slots=True)
class ParsedOutput:
    """Normalized parser output before it is attached to a scan result."""

    findings: tuple[StaticFinding, ...]
    warnings: tuple[str, ...] = ()
    tool_version: str | None = None


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    """Combined, deduplicated result for a group of configured analyzers."""

    status: ScanStatus
    findings: tuple[StaticFinding, ...]
    scans: tuple[ToolScanResult, ...]
    warnings: tuple[str, ...] = ()

    @property
    def available_tools(self) -> tuple[str, ...]:
        return tuple(scan.tool for scan in self.scans if scan.availability.available)

    @property
    def unavailable_tools(self) -> tuple[str, ...]:
        return tuple(scan.tool for scan in self.scans if not scan.availability.available)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "availableTools": list(self.available_tools),
            "unavailableTools": list(self.unavailable_tools),
            "warnings": list(self.warnings),
            "findingCount": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "toolScans": [scan.to_dict() for scan in self.scans],
        }
