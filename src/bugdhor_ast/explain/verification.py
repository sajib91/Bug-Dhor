"""Independent static verification for a proposed repair.

Verification deliberately reruns the AST, detection, and flow engines on the
modified source. It never trusts the explanation, recommendation, or patch to
prove that a finding is gone, and it never executes source code. All
coordinates in findings remain one-based, matching the existing engine.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..detection.engine import BugDhorDetectionEngine
from ..engine import BugDhorASTEngine
from ..flow import FlowEngine, taint_diagnostics
from ..languages import detect_language
from .evidence import finding_id_for
from .repair.patch import (
    Patch,
    PatchStaleError,
    replace_span_text,
    sha256_text,
    source_size,
)
from .schema import (
    ConfidenceLevel,
    EvidenceCollection,
    EvidenceRecord,
    EvidenceStatus,
)

VERIFICATION_SCHEMA_VERSION = "1.0"
VERIFICATION_SCOPE = "static_reanalysis"

_SIGNATURE_KEYS = frozenset({"rule_id", "language", "message"})
_CHECK_KEYS = frozenset({"id", "status", "detail"})
_SUMMARY_KEYS = frozenset(
    {
        "before_findings",
        "after_findings",
        "target_before",
        "target_after",
        "target_resolved",
        "new_finding_count",
        "new_findings",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "finding_id",
        "signature",
        "scope",
        "checks",
        "evidence",
        "summary",
        "confidence",
        "limitations",
    }
)

_BASE_LIMITATIONS = (
    "Static reanalysis only; functional correctness and exploitability are not proven.",
    "Taint findings are syntactic and require manual review; they are not runtime proofs.",
    "No modified, generated, or untrusted source code was executed.",
)


class VerificationStatus(str, Enum):
    """Outcome of independent static verification."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    FAILED = "failed"
    NOT_VERIFIED = "not_verified"


class CheckStatus(str, Enum):
    """Outcome of one deterministic verification check."""

    PASS = "pass"
    FAIL = "fail"
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


def _as_str_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list")
    return tuple(
        _as_str(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )


def _as_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _as_enum(value: Any, enum_type: type[Enum], label: str) -> Enum:
    try:
        return enum_type(value)
    except ValueError as error:
        allowed = ", ".join(item.value for item in enum_type)
        raise ValueError(f"{label} must be one of: {allowed}") from error


@dataclass(frozen=True)
class FindingSignature:
    """A location-independent identity for comparing findings after edits."""

    rule_id: str
    language: str
    message: str

    def __post_init__(self) -> None:
        _as_str(self.rule_id, "signature.rule_id")
        _as_str(self.language, "signature.language")
        _as_str(self.message, "signature.message")

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "language": self.language,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, value: Any) -> FindingSignature:
        value = _as_mapping(value, "signature")
        _check_keys(value, _SIGNATURE_KEYS, "signature")
        return cls(**dict(value))


@dataclass(frozen=True)
class VerificationCheck:
    """One deterministic check with a result and a human-readable detail."""

    id: str
    status: CheckStatus
    detail: str

    def __post_init__(self) -> None:
        _as_str(self.id, "check.id")
        object.__setattr__(
            self, "status", _as_enum(self.status, CheckStatus, "check.status")
        )
        _as_str(self.detail, "check.detail")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "status": self.status.value,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Any) -> VerificationCheck:
        value = _as_mapping(value, "verification check")
        _check_keys(value, _CHECK_KEYS, "verification check")
        return cls(**dict(value))


@dataclass(frozen=True)
class VerificationResult:
    """Stable, JSON-serializable result of one static verification run."""

    status: VerificationStatus
    finding_id: str
    signature: FindingSignature
    checks: tuple[VerificationCheck, ...]
    evidence: EvidenceCollection
    summary: Mapping[str, Any]
    confidence: ConfidenceLevel
    limitations: tuple[str, ...] = field(default_factory=tuple)
    scope: str = VERIFICATION_SCOPE
    schema_version: str = VERIFICATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", _as_enum(self.status, VerificationStatus, "result.status")
        )
        _as_str(self.finding_id, "result.finding_id")
        if not isinstance(self.signature, FindingSignature):
            raise TypeError("result.signature must be a FindingSignature")
        if not isinstance(self.checks, (list, tuple)) or not self.checks:
            raise ValueError("result.checks must not be empty")
        for item in self.checks:
            if not isinstance(item, VerificationCheck):
                raise TypeError("result.checks must contain VerificationCheck values")
        object.__setattr__(self, "checks", tuple(self.checks))
        if not isinstance(self.evidence, EvidenceCollection):
            raise TypeError("result.evidence must be an EvidenceCollection")
        value = _as_mapping(self.summary, "result.summary")
        _check_keys(value, _SUMMARY_KEYS, "result.summary")
        for name in (
            "before_findings",
            "after_findings",
            "target_before",
            "target_after",
            "new_finding_count",
        ):
            _as_int(value[name], f"result.summary.{name}")
        if not isinstance(value["target_resolved"], bool):
            raise TypeError("result.summary.target_resolved must be a boolean")
        if not isinstance(value["new_findings"], (list, tuple)):
            raise TypeError("result.summary.new_findings must be a list")
        object.__setattr__(self, "summary", dict(value))
        object.__setattr__(
            self,
            "confidence",
            _as_enum(self.confidence, ConfidenceLevel, "result.confidence"),
        )
        object.__setattr__(
            self, "limitations", _as_str_list(self.limitations, "result.limitations")
        )
        _as_str(self.scope, "result.scope")
        if self.schema_version != VERIFICATION_SCHEMA_VERSION:
            raise ValueError(
                f"result.schema_version must be {VERIFICATION_SCHEMA_VERSION}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "finding_id": self.finding_id,
            "signature": self.signature.to_dict(),
            "scope": self.scope,
            "checks": [item.to_dict() for item in self.checks],
            "evidence": self.evidence.to_dict(),
            "summary": dict(self.summary),
            "confidence": self.confidence.value,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, value: Any) -> VerificationResult:
        value = _as_mapping(value, "verification result")
        _check_keys(value, _RESULT_KEYS, "verification result")
        return cls(
            schema_version=value["schema_version"],
            status=VerificationStatus(value["status"]),
            finding_id=value["finding_id"],
            signature=FindingSignature.from_dict(value["signature"]),
            scope=value["scope"],
            checks=tuple(
                VerificationCheck.from_dict(item) for item in value["checks"]
            ),
            evidence=EvidenceCollection.from_dict(value["evidence"]),
            summary=value["summary"],
            confidence=ConfidenceLevel(value["confidence"]),
            limitations=value["limitations"],
        )


def signature_for_finding(finding: Any) -> FindingSignature:
    """Build a location-independent signature for an existing finding."""

    value = _as_mapping(finding, "finding")
    rule_id = value.get("rule_id")
    language = value.get("language")
    message = value.get("message")
    if not all(isinstance(item, str) and item.strip() for item in (rule_id, language, message)):
        raise ValueError("finding must have rule_id, language, and message")
    return FindingSignature(
        rule_id=" ".join(rule_id.split()),
        language=language,
        message=" ".join(message.split()),
    )


def _fresh_analysis(source_code: str, language: str, file: str) -> dict[str, Any]:
    """Run all analyzers from source text, independent of prior evidence."""

    ast_payload = BugDhorASTEngine().analyze_source(source_code, language)
    detection = BugDhorDetectionEngine().analyze_source(
        source_code, language, file=file
    )
    flow = FlowEngine().analyze_source(source_code, language, file=file)
    findings = [item.to_dict() for item in detection.diagnostics]
    findings.extend(item.to_dict() for item in taint_diagnostics(flow))
    return {
        "findings": findings,
        "has_syntax_errors": bool(
            ast_payload["has_syntax_errors"]
            or detection.has_syntax_errors
            or flow.has_syntax_errors
        ),
        "limitations": tuple(flow.limitations),
    }


def _expected_after(patch: Patch, source_before: str) -> str:
    modified = source_before
    ordered = sorted(
        patch.edits,
        key=lambda item: (item.start_line, item.start_column),
        reverse=True,
    )
    for edit in ordered:
        if replace_span_text(modified, edit, edit.original_code) != modified:
            raise PatchStaleError(
                "The patch span did not match the supplied before source."
            )
        modified = replace_span_text(modified, edit, edit.proposed_code)
    return modified


def _observed(record_id: str, summary: str, value: Any) -> EvidenceRecord:
    return EvidenceRecord(
        id=record_id,
        status=EvidenceStatus.OBSERVED,
        kind="verification",
        summary=summary,
        value=value,
    )


def _derived(record_id: str, summary: str, value: Any) -> EvidenceRecord:
    return EvidenceRecord(
        id=record_id,
        status=EvidenceStatus.DERIVED,
        kind="verification",
        summary=summary,
        value=value,
    )


def _unavailable(record_id: str, summary: str) -> EvidenceRecord:
    return EvidenceRecord(
        id=record_id,
        status=EvidenceStatus.UNAVAILABLE,
        kind="verification",
        summary=summary,
        value={"reason": summary},
    )


def _check(check_id: str, status: CheckStatus, detail: str) -> VerificationCheck:
    return VerificationCheck(id=check_id, status=status, detail=detail)


def _result(
    *,
    status: VerificationStatus,
    finding: Mapping[str, Any],
    signature: FindingSignature,
    checks: tuple[VerificationCheck, ...],
    evidence: EvidenceCollection,
    summary: dict[str, Any],
    limitations: tuple[str, ...],
) -> VerificationResult:
    confidence = {
        VerificationStatus.VERIFIED: ConfidenceLevel.MEDIUM,
        VerificationStatus.PARTIALLY_VERIFIED: ConfidenceLevel.LOW,
        VerificationStatus.FAILED: ConfidenceLevel.HIGH,
        VerificationStatus.NOT_VERIFIED: ConfidenceLevel.LOW,
    }[status]
    return VerificationResult(
        status=status,
        finding_id=str(finding.get("finding_id") or finding_id_for(finding)),
        signature=signature,
        checks=checks,
        evidence=evidence,
        summary=summary,
        confidence=confidence,
        limitations=tuple(dict.fromkeys((*limitations, *_BASE_LIMITATIONS))),
    )


def verify_repair(
    finding: Any,
    source_after: str,
    *,
    source_before: str = "",
    patch: Patch | None = None,
    file: str | None = None,
    language: str | None = None,
) -> VerificationResult:
    """Independently reanalyze before/after source and verify a repair.

    The function does not modify files or execute source code. A ``VERIFIED``
    result means the independently reproduced finding is absent from fresh
    static analysis and no new findings were introduced; it is not a claim of
    functional correctness or exploitability.
    """

    finding_value = _as_mapping(finding, "finding")
    signature = signature_for_finding(finding_value)
    target_file = str(
        file
        or finding_value.get("file")
        or (patch.file if patch is not None else "")
        or "<source>"
    )
    resolved_language = str(
        language
        or finding_value.get("language")
        or (patch.edits[0].language if patch is not None and patch.edits else "")
        or detect_language(target_file)
        or ""
    )
    empty_summary = {
        "before_findings": 0,
        "after_findings": 0,
        "target_before": 0,
        "target_after": 0,
        "target_resolved": False,
        "new_finding_count": 0,
        "new_findings": [],
    }

    if not isinstance(source_after, str) or not source_after:
        return _result(
            status=VerificationStatus.NOT_VERIFIED,
            finding=finding_value,
            signature=signature,
            checks=(
                _check(
                    "inputs",
                    CheckStatus.UNAVAILABLE,
                    "Modified source text is required for verification.",
                ),
            ),
            evidence=EvidenceCollection().add(
                _unavailable("verify.inputs", "Modified source text is unavailable.")
            ),
            summary=empty_summary,
            limitations=("No verification was performed without modified source.",),
        )
    if not resolved_language:
        return _result(
            status=VerificationStatus.NOT_VERIFIED,
            finding=finding_value,
            signature=signature,
            checks=(
                _check(
                    "language",
                    CheckStatus.UNAVAILABLE,
                    "Language could not be determined from the finding or file.",
                ),
            ),
            evidence=EvidenceCollection().add(
                _unavailable("verify.language", "Analysis language is unavailable.")
            ),
            summary=empty_summary,
            limitations=("No verification was performed with an unknown language.",),
        )

    evidence = EvidenceCollection()
    checks: list[VerificationCheck] = []
    limitations: list[str] = []

    try:
        before = _fresh_analysis(source_before, resolved_language, target_file)
        after = _fresh_analysis(source_after, resolved_language, target_file)
    except Exception as error:  # noqa: BLE001 - report every analyzer failure honestly
        detail = f"Independent analysis failed: {type(error).__name__}: {error}"
        return _result(
            status=VerificationStatus.NOT_VERIFIED,
            finding=finding_value,
            signature=signature,
            checks=(_check("analysis", CheckStatus.UNAVAILABLE, detail),),
            evidence=EvidenceCollection().add(
                _unavailable("verify.analysis", detail)
            ),
            summary=empty_summary,
            limitations=(detail,),
        )

    before_counter = Counter(
        signature_for_finding(item) for item in before["findings"]
    )
    after_counter = Counter(
        signature_for_finding(item) for item in after["findings"]
    )
    target_before = before_counter[signature]
    target_after = after_counter[signature]
    new_counter = after_counter - before_counter
    new_findings = [
        {**item.to_dict(), "count": count}
        for item, count in sorted(
            new_counter.items(),
            key=lambda pair: (pair[0].rule_id, pair[0].language, pair[0].message),
        )
    ]

    summary = {
        "before_findings": len(before["findings"]),
        "after_findings": len(after["findings"]),
        "target_before": target_before,
        "target_after": target_after,
        "target_resolved": target_after < target_before,
        "new_finding_count": sum(new_counter.values()),
        "new_findings": new_findings,
    }

    evidence = evidence.add(
        _observed(
            "verify.source.before",
            "SHA-256 of the supplied before source.",
            {
                "file": target_file,
                "size": len(source_before.encode("utf-8")),
                "sha256": hashlib.sha256(
                    source_before.encode("utf-8")
                ).hexdigest(),
            },
        )
    )
    evidence = evidence.add(
        _observed(
            "verify.source.after",
            "SHA-256 of the supplied modified source.",
            {
                "file": target_file,
                "size": len(source_after.encode("utf-8")),
                "sha256": hashlib.sha256(
                    source_after.encode("utf-8")
                ).hexdigest(),
            },
        )
    )
    evidence = evidence.add(
        _observed(
            "verify.analysis.counts",
            "Finding counts from fresh before and after analysis.",
            summary,
        )
    )
    limitations.extend(str(item) for item in after["limitations"])

    if target_before == 0:
        detail = "The target finding was not reproduced by fresh analysis of the before source."
        checks.append(_check("baseline", CheckStatus.UNAVAILABLE, detail))
        evidence = evidence.add(_unavailable("verify.baseline", detail))
        return _result(
            status=VerificationStatus.NOT_VERIFIED,
            finding=finding_value,
            signature=signature,
            checks=tuple(checks),
            evidence=evidence,
            summary=summary,
            limitations=(detail,),
        )
    checks.append(
        _check(
            "baseline",
            CheckStatus.PASS,
            f"The target finding was reproduced {target_before} time(s) before repair.",
        )
    )

    if after["has_syntax_errors"]:
        checks.append(
            _check(
                "reparse",
                CheckStatus.FAIL,
                "The modified source contains syntax errors after repair.",
            )
        )
    else:
        checks.append(
            _check(
                "reparse",
                CheckStatus.PASS,
                "The modified source reparsed without syntax errors.",
            )
        )

    if summary["target_resolved"]:
        checks.append(
            _check(
                "target_resolution",
                CheckStatus.PASS,
                (
                    f"Target findings decreased from {target_before} to "
                    f"{target_after} in fresh analysis."
                ),
            )
        )
        evidence = evidence.add(
            _derived(
                "verify.target_resolved",
                "The original finding signature was absent from fresh analysis.",
                value={"before": target_before, "after": target_after},
            )
        )
    else:
        checks.append(
            _check(
                "target_resolution",
                CheckStatus.FAIL,
                (
                    f"Target findings remained at {target_after} after repair "
                    f"(before: {target_before})."
                ),
            )
        )

    if summary["new_finding_count"]:
        checks.append(
            _check(
                "new_findings",
                CheckStatus.FAIL,
                f"Fresh analysis reported {summary['new_finding_count']} new finding(s).",
            )
        )
        evidence = evidence.add(
            _derived(
                "verify.new_findings",
                "New finding signatures introduced after repair.",
                value=new_findings,
            )
        )
    else:
        checks.append(
            _check(
                "new_findings",
                CheckStatus.PASS,
                "Fresh analysis reported no new finding signatures.",
            )
        )

    if patch is None:
        detail = "No patch identity was supplied; patch application was not independently checked."
        checks.append(_check("patch_identity", CheckStatus.UNAVAILABLE, detail))
        evidence = evidence.add(_unavailable("verify.patch", detail))
        limitations.append(detail)
    else:
        before_matches = (
            source_size(source_before) == patch.source_size
            and sha256_text(source_before) == patch.source_sha256
        )
        after_matches = False
        if not before_matches:
            detail = "The supplied before source does not match the reviewed patch."
            checks.append(_check("patch_identity", CheckStatus.FAIL, detail))
        else:
            try:
                expected = _expected_after(patch, source_before)
                after_matches = sha256_text(expected) == sha256_text(source_after)
                detail = (
                    "The modified source exactly matches the reviewed patch."
                    if after_matches
                    else "The modified source does not match the reviewed patch."
                )
                checks.append(
                    _check(
                        "patch_identity",
                        CheckStatus.PASS if after_matches else CheckStatus.FAIL,
                        detail,
                    )
                )
            except PatchStaleError as error:
                detail = str(error)
                checks.append(
                    _check("patch_identity", CheckStatus.FAIL, detail)
                )
        evidence = evidence.add(
            _observed(
                "verify.patch",
                "Patch identity check against before and after source bytes.",
                value={
                    "patch_id": patch.patch_id,
                    "before_matches": before_matches,
                    "after_matches": after_matches,
                },
            )
        )

    failed = any(item.status is CheckStatus.FAIL for item in checks)
    unavailable = any(item.status is CheckStatus.UNAVAILABLE for item in checks)
    if failed:
        status = VerificationStatus.FAILED
    elif unavailable:
        status = VerificationStatus.PARTIALLY_VERIFIED
    else:
        status = VerificationStatus.VERIFIED

    return _result(
        status=status,
        finding=finding_value,
        signature=signature,
        checks=tuple(checks),
        evidence=evidence,
        summary=summary,
        limitations=limitations,
    )


__all__ = [
    "VERIFICATION_SCHEMA_VERSION",
    "VERIFICATION_SCOPE",
    "CheckStatus",
    "FindingSignature",
    "VerificationCheck",
    "VerificationResult",
    "VerificationStatus",
    "signature_for_finding",
    "verify_repair",
]
