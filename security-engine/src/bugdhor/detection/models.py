"""Immutable records for evidence fusion and explainable vulnerability findings.

The engine keeps heterogeneous evidence separate until fusion. Each evidence
item retains its source, claim kind, location, strength, reliability, and
limitations. A fused finding records the contributions that produced its
heuristic risk and, when explicitly supplied, a separately calibrated
probability. The two are never presented as interchangeable numbers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote

from bugdhor.static.models import (
    SourceLocation,
    max_severity,
    severity_rank,
    utc_now_iso,
)

_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
_SEVERITIES = ("critical", "high", "medium", "low", "info")


class EvidenceType(StrEnum):
    """The analyzer that produced one evidence item."""

    AST = "ast"
    CFG = "cfg"
    DFG = "dfg"
    TAINT = "taint"
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    CODEQL = "codeql"
    JOERN = "joern"
    LLM = "llm"


class EvidenceFamily(StrEnum):
    """Coarse dependency family used to avoid double-counting evidence."""

    PROGRAM_ANALYSIS = "program_analysis"
    STATIC_TOOL = "static_tool"
    LLM = "llm"


class EvidencePolarity(StrEnum):
    """Whether evidence supports or refutes a candidate finding."""

    SUPPORTS = "supports"
    REFUTES = "refutes"


class ClaimKind(StrEnum):
    """Epistemic status of one evidence item."""

    OBSERVATION = "observation"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"


class VulnerabilityCategory(StrEnum):
    """Vulnerability classes the engine can classify without guessing."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_TLS = "insecure_tls"
    XXE = "xxe"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    INPUT_VALIDATION = "input_validation"
    UNKNOWN = "unknown"

    @property
    def is_classified(self) -> bool:
        return self is not VulnerabilityCategory.UNKNOWN


@dataclass(frozen=True, slots=True)
class EvidenceLocation:
    """A zero-based source range used for localization and grouping."""

    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        if not self.path or not self.path.strip():
            raise ValueError("evidence location path must not be empty")
        values = (self.start_line, self.start_column, self.end_line, self.end_column)
        if any(not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("evidence coordinates must be non-negative integers")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("evidence end must not precede start")

    @classmethod
    def from_static(cls, location: SourceLocation) -> EvidenceLocation:
        return cls(
            path=location.path,
            start_line=location.start_line,
            start_column=location.start_column,
            end_line=location.end_line,
            end_column=location.end_column,
        )

    @classmethod
    def from_source(cls, span: Any, path: str) -> EvidenceLocation:
        return cls(
            path=path,
            start_line=span.start.line,
            start_column=span.start.character,
            end_line=span.end.line,
            end_column=span.end.character,
        )

    @property
    def start(self) -> tuple[int, int]:
        return (self.start_line, self.start_column)

    @property
    def end(self) -> tuple[int, int]:
        return (self.end_line, self.end_column)

    def overlaps(self, other: EvidenceLocation) -> bool:
        return (
            _paths_match(self.path, other.path)
            and self.start <= other.end
            and other.start <= self.end
        )

    def line_distance(self, other: EvidenceLocation) -> int:
        if not _paths_match(self.path, other.path):
            return 1_000_000
        if self.overlaps(other):
            return 0
        if self.end_line < other.start_line:
            return other.start_line - self.end_line
        return self.start_line - other.end_line

    def to_contract_dict(self) -> dict[str, dict[str, int]]:
        return {
            "start": {"line": self.start_line, "column": self.start_column},
            "end": {"line": self.end_line, "column": self.end_column},
        }

    def to_api_range(self) -> dict[str, dict[str, int]]:
        return {
            "start": {"line": self.start_line, "character": self.start_column},
            "end": {"line": self.end_line, "character": self.end_column},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "startLine": self.start_line,
            "startColumn": self.start_column,
            "endLine": self.end_line,
            "endColumn": self.end_column,
        }


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One normalized observation, inference, or hypothesis."""

    evidence_id: str
    evidence_type: EvidenceType
    family: EvidenceFamily
    claim_kind: ClaimKind
    source: str
    location: EvidenceLocation
    category: VulnerabilityCategory = VulnerabilityCategory.UNKNOWN
    cwe: str | None = None
    strength: float = 0.0
    reliability: float = 1.0
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS
    severity_hint: str = "info"
    rule_id: str | None = None
    title: str | None = None
    detail: str = ""
    related_locations: tuple[EvidenceLocation, ...] = ()
    reference_url: str | None = None
    tool_version: str | None = None
    config_hash: str | None = None
    prompt_hash: str | None = None
    limitations: tuple[str, ...] = ()
    calibration: CalibratedProbability | None = None

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.source:
            raise ValueError("evidence_id and source must be non-empty")
        for name, value in (("strength", self.strength), ("reliability", self.reliability)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.cwe is not None and not _CWE_RE.match(self.cwe):
            raise ValueError(f"invalid CWE identifier: {self.cwe!r}")
        if self.severity_hint not in _SEVERITIES:
            raise ValueError(f"unsupported severity hint: {self.severity_hint!r}")

    @property
    def effective_support(self) -> float:
        return self.strength * self.reliability

    @property
    def evidence_kind(self) -> str:
        """Map to the shared contract's evidence kind vocabulary."""
        if self.evidence_type is EvidenceType.LLM:
            return "model_score"
        if self.family is EvidenceFamily.STATIC_TOOL:
            return "static"
        return "structural"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidenceId": self.evidence_id,
            "type": self.evidence_type.value,
            "family": self.family.value,
            "claimKind": self.claim_kind.value,
            "source": self.source,
            "category": self.category.value,
            "cwe": self.cwe,
            "location": self.location.to_dict(),
            "relatedLocations": [location.to_dict() for location in self.related_locations],
            "strength": round(self.strength, 4),
            "reliability": round(self.reliability, 4),
            "effectiveSupport": round(self.effective_support, 4),
            "polarity": self.polarity.value,
            "severityHint": self.severity_hint,
            "ruleId": self.rule_id,
            "title": self.title,
            "detail": self.detail,
            "referenceUrl": self.reference_url,
            "toolVersion": self.tool_version,
            "configHash": self.config_hash,
            "promptHash": self.prompt_hash,
            "limitations": list(self.limitations),
            "calibratedProbability": (
                self.calibration.to_dict() if self.calibration is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class CweSupport:
    """One CWE candidate and the evidence that supports it."""

    cwe: str
    category: VulnerabilityCategory
    support: float
    sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _CWE_RE.match(self.cwe):
            raise ValueError(f"invalid CWE identifier: {self.cwe!r}")
        if not 0.0 <= self.support <= 1.0:
            raise ValueError("CWE support must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "category": self.category.value,
            "support": round(self.support, 4),
            "sources": list(self.sources),
        }


@dataclass(frozen=True, slots=True)
class RiskContribution:
    """Why one evidence family contributed to the heuristic risk."""

    family: EvidenceFamily
    family_score: float
    marginal_contribution: float
    evidence_types: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "familyScore": round(self.family_score, 4),
            "marginalContribution": round(self.marginal_contribution, 4),
            "evidenceTypes": list(self.evidence_types),
        }


@dataclass(frozen=True, slots=True)
class HeuristicRisk:
    """A transparent, uncalibrated risk score in ``[0, 1]``."""

    value: float
    band: str
    contributions: tuple[RiskContribution, ...] = ()
    refutation_penalty: float = 0.0
    rationale: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("heuristic risk must be between 0 and 1")
        if self.band not in _SEVERITIES:
            raise ValueError(f"unsupported risk band: {self.band!r}")

    @property
    def interpretation(self) -> str:
        return "heuristic_risk"

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.value, 4),
            "kind": "heuristic",
            "interpretation": self.interpretation,
            "band": self.band,
            "contributions": [item.to_dict() for item in self.contributions],
            "refutationPenalty": round(self.refutation_penalty, 4),
            "rationale": list(self.rationale),
        }


@dataclass(frozen=True, slots=True)
class CalibratedProbability:
    """A probability that carries an explicitly validated calibrator."""

    value: float
    calibrator_artifact_id: str
    method: str
    dataset_id: str
    split_hash: str
    brier_score: float
    expected_calibration_error: float

    _METHODS = ("isotonic", "platt", "beta", "temperature_scaling")

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("calibrated probability must be between 0 and 1")
        if self.method not in self._METHODS:
            raise ValueError(f"unsupported calibration method: {self.method!r}")
        if not self.calibrator_artifact_id or not self.dataset_id:
            raise ValueError("calibrator artifact and dataset identifiers are required")
        if not _SHA256_RE.match(self.split_hash):
            raise ValueError("split_hash must be a lowercase SHA-256 digest")
        for name, metric in (
            ("brier_score", self.brier_score),
            ("expected_calibration_error", self.expected_calibration_error),
        ):
            if not 0.0 <= metric <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")

    @property
    def interpretation(self) -> str:
        return "calibrated_probability"

    def to_contract_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.calibrator_artifact_id,
            "method": self.method,
            "datasetId": self.dataset_id,
            "splitHash": self.split_hash,
            "metrics": {
                "brierScore": self.brier_score,
                "expectedCalibrationError": self.expected_calibration_error,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.value, 4),
            "kind": "calibrated",
            "interpretation": self.interpretation,
            "calibrator": self.to_contract_dict(),
        }


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Heuristic risk plus an optional, strictly separate calibrated probability."""

    heuristic: HeuristicRisk
    calibrated: CalibratedProbability | None = None

    @property
    def probability(self) -> float | None:
        """Return a probability only when a validated calibrator exists."""
        return self.calibrated.value if self.calibrated is not None else None

    def to_contract_dict(self) -> dict[str, Any]:
        """Return the single ``RiskScore`` object allowed by the shared schema.

        The calibrated value is used only when a calibrator is present. The
        heuristic score remains in the engine record and must not be rendered as
        a probability.
        """
        if self.calibrated is not None:
            return {
                "value": round(self.calibrated.value, 4),
                "kind": "calibrated",
                "interpretation": self.calibrated.interpretation,
                "band": self.heuristic.band,
                "calibrator": self.calibrated.to_contract_dict(),
            }
        return {
            "value": round(self.heuristic.value, 4),
            "kind": "heuristic",
            "interpretation": self.heuristic.interpretation,
            "band": self.heuristic.band,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "heuristic": self.heuristic.to_dict(),
            "calibratedProbability": (
                self.calibrated.to_dict() if self.calibrated is not None else None
            ),
            "scoreKind": "calibrated" if self.calibrated is not None else "heuristic",
        }


@dataclass(frozen=True, slots=True)
class Provenance:
    producer: str
    producer_version: str
    generated_at: str
    source: str
    config_hash: str | None = None

    def __post_init__(self) -> None:
        if not _ISO_RE.match(self.generated_at):
            raise ValueError("generated_at must be a UTC ISO-8601 timestamp")
        if self.source not in {"static", "model", "human", "hybrid"}:
            raise ValueError(f"unsupported provenance source: {self.source!r}")

    def to_contract_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "producer": self.producer,
            "producerVersion": self.producer_version,
            "generatedAt": self.generated_at,
            "source": self.source,
        }
        if self.config_hash:
            result["configHash"] = self.config_hash
        return result

    def to_dict(self) -> dict[str, Any]:
        return self.to_contract_dict()


@dataclass(frozen=True, slots=True)
class VulnerabilityFinding:
    """One explainable, deduplicated vulnerability finding."""

    finding_id: str
    category: VulnerabilityCategory
    cwe: str
    title: str
    severity: str
    location: EvidenceLocation
    document_uri: str | None
    evidence: tuple[EvidenceItem, ...]
    cwe_support: tuple[CweSupport, ...]
    risk: RiskAssessment
    explanation: str
    suggested_remediation: str
    provenance: Provenance
    limitations: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.finding_id or not self.title:
            raise ValueError("finding_id and title must be non-empty")
        if not _CWE_RE.match(self.cwe):
            raise ValueError(f"invalid CWE identifier: {self.cwe!r}")
        if self.severity not in _SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity!r}")

    @property
    def evidence_sources(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.source for item in self.evidence))

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.family.value for item in self.evidence))

    @property
    def priority_key(self) -> tuple[int, float, float, str]:
        """Severity first, then calibrated (if any) and heuristic risk."""
        calibrated = self.risk.probability
        secondary = calibrated if calibrated is not None else self.risk.heuristic.value
        return (
            -severity_rank(self.severity),
            -secondary,
            -self.risk.heuristic.value,
            self.finding_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "category": self.category.value,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "filePath": self.location.path,
            "documentUri": self.document_uri,
            "location": self.location.to_dict(),
            "relatedLocations": [
                location.to_dict()
                for item in self.evidence
                for location in (item.location, *item.related_locations)
                if location != self.location
            ],
            "ruleIds": list(self.rule_ids),
            "evidenceSources": [item.to_dict() for item in self.evidence],
            "cweSupport": [item.to_dict() for item in self.cwe_support],
            "riskAssessment": self.risk.to_dict(),
            "explanation": self.explanation,
            "suggestedRemediation": self.suggested_remediation,
            "provenance": self.provenance.to_dict(),
            "limitations": list(self.limitations),
            "conflicts": list(self.conflicts),
        }

    def to_contract_dict(self) -> dict[str, Any]:
        """Serialize as ``shared/schemas/vulnerability-finding.json``."""
        evidence_sources: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in self.evidence:
            core = (item.evidence_kind, item.source, item.detail)
            if core in seen:
                continue
            seen.add(core)
            payload: dict[str, Any] = {
                "kind": item.evidence_kind,
                "source": item.source[:200],
                "detail": item.detail[:5000],
            }
            if item.reference_url:
                payload["reference"] = {
                    "label": (item.title or item.rule_id or item.source)[:500],
                    "url": item.reference_url,
                }
            evidence_sources.append(payload)
            if len(evidence_sources) >= 50:
                break
        if not evidence_sources:
            evidence_sources.append(
                {
                    "kind": "structural",
                    "source": "bugdhor-detection",
                    "detail": "Fused program-analysis evidence.",
                }
            )
        payload = {
            "findingId": self.finding_id,
            "filePath": self.location.path[:4096],
            "location": self.location.to_contract_dict(),
            "cwe": self.cwe,
            "severity": self.severity,
            "evidenceSources": evidence_sources,
            "riskScore": self.risk.to_contract_dict(),
            "explanation": self.explanation[:100_000],
            "suggestedRemediation": self.suggested_remediation[:100_000],
            "provenance": self.provenance.to_contract_dict(),
            "limitations": [item[:5000] for item in self.limitations[:100]],
        }
        if self.document_uri:
            payload["documentUri"] = self.document_uri
        if self.title:
            payload["title"] = self.title[:500]
        if self.rule_ids:
            payload["ruleId"] = self.rule_ids[0][:500]
        return payload

    def to_api_finding(self) -> dict[str, Any]:
        """Serialize in the camelCase shape accepted by ``api.schemas.Finding``."""
        uri = self.document_uri or _file_uri(self.location.path)
        references = []
        for item in self.evidence:
            if not item.reference_url and not item.rule_id:
                continue
            reference: dict[str, Any] = {"label": (item.title or item.rule_id or item.source)[:500]}
            if item.reference_url:
                reference["url"] = item.reference_url
            references.append(reference)
            if len(references) >= 50:
                break
        return {
            "id": self.finding_id,
            "message": self.title[:5000],
            "severity": self.severity,
            "cwe": self.cwe,
            "ruleId": self.rule_ids[0][:500] if self.rule_ids else None,
            "location": {
                "uri": uri,
                "range": self.location.to_api_range(),
            },
            "evidence": "\n".join(item.detail for item in self.evidence)[:100_000],
            "explanation": self.explanation[:100_000],
            "sourceReferences": references,
            "repair": None,
        }


@dataclass(frozen=True, slots=True)
class UnclassifiedCandidate:
    """Evidence that could not be assigned a supported CWE mapping."""

    candidate_id: str
    location: EvidenceLocation
    reason: str
    evidence: tuple[EvidenceItem, ...] = ()
    heuristic_risk: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidateId": self.candidate_id,
            "location": self.location.to_dict(),
            "reason": self.reason,
            "heuristicRisk": (
                round(self.heuristic_risk, 4) if self.heuristic_risk is not None else None
            ),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class DetectionCoverage:
    """What the engine actually inspected and what it could not inspect."""

    program_analysis: bool
    syntax_error_count: int = 0
    tools_available: tuple[str, ...] = ()
    tools_missing: tuple[str, ...] = ()
    tools_failed: tuple[str, ...] = ()
    tools_timed_out: tuple[str, ...] = ()
    llm_accepted: int = 0
    llm_rejected: int = 0
    evidence_gaps: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.evidence_gaps and self.syntax_error_count == 0

    @property
    def no_findings_conclusive(self) -> bool:
        return self.complete

    def to_dict(self) -> dict[str, Any]:
        return {
            "programAnalysis": self.program_analysis,
            "syntaxErrorCount": self.syntax_error_count,
            "toolsAvailable": list(self.tools_available),
            "toolsMissing": list(self.tools_missing),
            "toolsFailed": list(self.tools_failed),
            "toolsTimedOut": list(self.tools_timed_out),
            "llmAccepted": self.llm_accepted,
            "llmRejected": self.llm_rejected,
            "evidenceGaps": list(self.evidence_gaps),
            "complete": self.complete,
            "noFindingsConclusive": self.no_findings_conclusive,
        }


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """The complete output of one detection run."""

    findings: tuple[VulnerabilityFinding, ...]
    unclassified: tuple[UnclassifiedCandidate, ...]
    coverage: DetectionCoverage
    warnings: tuple[str, ...] = ()
    generated_at: str = field(default_factory=utc_now_iso)
    config_hash: str | None = None
    score_semantics: dict[str, str] = field(
        default_factory=lambda: {
            "heuristic": (
                "A documented evidence-fusion risk in [0, 1]. It is not a "
                "probability and must not be rendered as one."
            ),
            "calibrated": (
                "A probability produced only by a validated calibrator with "
                "dataset, split hash, and calibration metrics."
            ),
        }
    )

    def __post_init__(self) -> None:
        if not _ISO_RE.match(self.generated_at):
            raise ValueError("generated_at must be a UTC ISO-8601 timestamp")

    @property
    def status(self) -> str:
        return "ok" if self.coverage.complete else "partial"

    @property
    def evidence_sources(self) -> tuple[str, ...]:
        sources = {item.source for finding in self.findings for item in finding.evidence}
        sources.update(self.coverage.tools_available)
        return tuple(sorted(sources))

    def finding(self, finding_id: str) -> VulnerabilityFinding:
        for item in self.findings:
            if item.finding_id == finding_id:
                return item
        raise KeyError(f"unknown finding: {finding_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "generatedAt": self.generated_at,
            "configHash": self.config_hash,
            "scoreSemantics": dict(self.score_semantics),
            "coverage": self.coverage.to_dict(),
            "warnings": list(self.warnings),
            "evidenceSources": list(self.evidence_sources),
            "findingCount": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "unclassified": [item.to_dict() for item in self.unclassified],
        }

    def to_contract_dicts(self) -> list[dict[str, Any]]:
        return [item.to_contract_dict() for item in self.findings]

    def to_api_findings(self) -> list[dict[str, Any]]:
        return [item.to_api_finding() for item in self.findings]


def stable_finding_id(
    *,
    path: str,
    category: VulnerabilityCategory,
    cwe: str,
    location: EvidenceLocation,
    rule_ids: tuple[str, ...],
) -> str:
    """Build a deterministic identifier from localization and classification."""
    material = "|".join(
        (
            path,
            category.value,
            cwe,
            str(location.start_line),
            str(location.start_column),
            str(location.end_line),
            str(location.end_column),
            ",".join(sorted(rule_ids)),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"bugdhor-{digest[:16]}"


def strongest_severity(*values: str) -> str:
    """Return the highest severity after validating every value."""
    for value in values:
        if value not in _SEVERITIES:
            raise ValueError(f"unsupported severity: {value!r}")
    return max_severity(*values, "info")


def _file_uri(path: str) -> str:
    if path.startswith("file:"):
        return path
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError):
        return f"file://{quote(path)}"


def _paths_match(left: str, right: str) -> bool:
    if left == right:
        return True
    left = left.replace("\\", "/")
    right = right.replace("\\", "/")
    return left.endswith("/" + right) or right.endswith("/" + left)


__all__ = [
    "CalibratedProbability",
    "ClaimKind",
    "CweSupport",
    "DetectionCoverage",
    "DetectionResult",
    "EvidenceFamily",
    "EvidenceItem",
    "EvidenceLocation",
    "EvidencePolarity",
    "EvidenceType",
    "HeuristicRisk",
    "Provenance",
    "RiskAssessment",
    "RiskContribution",
    "UnclassifiedCandidate",
    "VulnerabilityCategory",
    "VulnerabilityFinding",
    "stable_finding_id",
    "strongest_severity",
]
