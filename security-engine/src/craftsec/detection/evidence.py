"""Adapters that normalize heterogeneous analyzer output into evidence items.

Every adapter preserves the original analyzer identity, rule identifier, exact
location, and the reason a claim is merely an observation, an inference, or a
hypothesis. Nothing is scored here; scoring is a separate, documented fusion
step.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from craftsec.detection.ast_analysis import StructuralMatch, analyze_ast
from craftsec.detection.classification import (
    CATEGORY_INFO,
    category_for_taint,
    classify_text,
    default_cwe,
)
from craftsec.detection.config import FusionWeights
from craftsec.detection.llm import LLMClaim
from craftsec.detection.models import (
    ClaimKind,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidenceType,
    VulnerabilityCategory,
)
from craftsec.parsing.parser import ParsedSource
from craftsec.program_analysis.taint import TaintAnalysis, TaintFinding
from craftsec.static.models import (
    ScanStatus,
    StaticAnalysisResult,
    StaticFinding,
)

_TOOL_EVIDENCE_TYPES = {
    "semgrep": EvidenceType.SEMGREP,
    "bandit": EvidenceType.BANDIT,
    "codeql": EvidenceType.CODEQL,
    "joern": EvidenceType.JOERN,
}
_TOOL_RELIABILITY = {
    EvidenceType.SEMGREP: 0.85,
    EvidenceType.BANDIT: 0.80,
    EvidenceType.CODEQL: 0.95,
    EvidenceType.JOERN: 0.90,
}
_TAINT_SEVERITY = {
    "sql_injection": "high",
    "command_injection": "critical",
    "xss": "high",
    "path_traversal": "high",
    "unsafe_deserialization": "critical",
}


@dataclass(frozen=True, slots=True)
class StaticEvidenceBundle:
    """Static-tool evidence plus explicit coverage metadata."""

    items: tuple[EvidenceItem, ...] = ()
    tools_available: tuple[str, ...] = ()
    tools_missing: tuple[str, ...] = ()
    tools_failed: tuple[str, ...] = ()
    tools_timed_out: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LLMEvidenceBundle:
    """Accepted LLM hypothesis evidence and rejected-claim diagnostics."""

    items: tuple[EvidenceItem, ...] = ()
    rejected: tuple[str, ...] = ()
    accepted_count: int = 0
    rejected_count: int = 0


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """All evidence for one detection run before grouping and fusion."""

    items: tuple[EvidenceItem, ...] = ()
    tools_available: tuple[str, ...] = ()
    tools_missing: tuple[str, ...] = ()
    tools_failed: tuple[str, ...] = ()
    tools_timed_out: tuple[str, ...] = ()
    llm_accepted: int = 0
    llm_rejected: int = 0
    gaps: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def extended(self, extra: Iterable[EvidenceItem]) -> EvidenceBundle:
        return EvidenceBundle(
            items=(*self.items, *extra),
            tools_available=self.tools_available,
            tools_missing=self.tools_missing,
            tools_failed=self.tools_failed,
            tools_timed_out=self.tools_timed_out,
            llm_accepted=self.llm_accepted,
            llm_rejected=self.llm_rejected,
            gaps=self.gaps,
            warnings=self.warnings,
        )


def ast_evidence(
    parsed: ParsedSource,
    *,
    path: str | None = None,
    config_hash: str | None = None,
) -> tuple[EvidenceItem, ...]:
    """Convert conservative AST matches into observation evidence."""
    file_path = path or parsed.path or "<memory>"
    items: list[EvidenceItem] = []
    for match in analyze_ast(parsed, path=file_path):
        items.append(_ast_item(match, file_path, config_hash))
    return tuple(items)


def taint_evidence(
    analysis: TaintAnalysis,
    *,
    weights: FusionWeights,
    path: str | None = None,
    config_hash: str | None = None,
) -> tuple[EvidenceItem, ...]:
    """Convert potential source-to-sink flows into inference evidence."""
    file_path = path or analysis.parsed.path or "<memory>"
    items: list[EvidenceItem] = []
    for finding in analysis.findings:
        items.append(_taint_item(finding, file_path, weights, config_hash))
    return tuple(items)


def static_evidence(
    analysis: StaticAnalysisResult | Sequence[StaticFinding] | None,
    *,
    weights: FusionWeights,
    path: str | None = None,
) -> StaticEvidenceBundle:
    """Convert normalized static findings while preserving tool coverage."""
    if analysis is None:
        return StaticEvidenceBundle(
            warnings=("No external static-analyzer result was supplied.",),
        )
    if isinstance(analysis, StaticAnalysisResult):
        findings: Sequence[StaticFinding] = analysis.findings
        scans = analysis.scans
        warnings = tuple(analysis.warnings)
    else:
        findings = analysis
        scans = ()
        warnings = (
            "Static findings were supplied without tool coverage metadata; "
            "missing tools cannot be distinguished from clean tools.",
        )
    items: list[EvidenceItem] = []
    for finding in findings:
        if path is not None and not _paths_match(finding.location.path, path):
            continue
        items.append(_static_item(finding, weights))

    available: list[str] = []
    missing: list[str] = []
    failed: list[str] = []
    timed_out: list[str] = []
    gaps: list[str] = []
    for scan in scans:
        tool = scan.tool.lower()
        if not scan.availability.available:
            missing.append(tool)
            reason = scan.availability.reason_code or scan.availability.status.value
            gaps.append(f"{tool} was unavailable ({reason}); its findings are unknown.")
            continue
        available.append(tool)
        if scan.status is ScanStatus.TIMEOUT:
            timed_out.append(tool)
            gaps.append(f"{tool} timed out; its findings are incomplete.")
        elif scan.status in {ScanStatus.FAILED, ScanStatus.UNAVAILABLE}:
            failed.append(tool)
            reason = scan.reason_code or scan.status.value
            gaps.append(f"{tool} failed ({reason}); its findings are incomplete.")
        elif scan.status is ScanStatus.PARTIAL:
            gaps.append(f"{tool} completed partially; its findings may be incomplete.")
    if not scans:
        gaps.append(
            "External tool coverage is unknown; supplied findings cannot be "
            "treated as a complete scan."
        )
    return StaticEvidenceBundle(
        items=tuple(items),
        tools_available=tuple(dict.fromkeys(available)),
        tools_missing=tuple(dict.fromkeys(missing)),
        tools_failed=tuple(dict.fromkeys(failed)),
        tools_timed_out=tuple(dict.fromkeys(timed_out)),
        gaps=tuple(dict.fromkeys(gaps)),
        warnings=warnings,
    )


def llm_evidence(
    claims: Sequence[LLMClaim] | None,
    *,
    weights: FusionWeights,
    min_confidence: float = 0.35,
) -> LLMEvidenceBundle:
    """Accept only compatible, located, classifiable LLM claims.

    LLM confidence is neither calibrated nor comparable to a tool's severity.
    It is capped by ``FusionWeights.llm`` and recorded as a hypothesis.
    """
    if not claims:
        return LLMEvidenceBundle()
    items: list[EvidenceItem] = []
    rejected: list[str] = []
    for claim in claims:
        category = claim.resolved_category
        cwe = claim.resolved_cwe
        reason: str | None = None
        if not claim.compatible:
            reason = "claim is marked incompatible with the detection contract"
        elif category is VulnerabilityCategory.UNKNOWN:
            reason = "claim has no supported category or CWE mapping"
        elif cwe is None:
            reason = "claim has no supported CWE"
        elif claim.confidence < min_confidence:
            reason = "claim confidence is below the configured LLM threshold"
        if reason is not None:
            rejected.append(f"{claim.identity}: {reason}")
            continue
        items.append(
            EvidenceItem(
                evidence_id=_evidence_id(
                    "llm",
                    claim.identity,
                    claim.location,
                    claim.rule_id or category.value,
                    cwe,
                ),
                evidence_type=EvidenceType.LLM,
                family=EvidenceFamily.LLM,
                claim_kind=ClaimKind.HYPOTHESIS,
                source=claim.identity,
                location=claim.location,
                category=category,
                cwe=cwe,
                strength=weights.llm_support(claim.confidence),
                reliability=weights.llm_reliability,
                severity_hint=CATEGORY_INFO.get(category).base_severity
                if category in CATEGORY_INFO
                else "low",
                rule_id=claim.rule_id or f"llm.{category.value}",
                title=claim.title or f"LLM hypothesis: {category.value.replace('_', ' ')}",
                detail=(
                    "Compatible LLM analysis hypothesis. The confidence is "
                    "uncalibrated and must not be read as a probability."
                ),
                prompt_hash=claim.prompt_hash,
                limitations=(
                    "LLM analysis is a hypothesis generator, not a verifier.",
                    "Model confidence is uncalibrated in this run.",
                ),
                calibration=claim.calibration,
            )
        )
    return LLMEvidenceBundle(
        items=tuple(items),
        rejected=tuple(rejected),
        accepted_count=len(items),
        rejected_count=len(rejected),
    )


def build_evidence(
    *,
    parsed: ParsedSource,
    weights: FusionWeights,
    path: str | None = None,
    taint: TaintAnalysis | None = None,
    static: StaticAnalysisResult | Sequence[StaticFinding] | None = None,
    llm_claims: Sequence[LLMClaim] | None = None,
    config_hash: str | None = None,
    llm_min_confidence: float = 0.35,
) -> EvidenceBundle:
    """Run all evidence adapters and combine their records."""
    file_path = path or parsed.path or "<memory>"
    static_bundle = static_evidence(static, weights=weights, path=file_path)
    llm_bundle = llm_evidence(
        llm_claims,
        weights=weights,
        min_confidence=llm_min_confidence,
    )
    items: list[EvidenceItem] = list(ast_evidence(parsed, path=file_path, config_hash=config_hash))
    if taint is not None:
        items.extend(
            taint_evidence(
                taint,
                weights=weights,
                path=file_path,
                config_hash=config_hash,
            )
        )
    items.extend(static_bundle.items)
    items.extend(llm_bundle.items)
    gaps = list(static_bundle.gaps)
    warnings = list(static_bundle.warnings)
    warnings.extend(llm_bundle.rejected)
    return EvidenceBundle(
        items=tuple(items),
        tools_available=static_bundle.tools_available,
        tools_missing=static_bundle.tools_missing,
        tools_failed=static_bundle.tools_failed,
        tools_timed_out=static_bundle.tools_timed_out,
        llm_accepted=llm_bundle.accepted_count,
        llm_rejected=llm_bundle.rejected_count,
        gaps=tuple(dict.fromkeys(gaps)),
        warnings=tuple(warnings),
    )


def _ast_item(
    match: StructuralMatch,
    path: str,
    config_hash: str | None,
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=_evidence_id(
            "ast",
            "craftsec.ast",
            match.to_location(path),
            match.rule_id,
            match.cwe,
        ),
        evidence_type=EvidenceType.AST,
        family=EvidenceFamily.PROGRAM_ANALYSIS,
        claim_kind=ClaimKind.OBSERVATION,
        source="craftsec.ast",
        location=match.to_location(path),
        category=match.category,
        cwe=match.cwe,
        strength=match.strength,
        reliability=match.reliability,
        severity_hint=match.severity_hint,
        rule_id=match.rule_id,
        title=match.title,
        detail=match.detail,
        config_hash=config_hash,
        limitations=match.limitations
        + ("AST evidence is structural and does not establish attacker control.",),
    )


def _taint_item(
    finding: TaintFinding,
    path: str,
    weights: FusionWeights,
    config_hash: str | None,
) -> EvidenceItem:
    category = category_for_taint(finding.kind.value)
    if category is VulnerabilityCategory.COMMAND_INJECTION and _looks_like_code_sink(
        finding.sink_rule
    ):
        category = VulnerabilityCategory.CODE_INJECTION
    location = EvidenceLocation.from_source(finding.sink_span, path)
    source_location = EvidenceLocation.from_source(finding.source_span, path)
    related = tuple(
        dict.fromkeys(
            (
                source_location,
                *(EvidenceLocation.from_source(step.span, path) for step in finding.path[:-1]),
            )
        )
    )
    return EvidenceItem(
        evidence_id=_evidence_id(
            "taint",
            "craftsec.taint",
            location,
            finding.sink_rule,
            default_cwe(category),
        ),
        evidence_type=EvidenceType.TAINT,
        family=EvidenceFamily.PROGRAM_ANALYSIS,
        claim_kind=ClaimKind.INFERENCE,
        source="craftsec.taint",
        location=location,
        related_locations=related,
        category=category,
        cwe=default_cwe(category),
        strength=weights.taint,
        reliability=weights.taint_confidence_factor(finding.confidence.value),
        severity_hint=CATEGORY_INFO[category].base_severity
        if category in CATEGORY_INFO
        else "high",
        rule_id=f"taint.{finding.kind.value}",
        title=finding.title,
        detail=(
            f"Potential {finding.kind.value.replace('_', ' ')} flow from "
            f"{finding.source_rule} to {finding.sink_rule}. "
            "The path is syntactic; runtime exploitability is not established."
        ),
        config_hash=config_hash,
        limitations=tuple(finding.limitations)
        + ("Taint confidence describes the syntactic flow, not exploitability.",),
    )


def _static_item(finding: StaticFinding, weights: FusionWeights) -> EvidenceItem:
    tool = finding.tool.lower()
    evidence_type = _TOOL_EVIDENCE_TYPES.get(tool, EvidenceType.SEMGREP)
    classification = classify_text(
        rule_id=finding.rule_id,
        message=finding.message,
        title=finding.rule_name,
        cwes=finding.cwes,
    )
    category = classification.category
    cwe = classification.cwe
    severity = finding.severity
    location = EvidenceLocation.from_static(finding.location)
    detail = finding.message
    if finding.evidence:
        detail = f"{detail} Evidence: {finding.evidence}"
    return EvidenceItem(
        evidence_id=_evidence_id(
            tool,
            tool,
            location,
            finding.rule_id,
            cwe,
        ),
        evidence_type=evidence_type,
        family=EvidenceFamily.STATIC_TOOL,
        claim_kind=ClaimKind.OBSERVATION,
        source=tool,
        location=location,
        category=category,
        cwe=cwe,
        strength=weights.tool_support(tool, severity),
        reliability=_TOOL_RELIABILITY.get(evidence_type, 0.8),
        severity_hint=severity,
        rule_id=finding.rule_id,
        title=finding.rule_name or f"{tool} rule {finding.rule_id}",
        detail=detail,
        reference_url=None,
        tool_version=finding.tool_version,
        config_hash=finding.config_hash,
        limitations=(
            "External tool severity is tool-specific and uncalibrated.",
            *(
                ()
                if classification.classified
                else ("The tool did not supply a CWE mapped to a supported category.",)
            ),
        ),
    )


def _looks_like_code_sink(rule: str) -> bool:
    lowered = rule.lower()
    return any(token in lowered for token in ("eval", "exec", "code_injection", "code."))


def _evidence_id(
    prefix: str,
    source: str,
    location: EvidenceLocation,
    rule_id: str | None,
    cwe: str | None,
) -> str:
    material = "|".join(
        (
            prefix,
            source,
            location.path,
            str(location.start_line),
            str(location.start_column),
            str(location.end_line),
            str(location.end_column),
            rule_id or "",
            cwe or "",
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"ev-{digest[:20]}"


def _paths_match(left: str, right: str) -> bool:
    if left == right:
        return True
    left = left.replace("\\", "/")
    right = right.replace("\\", "/")
    return left.endswith("/" + right) or right.endswith("/" + left)


__all__ = [
    "EvidenceBundle",
    "LLMEvidenceBundle",
    "StaticEvidenceBundle",
    "ast_evidence",
    "build_evidence",
    "llm_evidence",
    "static_evidence",
    "taint_evidence",
]
