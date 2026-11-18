"""Evidence grouping, duplicate resolution, and transparent risk fusion.

The fusion strategy has four explicit steps:

1. Group compatible supporting evidence by source location and vulnerability
   category. This is duplicate resolution, not a vote.
2. Classify the group's category and CWE from weighted evidence. Unsupported
   groups remain unclassified instead of receiving a plausible CWE.
3. Score each evidence *family* independently. Within a family, repeated or
   dependent evidence is damped by a fixed redundancy decay and capped. Between
   families, independent signals are combined with a noisy-OR. Scores are never
   averaged.
4. Apply explicit refutation penalties from CFG reachability and observed
   sanitizers. Reachability alone is not support.

The result is a heuristic prioritization score. It is not a probability. A
calibrated probability is attached only when a caller supplies a validated
calibrator.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol, runtime_checkable

from bugdhor.detection.classification import (
    CATEGORY_INFO,
    Classification,
    classify_evidence,
    infer_category,
)
from bugdhor.detection.config import DEFAULT_DETECTION_CONFIG, DetectionConfig, FusionWeights
from bugdhor.detection.context import ContextAssessor
from bugdhor.detection.models import (
    CalibratedProbability,
    ClaimKind,
    DetectionCoverage,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidencePolarity,
    EvidenceType,
    HeuristicRisk,
    Provenance,
    RiskAssessment,
    RiskContribution,
    UnclassifiedCandidate,
    VulnerabilityCategory,
    VulnerabilityFinding,
    stable_finding_id,
)
from bugdhor.static.models import severity_rank, utc_now_iso

DETECTION_LIMITATIONS = (
    "LIM-DET-01: Fusion weights and family caps are documented configuration, "
    "not learned or calibrated probabilities.",
    "LIM-DET-02: AST, CFG, DFG, and taint evidence are one dependent program-"
    "analysis family. External tools are separate signals and may observe the "
    "same code path.",
    "LIM-DET-03: Compatible LLM output is a capped hypothesis family, never "
    "independent verification.",
    "LIM-DET-04: A CWE is emitted only when evidence supports both a category and "
    "a mapping. Unsupported evidence is retained as an unclassified candidate.",
    "LIM-DET-05: CFG and DFG context is intraprocedural. Unreachable-code "
    "refutation ignores external callers, reflection, and dynamic dispatch.",
    "LIM-DET-06: Missing, failed, and timed-out tools are coverage gaps. An empty "
    "result from an incomplete run is not a clean scan.",
    "LIM-DET-07: Calibrated probabilities are emitted only by an explicitly "
    "supplied calibrator with a dataset, split hash, and metrics. No calibrator "
    "ships with the engine.",
    "LIM-DET-08: Severity is the lower of the heuristic risk band and the "
    "vulnerability class's default severity. It is a prioritization label.",
)

_FAMILY_CAP_FIELDS = {
    EvidenceFamily.PROGRAM_ANALYSIS: "program_family_cap",
    EvidenceFamily.STATIC_TOOL: "static_family_cap",
    EvidenceFamily.LLM: "llm_family_cap",
}


@runtime_checkable
class CalibrationProvider(Protocol):
    """An explicitly validated source of calibrated probabilities.

    Implementations must not derive a probability from the heuristic score.
    Returning ``None`` is the correct behavior when a finding is outside the
    calibrator's validated distribution.
    """

    provider_id: str

    def calibrate(
        self,
        *,
        category: VulnerabilityCategory,
        cwe: str,
        location: EvidenceLocation,
        evidence: Sequence[EvidenceItem],
        heuristic: float,
    ) -> CalibratedProbability | None: ...


@dataclass(frozen=True, slots=True)
class FusionResult:
    findings: tuple[VulnerabilityFinding, ...]
    unclassified: tuple[UnclassifiedCandidate, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(slots=True)
class _Group:
    category: VulnerabilityCategory
    items: list[EvidenceItem] = field(default_factory=list)
    context: list[EvidenceItem] = field(default_factory=list)


def fuse_evidence(
    items: Iterable[EvidenceItem],
    *,
    assessor: ContextAssessor,
    config: DetectionConfig = DEFAULT_DETECTION_CONFIG,
    coverage: DetectionCoverage | None = None,
    calibration: CalibrationProvider | None = None,
    generated_at: str | None = None,
) -> FusionResult:
    """Group, classify, score, deduplicate, and prioritize evidence."""
    evidence_items = tuple(items)
    groups = _group_supporting_evidence(evidence_items, config)
    external_refutations = tuple(
        item for item in evidence_items if item.polarity is EvidencePolarity.REFUTES
    )
    warnings: list[str] = []
    findings: list[VulnerabilityFinding] = []
    unclassified: list[UnclassifiedCandidate] = []
    timestamp = generated_at or utc_now_iso()

    for group in groups:
        _attach_context(group, assessor, config)
        _attach_refutations(group, external_refutations, config)
        classification = classify_evidence(group.items)
        heuristic = _heuristic_risk(
            group.items,
            group.context,
            config,
            classification.category,
        )
        evidence = _merge_evidence(group.items, group.context, config.max_evidence)
        location = _representative_location(group.items)
        if classification.category is VulnerabilityCategory.UNKNOWN or classification.cwe is None:
            if config.include_unclassified:
                unclassified.append(
                    _unclassified_candidate(
                        group,
                        evidence,
                        classification.category,
                        classification.rationale,
                        heuristic,
                        location,
                    )
                )
            continue
        calibrated = None
        if calibration is not None:
            calibrated = calibration.calibrate(
                category=classification.category,
                cwe=classification.cwe,
                location=location,
                evidence=evidence,
                heuristic=heuristic.value,
            )
        finding = _build_finding(
            classification=classification,
            evidence=evidence,
            location=location,
            heuristic=heuristic,
            calibrated=calibrated,
            assessor=assessor,
            config=config,
            generated_at=timestamp,
            coverage=coverage,
        )
        findings.append(finding)

    findings.sort(key=lambda item: item.priority_key)
    if config.min_severity is not None:
        floor = severity_rank(config.min_severity)
        findings = [item for item in findings if severity_rank(item.severity) >= floor]
    if config.min_risk > 0.0:
        findings = [item for item in findings if item.risk.heuristic.value >= config.min_risk]
    if len(findings) > config.max_findings:
        warnings.append(
            f"Detection produced more than max_findings={config.max_findings}; "
            "lower-priority findings were truncated."
        )
        findings = findings[: config.max_findings]
    unclassified.sort(key=lambda item: (-(item.heuristic_risk or 0.0), item.candidate_id))
    return FusionResult(
        findings=tuple(findings),
        unclassified=tuple(unclassified),
        warnings=tuple(warnings),
    )


# --------------------------------------------------------------------------- #
# Grouping and duplicate resolution
# --------------------------------------------------------------------------- #
def _group_supporting_evidence(
    items: Sequence[EvidenceItem],
    config: DetectionConfig,
) -> list[_Group]:
    supports = [item for item in items if item.polarity is EvidencePolarity.SUPPORTS]
    supports.sort(key=_item_sort_key)
    groups: list[_Group] = []
    for item in supports:
        category = _resolved_category(item)
        if category is VulnerabilityCategory.UNKNOWN:
            groups.append(_Group(category=category, items=[item]))
            continue
        for group in groups:
            if group.category is not category:
                continue
            if any(
                _locations_compatible(
                    existing.location,
                    item.location,
                    config.group_line_tolerance,
                )
                for existing in group.items
            ):
                group.items.append(item)
                break
        else:
            groups.append(_Group(category=category, items=[item]))
    return groups


def _attach_context(
    group: _Group,
    assessor: ContextAssessor,
    config: DetectionConfig,
) -> None:
    has_taint_flow = any(
        item.evidence_type is EvidenceType.TAINT and item.polarity is EvidencePolarity.SUPPORTS
        for item in group.items
    )
    seen: set[str] = set()
    for location in dict.fromkeys(item.location for item in group.items):
        context_items = assessor.assess(
            location,
            group.category,
            weights=config.weights,
            has_taint_flow=has_taint_flow,
            enrich_cfg=config.enrich_cfg,
            enrich_dfg=config.enrich_dfg,
        )
        for item in context_items:
            if item.evidence_id in seen:
                continue
            seen.add(item.evidence_id)
            group.context.append(item)


def _attach_refutations(
    group: _Group,
    refutations: Sequence[EvidenceItem],
    config: DetectionConfig,
) -> None:
    """Keep caller-supplied refuting evidence instead of silently dropping it.

    Context analysis produces most refutations, but an adapter may already carry
    one (for example, a tool that reports a suppressed or unreachable result). A
    refutation is attached only to a group it actually touches, so a distant
    suppression cannot downgrade an unrelated finding.
    """
    seen = {item.evidence_id for item in group.context}
    for item in refutations:
        if item.evidence_id in seen:
            continue
        if not any(
            _locations_compatible(
                item.location,
                support.location,
                config.group_line_tolerance,
            )
            for support in group.items
        ):
            continue
        seen.add(item.evidence_id)
        group.context.append(item)


def _resolved_category(item: EvidenceItem) -> VulnerabilityCategory:
    if item.category is not VulnerabilityCategory.UNKNOWN:
        return item.category
    if item.cwe is not None:
        from bugdhor.detection.classification import category_for_cwe

        mapped = category_for_cwe(item.cwe)
        if mapped is not None:
            return mapped
    return infer_category(item.rule_id, item.title, item.detail)


def _locations_compatible(
    left: EvidenceLocation,
    right: EvidenceLocation,
    tolerance: int,
) -> bool:
    if left.overlaps(right):
        return True
    return left.line_distance(right) <= tolerance


def _item_sort_key(item: EvidenceItem) -> tuple[str, int, int, str]:
    return (
        item.location.path,
        item.location.start_line,
        item.location.start_column,
        item.evidence_id,
    )


def _representative_location(items: Sequence[EvidenceItem]) -> EvidenceLocation:
    priority = {
        EvidenceType.TAINT: 0,
        EvidenceType.CODEQL: 1,
        EvidenceType.SEMGREP: 1,
        EvidenceType.BANDIT: 1,
        EvidenceType.JOERN: 1,
        EvidenceType.PARSER: 1,
        EvidenceType.AST: 2,
        EvidenceType.LLM: 3,
    }
    return min(
        (item.location for item in items),
        key=lambda location: (
            min(priority.get(item.evidence_type, 4) for item in items if item.location == location),
            location.start_line,
            location.start_column,
            location.end_line,
            location.end_column,
        ),
    )


def _merge_evidence(
    support: Sequence[EvidenceItem],
    context: Sequence[EvidenceItem],
    limit: int,
) -> tuple[EvidenceItem, ...]:
    ordered = sorted(
        support,
        key=lambda item: (-item.effective_support, item.evidence_id),
    )
    merged = list(ordered[:limit])
    remaining = limit - len(merged)
    if remaining > 0:
        merged.extend(
            sorted(context, key=lambda item: (item.polarity.value, item.evidence_id))[:remaining]
        )
    return tuple(merged)


# --------------------------------------------------------------------------- #
# Risk fusion
# --------------------------------------------------------------------------- #
def _heuristic_risk(
    support: Sequence[EvidenceItem],
    context: Sequence[EvidenceItem],
    config: DetectionConfig,
    category: VulnerabilityCategory,
) -> HeuristicRisk:
    weights = config.weights
    scores = _family_scores(support, weights)
    combined = _noisy_or(scores.values())
    refutations = tuple(item for item in context if item.polarity is EvidencePolarity.REFUTES)
    refutation_noise = _noisy_or(item.effective_support for item in refutations)
    penalty = min(0.95, weights.refutation_scale * refutation_noise)
    value = max(0.0, min(1.0, combined * (1.0 - penalty)))
    band = config.thresholds.band(value)

    contributions: list[RiskContribution] = []
    for family, score in sorted(scores.items(), key=lambda pair: -pair[1]):
        others = _noisy_or(value for key, value in scores.items() if key is not family)
        marginal = max(0.0, combined - others) * (1.0 - penalty)
        types = tuple(
            dict.fromkeys(item.evidence_type.value for item in support if item.family is family)
        )
        contributions.append(
            RiskContribution(
                family=family,
                family_score=score,
                marginal_contribution=marginal,
                evidence_types=types,
            )
        )

    rationale = [
        "Family scores use redundancy-damped noisy-OR within each family; "
        "families are combined with noisy-OR, never averaged.",
    ]
    for contribution in contributions:
        rationale.append(
            f"{contribution.family.value} family contributed "
            f"{contribution.family_score:.2f} before cross-family combination."
        )
    if penalty > 0.0:
        rationale.append(f"Refutation evidence reduced the combined score by {penalty:.2f}.")
    if category in CATEGORY_INFO:
        rationale.append(
            f"{CATEGORY_INFO[category].title} has a class default severity of "
            f"{CATEGORY_INFO[category].base_severity}; severity cannot exceed it."
        )
    rationale.append("The value is a heuristic prioritization score, not a probability.")
    return HeuristicRisk(
        value=value,
        band=band,
        contributions=tuple(contributions),
        refutation_penalty=penalty,
        rationale=tuple(rationale),
    )


def _family_scores(
    items: Sequence[EvidenceItem],
    weights: FusionWeights,
) -> dict[EvidenceFamily, float]:
    by_family: dict[EvidenceFamily, list[EvidenceItem]] = {}
    for item in items:
        if item.polarity is not EvidencePolarity.SUPPORTS:
            continue
        by_family.setdefault(item.family, []).append(item)
    scores: dict[EvidenceFamily, float] = {}
    for family, entries in by_family.items():
        entries.sort(key=lambda item: (-item.effective_support, item.evidence_id))
        combined = 0.0
        for index, item in enumerate(entries):
            decayed = item.effective_support * (weights.redundancy_decay**index)
            combined = 1.0 - (1.0 - combined) * (1.0 - min(1.0, decayed))
        cap = getattr(weights, _FAMILY_CAP_FIELDS[family])
        scores[family] = min(cap, combined)
    program = by_family.get(EvidenceFamily.PROGRAM_ANALYSIS, ())
    distinct = {item.evidence_type for item in program}
    if len(distinct) > 1:
        bonus = min(
            weights.max_program_bonus,
            weights.program_family_bonus * (len(distinct) - 1),
        )
        scores[EvidenceFamily.PROGRAM_ANALYSIS] = min(
            weights.program_family_cap,
            scores.get(EvidenceFamily.PROGRAM_ANALYSIS, 0.0) + bonus,
        )
    return scores


def _noisy_or(values: Iterable[float]) -> float:
    product = 1.0
    for value in values:
        product *= 1.0 - max(0.0, min(1.0, value))
    return 1.0 - product


# --------------------------------------------------------------------------- #
# Finding construction
# --------------------------------------------------------------------------- #
def _build_finding(
    *,
    classification: Classification,
    evidence: Sequence[EvidenceItem],
    location: EvidenceLocation,
    heuristic: HeuristicRisk,
    calibrated: CalibratedProbability | None,
    assessor: ContextAssessor,
    config: DetectionConfig,
    generated_at: str,
    coverage: DetectionCoverage | None,
) -> VulnerabilityFinding:
    category: VulnerabilityCategory = classification.category
    cwe: str = classification.cwe
    info = CATEGORY_INFO[category]
    severity = _finding_severity(heuristic.band, info.base_severity)
    rule_ids = tuple(
        sorted(
            {
                item.rule_id
                for item in evidence
                if item.rule_id and item.polarity is EvidencePolarity.SUPPORTS
            }
        )
    )
    finding_id = stable_finding_id(
        path=location.path,
        category=category,
        cwe=cwe,
        location=location,
        rule_ids=rule_ids,
    )
    limitations = _finding_limitations(evidence, classification)
    explanation = _explain(
        category=category,
        cwe=cwe,
        severity=severity,
        location=location,
        evidence=evidence,
        classification=classification,
        heuristic=heuristic,
        calibrated=calibrated,
        coverage=coverage,
    )
    provenance_source = _provenance_source(evidence)
    confidence, confidence_basis = _confidence_summary(evidence)
    detection_method = _detection_method(evidence)
    uncertainty = tuple(dict.fromkeys((*limitations, *classification.conflicts)))
    return VulnerabilityFinding(
        finding_id=finding_id,
        category=category,
        cwe=cwe,
        title=f"{info.title} at {location.path}:{location.start_line + 1}",
        severity=severity,
        location=location,
        document_uri=None,
        evidence=tuple(evidence),
        cwe_support=tuple(classification.cwe_support),
        risk=RiskAssessment(heuristic=heuristic, calibrated=calibrated),
        explanation=explanation,
        suggested_remediation=info.remediation,
        provenance=Provenance(
            producer="bugdhor.detection",
            producer_version="0.1.0",
            generated_at=generated_at,
            source=provenance_source,
            config_hash=config.config_hash(),
        ),
        limitations=limitations,
        conflicts=tuple(classification.conflicts),
        rule_ids=rule_ids,
        confidence=confidence,
        confidence_basis=confidence_basis,
        uncertainty=uncertainty,
        detection_method=detection_method,
    )


def _unclassified_candidate(
    group: _Group,
    evidence: Sequence[EvidenceItem],
    category: VulnerabilityCategory,
    rationale: Sequence[str],
    heuristic: HeuristicRisk,
    location: EvidenceLocation,
) -> UnclassifiedCandidate:
    material = "|".join(
        (
            location.path,
            str(location.start_line),
            str(location.start_column),
            category.value,
            ",".join(sorted(item.evidence_id for item in evidence)),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return UnclassifiedCandidate(
        candidate_id=f"candidate-{digest[:16]}",
        location=location,
        reason=" ".join(rationale) or "No supported category and CWE mapping was available.",
        evidence=tuple(evidence),
        heuristic_risk=heuristic.value,
    )


def _confidence_summary(
    evidence: Sequence[EvidenceItem],
) -> tuple[str, str]:
    """Describe epistemic strength without inventing a probability."""
    supporting = [item for item in evidence if item.polarity is EvidencePolarity.SUPPORTS]
    claims = {item.claim_kind for item in supporting}
    if ClaimKind.OBSERVATION in claims:
        level = "observation"
    elif ClaimKind.INFERENCE in claims:
        level = "inference"
    elif claims:
        level = "hypothesis"
    else:
        level = "hypothesis"
    basis = (
        "Derived from the strongest supporting evidence claim kind "
        f"({', '.join(sorted(item.value for item in claims)) or 'none'}). "
        "This is an epistemic label, not a calibrated probability."
    )
    return level, basis


def _detection_method(evidence: Sequence[EvidenceItem]) -> str:
    """Name the concrete analysis layers that produced supporting evidence."""
    supporting = [item for item in evidence if item.polarity is EvidencePolarity.SUPPORTS]
    methods = tuple(dict.fromkeys(item.evidence_type.value for item in supporting))
    return "+".join(methods) or "unknown"


def _provenance_source(evidence: Sequence[EvidenceItem]) -> str:
    families = {item.family for item in evidence}
    if EvidenceFamily.LLM in families:
        return "model" if len(families) == 1 else "hybrid"
    return "static"


def _finding_severity(band: str, base_severity: str) -> str:
    """Use the lower of the risk band and the vulnerability-class ceiling."""
    if severity_rank(band) <= severity_rank(base_severity):
        return band
    return base_severity


def _finding_limitations(
    evidence: Sequence[EvidenceItem],
    classification: Classification,
) -> tuple[str, ...]:
    limitations: list[str] = list(DETECTION_LIMITATIONS)
    seen = set(limitations)
    for item in evidence:
        for limitation in item.limitations:
            if limitation not in seen:
                seen.add(limitation)
                limitations.append(limitation)
    for conflict in classification.conflicts:
        if conflict not in seen:
            seen.add(conflict)
            limitations.append(conflict)
    return tuple(limitations)


def _explain(
    *,
    category: VulnerabilityCategory,
    cwe: str,
    severity: str,
    location: EvidenceLocation,
    evidence: Sequence[EvidenceItem],
    classification: Classification,
    heuristic: HeuristicRisk,
    calibrated: CalibratedProbability | None,
    coverage: DetectionCoverage | None,
) -> str:
    info = CATEGORY_INFO[category]
    supporting = [item for item in evidence if item.polarity is EvidencePolarity.SUPPORTS]
    refuting = [item for item in evidence if item.polarity is EvidencePolarity.REFUTES]
    families = tuple(dict.fromkeys(item.family.value for item in supporting))
    sources = tuple(dict.fromkeys(item.source for item in supporting))
    rules = tuple(dict.fromkeys(item.rule_id for item in supporting if item.rule_id))
    lines = [
        f"{info.title} ({cwe}) was classified at "
        f"{location.path}:{location.start_line + 1}:{location.start_column + 1}.",
        f"Supporting evidence came from {len(supporting)} item(s) across "
        f"{', '.join(families) or 'no'} families"
        + (f" ({', '.join(sources)})." if sources else "."),
    ]
    if rules:
        lines.append("Rules and analyzers: " + ", ".join(rules[:8]) + ".")
    lines.append(" ".join(classification.rationale))
    lines.append(
        f"Heuristic risk is {heuristic.value:.2f} ({heuristic.band}); this is "
        "a documented fusion score, not a probability."
    )
    if calibrated is not None:
        lines.append(
            f"A separately validated calibrator produced a probability of "
            f"{calibrated.value:.2f} ({calibrated.method}, dataset "
            f"{calibrated.dataset_id})."
        )
    if heuristic.refutation_penalty > 0.0:
        lines.append(
            f"Refutation penalty {heuristic.refutation_penalty:.2f} was applied "
            f"from {len(refuting)} item(s)."
        )
        for item in refuting[:3]:
            lines.append(item.detail)
    if classification.conflicts:
        lines.append(
            "Conflicting CWE evidence was retained rather than discarded: "
            + " ".join(classification.conflicts[:3])
        )
    if coverage is not None and not coverage.complete:
        lines.append(
            "Coverage was incomplete: "
            + "; ".join(coverage.evidence_gaps[:4])
            + ("." if coverage.evidence_gaps else "syntax errors were present.")
        )
    lines.append(f"Severity is capped at the class default ({info.base_severity}).")
    return " ".join(lines)


def with_calibration(
    finding: VulnerabilityFinding,
    calibrated: CalibratedProbability | None,
) -> VulnerabilityFinding:
    """Return a copy with a calibrated probability attached or removed."""
    if calibrated is None:
        return finding
    return replace(
        finding,
        risk=RiskAssessment(heuristic=finding.risk.heuristic, calibrated=calibrated),
    )


__all__ = [
    "CalibrationProvider",
    "DETECTION_LIMITATIONS",
    "FusionResult",
    "fuse_evidence",
    "with_calibration",
]
