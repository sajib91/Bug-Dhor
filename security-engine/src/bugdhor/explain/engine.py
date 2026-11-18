"""Evidence-grounded vulnerability explanations.

This module assembles existing finding evidence without upgrading its
epistemic status. Program-analysis and static-tool records remain observations
or inferences, LLM text remains a hypothesis, SAE records remain associations,
and counterfactual records remain controlled output comparisons.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from bugdhor.detection.models import (
    ClaimKind,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidenceType,
    VulnerabilityFinding,
)
from bugdhor.program_analysis.taint import TaintAnalysis


@dataclass(frozen=True, slots=True)
class SAEFeatureReference:
    """A measured SAE feature reference, never a semantic feature label."""

    feature_index: int
    activation_strength: float | None = None
    model_id: str | None = None
    model_version: str | None = None
    layer: str | None = None
    sae_checkpoint: str | None = None
    association: str = "association_only; no causal or semantic claim"
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.feature_index < 0:
            raise ValueError("feature_index must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FeatureInteractionReference:
    """An interaction result included only when experimentally validated."""

    feature_indices: tuple[int, ...]
    estimate: float
    outcome_scale: str
    validated: bool
    uncertainty: Mapping[str, float] | None = None
    cwe: str | None = None
    experiment_id: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.feature_indices) < 2:
            raise ValueError("feature interactions require at least two features")
        if any(index < 0 for index in self.feature_indices):
            raise ValueError("feature indices must be non-negative")
        if not self.outcome_scale.strip():
            raise ValueError("outcome_scale must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CounterfactualReference:
    """A controlled intervention result with explicit causal limitations."""

    intervention: str
    outcome_change: float | None
    outcome_scale: str
    experiment_id: str | None = None
    uncertainty: Mapping[str, float] | None = None
    true_vulnerability_status_changed: bool | None = None
    limitations: tuple[str, ...] = (
        "Controlled output comparison does not establish a causal change in "
        "true vulnerability status.",
    )

    def __post_init__(self) -> None:
        if not self.intervention.strip() or not self.outcome_scale.strip():
            raise ValueError("counterfactual intervention and outcome scale are required")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VulnerabilityExplanation:
    """Structured explanation with evidence separated by epistemic status."""

    finding_id: str
    what: str
    where: Mapping[str, Any]
    cwe: str
    why_detected: tuple[dict[str, Any], ...]
    source_to_sink_paths: tuple[dict[str, Any], ...]
    supporting_static_analysis: tuple[dict[str, Any], ...]
    sae_features: tuple[dict[str, Any], ...]
    feature_interactions: tuple[dict[str, Any], ...]
    counterfactual_interventions: tuple[dict[str, Any], ...]
    potential_security_impact: str | None
    recommended_remediation: str
    directly_observed_evidence: tuple[dict[str, Any], ...]
    model_generated_explanations: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    provenance: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_human(self) -> str:
        """Render a concise report without turning hypotheses into facts."""
        lines = [
            f"{self.what} ({self.cwe})",
            (
                "Location: "
                f"{self.where.get('path')}:{self.where.get('startLine') + 1}:"
                f"{self.where.get('startColumn') + 1}"
            ),
            f"Why detected: {len(self.why_detected)} evidence item(s).",
            f"Source-to-sink paths: {len(self.source_to_sink_paths)}.",
            f"SAE features: {len(self.sae_features)} association(s).",
            f"Validated feature interactions: {len(self.feature_interactions)}.",
            f"Counterfactual interventions: {len(self.counterfactual_interventions)}.",
            "Potential impact: "
            + (self.potential_security_impact or "Unavailable from supplied evidence."),
            f"Recommended remediation: {self.recommended_remediation}",
        ]
        if self.model_generated_explanations:
            lines.append(
                "Model-generated explanations: hypotheses only; not directly observed "
                "and not causal."
            )
        if self.limitations:
            lines.append("Limitations: " + " ".join(self.limitations))
        return "\n".join(lines)


class ExplainableVulnerabilityEngine:
    """Build explanations from a fused finding and optional research evidence."""

    def explain(
        self,
        finding: VulnerabilityFinding,
        *,
        taint: TaintAnalysis | None = None,
        sae_features: Sequence[SAEFeatureReference] = (),
        feature_interactions: Sequence[FeatureInteractionReference] = (),
        counterfactuals: Sequence[CounterfactualReference] = (),
        potential_security_impact: str | None = None,
    ) -> VulnerabilityExplanation:
        direct = tuple(
            self._evidence_dict(item)
            for item in finding.evidence
            if item.evidence_type is not EvidenceType.LLM
        )
        model_generated = tuple(
            self._evidence_dict(item)
            for item in finding.evidence
            if item.evidence_type is EvidenceType.LLM
        )
        paths = self._source_to_sink_paths(finding, taint)
        static = tuple(
            self._evidence_dict(item)
            for item in finding.evidence
            if item.family is EvidenceFamily.STATIC_TOOL
        )
        validated_interactions = tuple(
            item.to_dict() for item in feature_interactions if item.validated
        )
        limitations = list(finding.limitations)
        if model_generated:
            limitations.append("LLM explanations are hypotheses and are not causal evidence.")
        if sae_features:
            limitations.append(
                "SAE features are reported as measured associations; no semantic meaning "
                "or causal role is claimed."
            )
        if feature_interactions and len(validated_interactions) < len(feature_interactions):
            limitations.append("Unvalidated feature interactions were excluded from the report.")
        if counterfactuals:
            limitations.append(
                "Counterfactual output changes do not establish a change in true "
                "vulnerability status."
            )
        return VulnerabilityExplanation(
            finding_id=finding.finding_id,
            what=finding.title,
            where=finding.location.to_dict(),
            cwe=finding.cwe,
            why_detected=tuple(self._evidence_dict(item) for item in finding.evidence),
            source_to_sink_paths=paths,
            supporting_static_analysis=static,
            sae_features=tuple(item.to_dict() for item in sae_features),
            feature_interactions=validated_interactions,
            counterfactual_interventions=tuple(item.to_dict() for item in counterfactuals),
            potential_security_impact=potential_security_impact,
            recommended_remediation=finding.suggested_remediation,
            directly_observed_evidence=direct,
            model_generated_explanations=model_generated,
            limitations=tuple(dict.fromkeys(limitations)),
            provenance=finding.provenance.to_dict(),
        )

    @staticmethod
    def _evidence_dict(item: EvidenceItem) -> dict[str, Any]:
        payload = item.to_dict()
        payload["status"] = (
            "directly_observed"
            if item.claim_kind is ClaimKind.OBSERVATION
            else item.claim_kind.value
        )
        return payload

    @staticmethod
    def _source_to_sink_paths(
        finding: VulnerabilityFinding,
        taint: TaintAnalysis | None,
    ) -> tuple[dict[str, Any], ...]:
        if taint is None:
            return ()
        paths: list[dict[str, Any]] = []
        for item in taint.findings:
            source = EvidenceLocation.from_source(item.source_span, finding.location.path)
            sink = EvidenceLocation.from_source(item.sink_span, finding.location.path)
            if not (
                item.kind.value == finding.category.value
                or source.overlaps(finding.location)
                or sink.overlaps(finding.location)
            ):
                continue
            paths.append(
                {
                    "findingId": item.finding_id,
                    "kind": item.kind.value,
                    "sourceRule": item.source_rule,
                    "sinkRule": item.sink_rule,
                    "source": source.to_dict(),
                    "sink": sink.to_dict(),
                    "argument": (
                        EvidenceLocation.from_source(
                            item.argument_span, finding.location.path
                        ).to_dict()
                        if item.argument_span is not None
                        else None
                    ),
                    "steps": [step.to_dict() for step in item.path],
                    "confidence": item.confidence.value,
                    "limitations": list(item.limitations),
                    "status": "potential_source_to_sink_flow",
                }
            )
        return tuple(paths)


__all__ = [
    "CounterfactualReference",
    "ExplainableVulnerabilityEngine",
    "FeatureInteractionReference",
    "SAEFeatureReference",
    "VulnerabilityExplanation",
]
