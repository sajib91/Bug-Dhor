"""Unified mathematical security risk engine.

The engine implements four explicit stages:

1. Normalize every supplied observation and estimate its reliability from
   measured metadata.
2. Collapse observations into declared dependency groups. Within a group the
   most reliable source determines group reliability and values are aggregated
   by a reliability-weighted mean. Correlated views of the same code therefore
   cannot contribute multiple independent votes.
3. Combine groups with a noisy-OR over independent group evidence. Refutations
   reduce support multiplicatively. Counterfactual interactions enter as a
   signed adjustment inside their dependency group, never as extra evidence.
4. Compute Eq. (28) ``R_index = a*p_hat + b*S + c*E + d*I`` and Eq. (29) bands,
   with explicit missing-component handling, uncertainty, and explanations.

A calibrated probability is attached only when a validated calibration artifact
is supplied. Otherwise the result is labelled ``heuristic_index`` and must not
be rendered as a probability.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from bugdhor.risk.calibration import CalibrationArtifact
from bugdhor.risk.models import (
    CalibrationSummary,
    ComponentScores,
    CwePriorityProfile,
    EvidenceObservation,
    EvidencePolarity,
    EvidenceSource,
    ExcludedEvidence,
    GroupScore,
    NormalizedEvidence,
    RiskAssessment,
    RiskConfig,
    RiskResult,
    RiskThresholds,
    Uncertainty,
    validate_finite_unit,
)
from bugdhor.risk.normalization import normalize_observation

_COMPONENT_SOURCES = frozenset(
    {
        EvidenceSource.CWE_METADATA,
        EvidenceSource.REPOSITORY_CONTEXT,
        EvidenceSource.EXPLOITABILITY,
        EvidenceSource.MODEL_PREDICTION,
    }
)


@dataclass(frozen=True, slots=True)
class FindingRiskInput:
    """All evidence available for one finding.

    Callers never ask the engine to infer missing observations. An empty field
    is reported as missing and excluded, which makes unavailable evidence
    explicit rather than silently neutral.
    """

    finding_id: str
    cwe: str | None = None
    observations: tuple[EvidenceObservation, ...] = ()
    calibration_artifact: CalibrationArtifact | None = None

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if self.cwe is not None and not self.cwe.strip():
            raise ValueError("cwe must be a non-empty string or None")
        if any(not isinstance(item, EvidenceObservation) for item in self.observations):
            raise TypeError("observations must contain EvidenceObservation instances")


@dataclass(slots=True)
class _GroupAccumulator:
    support_values: list[tuple[float, float]] = field(default_factory=list)
    refute_values: list[tuple[float, float]] = field(default_factory=list)
    interaction_delta: float = 0.0
    reliabilities: list[float] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


class UnifiedRiskEngine:
    """Produce explainable, correlation-aware risk assessments."""

    def __init__(self, config: RiskConfig) -> None:
        self.config = config
        self.config_hash = config.config_hash()

    def assess(self, finding: FindingRiskInput) -> RiskResult:
        """Assess one finding without mutating caller state."""
        normalized: list[NormalizedEvidence] = []
        excluded: list[ExcludedEvidence] = []
        for observation in finding.observations:
            item = normalize_observation(observation)
            if item.reliability_value <= 0.0:
                excluded.append(
                    ExcludedEvidence(
                        source_id=item.source_id,
                        source=item.source,
                        reason=item.reliability_method,
                    )
                )
                continue
            normalized.append(item)

        groups, interaction_adjustment = self._aggregate_groups(normalized)
        support, refutation = self._combine_groups(groups)
        p_hat = None if not groups else validate_finite_unit(support * (1.0 - refutation), "p_hat")

        components, component_notes = self._components(finding.cwe, tuple(normalized), p_hat)
        contributions, index = self._risk_index(components)
        band = self._thresholds(finding.cwe).band(index)

        probability: float | None = None
        calibration_summary: CalibrationSummary | None = None
        artifact = finding.calibration_artifact
        if artifact is not None:
            calibration_summary = CalibrationSummary(
                artifact_id=artifact.artifact_id,
                method=artifact.config.method,
                dataset_id=artifact.config.dataset_id,
                split_hash=artifact.split_hash,
                config_hash=artifact.config.config_hash(),
                status=artifact.status,
                metrics=artifact.metrics.to_dict(),
                metric_intervals=artifact.metric_intervals,
            )
            if index is not None:
                probability = artifact.probability(index)

        coverage = 1.0
        for group in groups:
            coverage *= 1.0 - group.reliability
        coverage = validate_finite_unit(1.0 - coverage, "evidence coverage")
        denominator = support + refutation
        conflict = 2.0 * min(support, refutation) / denominator if denominator > 0.0 else 0.0
        uncertainty_value = validate_finite_unit(max(1.0 - coverage, conflict), "uncertainty")
        low, high = self.config.uncertainty_bands
        if uncertainty_value >= high:
            level = "high"
        elif uncertainty_value >= low:
            level = "medium"
        else:
            level = "low"
        uncertainty = Uncertainty(
            value=uncertainty_value,
            level=level,
            coverage=coverage,
            conflict=conflict,
            basis=(
                "max(evidence_deficit, support_refutation_conflict); "
                f"bands={self.config.uncertainty_basis}"
            ),
        )

        explanation = self._explain(
            finding=finding,
            groups=groups,
            contributions=contributions,
            index=index,
            band=band,
            interaction_adjustment=interaction_adjustment,
            excluded=excluded,
            component_notes=component_notes,
            probability=probability,
            artifact=artifact,
        )
        return RiskResult(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            index=index,
            band=band,
            components=components,
            contributions=contributions,
            group_scores=groups,
            interaction_adjustment=interaction_adjustment,
            uncertainty=uncertainty,
            normalized_evidence=tuple(normalized),
            excluded_evidence=tuple(excluded),
            explanation=tuple(explanation),
            config_hash=self.config_hash,
            probability=probability,
            calibration=calibration_summary,
        )

    def assess_batch(self, findings: Iterable[FindingRiskInput]) -> RiskAssessment:
        """Assess and rank a batch of findings under one configuration."""
        results = [self.assess(finding) for finding in findings]
        ordered = sorted(
            results,
            key=lambda result: (
                result.index is not None,
                result.index if result.index is not None else -1.0,
                self._tie_breaker(result),
            ),
            reverse=True,
        )
        ranked = [
            replace(result, priority_rank=position) for position, result in enumerate(ordered, 1)
        ]
        warnings: list[str] = []
        if any(result.index is None for result in ranked):
            warnings.append("some findings had insufficient components and could not be scored")
        return RiskAssessment(tuple(ranked), self.config_hash, tuple(warnings))

    def _tie_breaker(self, result: RiskResult) -> str:
        if self.config.priority_tie_breaker == "cwe":
            return result.cwe or ""
        if self.config.priority_tie_breaker == "source_id":
            ids = [item.source_id for item in result.normalized_evidence]
            return ids[0] if ids else ""
        return result.finding_id

    def _aggregate_groups(
        self, evidence: Sequence[NormalizedEvidence]
    ) -> tuple[tuple[GroupScore, ...], float]:
        accumulators: dict[str, _GroupAccumulator] = {}
        for item in evidence:
            if item.polarity is EvidencePolarity.NEUTRAL:
                continue
            group_name = self.config.group_for(item.source)
            accumulator = accumulators.setdefault(group_name, _GroupAccumulator())
            accumulator.reliabilities.append(item.reliability_value)
            accumulator.evidence_ids.append(item.source_id)
            if item.source is EvidenceSource.COUNTERFACTUAL_INTERACTION:
                signed = item.value if item.polarity is EvidencePolarity.SUPPORTS else -item.value
                accumulator.interaction_delta += item.reliability_value * signed
            elif item.polarity is EvidencePolarity.SUPPORTS:
                accumulator.support_values.append((item.value, item.reliability_value))
            else:
                accumulator.refute_values.append((item.value, item.reliability_value))

        groups: list[GroupScore] = []
        total_interaction = 0.0
        for name, accumulator in sorted(accumulators.items()):
            reliability = max(accumulator.reliabilities, default=0.0)
            support = _weighted_mean(accumulator.support_values)
            refutation = _weighted_mean(accumulator.refute_values)
            delta = max(-1.0, min(1.0, accumulator.interaction_delta))
            total_interaction += delta
            if delta > 0:
                support = min(1.0, support + delta)
            elif delta < 0:
                refutation = min(1.0, refutation + abs(delta))
            groups.append(
                GroupScore(
                    group=name,
                    support=validate_finite_unit(support, "group support"),
                    refutation=validate_finite_unit(refutation, "group refutation"),
                    reliability=validate_finite_unit(reliability, "group reliability"),
                    evidence_ids=tuple(sorted(set(accumulator.evidence_ids))),
                )
            )
        adjustment = max(-1.0, min(1.0, total_interaction))
        return tuple(groups), adjustment

    @staticmethod
    def _combine_groups(groups: Sequence[GroupScore]) -> tuple[float, float]:
        support_remaining = 1.0
        refute_remaining = 1.0
        for group in groups:
            support_remaining *= 1.0 - group.reliability * group.support
            refute_remaining *= 1.0 - group.reliability * group.refutation
        return (
            validate_finite_unit(1.0 - support_remaining, "combined support"),
            validate_finite_unit(1.0 - refute_remaining, "combined refutation"),
        )

    def _components(
        self,
        cwe: str | None,
        evidence: Sequence[NormalizedEvidence],
        p_hat: float | None,
    ) -> tuple[ComponentScores, tuple[str, ...]]:
        notes: list[str] = []
        severity: float | None = None
        exposure: float | None = None
        impact: float | None = None
        profile: CwePriorityProfile | None = None
        if cwe is not None:
            profile = self.config.cwe_profiles.get(cwe)
            if profile is not None:
                severity = profile.severity
                exposure = profile.exposure
                impact = profile.impact
                notes.append(
                    "CWE profile "
                    + cwe
                    + " supplied severity/exposure/impact with basis "
                    + repr(profile.basis)
                    + "."
                )
            else:
                notes.append(f"No CWE priority profile is configured for {cwe}.")

        if severity is None:
            severity = self._component_from_evidence(evidence, "severity")
        if exposure is None:
            exposure = self._component_from_evidence(evidence, "exposure")
        if impact is None:
            impact = self._component_from_evidence(evidence, "impact")
        for name, value in (("severity", severity), ("exposure", exposure), ("impact", impact)):
            if value is None:
                notes.append(f"{name} evidence is unavailable; it is excluded from Eq. (28).")
        if p_hat is None:
            notes.append("No reliable finding-likelihood evidence is available.")
        return ComponentScores(p_hat, severity, exposure, impact), tuple(notes)

    @staticmethod
    def _component_from_evidence(
        evidence: Sequence[NormalizedEvidence], component: str
    ) -> float | None:
        candidates = [
            item
            for item in evidence
            if item.source in _COMPONENT_SOURCES
            and item.polarity is not EvidencePolarity.NEUTRAL
            and item.source_id.split(":")[-1].lower() == component
        ]
        if not candidates:
            return None
        best = max(candidates, key=lambda item: item.reliability_value)
        return best.value

    def _thresholds(self, cwe: str | None) -> RiskThresholds:
        profile = self.config.cwe_profiles.get(cwe) if cwe else None
        if profile is None or not profile.threshold_overrides:
            return self.config.thresholds
        values = {
            name: profile.threshold_overrides.get(name, getattr(self.config.thresholds, name))
            for name in ("low", "medium", "high")
        }
        thresholds = RiskThresholds(
            low=values["low"],
            medium=values["medium"],
            high=values["high"],
            basis=f"{self.config.thresholds.basis}; overridden by {profile.basis}",
        )
        return thresholds

    def _risk_index(
        self, components: ComponentScores
    ) -> tuple[dict[str, float | None], float | None]:
        available = {
            "p_hat": components.p_hat,
            "severity": components.severity,
            "exposure": components.exposure,
            "impact": components.impact,
        }
        weights = dict(
            zip(
                ("p_hat", "severity", "exposure", "impact"),
                self.config.weights.normalized(),
                strict=True,
            )
        )
        present = {
            name: value
            for name, value in available.items()
            if value is not None and math.isfinite(value)
        }
        if not present:
            return {name: None for name in available}, None
        if len(present) != len(available) and self.config.missing_policy == "unavailable":
            return {name: None for name in available}, None
        total_weight = sum(weights[name] for name in present)
        if total_weight <= 0:
            return {name: None for name in available}, None
        contributions = {
            name: (weights[name] * value / total_weight if name in present else None)
            for name, value in available.items()
        }
        index = sum(value for value in contributions.values() if value is not None)
        return contributions, validate_finite_unit(index, "risk index")

    @staticmethod
    def _explain(
        *,
        finding: FindingRiskInput,
        groups: Sequence[GroupScore],
        contributions: Mapping[str, float | None],
        index: float | None,
        band: str,
        interaction_adjustment: float,
        excluded: Sequence[ExcludedEvidence],
        component_notes: Sequence[str],
        probability: float | None,
        artifact: CalibrationArtifact | None,
    ) -> tuple[str, ...]:
        lines: list[str] = []
        if index is None:
            lines.append(
                "No interpretable index was produced because no Eq. (28) component was available."
            )
        else:
            top = sorted(
                ((name, value) for name, value in contributions.items() if value is not None),
                key=lambda item: item[1],
                reverse=True,
            )
            description = ", ".join(f"{name}={value:.3f}" for name, value in top)
            lines.append(
                f"Eq. (28) index {index:.3f} ({band}) from normalized contributions: {description}."
            )
        for group in groups:
            lines.append(
                f"Dependency group {group.group}: support={group.support:.3f}, "
                f"refutation={group.refutation:.3f}, reliability={group.reliability:.3f}; "
                "correlated items were collapsed before combination."
            )
        if interaction_adjustment != 0.0:
            lines.append(
                "Counterfactual interactions adjusted model evidence by "
                f"{interaction_adjustment:+.3f} inside its dependency group."
            )
        lines.extend(component_notes)
        for item in excluded:
            lines.append(f"Excluded {item.source_id}: {item.reason}.")
        if probability is not None and artifact is not None:
            lines.append(
                f"Calibrated probability {probability:.3f} comes from artifact "
                f"{artifact.artifact_id} validated on independent groups."
            )
        else:
            reason = artifact.status if artifact is not None else "no artifact supplied"
            lines.append(
                f"No calibrated probability is reported ({reason}); the index is heuristic, "
                "not a probability."
            )
        lines.append(
            f"Finding {finding.finding_id} was assessed without inventing missing evidence."
        )
        return tuple(lines)


def _weighted_mean(values: Sequence[tuple[float, float]]) -> float:
    denominator = sum(weight for _, weight in values if weight > 0)
    if denominator <= 0:
        return 0.0
    numerator = sum(value * weight for value, weight in values if weight > 0)
    return validate_finite_unit(numerator / denominator, "weighted mean")


__all__ = ["FindingRiskInput", "UnifiedRiskEngine"]
