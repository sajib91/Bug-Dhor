"""Evidence normalization and reliability estimation.

Nothing in this module invents an observation. It converts explicitly supplied
raw measurements to the shared ``[0, 1]`` scale and estimates reliability only
from metadata the caller provides. When the required metadata is absent, the
observation is assigned reliability ``0`` and the engine excludes it with a
reason instead of silently treating missing evidence as support.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from bugdhor.risk.models import (
    ClaimKind,
    EvidenceObservation,
    EvidencePolarity,
    EvidenceSource,
    NormalizedEvidence,
    ReliabilityEvidence,
    validate_finite_unit,
)


def estimate_reliability(
    observation: EvidenceObservation,
) -> tuple[float, str]:
    """Estimate reliability and name the method actually used.

    Precedence:

    1. Validation precision (support) or specificity (refutation) measured on
       an independent dataset.
    2. Self-reported confidence multiplied by observed coverage.
    3. Zero for hypotheses without validation, failed runs, or missing data.

    Coverage defaults to ``1`` only for a declared ``complete`` run. A partial
    run without a coverage fraction is not assigned an invented reliability.
    """
    metadata = observation.reliability
    if metadata.run_status in {"failed", "unavailable"}:
        return 0.0, f"run_{metadata.run_status}"

    coverage = metadata.coverage
    if coverage is None:
        coverage = 1.0 if metadata.run_status == "complete" else 0.0
    if metadata.run_status == "partial" and metadata.coverage is None:
        return 0.0, "partial_run_without_coverage"

    validation = (
        metadata.validation_precision
        if observation.polarity is EvidencePolarity.SUPPORTS
        else metadata.validation_specificity
    )
    if validation is not None:
        return validate_finite_unit(validation * coverage, "validation reliability"), (
            "validation_precision"
            if observation.polarity is EvidencePolarity.SUPPORTS
            else "validation_specificity"
        )

    if metadata.reported_confidence is not None:
        return validate_finite_unit(
            metadata.reported_confidence * coverage, "reported reliability"
        ), ("reported_confidence_x_coverage")

    if observation.claim_kind is ClaimKind.HYPOTHESIS:
        return 0.0, "unvalidated_hypothesis"
    return 0.0, "no_reliability_metadata"


def normalize_observation(observation: EvidenceObservation) -> NormalizedEvidence:
    """Attach an explicit reliability estimate to a normalized observation."""
    reliability, method = estimate_reliability(observation)
    return NormalizedEvidence(
        source=observation.source,
        source_id=observation.source_id,
        value=validate_finite_unit(observation.value, "evidence value"),
        reliability=observation.reliability,
        claim_kind=observation.claim_kind,
        polarity=observation.polarity,
        dependency_group=observation.dependency_group,
        normalized_from=observation.normalized_from,
        rationale=observation.rationale,
        limitations=observation.limitations,
        reliability_value=reliability,
        reliability_method=method,
    )


def normalize_observations(
    observations: list[EvidenceObservation] | tuple[EvidenceObservation, ...],
) -> tuple[NormalizedEvidence, ...]:
    """Normalize a sequence while preserving caller order."""
    return tuple(normalize_observation(observation) for observation in observations)


def from_cvss(score: float) -> float:
    """Normalize a CVSS base score on its defined ``[0, 10]`` scale."""
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        raise ValueError("CVSS base score must lie in [0, 10]")
    return score / 10.0


def from_fraction(value: float, name: str = "value") -> float:
    """Validate a value already expressed as a fraction in ``[0, 1]``."""
    return validate_finite_unit(value, name)


def from_binary(observed: bool) -> float:
    """Normalize a directly observed binary condition."""
    return 1.0 if observed else 0.0


def from_label(value: str, scale: Mapping[str, float]) -> float:
    """Normalize a categorical value using an explicitly supplied scale."""
    if value not in scale:
        raise ValueError(f"no normalized scale entry for label {value!r}")
    return validate_finite_unit(scale[value], f"scale[{value!r}]")


def from_activation(value: float, measured_reference: float) -> float:
    """Normalize an activation against a measured positive reference value.

    ``measured_reference`` must come from the same model/SAE artifact and
    population. This function does not estimate a reference from the value
    being normalized.
    """
    if not math.isfinite(value) or value < 0:
        raise ValueError("activation must be finite and non-negative")
    if not math.isfinite(measured_reference) or measured_reference <= 0:
        raise ValueError("measured activation reference must be positive")
    return min(1.0, value / measured_reference)


def from_contrast(contrast: float, scale_low: float, scale_high: float) -> float:
    """Linearly normalize a measured contrast using its documented scale.

    The caller must supply the observed scale endpoints. No endpoint is
    inferred from a single contrast, which would manufacture evidence.
    """
    if not all(math.isfinite(value) for value in (contrast, scale_low, scale_high)):
        raise ValueError("contrast and scale endpoints must be finite")
    if scale_high <= scale_low:
        raise ValueError("scale_high must exceed scale_low")
    normalized = (contrast - scale_low) / (scale_high - scale_low)
    return min(1.0, max(0.0, normalized))


def observation_from_mapping(payload: Mapping[str, Any]) -> EvidenceObservation:
    """Build an observation from a validated mapping (API/JSON boundary)."""
    required = ("source", "sourceId", "value", "reliability")
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError(f"missing evidence fields: {', '.join(missing)}")

    reliability_payload = payload["reliability"]
    if not isinstance(reliability_payload, Mapping):
        raise ValueError("reliability must be an object")
    reliability = ReliabilityEvidence(
        validation_precision=reliability_payload.get("validationPrecision"),
        validation_specificity=reliability_payload.get("validationSpecificity"),
        reported_confidence=reliability_payload.get("reportedConfidence"),
        coverage=reliability_payload.get("coverage"),
        run_status=str(reliability_payload.get("runStatus", "complete")),
        basis=str(reliability_payload.get("basis", "caller_supplied")),
    )
    limitations = payload.get("limitations", ())
    if not isinstance(limitations, (list, tuple)):
        raise ValueError("limitations must be a list")
    return EvidenceObservation(
        source=EvidenceSource(str(payload["source"])),
        source_id=str(payload["sourceId"]),
        value=float(payload["value"]),
        reliability=reliability,
        claim_kind=ClaimKind(str(payload.get("claimKind", "observation"))),
        polarity=EvidencePolarity(str(payload.get("polarity", "supports"))),
        dependency_group=str(payload.get("dependencyGroup", payload["source"])),
        normalized_from=str(payload.get("normalizedFrom", "caller_normalized")),
        rationale=str(payload.get("rationale", "")),
        limitations=tuple(str(item) for item in limitations),
    )


__all__ = [
    "estimate_reliability",
    "from_activation",
    "from_binary",
    "from_contrast",
    "from_cvss",
    "from_fraction",
    "from_label",
    "normalize_observation",
    "normalize_observations",
    "observation_from_mapping",
]
