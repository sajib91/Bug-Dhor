"""Loaders for the unified risk engine's versioned configuration."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from bugdhor.risk.models import (
    CwePriorityProfile,
    EvidenceSource,
    RiskConfig,
    RiskThresholds,
    RiskWeights,
)

DEFAULT_DEPENDENCY_GROUPS: dict[str, str] = {
    EvidenceSource.AST.value: "program_analysis",
    EvidenceSource.CFG.value: "program_analysis",
    EvidenceSource.DFG.value: "program_analysis",
    EvidenceSource.TAINT.value: "program_analysis",
    EvidenceSource.STATIC_ANALYSIS.value: "static_tool",
    EvidenceSource.SAE_ACTIVATION.value: "model_internal",
    EvidenceSource.COUNTERFACTUAL_INTERACTION.value: "model_internal",
    EvidenceSource.MODEL_PREDICTION.value: "model_internal",
    EvidenceSource.CWE_METADATA.value: "cwe_metadata",
    EvidenceSource.REPOSITORY_CONTEXT.value: "repository_context",
    EvidenceSource.EXPLOITABILITY.value: "exploitability",
    EvidenceSource.VERIFICATION.value: "verification",
}


def default_risk_config() -> RiskConfig:
    """Return the documented neutral baseline.

    Equal weights are a maximum-entropy choice under no validated preference,
    not an empirical claim. The basis is recorded in the config hash and in
    every assessment.
    """
    return RiskConfig(
        weights=RiskWeights(
            p_hat=1.0,
            severity=1.0,
            exposure=1.0,
            impact=1.0,
            basis="maximum_entropy_neutral_prior",
            version="1.0.0",
        ),
        thresholds=RiskThresholds(
            low=0.25,
            medium=0.50,
            high=0.75,
            basis="equal_width_ordinal_bands",
        ),
        dependency_groups=dict(DEFAULT_DEPENDENCY_GROUPS),
    )


def risk_config_from_mapping(payload: Mapping[str, Any]) -> RiskConfig:
    """Build a risk config from a validated JSON-style mapping."""
    weights_payload = payload.get("weights")
    thresholds_payload = payload.get("thresholds")
    if not isinstance(weights_payload, Mapping) or not isinstance(thresholds_payload, Mapping):
        raise ValueError("risk config requires weights and thresholds objects")

    weights = RiskWeights(
        p_hat=float(weights_payload["p_hat"]),
        severity=float(weights_payload["severity"]),
        exposure=float(weights_payload["exposure"]),
        impact=float(weights_payload["impact"]),
        basis=str(weights_payload["basis"]),
        version=str(weights_payload["version"]),
    )
    thresholds = RiskThresholds(
        low=float(thresholds_payload["low"]),
        medium=float(thresholds_payload["medium"]),
        high=float(thresholds_payload["high"]),
        basis=str(thresholds_payload["basis"]),
    )
    profiles: dict[str, CwePriorityProfile] = {}
    raw_profiles = payload.get("cweProfiles", {})
    if not isinstance(raw_profiles, Mapping):
        raise ValueError("cweProfiles must be an object")
    for cwe, item in raw_profiles.items():
        if not isinstance(item, Mapping):
            raise ValueError(f"CWE profile {cwe} must be an object")
        profiles[cwe] = CwePriorityProfile(
            cwe=cwe,
            severity=float(item["severity"]),
            exposure=float(item["exposure"]),
            impact=float(item["impact"]),
            basis=str(item["basis"]),
            threshold_overrides={
                key: float(value) for key, value in dict(item.get("thresholdOverrides", {})).items()
            },
        )

    raw_groups = payload.get("dependencyGroups", DEFAULT_DEPENDENCY_GROUPS)
    if not isinstance(raw_groups, Mapping):
        raise ValueError("dependencyGroups must be an object")
    raw_bands = payload.get("uncertaintyBands", [1.0 / 3.0, 2.0 / 3.0])
    if not isinstance(raw_bands, (list, tuple)) or len(raw_bands) != 2:
        raise ValueError("uncertaintyBands must contain two values")

    return RiskConfig(
        weights=weights,
        thresholds=thresholds,
        cwe_profiles=profiles,
        dependency_groups={str(key): str(value) for key, value in raw_groups.items()},
        missing_policy=str(payload.get("missingPolicy", "renormalize")),
        uncertainty_bands=(float(raw_bands[0]), float(raw_bands[1])),
        uncertainty_basis=str(payload.get("uncertaintyBasis", "equal_width_ordinal_bands")),
        priority_tie_breaker=str(payload.get("priorityTieBreaker", "finding_id")),
        name=str(payload.get("name", "unified-risk-baseline")),
        version=str(payload.get("version", "1.0.0")),
    )


def load_risk_config(path: str | Path) -> RiskConfig:
    """Load a risk config from a JSON file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("risk config root must be an object")
    return risk_config_from_mapping(payload)


__all__ = [
    "DEFAULT_DEPENDENCY_GROUPS",
    "default_risk_config",
    "load_risk_config",
    "risk_config_from_mapping",
]
