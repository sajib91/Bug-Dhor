"""Data contracts for evidence-backed model compatibility reporting.

The types in this module deliberately separate *declared* configuration from
*observed* probe output. A checkpoint being named in a registry or configuration
file never grants a capability; only a successful probe does.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class ProbeStatus(StrEnum):
    """Outcome of one independent capability probe."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    NOT_RUN = "not_run"
    ERROR = "error"


class Capability(StrEnum):
    """Independently probed capabilities."""

    CODE_GENERATION = "code_generation"
    CODE_ANALYSIS = "code_analysis"
    SECURE_CODE_GENERATION = "secure_code_generation"
    ACTIVATION_EXTRACTION = "activation_extraction"
    SAE_COMPATIBILITY = "sae_compatibility"
    COUNTERFACTUAL_INTERVENTION = "counterfactual_intervention"
    ACTIVATION_STEERING = "activation_steering"
    TOKEN_LEVEL_INTERVENTION = "token_level_intervention"
    OUTPUT_REPRODUCIBILITY = "output_reproducibility"
    HARDWARE_INFERENCE_LIMITS = "hardware_inference_limits"


class AssistantCapability(StrEnum):
    """Assistant integration capabilities A-F from the extension contract."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


@dataclass(frozen=True, slots=True)
class CapabilityProbe:
    """Result of a single capability probe."""

    capability: Capability
    status: ProbeStatus
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    claim_kind: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "reason": self.reason,
            "claimKind": self.claim_kind,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ModelCapabilityCard:
    """One model's declared metadata plus independently observed results."""

    target_id: str
    name: str
    checkpoint_identifier: str
    provider_identifier: str | None
    version: str | None
    revision: str | None
    architecture: str | None
    tokenizer: str | None
    available_layers: tuple[str | int, ...] | None
    activation_access: ProbeStatus
    sae_compatibility: ProbeStatus
    steering_compatibility: ProbeStatus
    hardware_requirements: dict[str, Any]
    inference_limitations: tuple[str, ...]
    runtime: str
    probes: tuple[CapabilityProbe, ...]
    declared_capabilities: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "name": self.name,
            "checkpointIdentifier": self.checkpoint_identifier,
            "providerIdentifier": self.provider_identifier,
            "version": self.version,
            "revision": self.revision,
            "architecture": self.architecture,
            "tokenizer": self.tokenizer,
            "availableLayers": list(self.available_layers)
            if self.available_layers is not None
            else None,
            "activationAccess": self.activation_access.value,
            "saeCompatibility": self.sae_compatibility.value,
            "steeringCompatibility": self.steering_compatibility.value,
            "hardwareRequirements": self.hardware_requirements,
            "inferenceLimitations": list(self.inference_limitations),
            "runtime": self.runtime,
            "declaredCapabilities": list(self.declared_capabilities),
            "probes": [probe.to_dict() for probe in self.probes],
        }


@dataclass(frozen=True, slots=True)
class AssistantIntegrationCard:
    """Observed availability of an AI assistant provider integration."""

    target_id: str
    provider_kind: str
    label: str
    status: ProbeStatus
    discovered_capabilities: tuple[str, ...]
    declared_capabilities: dict[str, str]
    reason: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "providerKind": self.provider_kind,
            "label": self.label,
            "status": self.status.value,
            "discoveredCapabilities": list(self.discovered_capabilities),
            "declaredCapabilities": dict(self.declared_capabilities),
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    """Portable report emitted by the compatibility matrix runner."""

    schema_version: str
    generated_at: str
    config_hash: str
    git_commit: str | None
    environment: dict[str, Any]
    models: tuple[ModelCapabilityCard, ...]
    assistant_integrations: tuple[AssistantIntegrationCard, ...]
    limitations: tuple[str, ...]
    claim_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "generatedAt": self.generated_at,
            "configHash": self.config_hash,
            "gitCommit": self.git_commit,
            "environment": self.environment,
            "models": [model.to_dict() for model in self.models],
            "assistantIntegrations": [
                integration.to_dict() for integration in self.assistant_integrations
            ],
            "limitations": list(self.limitations),
            "claimBoundary": self.claim_boundary,
        }


def model_capability_card_from_dict(payload: dict[str, Any]) -> ModelCapabilityCard:
    """Reconstruct a card from its serialized form."""
    probes = tuple(
        CapabilityProbe(
            capability=Capability(probe["capability"]),
            status=ProbeStatus(probe["status"]),
            evidence=dict(probe.get("evidence") or {}),
            reason=probe.get("reason"),
            claim_kind=probe.get("claimKind"),
            limitations=tuple(probe.get("limitations") or ()),
        )
        for probe in payload.get("probes", [])
    )
    layers = payload.get("availableLayers")
    return ModelCapabilityCard(
        target_id=payload["targetId"],
        name=payload["name"],
        checkpoint_identifier=payload["checkpointIdentifier"],
        provider_identifier=payload.get("providerIdentifier"),
        version=payload.get("version"),
        revision=payload.get("revision"),
        architecture=payload.get("architecture"),
        tokenizer=payload.get("tokenizer"),
        available_layers=tuple(layers) if layers is not None else None,
        activation_access=ProbeStatus(payload["activationAccess"]),
        sae_compatibility=ProbeStatus(payload["saeCompatibility"]),
        steering_compatibility=ProbeStatus(payload["steeringCompatibility"]),
        hardware_requirements=dict(payload.get("hardwareRequirements") or {}),
        inference_limitations=tuple(payload.get("inferenceLimitations") or ()),
        runtime=payload["runtime"],
        probes=probes,
        declared_capabilities=tuple(payload.get("declaredCapabilities") or ()),
    )


def as_plain(value: Any) -> Any:
    """Convert dataclass/enum values into JSON-safe primitives."""
    if isinstance(value, dict):
        return {str(key): as_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [as_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict"):
        return as_plain(value.to_dict())
    if hasattr(value, "__dataclass_fields__"):
        return as_plain(asdict(value))
    if isinstance(value, StrEnum):
        return value.value
    return value


__all__ = [
    "AssistantCapability",
    "AssistantIntegrationCard",
    "Capability",
    "CapabilityProbe",
    "CompatibilityReport",
    "ModelCapabilityCard",
    "ProbeStatus",
    "as_plain",
    "model_capability_card_from_dict",
]
