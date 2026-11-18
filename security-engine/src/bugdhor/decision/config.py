"""Versioned configuration for the transparent decision policy."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bugdhor.decision.models import DeveloperPreferences, PolicyAction
from bugdhor.risk.models import canonical_hash


@dataclass(frozen=True, slots=True)
class PolicyThresholds:
    """Documented thresholds for baseline rule matching."""

    warning: float
    critical: float
    uncertainty: float
    basis: str

    def __post_init__(self) -> None:
        for name in ("warning", "critical", "uncertainty"):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if not self.warning <= self.critical:
            raise ValueError("warning threshold must not exceed critical threshold")
        if not self.basis.strip():
            raise ValueError("policy thresholds require a basis")

    def to_dict(self) -> dict[str, Any]:
        return {
            "warning": self.warning,
            "critical": self.critical,
            "uncertainty": self.uncertainty,
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class UtilityConfig:
    """Preference-elicited utility terms for the adaptive policy.

    These are not measured effects. They express what the developer is willing
    to trade off and are reported as such. No claim of decision optimality is
    made unless a separate objective and experiment validate these terms.
    """

    efficacy: Mapping[str, float]
    cost: Mapping[str, float]
    harm: Mapping[str, float]
    basis: str

    def __post_init__(self) -> None:
        actions = {action.value for action in PolicyAction}
        for name, mapping in (
            ("efficacy", self.efficacy),
            ("cost", self.cost),
            ("harm", self.harm),
        ):
            if set(mapping) != actions:
                raise ValueError(f"utility {name} must define every policy action")
            for key, value in mapping.items():
                if not math.isfinite(value) or value < 0:
                    raise ValueError(f"utility {name}[{key}] must be finite and non-negative")
        if not self.basis.strip():
            raise ValueError("utility configuration requires a basis")

    def to_dict(self) -> dict[str, Any]:
        return {
            "efficacy": dict(sorted(self.efficacy.items())),
            "cost": dict(sorted(self.cost.items())),
            "harm": dict(sorted(self.harm.items())),
            "basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    mode: str
    thresholds: PolicyThresholds
    preferences: DeveloperPreferences
    utility: UtilityConfig
    name: str = "transparent-security-policy"
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if self.mode not in {"rule_baseline", "adaptive"}:
            raise ValueError("policy mode must be rule_baseline or adaptive")
        if not self.name.strip() or not self.version.strip():
            raise ValueError("policy config requires a name and version")

    def config_hash(self) -> str:
        return canonical_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "mode": self.mode,
            "thresholds": self.thresholds.to_dict(),
            "preferences": self.preferences.to_dict(),
            "utility": self.utility.to_dict(),
        }


def policy_config_from_mapping(payload: Mapping[str, Any]) -> PolicyConfig:
    """Build a policy config from a JSON-style mapping."""
    thresholds_payload = payload.get("thresholds")
    utility_payload = payload.get("utility")
    if not isinstance(thresholds_payload, Mapping) or not isinstance(utility_payload, Mapping):
        raise ValueError("policy config requires thresholds and utility objects")

    preferences_payload = payload.get("preferences", {})
    if not isinstance(preferences_payload, Mapping):
        raise ValueError("preferences must be an object")
    preferences = DeveloperPreferences(
        notification_level=str(preferences_payload.get("notificationLevel", "detailed")),
        allow_warnings=bool(preferences_payload.get("allowWarnings", True)),
        allow_practice_recommendations=bool(
            preferences_payload.get("allowPracticeRecommendations", True)
        ),
        allow_additional_analysis=bool(preferences_payload.get("allowAdditionalAnalysis", True)),
        allow_counterfactual_analysis=bool(
            preferences_payload.get("allowCounterfactualAnalysis", False)
        ),
        allow_activation_steering=bool(preferences_payload.get("allowActivationSteering", False)),
        allow_secure_code_generation=bool(
            preferences_payload.get("allowSecureCodeGeneration", True)
        ),
        require_independent_verification=bool(
            preferences_payload.get("requireIndependentVerification", True)
        ),
        enforcement=str(preferences_payload.get("enforcement", "advisory")),
        basis=str(preferences_payload.get("basis", "developer_configuration")),
    )
    thresholds = PolicyThresholds(
        warning=float(thresholds_payload["warning"]),
        critical=float(thresholds_payload["critical"]),
        uncertainty=float(thresholds_payload["uncertainty"]),
        basis=str(thresholds_payload["basis"]),
    )
    for name in ("efficacy", "cost", "harm"):
        if not isinstance(utility_payload.get(name), Mapping):
            raise ValueError(f"utility.{name} must be an object")
    utility = UtilityConfig(
        efficacy={str(key): float(value) for key, value in utility_payload["efficacy"].items()},
        cost={str(key): float(value) for key, value in utility_payload["cost"].items()},
        harm={str(key): float(value) for key, value in utility_payload["harm"].items()},
        basis=str(utility_payload["basis"]),
    )
    return PolicyConfig(
        mode=str(payload.get("mode", "rule_baseline")),
        thresholds=thresholds,
        preferences=preferences,
        utility=utility,
        name=str(payload.get("name", "transparent-security-policy")),
        version=str(payload.get("version", "1.0.0")),
    )


def load_policy_config(path: str | Path) -> PolicyConfig:
    """Load a policy config from JSON."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("policy config root must be an object")
    return policy_config_from_mapping(payload)


__all__ = [
    "PolicyConfig",
    "PolicyThresholds",
    "UtilityConfig",
    "load_policy_config",
    "policy_config_from_mapping",
]
