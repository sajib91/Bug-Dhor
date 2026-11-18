"""Configuration for deterministic, documented evidence fusion.

Weights are configuration, not empirical probabilities. They define how much a
piece of evidence is allowed to move the heuristic risk score. Changing them
changes prioritization, not the truth of a finding.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from bugdhor.program_analysis.taint import DEFAULT_TAINT_CONFIG, TaintConfig

_SEVERITY_FACTORS = {
    "info": 0.50,
    "low": 0.65,
    "medium": 0.85,
    "high": 1.00,
    "critical": 1.10,
}
_TAINT_CONFIDENCE = {
    "high": 1.00,
    "medium": 0.80,
    "low": 0.55,
}


@dataclass(frozen=True, slots=True)
class FusionWeights:
    """Documented support and family caps used by the fusion algorithm."""

    semgrep: float = 0.80
    bandit: float = 0.70
    codeql: float = 0.90
    joern: float = 0.85
    taint: float = 0.90
    llm: float = 0.40
    llm_reliability: float = 0.45
    program_family_bonus: float = 0.15
    max_program_bonus: float = 0.30
    program_family_cap: float = 0.95
    static_family_cap: float = 0.95
    llm_family_cap: float = 0.35
    refutation_scale: float = 0.80
    redundancy_decay: float = 0.55

    def __post_init__(self) -> None:
        for name in (
            "semgrep",
            "bandit",
            "codeql",
            "joern",
            "taint",
            "llm",
            "llm_reliability",
            "program_family_bonus",
            "max_program_bonus",
            "program_family_cap",
            "static_family_cap",
            "llm_family_cap",
            "refutation_scale",
            "redundancy_decay",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"FusionWeights.{name} must be between 0 and 1")

    def severity_factor(self, severity: str) -> float:
        return _SEVERITY_FACTORS.get(severity, _SEVERITY_FACTORS["info"])

    def taint_confidence_factor(self, confidence: str) -> float:
        return _TAINT_CONFIDENCE.get(confidence, _TAINT_CONFIDENCE["low"])

    def tool_support(self, tool: str, severity: str) -> float:
        base = {
            "semgrep": self.semgrep,
            "bandit": self.bandit,
            "codeql": self.codeql,
            "joern": self.joern,
        }.get(tool.lower(), self.bandit)
        return min(1.0, base * self.severity_factor(severity))

    def taint_support(self, confidence: str) -> float:
        return min(1.0, self.taint * self.taint_confidence_factor(confidence))

    def llm_support(self, confidence: float) -> float:
        return min(1.0, self.llm * max(0.0, min(1.0, confidence)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "semgrep": self.semgrep,
            "bandit": self.bandit,
            "codeql": self.codeql,
            "joern": self.joern,
            "taint": self.taint,
            "llm": self.llm,
            "llm_reliability": self.llm_reliability,
            "program_family_bonus": self.program_family_bonus,
            "max_program_bonus": self.max_program_bonus,
            "program_family_cap": self.program_family_cap,
            "static_family_cap": self.static_family_cap,
            "llm_family_cap": self.llm_family_cap,
            "refutation_scale": self.refutation_scale,
            "redundancy_decay": self.redundancy_decay,
        }


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    """Heuristic risk bands. These are prioritization buckets, not probabilities."""

    critical: float = 0.85
    high: float = 0.65
    medium: float = 0.40
    low: float = 0.20

    def __post_init__(self) -> None:
        values = (self.critical, self.high, self.medium, self.low)
        if any(not 0.0 <= value <= 1.0 for value in values):
            raise ValueError("risk thresholds must be between 0 and 1")
        if not (self.critical >= self.high >= self.medium >= self.low):
            raise ValueError("risk thresholds must be ordered critical >= high >= medium >= low")

    def band(self, value: float) -> str:
        if value >= self.critical:
            return "critical"
        if value >= self.high:
            return "high"
        if value >= self.medium:
            return "medium"
        if value >= self.low:
            return "low"
        return "info"

    def to_dict(self) -> dict[str, float]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
        }


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """All deterministic inputs that affect detection output."""

    weights: FusionWeights = field(default_factory=FusionWeights)
    thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    taint_config: TaintConfig = DEFAULT_TAINT_CONFIG
    group_line_tolerance: int = 0
    max_findings: int = 500
    max_evidence: int = 50
    min_risk: float = 0.0
    min_severity: str | None = None
    include_unclassified: bool = True
    enrich_cfg: bool = True
    enrich_dfg: bool = True
    llm_min_confidence: float = 0.35

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_risk <= 1.0:
            raise ValueError("min_risk must be between 0 and 1")
        if not 0.0 <= self.llm_min_confidence <= 1.0:
            raise ValueError("llm_min_confidence must be between 0 and 1")
        if self.min_severity is not None and self.min_severity not in _SEVERITY_FACTORS:
            raise ValueError(f"unsupported min_severity: {self.min_severity!r}")
        if self.group_line_tolerance < 0:
            raise ValueError("group_line_tolerance must be non-negative")
        if self.max_findings < 1 or self.max_evidence < 1:
            raise ValueError("max_findings and max_evidence must be positive")

    def config_hash(self) -> str:
        payload = {
            "weights": self.weights.to_dict(),
            "thresholds": self.thresholds.to_dict(),
            "taint": self.taint_config.to_dict(),
            "group_line_tolerance": self.group_line_tolerance,
            "max_findings": self.max_findings,
            "max_evidence": self.max_evidence,
            "min_risk": self.min_risk,
            "min_severity": self.min_severity,
            "include_unclassified": self.include_unclassified,
            "enrich_cfg": self.enrich_cfg,
            "enrich_dfg": self.enrich_dfg,
            "llm_min_confidence": self.llm_min_confidence,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


DEFAULT_DETECTION_CONFIG = DetectionConfig()

__all__ = [
    "DEFAULT_DETECTION_CONFIG",
    "DetectionConfig",
    "FusionWeights",
    "RiskThresholds",
]
