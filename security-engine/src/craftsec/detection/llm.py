"""Strict interface for compatible LLM analysis evidence.

An LLM analysis is compatible only when it supplies a stable provider/model
identity, a concrete source location, and a supported category or CWE. Its
confidence is treated as an uncalibrated hypothesis signal with a capped family
weight. A calibrated probability is accepted only when the claim carries a
validated calibrator with dataset, split hash, and calibration metrics.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from craftsec.detection.classification import category_for_cwe, default_cwe
from craftsec.detection.models import (
    CalibratedProbability,
    EvidenceLocation,
    VulnerabilityCategory,
)
from craftsec.parsing.parser import ParsedSource
from craftsec.static.cwe import normalize_cwe

_HASH_RE = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class LLMClaim:
    """One structured claim emitted by a compatible LLM analysis."""

    provider: str
    model: str
    model_version: str
    location: EvidenceLocation
    confidence: float
    compatible: bool = True
    category: VulnerabilityCategory | str | None = None
    cwe: str | None = None
    title: str | None = None
    rule_id: str | None = None
    rationale: str = ""
    prompt_hash: str | None = None
    calibration: CalibratedProbability | None = None

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.model.strip() or not self.model_version.strip():
            raise ValueError("LLM claims require provider, model, and model version")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("LLM confidence must be between 0 and 1")
        if self.prompt_hash is not None and not _HASH_RE.match(self.prompt_hash):
            raise ValueError("prompt_hash must be a lowercase SHA-256 digest")
        if self.category is not None and not isinstance(self.category, VulnerabilityCategory):
            object.__setattr__(self, "category", VulnerabilityCategory(self.category))
        if self.cwe is not None:
            normalized = normalize_cwe(self.cwe)
            if normalized is None:
                raise ValueError(f"invalid CWE identifier: {self.cwe!r}")
            object.__setattr__(self, "cwe", normalized)

    @property
    def identity(self) -> str:
        return f"{self.provider}/{self.model}@{self.model_version}"

    @property
    def resolved_category(self) -> VulnerabilityCategory:
        category = self.category
        if isinstance(category, VulnerabilityCategory) and category.is_classified:
            return category
        if self.cwe:
            mapped = category_for_cwe(self.cwe)
            if mapped is not None:
                return mapped
        return VulnerabilityCategory.UNKNOWN

    @property
    def resolved_cwe(self) -> str | None:
        if self.cwe:
            return self.cwe
        return default_cwe(self.resolved_category)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "modelVersion": self.model_version,
            "identity": self.identity,
            "compatible": self.compatible,
            "location": self.location.to_dict(),
            "confidence": self.confidence,
            "category": self.resolved_category.value,
            "cwe": self.resolved_cwe,
            "title": self.title,
            "ruleId": self.rule_id,
            "rationale": self.rationale,
            "promptHash": self.prompt_hash,
            "calibratedProbability": (
                self.calibration.to_dict() if self.calibration is not None else None
            ),
        }


class LLMAnalyzer(Protocol):
    """A caller-supplied analyzer returning compatible structured claims."""

    analyzer_id: str

    def analyze(self, parsed: ParsedSource) -> Sequence[LLMClaim]: ...


def collect_llm_claims(
    analyzer: LLMAnalyzer,
    parsed: ParsedSource,
) -> tuple[LLMClaim, ...]:
    """Invoke one compatible analyzer and normalize its return value."""
    if not getattr(analyzer, "analyzer_id", ""):
        raise ValueError("LLM analyzers must declare a non-empty analyzer_id")
    claims = analyzer.analyze(parsed)
    return tuple(claims)


__all__ = ["LLMClaim", "LLMAnalyzer", "collect_llm_claims"]
