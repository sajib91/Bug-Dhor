"""Functional-preservation constraints for security steering experiments."""

from __future__ import annotations

import ast
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Protocol

MetricValue = bool | float | None


@dataclass(frozen=True, slots=True)
class FunctionalConstraints:
    """Acceptance limits for a generated candidate.

    Metrics are evidence, not inferred properties.  A missing metric is
    rejected when its corresponding ``require_*`` flag is enabled.
    """

    require_syntax_valid: bool = True
    require_compilation_success: bool = False
    require_unit_test_result: bool = False
    require_behavioral_consistency: bool = False
    min_unit_test_pass_rate: float = 1.0
    min_behavioral_consistency: float = 1.0
    max_functional_regression: float = 0.0
    min_security_improvement: float | None = None
    max_generation_overhead: float | None = None
    reject_unavailable_evidence: bool = True

    def __post_init__(self) -> None:
        for name in (
            "min_unit_test_pass_rate",
            "min_behavioral_consistency",
            "max_functional_regression",
        ):
            value = getattr(self, name)
            if not 0 <= value <= 1 or not math.isfinite(value):
                raise ValueError(f"{name} must be finite and in [0, 1]")
        for name in ("min_security_improvement", "max_generation_overhead"):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(value) or value < 0):
                raise ValueError(f"{name} must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class FunctionalEvidence:
    """Measured candidate evidence supplied by validators and test runners."""

    syntax_valid: bool | None = None
    compilation_success: bool | None = None
    unit_test_pass_rate: float | None = None
    behavioral_consistency: float | None = None
    functional_regression: float | None = None
    security_improvement: float | None = None
    generation_seconds: float | None = None
    baseline_generation_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in (
            "unit_test_pass_rate",
            "behavioral_consistency",
            "functional_regression",
        ):
            value = getattr(self, name)
            if value is not None and (not 0 <= value <= 1 or not math.isfinite(value)):
                raise ValueError(f"{name} must be finite and in [0, 1]")
        for name in (
            "security_improvement",
            "generation_seconds",
            "baseline_generation_seconds",
        ):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(value) or value < 0):
                raise ValueError(f"{name} must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class FunctionalEvaluation:
    """Acceptance decision and measured security/functionality trade-off."""

    accepted: bool
    evidence: FunctionalEvidence
    rejection_reasons: tuple[str, ...] = ()
    tradeoff: Mapping[str, float | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class FunctionalEvidenceEvaluator(Protocol):
    """Application-specific functional and security test integration."""

    def evaluate(
        self, candidate: str, baseline: str, baseline_generation_seconds: float | None
    ) -> FunctionalEvidence: ...


SyntaxValidator = Callable[[str], bool]


class FunctionalConstraintEvaluator:
    """Evaluate candidates without assuming syntax implies functional equivalence."""

    def __init__(
        self,
        constraints: FunctionalConstraints,
        *,
        evidence_evaluator: FunctionalEvidenceEvaluator | None = None,
        syntax_validator: SyntaxValidator | None = None,
    ) -> None:
        self.constraints = constraints
        self.evidence_evaluator = evidence_evaluator
        self.syntax_validator = syntax_validator

    def evaluate(
        self,
        candidate: str,
        *,
        baseline: str,
        baseline_generation_seconds: float | None = None,
        evidence: FunctionalEvidence | None = None,
    ) -> FunctionalEvaluation:
        measured = evidence
        if measured is None and self.evidence_evaluator is not None:
            measured = self.evidence_evaluator.evaluate(
                candidate, baseline, baseline_generation_seconds
            )
        if measured is None:
            measured = FunctionalEvidence(
                syntax_valid=self._validate_syntax(candidate),
                baseline_generation_seconds=baseline_generation_seconds,
            )
        elif measured.syntax_valid is None and self.syntax_validator is not None:
            measured = FunctionalEvidence(
                **{
                    **asdict(measured),
                    "syntax_valid": self._validate_syntax(candidate),
                }
            )
        reasons = self._rejection_reasons(measured)
        return FunctionalEvaluation(
            accepted=not reasons,
            evidence=measured,
            rejection_reasons=tuple(reasons),
            tradeoff={
                "security_improvement": measured.security_improvement,
                "functional_regression": measured.functional_regression,
                "generation_overhead": self._generation_overhead(measured),
            },
        )

    def compare_candidates(
        self,
        baseline: str,
        candidates: Sequence[str],
        *,
        baseline_generation_seconds: float | None = None,
        evidence: Mapping[str, FunctionalEvidence] | None = None,
    ) -> tuple[FunctionalEvaluation, ...]:
        """Evaluate every candidate and preserve rejected-candidate evidence."""

        return tuple(
            self.evaluate(
                candidate,
                baseline=baseline,
                baseline_generation_seconds=baseline_generation_seconds,
                evidence=None if evidence is None else evidence.get(candidate),
            )
            for candidate in candidates
        )

    def _rejection_reasons(self, evidence: FunctionalEvidence) -> list[str]:
        constraints = self.constraints
        reasons: list[str] = []
        if constraints.require_syntax_valid and evidence.syntax_valid is not True:
            reasons.append("syntax validity is missing or failed")
        if constraints.require_compilation_success and evidence.compilation_success is not True:
            reasons.append("compilation success is missing or failed")
        if constraints.require_unit_test_result:
            if evidence.unit_test_pass_rate is None:
                reasons.append("unit-test pass rate is unavailable")
            elif evidence.unit_test_pass_rate < constraints.min_unit_test_pass_rate:
                reasons.append("unit-test pass rate is below the configured minimum")
        if constraints.require_behavioral_consistency:
            if evidence.behavioral_consistency is None:
                reasons.append("behavioral consistency is unavailable")
            elif evidence.behavioral_consistency < constraints.min_behavioral_consistency:
                reasons.append("behavioral consistency is below the configured minimum")
        if evidence.functional_regression is None:
            if constraints.reject_unavailable_evidence:
                reasons.append("functional regression evidence is unavailable")
        elif evidence.functional_regression > constraints.max_functional_regression:
            reasons.append("functional regression exceeds the configured maximum")
        if constraints.min_security_improvement is not None:
            if evidence.security_improvement is None:
                reasons.append("security improvement evidence is unavailable")
            elif evidence.security_improvement < constraints.min_security_improvement:
                reasons.append("security improvement is below the configured minimum")
        overhead = self._generation_overhead(evidence)
        if constraints.max_generation_overhead is not None:
            if overhead is None:
                reasons.append("generation overhead evidence is unavailable")
            elif overhead > constraints.max_generation_overhead:
                reasons.append("generation overhead exceeds the configured maximum")
        return reasons

    def _validate_syntax(self, candidate: str) -> bool | None:
        if self.syntax_validator is not None:
            return bool(self.syntax_validator(candidate))
        return None

    @staticmethod
    def _generation_overhead(evidence: FunctionalEvidence) -> float | None:
        if evidence.generation_seconds is None or evidence.baseline_generation_seconds is None:
            return None
        if evidence.baseline_generation_seconds == 0:
            return 0.0 if evidence.generation_seconds == 0 else math.inf
        return (
            evidence.generation_seconds - evidence.baseline_generation_seconds
        ) / evidence.baseline_generation_seconds


def python_syntax_validator(candidate: str) -> bool:
    """Validate Python syntax only; this does not establish functionality."""

    try:
        ast.parse(candidate)
    except (SyntaxError, ValueError):
        return False
    return True


__all__ = [
    "FunctionalConstraintEvaluator",
    "FunctionalConstraints",
    "FunctionalEvaluation",
    "FunctionalEvidence",
    "FunctionalEvidenceEvaluator",
    "python_syntax_validator",
]
