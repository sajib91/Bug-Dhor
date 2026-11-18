"""Transparent patch ranking and mandatory constraint evaluation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RankingPolicy:
    """Weighted preference policy.

    Each term is normalized to ``0..1`` from measured evidence or a documented
    patch metric. Weights are configuration, not learned or inferred scores.
    """

    security_improvement: float = 4.0
    functional_tests: float = 3.0
    regression_tests: float = 3.0
    syntax_validity: float = 2.0
    cwe_remediation: float = 3.0
    repository_consistency: float = 2.0
    patch_complexity: float = 1.0
    unnecessary_changes: float = 2.0

    def __post_init__(self) -> None:
        weights = self.weights
        if any(value < 0 for value in weights.values()) or sum(weights.values()) <= 0:
            raise ValueError("ranking weights must be non-negative and not all zero")

    @property
    def weights(self) -> dict[str, float]:
        return {
            "securityImprovement": self.security_improvement,
            "functionalTests": self.functional_tests,
            "regressionTests": self.regression_tests,
            "syntaxValidity": self.syntax_validity,
            "cweRemediation": self.cwe_remediation,
            "repositoryConsistency": self.repository_consistency,
            "patchComplexity": self.patch_complexity,
            "unnecessaryChanges": self.unnecessary_changes,
        }


@dataclass(frozen=True, slots=True)
class MandatoryConstraints:
    """Hard constraints. A candidate violating one cannot be selected."""

    require_syntax_valid: bool = True
    require_security_improvement: bool = False
    require_functional_tests: bool = False
    require_regression_tests: bool = False
    require_cwe_compliance: bool = True
    require_independent_verification: bool = True
    minimum_functional_pass_rate: float = 1.0
    max_touched_files: int = 2

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_functional_pass_rate <= 1:
            raise ValueError("minimum_functional_pass_rate must be between zero and one")
        if self.max_touched_files < 1:
            raise ValueError("max_touched_files must be positive")


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    candidate_id: str
    accepted: bool
    score: float | None
    terms: Mapping[str, float | None]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidateId": self.candidate_id,
            "accepted": self.accepted,
            "score": self.score,
            "terms": dict(self.terms),
            "reasons": list(self.reasons),
        }


class PatchRanker:
    """Evaluate hard constraints, then rank surviving candidates."""

    def __init__(
        self,
        policy: RankingPolicy | None = None,
        constraints: MandatoryConstraints | None = None,
    ) -> None:
        self.policy = policy or RankingPolicy()
        self.constraints = constraints or MandatoryConstraints()

    def rank(
        self,
        candidates: Sequence[Any],
        *,
        cwe: str | None = None,
    ) -> tuple[Any | None, tuple[CandidateDecision, ...]]:
        decisions: list[CandidateDecision] = []
        eligible: list[tuple[Any, CandidateDecision]] = []
        for candidate in candidates:
            decision = self.evaluate(candidate, cwe=cwe)
            decisions.append(decision)
            if decision.accepted:
                eligible.append((candidate, decision))
        selected = (
            max(eligible, key=lambda item: item[1].score or 0.0)[0] if eligible else None
        )
        return selected, tuple(decisions)

    def evaluate(self, candidate: Any, *, cwe: str | None = None) -> CandidateDecision:
        metadata = candidate.metadata
        evidence = metadata.get("evidence", {})
        reasons: list[str] = []
        if self.constraints.require_syntax_valid and not candidate.syntax_valid:
            reasons.append("rejected: syntax validation failed")
        if len(candidate.touched_files) > self.constraints.max_touched_files:
            reasons.append("rejected: touched-file limit exceeded")
        if (
            self.constraints.require_security_improvement
            and evidence.get("securityImprovement") is not True
        ):
            reasons.append("rejected: independent security improvement evidence is missing")
        if self.constraints.require_independent_verification and not candidate.verified:
            reasons.append("rejected: independent verification has not passed")
        functional_rate = _number(evidence.get("functionalTestPassRate"))
        if self.constraints.require_functional_tests and (
            functional_rate is None
            or functional_rate < self.constraints.minimum_functional_pass_rate
        ):
            reasons.append("rejected: mandatory functional-test threshold was not met")
        if (
            self.constraints.require_regression_tests
            and evidence.get("regressionTestsPassed") is not True
        ):
            reasons.append("rejected: regression tests did not pass independently")
        cwe_met = evidence.get("cweRequirementsMet")
        if self.constraints.require_cwe_compliance and cwe and cwe_met is False:
            reasons.append(f"rejected: remediation requirements for {cwe} were not met")
        terms = self._terms(candidate, evidence, cwe)
        if reasons:
            return CandidateDecision(candidate.candidate_id, False, None, terms, tuple(reasons))
        score = _weighted_score(terms, self.policy.weights)
        reasons.extend(
            [
                "accepted: all mandatory constraints passed",
                f"ranked by weighted normalized score {score:.4f}",
            ]
        )
        return CandidateDecision(candidate.candidate_id, True, score, terms, tuple(reasons))

    def _terms(
        self,
        candidate: Any,
        evidence: Mapping[str, Any],
        cwe: str | None,
    ) -> dict[str, float | None]:
        return {
            "securityImprovement": _boolean_score(evidence.get("securityImprovement")),
            "functionalTests": _number(evidence.get("functionalTestPassRate")),
            "regressionTests": _boolean_score(evidence.get("regressionTestsPassed")),
            "syntaxValidity": 1.0 if candidate.syntax_valid else 0.0,
            "cweRemediation": _cwe_score(evidence.get("cweRequirementsMet"), cwe),
            "repositoryConsistency": _number(evidence.get("repositoryConsistencyScore")),
            "patchComplexity": _complexity_score(candidate.patch),
            "unnecessaryChanges": _inverse_score(evidence.get("unnecessaryChangesRatio")),
        }


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1:
        return float(value)
    return None


def _boolean_score(value: object) -> float | None:
    return 1.0 if value is True else 0.0 if value is False else None


def _cwe_score(value: object, cwe: str | None) -> float | None:
    if not cwe or value is None:
        return None
    return _boolean_score(value)


def _inverse_score(value: object) -> float | None:
    number = _number(value)
    return None if number is None else 1.0 - number


def _complexity_score(patch: str) -> float:
    """Use changed-line count: ``1 / (1 + additions + deletions)``."""
    changed = sum(
        1
        for line in patch.splitlines()
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith(("+++", "---"))
    )
    return 1.0 / (1.0 + changed)


def _weighted_score(terms: Mapping[str, float | None], weights: Mapping[str, float]) -> float:
    denominator = sum(weights.values())
    return sum((terms[name] or 0.0) * weight for name, weight in weights.items()) / denominator


__all__ = [
    "CandidateDecision",
    "MandatoryConstraints",
    "PatchRanker",
    "RankingPolicy",
]
