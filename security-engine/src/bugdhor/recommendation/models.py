"""Data contracts for the secure code recommendation workflow."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from bugdhor.repair.engine import CandidatePatch
from bugdhor.repair.ranking import CandidateDecision

WORKFLOW_STAGES: tuple[str, ...] = (
    "receive_findings",
    "source_context",
    "cwe_requirements",
    "repository_context",
    "security_evidence",
    "secure_prompt",
    "generate_candidates",
    "syntax",
    "static_analysis",
    "functional_tests",
    "rank_candidates",
    "display_recommendation",
)

_STAGE_COMPLETED = "completed"
_STAGE_SKIPPED = "skipped"
_STAGE_UNAVAILABLE = "unavailable"
_STAGE_FAILED = "failed"


@dataclass(frozen=True, slots=True)
class StageRecord:
    """One honest workflow-stage status."""

    stage: str
    status: str
    detail: str = ""
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in WORKFLOW_STAGES:
            raise ValueError(f"unknown recommendation stage: {self.stage!r}")
        if self.status not in {
            _STAGE_COMPLETED,
            _STAGE_SKIPPED,
            _STAGE_UNAVAILABLE,
            _STAGE_FAILED,
        }:
            raise ValueError(f"unknown stage status: {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
            "data": dict(self.data),
        }


@dataclass(frozen=True, slots=True)
class SecurePrompt:
    """Prompt metadata and text for a reproducible secure-generation request."""

    text: str
    prompt_hash: str
    cwe: str | None
    provider_id: str
    model_id: str
    steering_applied: bool
    steering_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "providerId": self.provider_id,
            "modelId": self.model_id,
            "promptHash": self.prompt_hash,
            "steeringApplied": self.steering_applied,
            "steeringReason": self.steering_reason,
        }


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    """Verification evidence for one generated candidate."""

    candidate_id: str
    patch: str
    patch_sha256: str
    patched_source: str
    touched_files: tuple[str, ...]
    syntax_valid: bool
    verification: Mapping[str, Any]
    functional: Mapping[str, Any]
    cwe_requirements_met: bool
    requirement_reasons: tuple[str, ...]
    evidence: Mapping[str, Any]
    candidate: CandidatePatch | None = None
    decision: CandidateDecision | None = None
    rejection_reason: str | None = None

    def to_dict(self, *, include_source: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "candidateId": self.candidate_id,
            "patch": self.patch,
            "patchSha256": self.patch_sha256,
            "touchedFiles": list(self.touched_files),
            "syntaxValid": self.syntax_valid,
            "verification": dict(self.verification),
            "functional": dict(self.functional),
            "cweRequirementsMet": self.cwe_requirements_met,
            "requirementReasons": list(self.requirement_reasons),
            "evidence": dict(self.evidence),
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "rejectionReason": self.rejection_reason,
            "accepted": bool(self.decision and self.decision.accepted),
        }
        if include_source:
            payload["patchedSource"] = self.patched_source
        return payload


@dataclass(frozen=True, slots=True)
class RecommendationExplanation:
    """Human-readable comparison of original and proposed code."""

    summary: str
    changes: tuple[str, ...]
    why: tuple[str, ...]
    remaining_risks: tuple[str, ...]
    functional_assurance: str
    security_guarantee: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "changes": list(self.changes),
            "why": list(self.why),
            "remainingRisks": list(self.remaining_risks),
            "functionalAssurance": self.functional_assurance,
            "securityGuarantee": self.security_guarantee,
        }


@dataclass(frozen=True, slots=True)
class RecommendationResult:
    """A proposal-only recommendation with full verification provenance."""

    finding_id: str
    cwe: str | None
    original_source: str
    selected: CandidateEvaluation | None
    candidates: tuple[CandidateEvaluation, ...]
    prompt: SecurePrompt
    stages: tuple[StageRecord, ...]
    explanation: RecommendationExplanation
    state: str
    requires_approval: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return self.state == "recommended" and self.selected is not None

    def to_dict(self) -> dict[str, Any]:
        selected = self.selected
        return {
            "findingId": self.finding_id,
            "cwe": self.cwe,
            "originalCode": self.original_source,
            "repairedCode": selected.patched_source if selected is not None else None,
            "state": self.state,
            "selected": selected.to_dict(include_source=True) if selected is not None else None,
            "candidates": [item.to_dict() for item in self.candidates],
            "prompt": self.prompt.to_dict(),
            "stages": [stage.to_dict() for stage in self.stages],
            "explanation": self.explanation.to_dict(),
            "requiresApproval": self.requires_approval,
            "verified": self.verified,
            "metadata": dict(self.metadata),
        }


def hash_source(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = [
    "WORKFLOW_STAGES",
    "CandidateEvaluation",
    "RecommendationExplanation",
    "RecommendationResult",
    "SecurePrompt",
    "StageRecord",
    "hash_source",
]
