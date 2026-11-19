"""Persistent, local-only session state for the Phase 6 workflow.

The session file stores exact source snapshots needed for safe revert and
verification. It is not sent to a backend and is created only by explicit
local Phase 6 commands.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..explain.repair import (
    Patch,
    PatchHistory,
    RepairRecommendation,
    validate_patch,
    validate_recommendation,
)

SESSION_SCHEMA_VERSION = "1.0"

_SESSION_KEYS = frozenset(
    {
        "schema_version",
        "history",
        "patches",
        "recommendations",
        "findings",
    }
)


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


@dataclass
class Phase6Session:
    """Local persistence for patches, history, and finding snapshots."""

    path: Path
    history: PatchHistory = field(default_factory=PatchHistory)
    patches: dict[str, dict[str, Any]] = field(default_factory=dict)
    recommendations: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.path, str):
            self.path = Path(self.path)
        if not isinstance(self.path, Path):
            raise TypeError("session.path must be a path")

    @classmethod
    def load(cls, path: str | Path) -> Phase6Session:
        """Load a session, returning an empty session when none exists."""

        session_path = Path(path)
        if not session_path.exists():
            return cls(path=session_path)
        try:
            payload = json.loads(session_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Cannot read Phase 6 session: {error}") from error
        value = _as_mapping(payload, "session")
        if set(value) != _SESSION_KEYS:
            raise ValueError("Phase 6 session has invalid keys")
        if value["schema_version"] != SESSION_SCHEMA_VERSION:
            raise ValueError(
                f"session.schema_version must be {SESSION_SCHEMA_VERSION}"
            )
        patches = _as_mapping(value["patches"], "session.patches")
        recommendations = _as_mapping(
            value["recommendations"], "session.recommendations"
        )
        findings = _as_mapping(value["findings"], "session.findings")
        for patch_value in patches.values():
            validate_patch(patch_value)
        for recommendation_value in recommendations.values():
            validate_recommendation(recommendation_value)
        return cls(
            path=session_path,
            history=PatchHistory.from_dict(value["history"]),
            patches=dict(patches),
            recommendations=dict(recommendations),
            findings=dict(findings),
        )

    def save(self) -> None:
        """Atomically write the session with owner-only permissions."""

        payload = {
            "schema_version": SESSION_SCHEMA_VERSION,
            "history": self.history.to_dict(),
            "patches": self.patches,
            "recommendations": self.recommendations,
            "findings": self.findings,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(self.path)

    def record_preview(
        self,
        finding: Mapping[str, Any],
        recommendation: RepairRecommendation,
        patch: Patch,
    ) -> None:
        """Store a reviewed preview for later apply, verify, and revert."""

        self.findings[recommendation.finding_id] = dict(finding)
        self.recommendations[recommendation.finding_id] = recommendation.to_dict()
        self.patches[patch.patch_id] = patch.to_dict()

    def get_patch(self, patch_id: str) -> Patch:
        value = self.patches.get(patch_id)
        if value is None:
            raise KeyError(f"Unknown patch: {patch_id}")
        return Patch.from_dict(value)

    def get_recommendation(self, finding_id: str) -> RepairRecommendation:
        value = self.recommendations.get(finding_id)
        if value is None:
            raise KeyError(f"Unknown recommendation: {finding_id}")
        return RepairRecommendation.from_dict(value)

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        value = self.findings.get(finding_id)
        if value is None:
            raise KeyError(f"Unknown finding: {finding_id}")
        return dict(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SESSION_SCHEMA_VERSION,
            "history": self.history.to_dict(),
            "patches": self.patches,
            "recommendations": self.recommendations,
            "findings": self.findings,
        }


__all__ = ["SESSION_SCHEMA_VERSION", "Phase6Session"]
