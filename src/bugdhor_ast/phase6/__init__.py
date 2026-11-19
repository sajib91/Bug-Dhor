"""Opt-in local Phase 6 explanation, repair, and verification service.

This package is additive. Existing detection, flow, CLI, and FastAPI contracts
are untouched; callers must explicitly select these commands.
"""

from .service import (
    Phase6Error,
    apply_preview,
    build_analysis_payload,
    build_preview,
    explain_selected,
    list_findings,
    list_history,
    revert_applied,
    suggest_selected,
    verify_applied,
)
from .session import SESSION_SCHEMA_VERSION, Phase6Session

__all__ = [
    "SESSION_SCHEMA_VERSION",
    "Phase6Error",
    "Phase6Session",
    "apply_preview",
    "build_analysis_payload",
    "build_preview",
    "explain_selected",
    "list_findings",
    "list_history",
    "revert_applied",
    "suggest_selected",
    "verify_applied",
]
