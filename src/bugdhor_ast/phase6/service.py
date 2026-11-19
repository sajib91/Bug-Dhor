"""Local Phase 6 workflow service built from existing analyzers.

Every function is explicit: previews never write source, apply/revert require a
matching confirmation, and verification reruns analyzers from current bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..detection.engine import BugDhorDetectionEngine
from ..engine import BugDhorASTEngine
from ..explain import explain_finding, recommend_repair, verify_repair
from ..explain.repair import (
    AiRepairConfig,
    PatchApproval,
    PatchError,
    RepairStatus,
    apply_patch,
    build_patch,
    request_ai_repair,
    revert_patch,
)
from ..flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics
from ..languages import detect_language
from .session import Phase6Session


class Phase6Error(Exception):
    """A user-facing Phase 6 workflow error."""


def _read_source(file: str | Path) -> str:
    path = Path(file)
    if not path.is_file():
        raise Phase6Error(f"Source file does not exist: {path}")
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise Phase6Error(f"Source file is not valid UTF-8: {path}") from error


def _language_for(file: str | Path) -> str:
    language = detect_language(str(file))
    if language is None:
        raise Phase6Error(f"Unsupported source extension: {Path(file).suffix}")
    return language


def build_analysis_payload(
    source_code: str, language: str, file: str | Path
) -> dict[str, Any]:
    """Assemble the analysis payload expected by the explanation layer."""

    ast_payload = BugDhorASTEngine().analyze_source(source_code, language)
    detection = BugDhorDetectionEngine().analyze_source(
        source_code, language, file=str(file)
    )
    detection_payload = detection.to_dict()
    flow = FlowEngine().analyze_source(source_code, language, file=str(file))
    flow_payload = flow.to_dict(FLOW_SECTIONS)

    payload: dict[str, Any] = dict(detection_payload)
    payload["diagnostics"] = list(detection_payload["diagnostics"]) + [
        item.to_dict() for item in taint_diagnostics(flow)
    ]
    for section in FLOW_SECTIONS:
        payload[section] = flow_payload[section]
    payload["unresolved_references"] = flow_payload["unresolved_references"]
    payload["limitations"] = flow_payload["limitations"]
    for key in (
        "functions",
        "classes",
        "variables",
        "function_calls",
        "imports",
        "syntax_errors",
    ):
        payload[key] = ast_payload[key]
    return payload


def _locate(
    findings: list[dict[str, Any]],
    *,
    finding_id: str | None,
    index: int | None,
) -> dict[str, Any]:
    if finding_id is not None:
        try:
            selected = next(
                item for item in findings if item["finding_id"] == finding_id
            )
        except (KeyError, StopIteration) as error:
            raise Phase6Error(f"Finding is not available: {finding_id}") from error
        return selected
    if index is not None:
        if index < 0 or index >= len(findings):
            raise Phase6Error(
                f"Finding index {index} is outside the range 0-{len(findings) - 1}"
            )
        return findings[index]
    if len(findings) == 1:
        return findings[0]
    raise Phase6Error(
        "Select a finding by --finding-id or --index; "
        f"{len(findings)} findings are available."
    )


def _summaries(
    source_code: str,
    language: str,
    file: str | Path,
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, finding in enumerate(analysis["diagnostics"]):
        explanation = explain_finding(finding, analysis)
        recommendation = recommend_repair(
            finding,
            analysis,
            explanation,
            source_code=source_code,
            file=str(file),
        )
        findings.append(
            {
                "index": index,
                "finding_id": explanation.finding_id,
                "rule_id": finding.get("rule_id", ""),
                "severity": finding.get("severity", ""),
                "language": language,
                "message": finding.get("message", ""),
                "location": explanation.location.to_dict(),
                "cwe": [item.to_dict() for item in explanation.cwe],
                "root_cause_status": explanation.root_cause.status.value,
                "recommendation_status": recommendation.status.value,
                "strategy": recommendation.strategy,
            }
        )
    return findings


def _selected(
    source_code: str,
    language: str,
    file: str | Path,
    *,
    finding_id: str | None,
    index: int | None,
) -> tuple[dict[str, Any], dict[str, Any], Any, Any]:
    analysis = build_analysis_payload(source_code, language, file)
    summary = _locate(
        _summaries(source_code, language, file, analysis),
        finding_id=finding_id,
        index=index,
    )
    finding = analysis["diagnostics"][summary["index"]]
    explanation = explain_finding(finding, analysis)
    return finding, analysis, explanation, summary


def list_findings(file: str | Path) -> dict[str, Any]:
    """Return all current findings with explanation summaries."""

    source_code = _read_source(file)
    language = _language_for(file)
    analysis = build_analysis_payload(source_code, language, file)
    findings = _summaries(source_code, language, file, analysis)
    return {
        "file": str(file),
        "language": language,
        "finding_count": len(findings),
        "findings": findings,
    }


def explain_selected(
    file: str | Path,
    *,
    finding_id: str | None = None,
    index: int | None = None,
) -> dict[str, Any]:
    """Return an evidence-based explanation without creating any state."""

    source_code = _read_source(file)
    language = _language_for(file)
    finding, _, explanation, _ = _selected(
        source_code,
        language,
        file,
        finding_id=finding_id,
        index=index,
    )
    return {
        "file": str(file),
        "language": language,
        "finding": finding,
        "finding_id": explanation.finding_id,
        "explanation": explanation.to_dict(),
    }


def suggest_selected(
    file: str | Path,
    *,
    finding_id: str | None = None,
    index: int | None = None,
    ai_config: AiRepairConfig | None = None,
    secret_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return a deterministic repair and optional untrusted AI candidate."""

    source_code = _read_source(file)
    language = _language_for(file)
    finding, analysis, explanation, _ = _selected(
        source_code,
        language,
        file,
        finding_id=finding_id,
        index=index,
    )
    recommendation = recommend_repair(
        finding,
        analysis,
        explanation,
        source_code=source_code,
        file=str(file),
    )
    result: dict[str, Any] = {
        "file": str(file),
        "language": language,
        "finding": finding,
        "finding_id": explanation.finding_id,
        "recommendation": recommendation.to_dict(),
        "ai": None,
    }
    if ai_config is not None:
        ai_result = request_ai_repair(
            finding,
            analysis,
            explanation,
            source_code=source_code,
            file=str(file),
            config=ai_config,
            secret_values=secret_values,
        )
        result["ai"] = ai_result.to_dict()
    return result


def build_preview(
    file: str | Path,
    *,
    finding_id: str | None = None,
    index: int | None = None,
    session: Phase6Session,
) -> dict[str, Any]:
    """Build an explanation, recommendation, and exact patch without writing."""

    source_code = _read_source(file)
    language = _language_for(file)
    finding, analysis, explanation, _ = _selected(
        source_code,
        language,
        file,
        finding_id=finding_id,
        index=index,
    )
    recommendation = recommend_repair(
        finding,
        analysis,
        explanation,
        source_code=source_code,
        file=str(file),
    )
    patch = None
    if recommendation.status is RepairStatus.READY:
        patch = build_patch(recommendation, source_code, file=str(file))
        session.record_preview(finding, recommendation, patch)
        session.save()
    return {
        "file": str(file),
        "language": language,
        "finding": finding,
        "finding_id": explanation.finding_id,
        "explanation": explanation.to_dict(),
        "recommendation": recommendation.to_dict(),
        "patch": patch.to_dict() if patch is not None else None,
        "can_apply": patch is not None,
        "requires_approval": patch is not None,
    }


def _same_file(left: str | Path, right: str | Path) -> bool:
    return Path(left).resolve() == Path(right).resolve()


def apply_preview(
    file: str | Path,
    *,
    patch_id: str,
    confirmation: str,
    session: Phase6Session,
) -> dict[str, Any]:
    """Apply one previewed patch after explicit matching confirmation."""

    try:
        patch = session.get_patch(patch_id)
    except KeyError as error:
        raise Phase6Error(str(error)) from error
    if not _same_file(patch.file, file):
        raise Phase6Error("The reviewed patch targets a different file.")
    existing = [
        entry
        for entry in session.history.find_by_patch(patch_id)
        if entry.reverted_at is None
    ]
    if existing:
        raise Phase6Error("This patch has already been applied and not reverted.")

    approval = PatchApproval(approved=True, confirmation=confirmation)
    try:
        result = apply_patch(patch, approval, history=session.history)
    except PatchError as error:
        raise Phase6Error(str(error)) from error
    session.save()
    return result.to_dict()


def _history_entry(entry_id: str, session: Phase6Session) -> Any:
    entry = session.history.get(entry_id)
    if entry is None:
        raise Phase6Error(f"Unknown history entry: {entry_id}")
    return entry


def verify_applied(entry_id: str, session: Phase6Session) -> dict[str, Any]:
    """Verify one applied patch with fresh local analyzers."""

    entry = _history_entry(entry_id, session)
    if entry.reverted_at is not None:
        raise Phase6Error("Cannot verify a reverted history entry.")
    try:
        patch = session.get_patch(entry.patch_id)
        finding = session.get_finding(patch.finding_id)
    except KeyError as error:
        raise Phase6Error(str(error)) from error
    source_after = _read_source(entry.file)
    result = verify_repair(
        finding,
        source_after,
        source_before=entry.backup_code,
        patch=patch,
        file=entry.file,
        language=patch.edits[0].language,
    )
    return result.to_dict()


def revert_applied(
    entry_id: str,
    *,
    confirmation: str,
    session: Phase6Session,
) -> dict[str, Any]:
    """Restore exact pre-apply source bytes after explicit confirmation."""

    entry = _history_entry(entry_id, session)
    approval = PatchApproval(approved=True, confirmation=confirmation)
    try:
        result = revert_patch(entry, approval, history=session.history)
    except PatchError as error:
        raise Phase6Error(str(error)) from error
    session.save()
    return result.to_dict()


def list_history(session: Phase6Session) -> dict[str, Any]:
    """Return the persisted patch history without modifying it."""

    payload = session.history.to_dict()
    return {"entry_count": len(payload["entries"]), "history": payload}


__all__ = [
    "Phase6Error",
    "build_analysis_payload",
    "build_preview",
    "explain_selected",
    "list_findings",
    "list_history",
    "revert_applied",
    "suggest_selected",
    "verify_applied",
]
