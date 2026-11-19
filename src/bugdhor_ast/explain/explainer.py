"""Unified explanation orchestration.

The low-level adapter in :mod:`bugdhor_ast.explain.evidence` preserves facts.
This module adds deterministic root-cause localization while keeping the v1
explanation schema unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .cwe import map_cwe
from .evidence import build_explanation
from .root_cause import analyze_root_cause
from .schema import FindingExplanation


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("analysis payloads must be mappings")
    return dict(value)


def _deduplicate(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if isinstance(value, str)))


def explain_finding(finding: Any, analysis: Any = None) -> FindingExplanation:
    """Build a full explanation with deterministic root-cause analysis."""

    explanation = build_explanation(finding, analysis)
    root_cause_result = analyze_root_cause(
        finding, analysis, explanation=explanation
    )
    evidence = explanation.evidence
    for record in root_cause_result.evidence:
        evidence = evidence.add(record)
    enriched = replace(
        explanation,
        root_cause=root_cause_result.root_cause,
        evidence=evidence,
        limitations=_deduplicate(
            explanation.limitations + root_cause_result.limitations
        ),
    )
    cwe = map_cwe(finding, analysis, explanation=enriched)
    return replace(enriched, cwe=cwe)


def explain_findings(findings: Any, analysis: Any = None) -> list[FindingExplanation]:
    """Explain every finding in an existing detection payload or list."""

    value = findings
    if hasattr(value, "to_dict"):
        value = value.to_dict().get("diagnostics", [])
    if not isinstance(value, (list, tuple)):
        raise TypeError("findings must be a list")
    return [explain_finding(item, analysis) for item in value]
