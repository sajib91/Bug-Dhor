"""CWE-specific remediation requirements for secure recommendations.

Requirements are explicit, auditable rules. They guide prompt construction and
candidate screening, but they are never substituted for independent security
verification or functional tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from bugdhor.detection.classification import CATEGORY_INFO, category_for_cwe


@dataclass(frozen=True, slots=True)
class RemediationRequirement:
    """Concrete controls a candidate must satisfy for a target CWE."""

    cwe: str
    title: str
    summary: str
    required_controls: tuple[str, ...]
    required_indicators: tuple[re.Pattern[str], ...]
    forbidden_patterns: tuple[re.Pattern[str], ...]
    verification_checks: tuple[str, ...]
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "title": self.title,
            "summary": self.summary,
            "requiredControls": list(self.required_controls),
            "requiredIndicatorCount": len(self.required_indicators),
            "forbiddenPatternCount": len(self.forbidden_patterns),
            "verificationChecks": list(self.verification_checks),
            "confidence": self.confidence,
        }


def _requirement(
    cwe: str,
    summary: str,
    controls: tuple[str, ...],
    indicators: tuple[str, ...],
    forbidden: tuple[str, ...],
    checks: tuple[str, ...],
    *,
    confidence: str = "high",
) -> RemediationRequirement:
    category = category_for_cwe(cwe)
    info = CATEGORY_INFO.get(category) if category is not None else None
    return RemediationRequirement(
        cwe=cwe,
        title=info.title if info is not None else cwe,
        summary=summary,
        required_controls=controls,
        required_indicators=tuple(re.compile(pattern, re.IGNORECASE) for pattern in indicators),
        forbidden_patterns=tuple(re.compile(pattern, re.IGNORECASE) for pattern in forbidden),
        verification_checks=checks,
        confidence=confidence,
    )


_REQUIREMENTS: dict[str, RemediationRequirement] = {
    "CWE-89": _requirement(
        "CWE-89",
        "Use a parameterized query or query builder; never interpolate untrusted "
        "values into SQL text.",
        (
            "Bind untrusted values as parameters",
            "Keep the SQL statement static",
            "Preserve the original query result shape",
        ),
        (r"execute\s*\([^)]*,\s*\(", r"execute\s*\(\s*[\"'][^\"']*\?", r"bind\w*\s*\("),
        (r"%\s*\w+", r"\.format\s*\(", r"f[\"'][^\"']*(select|insert|update|delete)", r"\+ *\w+"),
        (
            "before/after taint-flow comparison",
            "static-analysis comparison",
            "CWE-89 evidence reduction",
        ),
    ),
    "CWE-78": _requirement(
        "CWE-78",
        "Pass an argument vector to the process API with shell interpretation disabled.",
        (
            "Use an argument list instead of a command string",
            "Set shell=False explicitly where the API supports it",
            "Validate or allowlist command components",
        ),
        (r"subprocess\.(run|check_output|Popen)\s*\(\s*\[", r"shell\s*=\s*False"),
        (r"shell\s*=\s*True", r"os\.system\s*\(", r"commands\s*\("),
        (
            "before/after taint-flow comparison",
            "static-analysis comparison",
            "CWE-78 evidence reduction",
        ),
    ),
    "CWE-79": _requirement(
        "CWE-79",
        "Contextually encode untrusted output and rely on framework auto-escaping.",
        (
            "Encode untrusted output for its destination context",
            "Avoid raw HTML sinks",
            "Preserve rendered output for trusted input",
        ),
        (r"html\.escape\s*\(", r"escape\s*\(", r"autoescape", r"textContent\s*="),
        (r"innerHTML\s*=", r"dangerouslySetInnerHTML", r"\| *safe", r"mark_safe\s*\("),
        (
            "before/after taint-flow comparison",
            "static-analysis comparison",
            "CWE-79 evidence reduction",
        ),
    ),
    "CWE-22": _requirement(
        "CWE-22",
        "Resolve requested paths under a fixed root and reject escapes.",
        (
            "Resolve the candidate path",
            "Verify containment under the allowed root",
            "Reject escape attempts before file access",
        ),
        (r"\.resolve\s*\(", r"is_relative_to\s*\(", r"commonpath\s*\("),
        (r"open\s*\(\s*\w+\s*\+", r"os\.path\.join\s*\([^)]*\.\."),
        (
            "before/after taint-flow comparison",
            "static-analysis comparison",
            "CWE-22 evidence reduction",
        ),
    ),
    "CWE-502": _requirement(
        "CWE-502",
        "Deserialize untrusted data only with data-only formats and safe loaders.",
        (
            "Use a data-only format",
            "Use a safe loader",
            "Reject executable object graphs",
        ),
        (r"json\.loads?\s*\(", r"yaml\.safe_load\s*\("),
        (r"pickle\.loads?\s*\(", r"yaml\.load\s*\(", r"eval\s*\("),
        (
            "before/after taint-flow comparison",
            "static-analysis comparison",
            "CWE-502 evidence reduction",
        ),
    ),
    "CWE-639": _requirement(
        "CWE-639",
        "Verify the authenticated principal's entitlement for every object identifier.",
        ("Check ownership or entitlement", "Deny access by default"),
        (r"permission|entitlement|ownership|authorize",),
        (r"return\s+\w+\s*#\s*unauthorized",),
        ("static-analysis comparison", "functional and authorization tests"),
        confidence="medium",
    ),
    "CWE-862": _requirement(
        "CWE-862",
        "Enforce authorization on every protected operation and deny by default.",
        ("Check the authenticated principal's permissions", "Fail closed"),
        (r"permission|authorize|require_auth",),
        (r"#\s*(skip|disable)\s*auth",),
        ("static-analysis comparison", "functional and authorization tests"),
        confidence="medium",
    ),
    "CWE-287": _requirement(
        "CWE-287",
        "Enforce authentication on every protected path and add negative tests.",
        ("Authenticate before access", "Fail closed", "Add negative tests"),
        (r"require_auth|authenticate",),
        (r"#\s*(skip|disable)\s*auth",),
        ("static-analysis comparison", "functional and authentication tests"),
        confidence="medium",
    ),
}


_GENERIC_REQUIREMENT = RemediationRequirement(
    cwe="unknown",
    title="Unclassified weakness",
    summary=(
        "Use a framework-supported, context-appropriate remediation after confirming the weakness."
    ),
    required_controls=(
        "Identify the affected trust boundary",
        "Apply the framework's documented safe API",
        "Add a regression test for the reported weakness",
    ),
    required_indicators=(),
    forbidden_patterns=(),
    verification_checks=("independent security verification", "functional and regression tests"),
    confidence="low",
)


def requirement_for_cwe(cwe: str | None) -> RemediationRequirement:
    """Return the explicit requirement for ``cwe`` or an honest generic fallback."""

    if cwe is None:
        return _GENERIC_REQUIREMENT
    requirement = _REQUIREMENTS.get(cwe)
    if requirement is not None:
        return requirement
    category = category_for_cwe(cwe)
    info = CATEGORY_INFO.get(category) if category is not None else None
    return RemediationRequirement(
        cwe=cwe,
        title=info.title if info is not None else cwe,
        summary=info.remediation if info is not None else _GENERIC_REQUIREMENT.summary,
        required_controls=_GENERIC_REQUIREMENT.required_controls,
        required_indicators=(),
        forbidden_patterns=(),
        verification_checks=_GENERIC_REQUIREMENT.verification_checks,
        confidence="low",
    )


def evaluate_requirement(
    requirement: RemediationRequirement, patched_source: str
) -> tuple[bool, list[str]]:
    """Check explicit CWE controls against a patched source snapshot."""

    reasons: list[str] = []
    if requirement.required_indicators and not any(
        pattern.search(patched_source) for pattern in requirement.required_indicators
    ):
        reasons.append(f"no observed {requirement.cwe} remediation indicator in the patched source")
    for pattern in requirement.forbidden_patterns:
        match = pattern.search(patched_source)
        if match is not None:
            reasons.append(f"forbidden pattern remains: {match.group(0).strip()[:80]}")
    return (not reasons), reasons


def requirement_is_supported(cwe: str | None) -> bool:
    return cwe in _REQUIREMENTS


__all__ = [
    "RemediationRequirement",
    "evaluate_requirement",
    "requirement_for_cwe",
    "requirement_is_supported",
]
