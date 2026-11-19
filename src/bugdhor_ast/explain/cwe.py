"""Evidence-based CWE mapping for Bug-Dhor explanations.

Mappings are keyed to concrete analysis evidence, not broad rule names. Taint
mappings require a raw taint finding with a known sink rule; a dangerous call
without taint evidence is deliberately left unmapped.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .evidence import _finding_location, _matching_taint
from .schema import ConfidenceLevel, CweMapping, FindingExplanation

_CWE_PATTERN = re.compile(r"^CWE-\d+$")

TAINT_PATH_REQUIREMENT = "taint_path"
DETECTION_RULE_REQUIREMENT = "detection_rule"


@dataclass(frozen=True)
class CweRule:
    """A maintainable rule-to-CWE mapping definition."""

    rule_id: str
    cwe_id: str
    confidence: ConfidenceLevel
    rationale: str
    evidence_requirement: str
    evidence_kinds: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("cwe rule_id must not be empty")
        if not isinstance(self.cwe_id, str) or not _CWE_PATTERN.match(self.cwe_id):
            raise ValueError("cwe_id must look like CWE-123")
        object.__setattr__(
            self,
            "confidence",
            ConfidenceLevel(self.confidence),
        )
        if not self.rationale.strip():
            raise ValueError("cwe rationale must not be empty")
        if self.evidence_requirement not in {
            TAINT_PATH_REQUIREMENT,
            DETECTION_RULE_REQUIREMENT,
        }:
            raise ValueError("unsupported CWE evidence requirement")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "evidence_requirement": self.evidence_requirement,
            "evidence_kinds": list(self.evidence_kinds),
        }


CWE_RULES: tuple[CweRule, ...] = (
    # Python taint sinks.
    CweRule(
        "PY-SNK-001",
        "CWE-94",
        ConfidenceLevel.HIGH,
        "eval executes dynamically constructed Python code.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-001",
        "CWE-95",
        ConfidenceLevel.MEDIUM,
        "eval is the direct-evaluation specialization of code injection.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-002",
        "CWE-94",
        ConfidenceLevel.HIGH,
        "exec executes dynamically constructed Python code.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-003",
        "CWE-78",
        ConfidenceLevel.HIGH,
        "os.system passes a constructed string to the operating-system shell.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-004",
        "CWE-78",
        ConfidenceLevel.MEDIUM,
        "subprocess.run can execute OS commands; injection depends on argument construction.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-005",
        "CWE-78",
        ConfidenceLevel.MEDIUM,
        "subprocess.call can execute OS commands; injection depends on argument construction.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-006",
        "CWE-78",
        ConfidenceLevel.MEDIUM,
        "subprocess.Popen can execute OS commands; injection depends on argument construction.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "PY-SNK-007",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "cursor.execute is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    # JavaScript taint sinks.
    CweRule(
        "JS-SNK-001",
        "CWE-94",
        ConfidenceLevel.HIGH,
        "eval executes dynamically constructed JavaScript code.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-001",
        "CWE-95",
        ConfidenceLevel.MEDIUM,
        "eval is the direct-evaluation specialization of code injection.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-002",
        "CWE-94",
        ConfidenceLevel.HIGH,
        "Function constructs code from a dynamic string.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-003",
        "CWE-79",
        ConfidenceLevel.HIGH,
        "innerHTML writes the tracked value into a DOM HTML context.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-004",
        "CWE-79",
        ConfidenceLevel.HIGH,
        "outerHTML writes the tracked value into a DOM HTML context.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-005",
        "CWE-79",
        ConfidenceLevel.HIGH,
        "document.write emits the tracked value into an HTML parsing context.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-006",
        "CWE-78",
        ConfidenceLevel.HIGH,
        "child_process.exec interprets a constructed string through a shell.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-007",
        "CWE-78",
        ConfidenceLevel.HIGH,
        "child_process.execSync interprets a constructed string through a shell.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-008",
        "CWE-78",
        ConfidenceLevel.MEDIUM,
        "child_process.spawn can execute OS commands; injection depends on shell and argument use.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-009",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "db.query is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-010",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "connection.query is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-011",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "stmt.executeQuery is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JS-SNK-012",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "sql.query is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    # Java taint sinks.
    CweRule(
        "JAVA-SNK-001",
        "CWE-78",
        ConfidenceLevel.HIGH,
        "Runtime.getRuntime().exec executes an OS command from the tracked value.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-002",
        "CWE-78",
        ConfidenceLevel.MEDIUM,
        "ProcessBuilder can execute OS commands; injection depends on argument construction.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-003",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "executeQuery is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-004",
        "CWE-89",
        ConfidenceLevel.HIGH,
        "executeUpdate is a SQL statement sink and the tracked value reaches its statement text.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-005",
        "CWE-502",
        ConfidenceLevel.HIGH,
        "ObjectInputStream is a deserialization sink for untrusted data.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-006",
        "CWE-502",
        ConfidenceLevel.HIGH,
        "readObject deserializes data from an ObjectInputStream.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-007",
        "CWE-94",
        ConfidenceLevel.HIGH,
        "ScriptEngine.eval executes dynamically constructed script code.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-007",
        "CWE-95",
        ConfidenceLevel.MEDIUM,
        "ScriptEngine.eval is the direct-evaluation specialization of code injection.",
        TAINT_PATH_REQUIREMENT,
    ),
    CweRule(
        "JAVA-SNK-008",
        "CWE-94",
        ConfidenceLevel.MEDIUM,
        "the configured eval-style sink executes dynamic code in the Java profile.",
        TAINT_PATH_REQUIREMENT,
    ),
    # Conservative direct rule semantics.
    CweRule(
        "PY007",
        "CWE-476",
        ConfidenceLevel.MEDIUM,
        "Potential None Access targets dereference of a None-bound name without a visible guard.",
        DETECTION_RULE_REQUIREMENT,
        ("finding", "ast_variables"),
    ),
    CweRule(
        "JS007",
        "CWE-476",
        ConfidenceLevel.MEDIUM,
        "Potential Null Access targets dereference of a null-bound name without a visible guard.",
        DETECTION_RULE_REQUIREMENT,
        ("finding", "ast_variables"),
    ),
    CweRule(
        "JAVA007",
        "CWE-476",
        ConfidenceLevel.MEDIUM,
        "Potential Null Access targets dereference of a null-bound name without a visible guard.",
        DETECTION_RULE_REQUIREMENT,
        ("finding", "ast_variables"),
    ),
)


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("analysis payloads must be mappings")
    return dict(value)


def _location_span(
    location: Any,
) -> tuple[tuple[int, int], tuple[int, int]]:
    return (
        (location.start_line, location.start_column),
        (location.end_line, location.end_column),
    )


def _evidence_refs(
    explanation: FindingExplanation | None,
    kinds: set[str],
    *,
    limit: int = 5,
) -> tuple[str, ...]:
    if explanation is None:
        return ()
    matches = [
        record.id
        for record in explanation.evidence.all_records()
        if record.kind in kinds
    ]
    return tuple(matches[:limit])


def map_cwe(
    finding: Any,
    analysis: Any = None,
    *,
    explanation: FindingExplanation | None = None,
) -> tuple[CweMapping, ...]:
    """Return only CWE mappings supported by supplied evidence."""

    finding_dict = _as_dict(finding)
    analysis_dict = _as_dict(analysis)
    location = _finding_location(finding_dict)
    rule_id = str(finding_dict.get("rule_id", ""))
    raw_taint: Mapping[str, Any] | None = None
    if rule_id.endswith("-TAINT001"):
        raw_taint, _, _ = _matching_taint(
            analysis_dict, finding_dict, _location_span(location)
        )

    mappings: list[CweMapping] = []
    seen: set[tuple[str, str]] = set()
    for entry in CWE_RULES:
        if entry.evidence_requirement == TAINT_PATH_REQUIREMENT:
            if raw_taint is None or entry.rule_id != raw_taint.get("sink_rule"):
                continue
            evidence_kinds = {"taint_source_sink", "taint_path", "root_cause_taint_origin"}
        else:
            if entry.rule_id != rule_id:
                continue
            evidence_kinds = set(entry.evidence_kinds)

        key = (entry.rule_id, entry.cwe_id)
        if key in seen:
            continue
        seen.add(key)
        refs = _evidence_refs(explanation, evidence_kinds)
        if not refs:
            refs = _evidence_refs(explanation, {"finding"})
        mappings.append(
            CweMapping(
                id=entry.cwe_id,
                confidence=entry.confidence,
                rationale=entry.rationale,
                evidence_refs=refs,
            )
        )
    return tuple(mappings)
