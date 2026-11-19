"""Adapters from existing Bug-Dhor analysis JSON into explanation evidence.

The adapter is deliberately conservative: it copies facts from detection and
flow output, records missing evidence explicitly, and never invents causality,
CWE identifiers, or successful verification.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .schema import (
    ConfidenceAssessment,
    ConfidenceLevel,
    EvidenceCollection,
    EvidenceRecord,
    EvidenceStatus,
    ExplanationLocation,
    FindingExplanation,
    RootCause,
    RootCauseStatus,
)

AST_ITEM_KINDS = (
    "functions",
    "classes",
    "variables",
    "function_calls",
    "imports",
    "syntax_errors",
)

FLOW_SECTIONS = (
    "symbols",
    "scopes",
    "control_flow_graph",
    "data_flow",
    "taint_analysis",
)

DEFAULT_VERIFICATION_REQUIREMENTS = (
    "Reparse the modified source.",
    "Rerun static detection and taint analysis.",
    "Compare original, related, and new security findings.",
    "Run relevant regression tests when configured.",
    "Review the final diff and source context manually.",
)


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("analysis payloads must be mappings")
    return dict(value)


def _start_point(item: Mapping[str, Any]) -> tuple[int, int] | None:
    if "line" in item and "column" in item:
        line, column = item["line"], item["column"]
    elif "start_line" in item and "start_column" in item:
        line, column = item["start_line"], item["start_column"]
    else:
        return None
    if not isinstance(line, int) or not isinstance(column, int):
        return None
    return line, column


def _end_point(item: Mapping[str, Any]) -> tuple[int, int] | None:
    if "end_line" in item and "end_column" in item:
        line, column = item["end_line"], item["end_column"]
    else:
        return _start_point(item)
    if not isinstance(line, int) or not isinstance(column, int):
        return None
    return line, column


def _span(item: Mapping[str, Any]) -> tuple[tuple[int, int], tuple[int, int]] | None:
    start = _start_point(item)
    end = _end_point(item)
    if start is None or end is None:
        return None
    return start, end


def _overlaps(
    first: tuple[tuple[int, int], tuple[int, int]] | None,
    second: tuple[tuple[int, int], tuple[int, int]] | None,
) -> bool:
    if first is None or second is None:
        return False
    return first[0] <= second[1] and second[0] <= first[1]


def _format_point(point: tuple[int, int] | None) -> str:
    if point is None:
        return "unknown location"
    return f"{point[0]}:{point[1]}"


def _finding_location(finding: Mapping[str, Any]) -> ExplanationLocation:
    start_line = finding.get("line", finding.get("start_line", 0))
    start_column = finding.get("column", finding.get("start_column", 0))
    end_line = finding.get("end_line", start_line)
    end_column = finding.get("end_column", start_column)
    return ExplanationLocation(
        file=str(finding.get("file", "<source>")),
        start_line=int(start_line or 0),
        start_column=int(start_column or 0),
        end_line=int(end_line or start_line or 0),
        end_column=int(end_column or start_column or 0),
    )


def finding_id_for(finding: Any) -> str:
    """Return a deterministic finding ID without mutating the finding."""

    value = _as_dict(finding)
    identity = {
        key: value.get(key)
        for key in (
            "file",
            "language",
            "rule_id",
            "message",
            "line",
            "column",
            "end_line",
            "end_column",
        )
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:12]
    return f"finding:{digest}"


def _unavailable(record_id: str, kind: str, reason: str) -> EvidenceRecord:
    return EvidenceRecord(
        id=record_id,
        status=EvidenceStatus.UNAVAILABLE,
        kind=kind,
        summary=reason,
        value={"reason": reason},
    )


def _ast_summary(kind: str, item: Mapping[str, Any]) -> str:
    name = item.get("name") or item.get("type") or "item"
    return (
        f"{kind} {name} at "
        f"{_format_point(_start_point(item))}-{_format_point(_end_point(item))}"
    )


def _ast_evidence(
    analysis: Mapping[str, Any],
    span: tuple[tuple[int, int], tuple[int, int]],
    *,
    limit: int = 16,
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    seen: set[str] = set()
    for kind in AST_ITEM_KINDS:
        items = analysis.get(kind, [])
        if not isinstance(items, (list, tuple)):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, Mapping) or not _overlaps(_span(item), span):
                continue
            ref = (
                f"ast:{kind}:{index}:"
                f"{item.get('type', 'item')}:{_format_point(_start_point(item))}"
            )
            if ref in seen:
                continue
            seen.add(ref)
            records.append(
                EvidenceRecord(
                    id=ref,
                    status=EvidenceStatus.OBSERVED,
                    kind=f"ast_{kind}",
                    summary=_ast_summary(kind, item),
                    value=dict(item),
                )
            )
            if len(records) >= limit:
                return records
    return records


def _trigger_from_ast(records: list[EvidenceRecord]) -> dict[str, Any] | None:
    preferred = ("ast_function_calls", "ast_variables", "ast_imports", "ast_syntax_errors")
    for kind in preferred:
        record = next((item for item in records if item.kind == kind), None)
        if record is None or not isinstance(record.value, Mapping):
            continue
        item = record.value
        return {
            "kind": kind,
            "name": item.get("name") or item.get("type") or "unknown",
            "text": item.get("source") or item.get("message") or "",
            "location": {
                key: item.get(key, 0)
                for key in (
                    "line",
                    "column",
                    "end_line",
                    "end_column",
                )
            },
            "evidence_ref": record.id,
        }
    return None


def _trigger_from_taint(finding: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if finding is None:
        return None
    return {
        "kind": "taint_sink",
        "name": finding.get("sink_name", "unknown"),
        "text": finding.get("sink_rule", ""),
        "location": dict(finding.get("sink_location", {})),
        "evidence_ref": f"taint:{finding.get('id', 'finding')}:sink",
    }


def _trigger_from_finding(finding: Mapping[str, Any]) -> dict[str, Any] | None:
    """Use the detection finding itself as an observed trigger fallback."""

    message = finding.get("message")
    if not isinstance(message, str) or not message:
        return None
    return {
        "kind": "finding",
        "name": str(finding.get("rule_id", "unknown")),
        "text": message,
        "location": {
            "line": finding.get("line", 0),
            "column": finding.get("column", 0),
            "end_line": finding.get("end_line", finding.get("line", 0)),
            "end_column": finding.get("end_column", finding.get("column", 0)),
        },
        "evidence_ref": (
            f"finding:{finding.get('rule_id', 'unknown')}:"
            f"{_format_point(_start_point(finding))}"
        ),
    }


def _matching_cfg(
    analysis: Mapping[str, Any],
    span: tuple[tuple[int, int], tuple[int, int]],
    *,
    limit: int = 8,
) -> list[EvidenceRecord]:
    graphs = analysis.get("control_flow_graph", [])
    if not isinstance(graphs, (list, tuple)):
        return []
    records: list[EvidenceRecord] = []
    for graph_index, graph in enumerate(graphs):
        if not isinstance(graph, Mapping):
            continue
        nodes = graph.get("nodes", [])
        if not isinstance(nodes, (list, tuple)):
            continue
        matched: list[Mapping[str, Any]] = []
        for node in nodes:
            if isinstance(node, Mapping) and _overlaps(_span(node.get("location", {})), span):
                matched.append(node)
        if not matched:
            continue
        matched_ids = {
            str(node.get("id")) for node in matched if node.get("id") is not None
        }
        for node_index, node in enumerate(matched[:limit]):
            ref = f"cfg:{graph_index}:node:{node_index}:{node.get('id', 'unknown')}"
            records.append(
                EvidenceRecord(
                    id=ref,
                    status=EvidenceStatus.DERIVED,
                    kind="cfg_node",
                    summary=(
                        f"CFG node {node.get('kind', 'unknown')} in "
                        f"{graph.get('scope_kind', 'scope')} "
                        f"{graph.get('scope_id', graph_index)}"
                    ),
                    value={
                        "scope_id": graph.get("scope_id"),
                        "scope_kind": graph.get("scope_kind"),
                        "consistent": graph.get("consistent"),
                        "node": dict(node),
                    },
                    refs=(str(graph.get("scope_id", "")),),
                )
            )
        edges = [
            dict(edge)
            for edge in graph.get("edges", [])
            if isinstance(edge, Mapping)
            and (str(edge.get("source")) in matched_ids or str(edge.get("target")) in matched_ids)
        ]
        if edges:
            records.append(
                EvidenceRecord(
                    id=f"cfg:{graph_index}:edges",
                    status=EvidenceStatus.DERIVED,
                    kind="cfg_edges",
                    summary=f"{len(edges)} CFG edge(s) touch the affected nodes",
                    value=edges,
                )
            )
    return records


def _names_of_interest(
    ast_records: list[EvidenceRecord],
    taint_finding: Mapping[str, Any] | None,
) -> list[str]:
    names: list[str] = []
    for record in ast_records:
        value = record.value
        if isinstance(value, Mapping):
            name = value.get("name")
            if isinstance(name, str) and name:
                names.extend((name, name.rsplit(".", 1)[-1]))
    if taint_finding is not None:
        for key in ("source_name", "sink_name"):
            name = taint_finding.get(key)
            if isinstance(name, str) and name:
                names.extend((name, name.rsplit(".", 1)[-1]))
    return list(dict.fromkeys(names))


def _matching_symbols(
    analysis: Mapping[str, Any],
    span: tuple[tuple[int, int], tuple[int, int]],
    names: list[str],
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    name_set = set(names)

    for index, symbol in enumerate(analysis.get("symbols", [])):
        if not isinstance(symbol, Mapping):
            continue
        declaration_points = [
            _span(item)
            for item in symbol.get("declaration_locations", [])
            if isinstance(item, Mapping)
        ]
        declaration = symbol.get("declaration")
        if isinstance(declaration, Mapping):
            declaration_points.append(_span(declaration))
        reference_points = [
            _span(item)
            for item in symbol.get("references", [])
            if isinstance(item, Mapping)
        ]
        assignment_points = [
            _span(item)
            for item in symbol.get("assignments", [])
            if isinstance(item, Mapping)
        ]
        all_points = declaration_points + reference_points + assignment_points
        located = any(_overlaps(point, span) for point in all_points)
        named = symbol.get("name") in name_set
        if not located and not named:
            continue
        records.append(
            EvidenceRecord(
                id=f"symbol:{index}:{symbol.get('id', symbol.get('name', 'unknown'))}",
                status=EvidenceStatus.DERIVED,
                kind="symbol",
                summary=(
                    f"Symbol {symbol.get('name', 'unknown')} "
                    f"({symbol.get('symbol_type', 'unknown')})"
                ),
                value={
                    "id": symbol.get("id"),
                    "name": symbol.get("name"),
                    "symbol_type": symbol.get("symbol_type"),
                    "scope_id": symbol.get("scope_id"),
                    "located_at_finding": located,
                },
            )
        )

    for index, reference in enumerate(analysis.get("unresolved_references", [])):
        if not isinstance(reference, Mapping):
            continue
        if _overlaps(_span(reference.get("location", {})), span):
            records.append(
                EvidenceRecord(
                    id=f"unresolved:{index}:{reference.get('name', 'unknown')}",
                    status=EvidenceStatus.OBSERVED,
                    kind="unresolved_reference",
                    summary=f"Unresolved reference {reference.get('name', 'unknown')}",
                    value=dict(reference),
                )
            )
    return records


def _matching_dataflow(
    analysis: Mapping[str, Any],
    span: tuple[tuple[int, int], tuple[int, int]],
    names: list[str],
    cfg_records: list[EvidenceRecord],
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    name_set = set(names)
    statement_ids: set[str] = set()
    for record in cfg_records:
        value = record.value
        if isinstance(value, Mapping):
            node = value.get("node")
            if isinstance(node, Mapping) and node.get("statement_id"):
                statement_ids.add(str(node["statement_id"]))

    for scope_index, scope in enumerate(analysis.get("data_flow", [])):
        if not isinstance(scope, Mapping):
            continue
        definitions = [
            dict(item)
            for item in scope.get("definitions", [])
            if isinstance(item, Mapping) and _overlaps(_span(item.get("location", {})), span)
        ]
        uses = [
            dict(item)
            for item in scope.get("uses", [])
            if isinstance(item, Mapping) and _overlaps(_span(item.get("location", {})), span)
        ]
        for item in definitions + uses:
            if item.get("statement_id"):
                statement_ids.add(str(item["statement_id"]))

        related: dict[str, Any] = {}
        for key in (
            "reaching_definitions",
            "live_variables",
            "def_use_chains",
            "use_def_chains",
            "dependencies",
            "assignment_propagation",
        ):
            mapping = scope.get(key, {})
            if not isinstance(mapping, Mapping):
                continue
            matched = {
                str(key_value): value
                for key_value, value in mapping.items()
                if str(key_value) in statement_ids or str(key_value) in name_set
            }
            if matched:
                related[key] = matched

        call_edges = [
            dict(edge)
            for edge in scope.get("call_edges", [])
            if isinstance(edge, Mapping)
            and (
                str(edge.get("statement_id")) in statement_ids
                or edge.get("callee_name") in name_set
            )
        ]
        if not (definitions or uses or related or call_edges):
            continue
        records.append(
            EvidenceRecord(
                id=f"dataflow:{scope_index}:{scope.get('scope_id', 'scope')}",
                status=EvidenceStatus.DERIVED,
                kind="data_flow",
                summary=(
                    f"Data-flow facts for scope {scope.get('scope_id', 'unknown')}: "
                    f"{len(definitions)} definition(s), {len(uses)} use(s), "
                    f"{len(call_edges)} call edge(s)"
                ),
                value={
                    "scope_id": scope.get("scope_id"),
                    "definitions": definitions,
                    "uses": uses,
                    "related": related,
                    "call_edges": call_edges,
                },
            )
        )

    for index, summary in enumerate(analysis.get("function_summaries", [])):
        if not isinstance(summary, Mapping):
            continue
        if summary.get("name") in name_set:
            records.append(
                EvidenceRecord(
                    id=f"function-summary:{index}:{summary.get('symbol_id', 'unknown')}",
                    status=EvidenceStatus.DERIVED,
                    kind="function_summary",
                    summary=f"Function summary for {summary.get('name', 'unknown')}",
                    value=dict(summary),
                )
            )
    return records


def _matching_taint(
    analysis: Mapping[str, Any],
    finding: Mapping[str, Any],
    span: tuple[tuple[int, int], tuple[int, int]],
) -> tuple[Mapping[str, Any] | None, list[EvidenceRecord], list[str]]:
    taint = analysis.get("taint_analysis")
    if not isinstance(taint, Mapping):
        return None, [], []
    raw_findings = [
        item for item in taint.get("findings", []) if isinstance(item, Mapping)
    ]
    if not raw_findings:
        return None, [], list(taint.get("limitations", []))

    raw = next(
        (
            item
            for item in raw_findings
            if _overlaps(_span(item.get("sink_location", {})), span)
        ),
        None,
    )
    rule_id = str(finding.get("rule_id", ""))
    if raw is None and rule_id.endswith("-TAINT001") and len(raw_findings) == 1:
        raw = raw_findings[0]

    limitations = list(taint.get("limitations", []))
    if raw is None:
        return None, [], limitations

    limitations.extend(item for item in raw.get("limitations", []) if isinstance(item, str))
    identifier = str(raw.get("id", "unknown"))
    source_sink = {
        "id": raw.get("id"),
        "source_rule": raw.get("source_rule"),
        "source_name": raw.get("source_name"),
        "source_location": raw.get("source_location"),
        "sink_rule": raw.get("sink_rule"),
        "sink_name": raw.get("sink_name"),
        "sink_location": raw.get("sink_location"),
        "confidence": raw.get("confidence"),
        "sanitizers": raw.get("sanitizers", []),
    }
    records = [
        EvidenceRecord(
            id=f"taint:{identifier}:source-sink",
            status=EvidenceStatus.OBSERVED,
            kind="taint_source_sink",
            summary=(
                f"Taint source {raw.get('source_name', 'unknown')} reaches "
                f"sink {raw.get('sink_name', 'unknown')}"
            ),
            value=source_sink,
        ),
        EvidenceRecord(
            id=f"taint:{identifier}:path",
            status=EvidenceStatus.DERIVED,
            kind="taint_path",
            summary=f"Tracked {len(raw.get('path', []))} propagation step(s)",
            value=list(raw.get("path", [])),
        ),
    ]
    return raw, records, limitations


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if isinstance(value, str)))


def _confidence(
    taint_finding: Mapping[str, Any] | None,
    observed_count: int,
) -> ConfidenceAssessment:
    if taint_finding is not None:
        raw_value = taint_finding.get("confidence")
        try:
            level = ConfidenceLevel(str(raw_value))
        except ValueError:
            level = ConfidenceLevel.LOW
        return ConfidenceAssessment(
            value=level,
            basis=(
                "Taint engine confidence from the sink rule; the path is "
                "syntactic and is not exploitability evidence."
            ),
        )
    if observed_count:
        return ConfidenceAssessment(
            value=ConfidenceLevel.MEDIUM,
            basis=(
                "Detection rule and AST/source facts were observed; no "
                "calibrated confidence source is available."
            ),
        )
    return ConfidenceAssessment(
        value=ConfidenceLevel.LOW,
        basis="Insufficient evidence was available for this finding.",
    )


def _category(
    finding: Mapping[str, Any], taint_finding: Mapping[str, Any] | None
) -> str | None:
    rule_id = str(finding.get("rule_id", "")).upper()
    if rule_id.endswith("-TAINT001") or taint_finding is not None:
        return "taint_flow"
    if rule_id == "AST001":
        return "syntax_error"
    return None


def build_explanation(
    finding: Any,
    analysis: Any = None,
    *,
    finding_id: str | None = None,
    root_cause: RootCause | None = None,
    cwe: tuple[Any, ...] = (),
    suggested_remediation: str | None = None,
    verification_requirements: tuple[str, ...] | None = None,
) -> FindingExplanation:
    """Build a v1 explanation from existing detection/flow payloads.

    ``analysis`` may be a combined CLI payload containing detection diagnostics
    and flow sections. Missing sections yield explicit unavailable evidence
    rather than inferred facts.
    """

    finding_dict = _as_dict(finding)
    analysis_dict = _as_dict(analysis)
    location = _finding_location(finding_dict)
    span = (
        (location.start_line, location.start_column),
        (location.end_line, location.end_column),
    )

    evidence = EvidenceCollection().add(
        EvidenceRecord(
            id=f"finding:{finding_dict.get('rule_id', 'unknown')}:{_format_point(span[0])}",
            status=EvidenceStatus.OBSERVED,
            kind="finding",
            summary=(
                f"{finding_dict.get('rule_id', 'unknown')}: "
                f"{finding_dict.get('message', '')}"
            ),
            value=dict(finding_dict),
        )
    )

    ast_records = _ast_evidence(analysis_dict, span)
    for record in ast_records:
        evidence = evidence.add(record)
    if not ast_records:
        evidence = evidence.add(
            _unavailable("ast:unavailable", "ast_evidence", "No AST item overlaps this finding span.")
        )

    taint_finding, taint_records, taint_limitations = _matching_taint(
        analysis_dict, finding_dict, span
    )
    for record in taint_records:
        evidence = evidence.add(record)

    names = _names_of_interest(ast_records, taint_finding)

    cfg_records = _matching_cfg(analysis_dict, span)
    for record in cfg_records:
        evidence = evidence.add(record)
    if not cfg_records:
        evidence = evidence.add(
            _unavailable("cfg:unavailable", "cfg_evidence", "No CFG node overlaps this finding span.")
        )

    symbol_records = _matching_symbols(analysis_dict, span, names)
    for record in symbol_records:
        evidence = evidence.add(record)

    dataflow_records = _matching_dataflow(analysis_dict, span, names, cfg_records)
    for record in dataflow_records:
        evidence = evidence.add(record)
    if not dataflow_records:
        evidence = evidence.add(
            _unavailable(
                "data_flow:unavailable",
                "data_flow_evidence",
                "No def-use or data-flow fact overlaps this finding span.",
            )
        )

    missing_sections = [
        section for section in FLOW_SECTIONS if section not in analysis_dict
    ]
    for section in missing_sections:
        evidence = evidence.add(
            _unavailable(
                f"section:{section}:unavailable",
                f"flow_section_{section}",
                f"Flow section {section} was not supplied.",
            )
        )

    trigger = (
        _trigger_from_ast(ast_records)
        or _trigger_from_taint(taint_finding)
        or _trigger_from_finding(finding_dict)
    )
    if trigger is None:
        evidence = evidence.add(
            _unavailable("trigger:unavailable", "trigger", "No triggering expression was located.")
        )

    if root_cause is None:
        observed_refs = [record.id for record in evidence.observed[:4]]
        root_cause = RootCause(
            status=RootCauseStatus.UNKNOWN,
            location=None,
            rationale=(
                "Root cause was not localized because no deterministic "
                "causal rule was applied to the available evidence."
            ),
            evidence_refs=tuple(observed_refs),
        )

    limitations = _dedupe(
        list(analysis_dict.get("limitations", []))
        + taint_limitations
        + [
            "Explanations describe analysis evidence, not exploitability.",
            "Root cause is reported as unknown unless explicitly localized.",
        ]
    )
    static_suggestion = finding_dict.get("suggestion")
    if suggested_remediation is None and isinstance(static_suggestion, str) and static_suggestion:
        suggested_remediation = static_suggestion
        limitations.append(
            "Suggested remediation is static rule guidance, not a validated repair."
        )
    limitations = _dedupe(limitations)

    source_to_sink_path: list[Any] = []
    if taint_finding is not None:
        source_to_sink_path = [
            dict(step) for step in taint_finding.get("path", []) if isinstance(step, Mapping)
        ]

    if verification_requirements is None:
        verification_requirements = DEFAULT_VERIFICATION_REQUIREMENTS

    return FindingExplanation(
        finding_id=finding_id or finding_id_for(finding_dict),
        rule_id=str(finding_dict.get("rule_id", "unknown")),
        severity=str(finding_dict.get("severity", "info")),
        language=str(finding_dict.get("language", analysis_dict.get("language", "unknown"))),
        category=_category(finding_dict, taint_finding),
        cwe=tuple(cwe),
        location=location,
        root_cause=root_cause,
        trigger=trigger,
        evidence=evidence,
        source_to_sink_path=source_to_sink_path,
        confidence=_confidence(taint_finding, len(evidence.observed)),
        limitations=tuple(limitations),
        suggested_remediation=suggested_remediation,
        verification_requirements=tuple(verification_requirements),
    )


def build_explanations(findings: Any, analysis: Any = None) -> list[FindingExplanation]:
    """Build one explanation per existing finding, preserving input order."""

    values = findings
    if hasattr(values, "to_dict"):
        values = values.to_dict().get("diagnostics", [])
    if not isinstance(values, (list, tuple)):
        raise TypeError("findings must be a list")
    return [build_explanation(item, analysis) for item in values]
