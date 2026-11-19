from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int
    end_line: int
    end_column: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Reference:
    file: str
    line: int
    column: int
    kind: str
    statement_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AssignmentRecord:
    file: str
    line: int
    column: int
    statement_id: str
    value_text: str
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Symbol:
    id: str
    name: str
    symbol_type: str
    scope_id: str
    language: str
    declaration: SourceLocation
    declarations: list[SourceLocation] = field(
        default_factory=list
    )
    references: list[Reference] = field(default_factory=list)
    assignments: list[AssignmentRecord] = field(
        default_factory=list
    )

    @property
    def declaration_file(self) -> str:
        return self.declaration.file

    @property
    def declaration_line(self) -> int:
        return self.declaration.line

    @property
    def declaration_column(self) -> int:
        return self.declaration.column

    def add_declaration(self, location: SourceLocation) -> None:
        if location not in self.declarations:
            self.declarations.append(location)

    def add_reference(self, reference: Reference) -> None:
        self.references.append(reference)

    def add_assignment(self, assignment: AssignmentRecord) -> None:
        self.assignments.append(assignment)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "symbol_type": self.symbol_type,
            "scope_id": self.scope_id,
            "language": self.language,
            "declaration_file": self.declaration_file,
            "declaration_line": self.declaration_line,
            "declaration_column": self.declaration_column,
            "declaration": self.declaration.to_dict(),
            "declaration_locations": [
                item.to_dict() for item in self.declarations
            ],
            "references": [
                item.to_dict() for item in self.references
            ],
            "assignments": [
                item.to_dict() for item in self.assignments
            ],
        }


@dataclass
class Scope:
    id: str
    kind: str
    name: str
    parent_id: str | None
    language: str
    location: SourceLocation
    children: list[str] = field(default_factory=list)
    symbol_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "parent_id": self.parent_id,
            "language": self.language,
            "location": self.location.to_dict(),
            "children": list(self.children),
            "symbols": dict(self.symbol_ids),
        }


@dataclass(frozen=True)
class IRStatement:
    id: str
    kind: str
    node_type: str
    location: SourceLocation
    text: str
    scope_id: str
    definitions: tuple[str, ...] = ()
    uses: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()
    call_arguments: tuple[str, ...] = ()
    literal: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CFGNode:
    id: str
    kind: str
    location: SourceLocation
    text: str
    scope_id: str
    statement_id: str = ""
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "location": self.location.to_dict(),
            "text": self.text,
            "scope_id": self.scope_id,
            "statement_id": self.statement_id,
            "successors": list(self.successors),
            "predecessors": list(self.predecessors),
        }


@dataclass(frozen=True)
class CFGEdge:
    source: str
    target: str
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ControlFlowGraph:
    scope_id: str
    scope_kind: str
    entry: str
    exit: str
    nodes: dict[str, CFGNode] = field(default_factory=dict)
    edges: list[CFGEdge] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.entry not in self.nodes:
            errors.append(f"Missing entry node: {self.entry}")
        if self.exit not in self.nodes:
            errors.append(f"Missing exit node: {self.exit}")

        seen_edges: set[tuple[str, str, str]] = set()
        for edge in self.edges:
            if edge.source not in self.nodes:
                errors.append(
                    f"Edge source not found: {edge.source}"
                )
            if edge.target not in self.nodes:
                errors.append(
                    f"Edge target not found: {edge.target}"
                )
            key = (edge.source, edge.target, edge.kind)
            if key in seen_edges:
                errors.append(f"Duplicate edge: {key}")
            seen_edges.add(key)

        for node in self.nodes.values():
            expected_successors = {
                edge.target
                for edge in self.edges
                if edge.source == node.id
            }
            expected_predecessors = {
                edge.source
                for edge in self.edges
                if edge.target == node.id
            }
            if set(node.successors) != expected_successors:
                errors.append(
                    f"Inconsistent successors for {node.id}"
                )
            if set(node.predecessors) != expected_predecessors:
                errors.append(
                    f"Inconsistent predecessors for {node.id}"
                )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "scope_kind": self.scope_kind,
            "entry": self.entry,
            "exit": self.exit,
            "consistent": not self.validate(),
            "nodes": [
                self.nodes[key].to_dict() for key in sorted(self.nodes)
            ],
            "edges": [edge.to_dict() for edge in self.edges],
        }


@dataclass(frozen=True)
class Definition:
    id: str
    name: str
    symbol_id: str | None
    scope_id: str
    statement_id: str
    location: SourceLocation
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Use:
    id: str
    name: str
    symbol_id: str | None
    scope_id: str
    statement_id: str
    location: SourceLocation
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScopeDataFlow:
    scope_id: str
    definitions: list[Definition] = field(default_factory=list)
    uses: list[Use] = field(default_factory=list)
    reaching_definitions: dict[str, list[str]] = field(
        default_factory=dict
    )
    live_variables: dict[str, dict[str, list[str]]] = field(
        default_factory=dict
    )
    def_use_chains: dict[str, list[str]] = field(
        default_factory=dict
    )
    use_def_chains: dict[str, list[str]] = field(
        default_factory=dict
    )
    dependencies: dict[str, list[str]] = field(
        default_factory=dict
    )
    assignment_propagation: dict[str, str | None] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "definitions": [
                item.to_dict() for item in self.definitions
            ],
            "uses": [item.to_dict() for item in self.uses],
            "reaching_definitions": {
                key: list(value)
                for key, value in self.reaching_definitions.items()
            },
            "live_variables": {
                key: dict(value)
                for key, value in self.live_variables.items()
            },
            "def_use_chains": {
                key: list(value)
                for key, value in self.def_use_chains.items()
            },
            "use_def_chains": {
                key: list(value)
                for key, value in self.use_def_chains.items()
            },
            "dependencies": {
                key: list(value)
                for key, value in self.dependencies.items()
            },
            "assignment_propagation": dict(
                self.assignment_propagation
            ),
        }


@dataclass(frozen=True)
class FunctionSummary:
    symbol_id: str
    name: str
    parameters: tuple[str, ...]
    returns: str | None
    calls: tuple[str, ...]
    globals_used: tuple[str, ...]
    call_sites: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CallEdge:
    caller_scope_id: str
    callee_symbol_id: str
    callee_name: str
    statement_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DataFlowResult:
    scopes: list[ScopeDataFlow] = field(default_factory=list)
    function_summaries: list[FunctionSummary] = field(
        default_factory=list
    )
    call_edges: list[CallEdge] = field(default_factory=list)
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scopes": [item.to_dict() for item in self.scopes],
            "function_summaries": [
                item.to_dict() for item in self.function_summaries
            ],
            "call_edges": [
                item.to_dict() for item in self.call_edges
            ],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class TaintRule:
    id: str
    kind: str
    name: str
    pattern: str
    language: str
    argument_index: int = 0
    description: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintFinding:
    id: str
    source_rule: str
    source_name: str
    source_location: SourceLocation
    sink_rule: str
    sink_name: str
    sink_location: SourceLocation
    path: list[dict[str, Any]] = field(default_factory=list)
    confidence: str = "medium"
    sanitizers: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_rule": self.source_rule,
            "source_name": self.source_name,
            "source_location": self.source_location.to_dict(),
            "sink_rule": self.sink_rule,
            "sink_name": self.sink_name,
            "sink_location": self.sink_location.to_dict(),
            "path": list(self.path),
            "confidence": self.confidence,
            "sanitizers": list(self.sanitizers),
            "limitations": list(self.limitations),
        }


@dataclass
class TaintResult:
    language: str
    findings: list[TaintFinding] = field(default_factory=list)
    rules: list[TaintRule] = field(default_factory=list)
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "summary": {
                "findings": len(self.findings),
                "sources": sum(
                    1 for rule in self.rules if rule.kind == "source"
                ),
                "sanitizers": sum(
                    1 for rule in self.rules if rule.kind == "sanitizer"
                ),
                "sinks": sum(
                    1 for rule in self.rules if rule.kind == "sink"
                ),
            },
            "rules": [rule.to_dict() for rule in self.rules],
            "findings": [item.to_dict() for item in self.findings],
            "limitations": list(self.limitations),
        }


FLOW_SECTIONS = (
    "symbols",
    "scopes",
    "control_flow_graph",
    "data_flow",
    "taint_analysis",
)


@dataclass
class FlowAnalysisResult:
    file: str
    language: str
    scopes: list[Scope] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    control_flow_graphs: list[ControlFlowGraph] = field(
        default_factory=list
    )
    data_flow: DataFlowResult | None = None
    taint_analysis: TaintResult | None = None
    unresolved_references: list[dict[str, Any]] = field(
        default_factory=list
    )
    has_syntax_errors: bool = False
    limitations: tuple[str, ...] = ()

    def to_dict(
        self, sections: tuple[str, ...] | None = None
    ) -> dict[str, Any]:
        wanted = FLOW_SECTIONS if sections is None else tuple(sections)
        payload: dict[str, Any] = {
            "file": self.file,
            "language": self.language,
            "has_syntax_errors": self.has_syntax_errors,
            "summary": {
                "scopes": len(self.scopes),
                "symbols": len(self.symbols),
                "control_flow_graphs": len(
                    self.control_flow_graphs
                ),
                "unresolved_references": len(
                    self.unresolved_references
                ),
            },
            "limitations": list(self.limitations),
        }
        if "scopes" in wanted:
            payload["scopes"] = [
                item.to_dict() for item in self.scopes
            ]
        if "symbols" in wanted:
            payload["symbols"] = [
                item.to_dict() for item in self.symbols
            ]
        if "control_flow_graph" in wanted:
            payload["control_flow_graph"] = [
                item.to_dict() for item in self.control_flow_graphs
            ]
        if "data_flow" in wanted:
            payload["data_flow"] = (
                self.data_flow.to_dict()
                if self.data_flow is not None
                else None
            )
        if "taint_analysis" in wanted:
            payload["taint_analysis"] = (
                self.taint_analysis.to_dict()
                if self.taint_analysis is not None
                else None
            )
        payload["unresolved_references"] = list(
            self.unresolved_references
        )
        return payload
