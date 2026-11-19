from dataclasses import dataclass

from tree_sitter import Node

from .ir import (
    IRProgram,
    child_regions,
    collect_region_statements,
    statement_kind_for_node,
)
from .models import CFGEdge, CFGNode, ControlFlowGraph, SourceLocation
from .profiles import LanguageProfile
from .scopes import ScopeAnalysis
from .tree import FlowContext, node_key, statement_id


CFG_SCOPE_KINDS = {"module", "function", "class"}


@dataclass(frozen=True)
class LoopContext:
    header: str
    exit_target: str


class CFGBuilder:
    """Build a validated control-flow graph for one execution scope."""

    def __init__(
        self,
        scope_id: str,
        context: FlowContext,
        profile: LanguageProfile,
        scope_analysis: ScopeAnalysis,
        ir_program: IRProgram,
    ) -> None:
        self.scope_id = scope_id
        self.context = context
        self.profile = profile
        self.scope_analysis = scope_analysis
        self.ir_program = ir_program
        self.scope = next(
            item
            for item in scope_analysis.scopes
            if item.id == scope_id
        )
        self.root = scope_analysis.scope_root[scope_id]
        self.entry = f"cfg:{scope_id}:entry"
        self.exit = f"cfg:{scope_id}:exit"
        self.graph = ControlFlowGraph(
            scope_id=scope_id,
            scope_kind=self.scope.kind,
            entry=self.entry,
            exit=self.exit,
        )
        self._counter = 0
        self._loops: list[LoopContext] = []
        self._boundaries = {
            node_key(scope_analysis.scope_root[scope.id])
            for scope in scope_analysis.scopes
            if scope.kind in {"lambda", "comprehension"}
        }

    def build(self) -> ControlFlowGraph:
        self._add_generic_node(
            self.entry, "entry", self.scope.location, "entry"
        )
        self._add_generic_node(
            self.exit, "exit", self.scope.location, "exit"
        )
        if self.scope.kind in {"function", "class"}:
            statements = collect_region_statements(
                self.context,
                self.profile,
                self._boundaries,
                self.root,
            )
        else:
            statements = self._direct(self.root)
        entry = self._build_region(statements, self.exit)
        self._add_edge(self.entry, entry, "entry")
        self._finalize()
        errors = self.graph.validate()
        if errors:
            raise ValueError(
                "CFG consistency error: " + "; ".join(errors)
            )
        return self.graph

    def _add_generic_node(
        self,
        node_id: str,
        kind: str,
        location: SourceLocation,
        text: str,
        scope_id: str | None = None,
        statement_ref: str = "",
    ) -> str:
        if node_id in self.graph.nodes:
            return node_id
        self.graph.nodes[node_id] = CFGNode(
            id=node_id,
            kind=kind,
            location=location,
            text=text,
            scope_id=scope_id or self.scope_id,
            statement_id=statement_ref,
        )
        return node_id

    def _add_statement_node(
        self, node: Node, kind: str
    ) -> str:
        node_id = f"cfg:{self.scope_id}:{statement_id(node)}"
        statement = self.ir_program.by_node.get(node_key(node))
        return self._add_generic_node(
            node_id=node_id,
            kind=kind,
            location=self.context.location(node),
            text=self.context.text(node),
            scope_id=self.scope_analysis.scope_for(node),
            statement_ref=statement.id if statement else statement_id(node),
        )

    def _add_synthetic_node(
        self, kind: str, node: Node
    ) -> str:
        self._counter += 1
        node_id = f"cfg:{self.scope_id}:{kind}:{self._counter}"
        return self._add_generic_node(
            node_id=node_id,
            kind=kind,
            location=self.context.location(node),
            text=kind,
        )

    def _add_edge(
        self, source: str, target: str, kind: str
    ) -> None:
        if any(
            edge.source == source
            and edge.target == target
            and edge.kind == kind
            for edge in self.graph.edges
        ):
            return
        self.graph.edges.append(
            CFGEdge(source=source, target=target, kind=kind)
        )

    def _finalize(self) -> None:
        self.graph.edges.sort(
            key=lambda edge: (
                edge.source,
                edge.target,
                edge.kind,
            )
        )
        for node in self.graph.nodes.values():
            node.successors = sorted(
                {
                    edge.target
                    for edge in self.graph.edges
                    if edge.source == node.id
                }
            )
            node.predecessors = sorted(
                {
                    edge.source
                    for edge in self.graph.edges
                    if edge.target == node.id
                }
            )

    def _direct(self, root: Node | None) -> list[Node]:
        if root is None:
            return []
        if statement_kind_for_node(
            self.context, self.profile, root
        ):
            return [root]
        return collect_region_statements(
            self.context, self.profile, self._boundaries, root
        )

    def _region_entry(
        self, root: Node | None, next_id: str
    ) -> str:
        return self._build_region(self._direct(root), next_id)

    def _build_region(
        self, statements: list[Node], next_id: str
    ) -> str:
        entry = next_id
        for node in reversed(statements):
            entry = self._build_statement(node, entry)
        return entry

    def _kind_for(self, node: Node) -> str:
        statement = self.ir_program.by_node.get(node_key(node))
        if statement is not None:
            return statement.kind
        return self.profile.statement_kind(node, self.context)

    def _build_statement(
        self, node: Node, next_id: str
    ) -> str:
        kind = self._kind_for(node)
        if kind == "if":
            return self._build_if(node, next_id)
        if kind == "loop":
            return self._build_loop(node, next_id)
        if kind == "try":
            return self._build_try(node, next_id)
        if kind in {"else", "handler", "finally"}:
            return self._build_container(node, next_id, kind)
        return self._emit_statement(node, kind, next_id)

    def _emit_statement(
        self, node: Node, kind: str, next_id: str
    ) -> str:
        node_id = self._add_statement_node(node, kind)
        if kind in {"return", "throw"}:
            target = self.exit
        elif kind == "break":
            target = (
                self._loops[-1].exit_target
                if self._loops
                else next_id
            )
        elif kind == "continue":
            target = (
                self._loops[-1].header if self._loops else next_id
            )
        else:
            target = next_id
        self._add_edge(node_id, target, kind)
        return node_id

    def _build_if(self, node: Node, next_id: str) -> str:
        if_id = self._add_statement_node(node, "if")
        body = self._region_entry(
            self.profile.body_node(node, self.context), next_id
        )
        alternative = self.profile.alternative_node(
            node, self.context
        )
        if alternative is None:
            otherwise = next_id
        else:
            otherwise = self._region_entry(alternative, next_id)
        self._add_edge(if_id, body, "true")
        self._add_edge(if_id, otherwise, "false")
        return if_id

    def _build_loop(self, node: Node, next_id: str) -> str:
        loop_id = self._add_statement_node(node, "loop")
        loop_context = LoopContext(loop_id, next_id)
        self._loops.append(loop_context)
        body = self._region_entry(
            self.profile.body_node(node, self.context), loop_id
        )
        self._loops.pop()
        if body != loop_id:
            self._add_edge(loop_id, body, "body")
        self._add_edge(loop_id, next_id, "exit")
        alternative = self.profile.alternative_node(
            node, self.context
        )
        if alternative is not None:
            else_entry = self._region_entry(alternative, next_id)
            self._add_edge(loop_id, else_entry, "else")
        return loop_id

    def _build_container(
        self, node: Node, next_id: str, kind: str
    ) -> str:
        container_id = self._add_statement_node(node, kind)
        body_nodes: list[Node] = []
        for region in child_regions(
            self.context, self.profile, node
        ):
            body_nodes.extend(self._direct(region))
        body_entry = self._build_region(body_nodes, next_id)
        self._add_edge(container_id, body_entry, "body")
        return container_id

    def _build_try(self, node: Node, next_id: str) -> str:
        try_id = self._add_statement_node(node, "try")
        join_id = self._add_synthetic_node("try_join", node)
        finalizer = self.profile.finally_node(node, self.context)
        final_entry = (
            self._build_statement(finalizer, next_id)
            if finalizer is not None
            else next_id
        )
        for handler in self.profile.handler_nodes(
            node, self.context
        ):
            handler_entry = self._build_statement(
                handler, final_entry
            )
            self._add_edge(join_id, handler_entry, "handler")
        body = self._region_entry(
            self.profile.body_node(node, self.context), join_id
        )
        self._add_edge(try_id, body, "body")
        self._add_edge(join_id, final_entry, "normal")
        return try_id


def build_cfgs(
    context: FlowContext,
    profile: LanguageProfile,
    scope_analysis: ScopeAnalysis,
    ir_program: IRProgram,
) -> list[ControlFlowGraph]:
    graphs: list[ControlFlowGraph] = []
    for scope in scope_analysis.scopes:
        if scope.kind not in CFG_SCOPE_KINDS:
            continue
        graphs.append(
            CFGBuilder(
                scope.id,
                context,
                profile,
                scope_analysis,
                ir_program,
            ).build()
        )
    return graphs
