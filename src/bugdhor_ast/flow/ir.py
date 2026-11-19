from dataclasses import dataclass, field

from tree_sitter import Node

from .models import IRStatement
from .profiles import (
    LanguageProfile,
    is_function_scope_node,
)
from .scopes import PARAMETER_CONTAINER_TYPES, ScopeAnalysis
from .tree import FlowContext, node_key, statement_id


BOUNDARY_SCOPE_KINDS = {
    "function",
    "lambda",
    "class",
    "comprehension",
}

COMPOUND_NODE_TYPES = {
    "if_statement",
    "elif_clause",
    "else_clause",
    "for_statement",
    "while_statement",
    "do_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "try_statement",
    "handler",
    "except_clause",
    "catch_clause",
    "finally_clause",
    "finally_block",
}


def statement_kind_for_node(
    context: FlowContext,
    profile: LanguageProfile,
    node: Node,
) -> str:
    if node.type in PARAMETER_CONTAINER_TYPES:
        return "params"
    if (
        node.type in {"lambda", "lambda_expression"}
        and not is_function_scope_node(node, profile, context)
    ):
        return ""
    kind = profile.statement_kind(node, context)
    if kind == "expr":
        return ""
    if node.type == "expression_statement":
        for child in context.walk(node):
            if node_key(child) == node_key(node):
                continue
            if statement_kind_for_node(context, profile, child):
                return ""
    return kind


def child_regions(
    context: FlowContext,
    profile: LanguageProfile,
    node: Node,
) -> list[Node]:
    regions: list[Node] = []
    body = profile.body_node(node, context)
    if body is not None:
        regions.append(body)
    alternative = profile.alternative_node(node, context)
    if alternative is not None:
        regions.append(alternative)
    for handler in profile.handler_nodes(node, context):
        regions.append(handler)
    finally_node = profile.finally_node(node, context)
    if finally_node is not None:
        regions.append(finally_node)
    if not regions:
        regions.extend(node.named_children)
    return regions


def collect_region_statements(
    context: FlowContext,
    profile: LanguageProfile,
    boundaries: set[tuple[int, int, str]],
    root: Node,
) -> list[Node]:
    """Collect only the direct statements of one execution region."""
    nodes: list[Node] = []
    seen: set[tuple[int, int, str]] = set()

    def add(node: Node) -> None:
        key = node_key(node)
        if key not in seen:
            seen.add(key)
            nodes.append(node)

    def collect(current: Node) -> None:
        for child in current.children:
            key = node_key(child)
            if key in boundaries:
                continue
            if statement_kind_for_node(context, profile, child):
                add(child)
                continue
            collect(child)

    collect(root)
    return nodes


def collect_statement_nodes(
    context: FlowContext,
    profile: LanguageProfile,
    boundaries: set[tuple[int, int, str]],
    root: Node,
) -> list[Node]:
    """Collect executable statement nodes in source order."""
    nodes: list[Node] = []
    seen: set[tuple[int, int, str]] = set()

    def add(node: Node) -> None:
        key = node_key(node)
        if key not in seen:
            seen.add(key)
            nodes.append(node)

    def collect(current: Node) -> None:
        for child in current.children:
            key = node_key(child)
            if key in boundaries:
                continue
            if statement_kind_for_node(context, profile, child):
                add(child)
                if child.type in COMPOUND_NODE_TYPES:
                    for region in child_regions(
                        context, profile, child
                    ):
                        collect(region)
                continue
            collect(child)

    collect(root)
    return nodes


@dataclass
class IRProgram:
    language: str
    statements: list[IRStatement] = field(default_factory=list)
    by_id: dict[str, IRStatement] = field(default_factory=dict)
    by_node: dict[tuple[int, int, str], IRStatement] = field(
        default_factory=dict
    )

    def statement_for(self, node: Node) -> IRStatement | None:
        return self.by_node.get(node_key(node))


class IRBuilder:
    """Lower parse trees into a language-neutral statement IR."""

    def __init__(
        self,
        context: FlowContext,
        profile: LanguageProfile,
        scope_analysis: ScopeAnalysis,
    ) -> None:
        self.context = context
        self.profile = profile
        self.scope_analysis = scope_analysis
        self.program = IRProgram(language=context.language)
        self._boundary_keys = {
            node_key(scope_analysis.scope_root[scope.id])
            for scope in scope_analysis.scopes
            if scope.kind in BOUNDARY_SCOPE_KINDS
        }

    def build(self) -> IRProgram:
        nodes: list[Node] = []
        seen: set[tuple[int, int, str]] = set()

        def add(node: Node) -> None:
            key = node_key(node)
            if key in seen:
                return
            seen.add(key)
            nodes.append(node)

        for scope in self.scope_analysis.scopes:
            root = self.scope_analysis.scope_root[scope.id]
            root_key = node_key(root)
            if scope.kind in {"function", "class"}:
                if statement_kind_for_node(
                    self.context, self.profile, root
                ):
                    add(root)
            active_boundaries = set(self._boundary_keys)
            active_boundaries.discard(root_key)
            for node in collect_statement_nodes(
                self.context,
                self.profile,
                active_boundaries,
                root,
            ):
                add(node)

        for node in nodes:
            self._add_statement(node)
        return self.program

    def _kind(self, node: Node) -> str:
        return statement_kind_for_node(
            self.context, self.profile, node
        )

    def _add_statement(self, node: Node) -> None:
        statement = statement_id(node)
        declarations = self.scope_analysis.declarations_by_statement.get(
            statement, []
        )
        uses = self.scope_analysis.uses_by_statement.get(
            statement, []
        )
        calls = [
            call
            for call in self.scope_analysis.calls
            if call.statement_id == statement
        ]
        literal = None
        for declaration in declarations:
            literal = self.profile.literal_value(
                declaration.value_node, self.context
            )
            if literal is not None:
                break
        if literal is None and declarations:
            declaration = declarations[0]
            for field_name in ("right", "value", "initializer"):
                value_node = self.context.field(
                    self.context.parent(declaration.node) or node,
                    field_name,
                )
                if value_node is not None:
                    literal = self.profile.literal_value(
                        value_node, self.context
                    )
                    if literal is not None:
                        break

        ir_statement = IRStatement(
            id=statement,
            kind=self._kind(node),
            node_type=node.type,
            location=self.context.location(node),
            text=self.context.text(node),
            scope_id=self.scope_analysis.scope_for(node),
            definitions=tuple(
                sorted({item.symbol_id for item in declarations})
            ),
            uses=tuple(
                sorted(
                    {
                        item.symbol_id
                        for item in uses
                        if item.symbol_id is not None
                    }
                )
            ),
            calls=tuple(call.name for call in calls),
            call_arguments=tuple(
                argument for call in calls for argument in call.arguments
            ),
            literal=literal,
        )
        self.program.statements.append(ir_statement)
        self.program.by_id[ir_statement.id] = ir_statement
        self.program.by_node[node_key(node)] = ir_statement
