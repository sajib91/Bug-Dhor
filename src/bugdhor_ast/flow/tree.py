from typing import Iterator

from tree_sitter import Node

from ..engine import BugDhorASTEngine
from .models import SourceLocation


def node_key(node: Node | None) -> tuple[int, int, str]:
    """Stable identity for tree-sitter nodes across wrapper objects."""
    if node is None:
        return (-1, -1, "")
    return (node.start_byte, node.end_byte, node.type)


def statement_id(node: Node | None) -> str:
    """Stable JSON-safe id for a statement-like syntax node."""
    if node is None:
        return ""
    return f"stmt:{node.start_byte}:{node.end_byte}:{node.type}"


class FlowContext:
    """Parse-tree access shared by all flow analysis passes."""

    def __init__(
        self,
        source_code: str,
        language: str,
        file: str,
        root: Node,
    ) -> None:
        self.source = source_code
        self.source_bytes = source_code.encode("utf-8")
        self.language = language
        self.file = file
        self.root = root
        self._parents: dict[tuple[int, int, str], Node] = {}
        self._build_parents()

    def _build_parents(self) -> None:
        for node in self.walk():
            for child in node.children:
                self._parents[node_key(child)] = node

    def walk(self, node: Node | None = None) -> Iterator[Node]:
        current = self.root if node is None else node
        yield current
        for child in current.children:
            yield from self.walk(child)

    def nodes_of_type(self, *types: str) -> Iterator[Node]:
        wanted = set(types)
        for node in self.walk():
            if node.type in wanted:
                yield node

    def parent(self, node: Node) -> Node | None:
        return self._parents.get(node_key(node))

    def field(self, node: Node, name: str) -> Node | None:
        return node.child_by_field_name(name)

    def field_text(self, node: Node, name: str) -> str | None:
        child = self.field(node, name)
        return None if child is None else self.text(child)

    def text(self, node: Node | None) -> str:
        if node is None:
            return ""
        return BugDhorASTEngine.get_node_text(
            node, self.source_bytes
        )

    def location(self, node: Node | None) -> SourceLocation:
        if node is None:
            return SourceLocation(self.file, 0, 0, 0, 0)
        return SourceLocation(
            self.file,
            node.start_point.row + 1,
            node.start_point.column + 1,
            node.end_point.row + 1,
            node.end_point.column + 1,
        )

    def ancestors(self, node: Node) -> Iterator[Node]:
        current = self.parent(node)
        while current is not None:
            yield current
            current = self.parent(current)

    def has_ancestor(self, node: Node, *types: str) -> bool:
        wanted = set(types)
        return any(item.type in wanted for item in self.ancestors(node))

    def enclosing_function(self, node: Node) -> Node | None:
        for ancestor in self.ancestors(node):
            if ancestor.type in FUNCTION_NODE_TYPES:
                return ancestor
        return None


FUNCTION_NODE_TYPES = {
    "function_definition",
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "arrow_function",
    "lambda",
    "method_declaration",
    "method_definition",
    "constructor_declaration",
}
