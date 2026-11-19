from typing import Iterator

from tree_sitter import Node

from ..engine import BugDhorASTEngine
from .models import Diagnostic, RuleMetadata


class AnalysisContext:
    """Shared parse tree access for detection rules."""

    def __init__(
        self,
        source_code: str,
        language: str,
        file: str,
        root: Node,
    ) -> None:
        self.language = language
        self.file = file
        self.root = root
        self.source = source_code
        self.source_bytes = source_code.encode("utf-8")
        self._parents: dict[int, Node] = {}
        self._build_parents()

    def _build_parents(self) -> None:
        for node in self.walk():
            for child in node.children:
                self._parents[id(child)] = node

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
        return self._parents.get(id(node))

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

    @staticmethod
    def line(node: Node) -> int:
        return node.start_point.row + 1

    @staticmethod
    def column(node: Node) -> int:
        return node.start_point.column + 1

    @staticmethod
    def end_line(node: Node) -> int:
        return node.end_point.row + 1

    @staticmethod
    def end_column(node: Node) -> int:
        return node.end_point.column + 1

    def has_ancestor(
        self, node: Node, *types: str
    ) -> bool:
        wanted = set(types)
        current = self.parent(node)
        while current is not None:
            if current.type in wanted:
                return True
            current = self.parent(current)
        return False

    def enclosing_function(self, node: Node) -> Node | None:
        current = self.parent(node)
        while current is not None:
            if current.type in {
                "function_definition",
                "function_declaration",
                "method_declaration",
                "method_definition",
                "arrow_function",
                "function_expression",
                "constructor_declaration",
            }:
                return current
            current = self.parent(current)
        return None

    def diagnostic(
        self,
        metadata: RuleMetadata,
        node: Node,
        message: str,
        suggestion: str | None = None,
    ) -> Diagnostic:
        return Diagnostic(
            rule_id=metadata.rule_id,
            rule_name=metadata.name,
            severity=metadata.severity,
            message=message,
            file=self.file,
            line=self.line(node),
            column=self.column(node),
            end_line=self.end_line(node),
            end_column=self.end_column(node),
            explanation=metadata.description,
            suggestion=(
                metadata.suggestion
                if suggestion is None
                else suggestion
            ),
            language=self.language,
        )
