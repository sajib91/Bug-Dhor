from tree_sitter import Node

from ..context import AnalysisContext


IDENTIFIER_TYPES = {
    "identifier",
    "field_identifier",
    "type_identifier",
    "shorthand_property_identifier_pattern",
}

TERMINATOR_TYPES = {
    "return_statement",
    "raise_statement",
    "throw_statement",
    "break_statement",
    "continue_statement",
    "yield_statement",
}

CALL_TYPES = {
    "call",
    "call_expression",
    "new_expression",
    "method_invocation",
}


def identifier_name(node: Node | None) -> str | None:
    if node is None or node.type not in IDENTIFIER_TYPES:
        return None
    return node.text.decode("utf-8", errors="replace")


def walk_identifiers(
    context: AnalysisContext, root: Node | None = None
):
    for node in context.walk(root):
        if node.type in IDENTIFIER_TYPES:
            yield node


def call_name(context: AnalysisContext, node: Node) -> str:
    if node.type == "method_invocation":
        name = context.field_text(node, "name") or ""
        obj = context.field_text(node, "object") or ""
        return f"{obj}.{name}" if obj else name

    function = context.field(node, "function")
    if function is not None:
        return context.text(function)

    for child in node.named_children:
        if child.type in {
            "identifier",
            "attribute",
            "member_expression",
            "subscript_expression",
        }:
            return context.text(child)

    return ""


def call_keyword_arguments(
    context: AnalysisContext, node: Node
) -> dict[str, Node]:
    keywords: dict[str, Node] = {}
    for argument in context.walk(node):
        if argument.type not in {
            "keyword_argument",
            "argument",
            "pair_pattern",
        }:
            continue
        name_node = context.field(argument, "name")
        if name_node is not None:
            keywords[context.text(name_node)] = argument
    return keywords


def call_argument_nodes(
    context: AnalysisContext, node: Node
) -> list[Node]:
    arguments: list[Node] = []
    for child in node.named_children:
        if child.type in {
            "argument_list",
            "arguments",
        }:
            arguments.extend(
                item
                for item in child.named_children
                if item.type != "comment"
            )
    return arguments


def is_empty_block(
    context: AnalysisContext,
    block: Node | None,
    *,
    pass_types: tuple[str, ...] = (),
) -> bool:
    if block is None:
        return True

    for child in block.named_children:
        if child.type in {"comment", "line_comment", "block_comment"}:
            continue
        if child.type in pass_types:
            continue
        return False
    return True


def is_none_literal(
    context: AnalysisContext, node: Node | None
) -> bool:
    if node is None:
        return False
    return node.type in {"none", "null", "nil"} or context.text(
        node
    ) in {"None", "null"}
