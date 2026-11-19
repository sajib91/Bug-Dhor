from bugdhor_ast.detection import DEFAULT_REGISTRY
from bugdhor_ast.detection.context import AnalysisContext
from bugdhor_ast.detection.rules.common import (
    call_name,
    identifier_name,
    is_empty_block,
    is_none_literal,
    walk_identifiers,
)
from bugdhor_ast.engine import BugDhorASTEngine


SOURCE = """
def outer():
    value = None
    def inner():
        print(value)
    return inner
"""


def make_context(source=SOURCE):
    root = (
        BugDhorASTEngine()
        .get_parser("python")
        .parse(source.encode("utf-8"))
        .root_node
    )
    return AnalysisContext(source, "python", "sample.py", root)


def test_context_exposes_one_based_spans_and_text():
    context = make_context()
    node = next(context.nodes_of_type("identifier"))

    assert context.text(node) == "outer"
    assert context.text(None) == ""
    assert context.field_text(node, "missing_field") is None
    assert (context.line(node), context.column(node)) == (2, 5)
    assert (context.end_line(node), context.end_column(node)) == (
        2,
        10,
    )


def test_context_ancestor_and_enclosing_function():
    context = make_context()
    call = next(context.nodes_of_type("call"))

    assert context.has_ancestor(call, "function_definition") is True
    assert context.has_ancestor(call, "class_definition") is False

    enclosing = context.enclosing_function(call)
    assert enclosing is not None
    assert context.text(context.field(enclosing, "name")) == "inner"

    module_context = make_context("value = 1\n")
    assignment = next(module_context.nodes_of_type("assignment"))
    assert module_context.enclosing_function(assignment) is None


def test_common_helpers_handle_absent_nodes():
    context = make_context()

    assert identifier_name(None) is None
    assert identifier_name(
        next(context.nodes_of_type("identifier"))
    ) == "outer"
    assert is_none_literal(context, None) is False
    assert is_empty_block(context, None) is True
    assert is_none_literal(
        context, next(context.nodes_of_type("none"))
    ) is True
    assert list(walk_identifiers(context))
    assert call_name(
        context, next(context.nodes_of_type("call"))
    ) == "print"


class _FakeNode:
    def __init__(self, type, named_children=(), text=b""):
        self.type = type
        self.named_children = list(named_children)
        self.text = text


class _FakeContext:
    @staticmethod
    def field(node, name):
        return None

    @staticmethod
    def text(node):
        return node.text.decode("utf-8")


def test_call_name_falls_back_to_named_children():
    context = _FakeContext()

    target = _FakeNode(
        "call",
        named_children=[_FakeNode("identifier", text=b"run")],
    )
    empty = _FakeNode("call")

    assert call_name(context, target) == "run"
    assert call_name(context, empty) == ""


def test_base_rule_repr_includes_id_and_language():
    assert repr(DEFAULT_REGISTRY.get_rule("PY001")) == (
        "PythonUndefinedVariableRule(PY001, python)"
    )
