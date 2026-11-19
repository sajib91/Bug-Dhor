from dataclasses import dataclass

from tree_sitter import Node

from ..engine import BugDhorASTEngine
from .tree import FlowContext, node_key


@dataclass(frozen=True)
class Declaration:
    name_node: Node
    name: str
    kind: str
    target: str = ""
    value_node: Node | None = None
    name_is_use: bool = False


IDENTIFIER_TYPES = {
    "identifier",
    "field_identifier",
    "type_identifier",
    "property_identifier",
    "private_property_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
}

PROPERTY_PARENTS = {
    "attribute": "attribute",
    "member_expression": "property",
    "field_access": "field",
    "method_invocation": "name",
}

TYPE_NODE_TYPES = {
    "type",
    "type_annotation",
    "type_arguments",
    "type_parameter",
    "generic_type",
    "integral_type",
    "floating_point_type",
    "void_type",
    "array_type",
    "union_type",
    "scoped_type_identifier",
}

KEYWORD_PARENTS = {"keyword_argument", "pair_pattern", "pair"}
LABEL_PARENTS = {"label_statement", "labeled_statement"}


class LanguageProfile:
    """Grammar-specific hooks shared by scope, IR, CFG, and flow passes."""

    language = ""
    module_types: set[str] = set()
    function_types: set[str] = set()
    class_types: set[str] = set()
    block_types: set[str] = set()
    comprehension_types: set[str] = set()

    def is_module(self, node: Node) -> bool:
        return node.type in self.module_types

    def is_function(self, node: Node) -> bool:
        return node.type in self.function_types

    def is_class(self, node: Node) -> bool:
        return node.type in self.class_types

    def is_block(self, node: Node) -> bool:
        return node.type in self.block_types

    def is_comprehension(self, node: Node) -> bool:
        return node.type in self.comprehension_types

    def function_info(
        self, node: Node, context: FlowContext
    ) -> tuple[Node | None, str, Node | None, Node | None]:
        name_node = context.field(node, "name")
        params = context.field(node, "parameters")
        body = context.field(node, "body")
        return name_node, context.text(name_node), params, body

    def class_info(
        self, node: Node, context: FlowContext
    ) -> tuple[Node | None, str, Node | None]:
        name_node = context.field(node, "name")
        return name_node, context.text(name_node), context.field(
            node, "body"
        )

    def block_creates_scope(
        self, node: Node, context: FlowContext
    ) -> bool:
        return False

    def declaration_names(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        return []

    def global_names(
        self, node: Node, context: FlowContext
    ) -> list[str]:
        return []

    def nonlocal_names(
        self, node: Node, context: FlowContext
    ) -> list[str]:
        return []

    def handler_declarations(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        return []

    def statement_kind(
        self, node: Node, context: FlowContext
    ) -> str:
        return "expr"

    def condition_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        for name in ("condition", "right", "value"):
            child = context.field(node, name)
            if child is not None:
                return child
        return None

    def body_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        for name in ("body", "consequence", "block"):
            child = context.field(node, name)
            if child is not None:
                return child
        return None

    def alternative_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        return context.field(node, "alternative")

    def handler_nodes(
        self, node: Node, context: FlowContext
    ) -> list[Node]:
        return [
            child
            for child in node.named_children
            if child.type in {
                "except_clause",
                "catch_clause",
                "catch_block",
            }
        ]

    def finally_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        for child in node.named_children:
            if child.type in {"finally_clause", "finally_block"}:
                return child
        return None

    def call_name(
        self, node: Node, context: FlowContext
    ) -> str:
        for field in ("function", "constructor"):
            child = context.field(node, field)
            if child is not None:
                return context.text(child)
        return ""

    def call_arguments(
        self, node: Node, context: FlowContext
    ) -> tuple[str, ...]:
        for child in node.named_children:
            if child.type in {
                "argument_list",
                "arguments",
            }:
                return tuple(
                    context.text(item)
                    for item in child.named_children
                    if item.type != "comment"
                )
        return ()

    def literal_value(
        self, node: Node | None, context: FlowContext
    ) -> str | None:
        if node is None:
            return None
        text = context.text(node).strip()
        if node.type in {
            "integer",
            "decimal_integer_literal",
            "number",
            "decimal_floating_point_literal",
        }:
            return text
        if node.type in {"true", "false"}:
            return text
        if node.type in {
            "none",
            "null",
            "null_literal",
            "undefined",
        }:
            return text
        if node.type == "string":
            return text.strip("\"'")
        if node.type == "string_literal":
            return text.strip('"')
        if node.type == "identifier":
            return f"@alias:{text}"
        return None

    def is_non_use_node(
        self, node: Node, context: FlowContext
    ) -> bool:
        if node.type not in IDENTIFIER_TYPES:
            return True
        parent = context.parent(node)
        if parent is None:
            return False
        field_name = PROPERTY_PARENTS.get(parent.type)
        if field_name is not None:
            prop = context.field(parent, field_name)
            if prop is not None and node_key(prop) == node_key(node):
                return True
        if parent.type in TYPE_NODE_TYPES:
            return True
        if parent.type in KEYWORD_PARENTS:
            name = context.field(parent, "name") or context.field(
                parent, "key"
            )
            if name is not None and node_key(name) == node_key(node):
                return True
        if parent.type in LABEL_PARENTS:
            label = context.field(parent, "label")
            if label is not None and node_key(label) == node_key(node):
                return True
        if context.has_ancestor(node, *self.import_types()):
            return True
        return False

    def import_types(self) -> tuple[str, ...]:
        return (
            "import_statement",
            "import_from_statement",
            "import_declaration",
        )

    def identifier_nodes(
        self, node: Node | None, context: FlowContext
    ):
        if node is None:
            return
        for current in context.walk(node):
            if not self.is_non_use_node(current, context):
                yield current


class PythonProfile(LanguageProfile):
    language = "python"
    module_types = {"module"}
    function_types = {"function_definition", "lambda"}
    class_types = {"class_definition"}
    block_types = {"block"}
    comprehension_types = {
        "list_comprehension",
        "set_comprehension",
        "dictionary_comprehension",
        "generator_expression",
    }

    def block_creates_scope(
        self, node: Node, context: FlowContext
    ) -> bool:
        return False

    def declaration_names(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        if node.type in {
            "assignment",
            "augmented_assignment",
            "named_expression",
        }:
            right = context.field(node, "right")
            return [
                Declaration(
                    name_node,
                    name,
                    "variable",
                    "",
                    right,
                    node.type == "augmented_assignment",
                )
                for name_node, name in (
                    BugDhorASTEngine().get_python_variable_names(
                        node, context.source_bytes
                    )
                )
            ]
        if node.type in {"parameters", "lambda_parameters"}:
            return [
                Declaration(name_node, name, "parameter", "function")
                for name_node, name in (
                    BugDhorASTEngine().get_python_parameter_names(
                        node, context.source_bytes
                    )
                )
            ]
        if node.type in {"import_statement", "import_from_statement"}:
            return [
                Declaration(name_node, name, "import", "module")
                for name, name_node in self._import_bindings(
                    node, context
                )
            ]
        if node.type in {"function_definition", "lambda"}:
            name_node, name, _, _ = self.function_info(node, context)
            if name_node is None:
                return []
            return [
                Declaration(name_node, name, "function", "lexical")
            ]
        if node.type == "class_definition":
            name_node, name, _ = self.class_info(node, context)
            if name_node is None:
                return []
            return [
                Declaration(name_node, name, "class", "lexical")
            ]
        if node.type == "except_clause":
            value = context.field(node, "value")
            if value is None or value.type != "as_pattern":
                return []
            name_node = context.field(value, "name")
            if name_node is None:
                for child in value.named_children:
                    if child.type == "identifier":
                        name_node = child
            if name_node is None:
                return []
            return [
                Declaration(
                    name_node,
                    context.text(name_node),
                    "variable",
                    "lexical",
                )
            ]
        if node.type == "for_in_clause":
            left = context.field(node, "left")
            if left is None:
                return []
            return [
                Declaration(
                    left,
                    context.text(left),
                    "variable",
                    "comprehension",
                    context.field(node, "right"),
                )
            ]
        return []

    @staticmethod
    def _import_bindings(node: Node, context: FlowContext):
        for index, child in enumerate(node.children):
            if node.field_name_for_child(index) != "name":
                continue
            if child.type == "wildcard_import":
                continue
            if child.type == "aliased_import":
                alias = context.field(child, "alias")
                if alias is not None:
                    yield context.text(alias), alias
                continue
            if child.type == "dotted_name" and child.named_children:
                first = child.named_children[0]
                yield context.text(first), first
            elif child.type == "identifier":
                yield context.text(child), child

    def global_names(
        self, node: Node, context: FlowContext
    ) -> list[str]:
        if node.type != "global_statement":
            return []
        return [
            context.text(child)
            for child in node.named_children
            if child.type == "identifier"
        ]

    def nonlocal_names(
        self, node: Node, context: FlowContext
    ) -> list[str]:
        if node.type != "nonlocal_statement":
            return []
        return [
            context.text(child)
            for child in node.named_children
            if child.type == "identifier"
        ]

    def statement_kind(
        self, node: Node, context: FlowContext
    ) -> str:
        kinds = {
            "assignment": "assign",
            "augmented_assignment": "assign",
            "named_expression": "assign",
            "import_statement": "import",
            "import_from_statement": "import",
            "function_definition": "function",
            "class_definition": "class",
            "lambda": "function",
            "if_statement": "if",
            "elif_clause": "if",
            "else_clause": "else",
            "for_statement": "loop",
            "while_statement": "loop",
            "break_statement": "break",
            "continue_statement": "continue",
            "return_statement": "return",
            "raise_statement": "throw",
            "try_statement": "try",
            "except_clause": "handler",
            "finally_clause": "finally",
            "global_statement": "decl",
            "nonlocal_statement": "decl",
            "parameters": "params",
            "lambda_parameters": "params",
            "pass_statement": "noop",
            "expression_statement": "call"
            if any(
                child.type == "call"
                for child in context.walk(node)
            )
            else "expr_stmt",
        }
        return kinds.get(node.type, "expr")

    def condition_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type in {"if_statement", "elif_clause", "while_statement"}:
            return context.field(node, "condition")
        if node.type == "for_statement":
            return context.field(node, "right")
        return None

    def body_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type in {"if_statement", "elif_clause"}:
            return context.field(node, "consequence")
        return context.field(node, "body")

    def alternative_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        return context.field(node, "alternative")

    def call_name(
        self, node: Node, context: FlowContext
    ) -> str:
        if node.type != "call":
            return ""
        return context.text(context.field(node, "function"))

    def call_arguments(
        self, node: Node, context: FlowContext
    ) -> tuple[str, ...]:
        arguments = context.field(node, "arguments")
        if arguments is None:
            return ()
        return tuple(
            context.text(child)
            for child in arguments.named_children
            if child.type != "comment"
        )

    def literal_value(
        self, node: Node | None, context: FlowContext
    ) -> str | None:
        if node is None:
            return None
        if node.type == "string":
            text = context.text(node)
            return text.strip("\"'")
        if node.type == "true":
            return "True"
        if node.type == "false":
            return "False"
        return super().literal_value(node, context)


class JavaScriptProfile(LanguageProfile):
    language = "javascript"
    module_types = {"program"}
    function_types = {
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "arrow_function",
        "method_definition",
        "constructor_declaration",
    }
    class_types = {"class_declaration", "class_expression"}
    block_types = {"statement_block"}

    def block_creates_scope(
        self, node: Node, context: FlowContext
    ) -> bool:
        parent = context.parent(node)
        if parent is not None and parent.type in self.function_types:
            return False
        if parent is not None and parent.type in self.class_types:
            return False
        if parent is not None and parent.type == "catch_clause":
            return True
        return True

    def function_info(
        self, node: Node, context: FlowContext
    ) -> tuple[Node | None, str, Node | None, Node | None]:
        name_node = context.field(node, "name")
        return (
            name_node,
            context.text(name_node),
            context.field(node, "parameters"),
            context.field(node, "body"),
        )

    def declaration_names(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        if node.type == "variable_declarator":
            name_node = context.field(node, "name")
            if name_node is None:
                return []
            parent = context.parent(node)
            target = "block"
            if parent is not None and parent.type == "variable_declaration":
                target = "function"
            for binding in self._binding_names(name_node):
                yield Declaration(
                    binding,
                    context.text(binding),
                    "variable",
                    target,
                    context.field(node, "value"),
                )
            return
        if node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
        }:
            yield from self._assignment_declaration(node, context)
            return
        if node.type == "formal_parameters":
            for child in node.named_children:
                for binding in self._binding_names(child):
                    yield Declaration(
                        binding,
                        context.text(binding),
                        "parameter",
                        "function",
                    )
            return
        if node.type in self.function_types:
            name_node, name, _, _ = self.function_info(node, context)
            if name_node is not None:
                yield Declaration(
                    name_node, name, "function", "lexical"
                )
            return
        if node.type in self.class_types:
            name_node, name, _ = self.class_info(node, context)
            if name_node is not None:
                yield Declaration(
                    name_node, name, "class", "lexical"
                )
            return
        if node.type == "catch_clause":
            parameter = context.field(node, "parameter")
            if parameter is not None:
                yield Declaration(
                    parameter,
                    context.text(parameter),
                    "variable",
                    "block",
                )
            return
        if node.type == "field_definition":
            name_node = context.field(node, "property")
            if name_node is not None:
                yield Declaration(
                    name_node,
                    context.text(name_node),
                    "field",
                    "class",
                    context.field(node, "value"),
                )
            return
        if node.type == "import_specifier":
            name_node = context.field(node, "alias") or context.field(
                node, "name"
            )
            if name_node is not None:
                yield Declaration(
                    name_node,
                    context.text(name_node),
                    "import",
                    "module",
                )
            return
        if node.type == "import_clause":
            for child in node.named_children:
                if child.type in {"identifier", "statement_identifier"}:
                    yield Declaration(
                        child,
                        context.text(child),
                        "import",
                        "module",
                    )
                elif child.type == "namespace_import":
                    for binding in self._binding_names(child):
                        yield Declaration(
                            binding,
                            context.text(binding),
                            "import",
                            "module",
                        )

    @staticmethod
    def _assignment_declaration(node: Node, context: FlowContext):
        left = context.field(node, "left")
        if left is None or left.type not in IDENTIFIER_TYPES:
            return
        yield Declaration(
            left,
            context.text(left),
            "variable",
            "assign",
            context.field(node, "right"),
            node.type == "augmented_assignment_expression",
        )

    @staticmethod
    def _binding_names(node: Node | None):
        if node is None:
            return
        if node.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
        }:
            yield node
            return
        if node.type == "pair_pattern":
            value = node.child_by_field_name("value")
            yield from JavaScriptProfile._binding_names(value)
            return
        for child in node.named_children:
            if child.type in {
                "property_identifier",
                "computed_property_name",
                "string",
                "number",
                "true",
                "false",
                "null",
            }:
                continue
            yield from JavaScriptProfile._binding_names(child)

    def handler_declarations(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        return self.declaration_names(node, context)

    def statement_kind(
        self, node: Node, context: FlowContext
    ) -> str:
        kinds = {
            "lexical_declaration": "assign",
            "variable_declaration": "assign",
            "function_declaration": "function",
            "class_declaration": "class",
            "if_statement": "if",
            "else_clause": "else",
            "for_statement": "loop",
            "for_in_statement": "loop",
            "while_statement": "loop",
            "do_statement": "loop",
            "break_statement": "break",
            "continue_statement": "continue",
            "return_statement": "return",
            "throw_statement": "throw",
            "try_statement": "try",
            "catch_clause": "handler",
            "finally_clause": "finally",
            "import_statement": "import",
            "formal_parameters": "params",
            "empty_statement": "noop",
            "expression_statement": "call"
            if any(
                child.type in {"call_expression", "new_expression"}
                for child in context.walk(node)
            )
            else "expr_stmt",
        }
        return kinds.get(node.type, "expr")

    def condition_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type in {
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "if_statement",
        }:
            return context.field(node, "condition")
        return None

    def body_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type == "if_statement":
            return context.field(node, "consequence")
        return context.field(node, "body")

    def call_name(
        self, node: Node, context: FlowContext
    ) -> str:
        if node.type == "new_expression":
            return context.text(context.field(node, "constructor"))
        if node.type in {"call_expression", "call"}:
            return context.text(context.field(node, "function"))
        return ""

    def call_arguments(
        self, node: Node, context: FlowContext
    ) -> tuple[str, ...]:
        return super().call_arguments(node, context)

    def literal_value(
        self, node: Node | None, context: FlowContext
    ) -> str | None:
        if node is None:
            return None
        if node.type == "template_string":
            return context.text(node).strip("`")
        return super().literal_value(node, context)


class JavaProfile(LanguageProfile):
    language = "java"
    module_types = {"program"}
    function_types = {
        "method_declaration",
        "constructor_declaration",
        "lambda_expression",
    }
    class_types = {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
    }
    block_types = {"block", "constructor_body"}

    def block_creates_scope(
        self, node: Node, context: FlowContext
    ) -> bool:
        parent = context.parent(node)
        if parent is not None and parent.type in self.function_types:
            return False
        return True

    def declaration_names(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        if node.type in {"field_declaration", "constant_declaration"}:
            for child in node.named_children:
                if child.type != "variable_declarator":
                    continue
                name_node = context.field(child, "name")
                if name_node is not None:
                    yield Declaration(
                        name_node,
                        context.text(name_node),
                        "field",
                        "class",
                        context.field(child, "value"),
                    )
            return
        if node.type in {
            "local_variable_declaration",
            "variable_declaration",
        }:
            for child in node.named_children:
                if child.type != "variable_declarator":
                    continue
                name_node = context.field(child, "name")
                if name_node is not None:
                    yield Declaration(
                        name_node,
                        context.text(name_node),
                        "variable",
                        "block",
                        context.field(child, "value"),
                    )
            return
        if node.type == "assignment_expression":
            yield from self._assignment_declaration(node, context)
            return
        if node.type in {"formal_parameter", "spread_parameter"}:
            name_node = context.field(node, "name")
            if name_node is not None:
                yield Declaration(
                    name_node,
                    context.text(name_node),
                    "parameter",
                    "function",
                )
            return
        if node.type == "enhanced_for_statement":
            name_node = context.field(node, "name")
            if name_node is not None:
                yield Declaration(
                    name_node,
                    context.text(name_node),
                    "variable",
                    "block",
                    context.field(node, "value"),
                )
            return
        if node.type == "catch_formal_parameter":
            name_node = context.field(node, "name")
            if name_node is not None:
                yield Declaration(
                    name_node,
                    context.text(name_node),
                    "variable",
                    "block",
                )
            return
        if node.type in self.function_types:
            name_node, name, _, _ = self.function_info(node, context)
            if name_node is not None and node.type != "lambda_expression":
                yield Declaration(
                    name_node, name, "function", "class"
                )
            return
        if node.type in self.class_types:
            name_node, name, _ = self.class_info(node, context)
            if name_node is not None:
                yield Declaration(
                    name_node, name, "class", "lexical"
                )
            return
        if node.type == "import_declaration":
            name = self._import_name(node, context)
            if name:
                name_node = node.named_children[-1]
                yield Declaration(
                    name_node, name, "import", "module"
                )

    @staticmethod
    def _assignment_declaration(node: Node, context: FlowContext):
        left = context.field(node, "left")
        if left is None or left.type not in IDENTIFIER_TYPES:
            return
        operator = context.field(node, "operator")
        is_compound = (
            operator is not None
            and context.text(operator).strip() != "="
        )
        yield Declaration(
            left,
            context.text(left),
            "variable",
            "assign",
            context.field(node, "right"),
            is_compound,
        )

    @staticmethod
    def _import_name(node: Node, context: FlowContext) -> str:
        if "asterisk" in {
            child.type for child in context.walk(node)
        }:
            return ""
        identifiers = [
            child
            for child in context.walk(node)
            if child.type == "identifier"
        ]
        return context.text(identifiers[-1]) if identifiers else ""

    def handler_declarations(
        self, node: Node, context: FlowContext
    ) -> list[Declaration]:
        found: list[Declaration] = []
        for child in context.walk(node):
            if child.type == "catch_formal_parameter":
                found.extend(self.declaration_names(child, context))
        return found

    def statement_kind(
        self, node: Node, context: FlowContext
    ) -> str:
        kinds = {
            "local_variable_declaration": "assign",
            "field_declaration": "decl",
            "constant_declaration": "decl",
            "method_declaration": "function",
            "constructor_declaration": "function",
            "class_declaration": "class",
            "if_statement": "if",
            "for_statement": "loop",
            "enhanced_for_statement": "loop",
            "while_statement": "loop",
            "do_statement": "loop",
            "break_statement": "break",
            "continue_statement": "continue",
            "return_statement": "return",
            "throw_statement": "throw",
            "try_statement": "try",
            "catch_clause": "handler",
            "finally_clause": "finally",
            "import_declaration": "import",
            "formal_parameters": "params",
            "expression_statement": "call"
            if any(
                child.type
                in {"method_invocation", "object_creation_expression"}
                for child in context.walk(node)
            )
            else "expr_stmt",
        }
        return kinds.get(node.type, "expr")

    def body_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type == "if_statement":
            consequence = context.field(node, "consequence")
            if consequence is not None:
                return consequence
        return context.field(node, "body")

    def alternative_node(
        self, node: Node, context: FlowContext
    ) -> Node | None:
        if node.type == "if_statement":
            return context.field(node, "alternative")
        return None

    def call_name(
        self, node: Node, context: FlowContext
    ) -> str:
        if node.type == "method_invocation":
            name = context.text(context.field(node, "name"))
            obj = context.text(context.field(node, "object"))
            return f"{obj}.{name}" if obj else name
        if node.type == "object_creation_expression":
            return context.text(context.field(node, "type"))
        return ""

    def call_arguments(
        self, node: Node, context: FlowContext
    ) -> tuple[str, ...]:
        arguments = context.field(
            node, "arguments"
        ) or context.field(node, "argument_list")
        if arguments is None:
            return ()
        return tuple(
            context.text(child)
            for child in arguments.named_children
            if child.type != "comment"
        )


PROFILES: dict[str, LanguageProfile] = {
    "python": PythonProfile(),
    "javascript": JavaScriptProfile(),
    "java": JavaProfile(),
}


def get_profile(language: str) -> LanguageProfile:
    if language not in PROFILES:
        raise ValueError(
            f"Flow analysis is not supported for language: {language}"
        )
    return PROFILES[language]


def is_function_scope_node(
    node: Node,
    profile: LanguageProfile,
    context: FlowContext,
) -> bool:
    """Distinguish a real function body from grammar keyword nodes."""
    if not profile.is_function(node):
        return False
    if node.type in {"lambda", "lambda_expression"}:
        return context.field(node, "body") is not None
    return True
