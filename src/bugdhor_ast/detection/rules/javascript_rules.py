from dataclasses import dataclass

from tree_sitter import Node

from ..context import AnalysisContext
from ..models import RuleMetadata
from .base import BaseRule
from .common import (
    call_argument_nodes,
    call_name,
    identifier_name,
    is_empty_block,
    is_none_literal,
    walk_identifiers,
)


JS001 = RuleMetadata(
    "JS001",
    "Undefined Variable",
    "A variable is used without a visible definition.",
    "error",
    "javascript",
    "Define the variable before using it.",
    (
        "Name resolution is file-wide and does not model control flow; "
        "a fixed global allowlist is assumed.",
    ),
)
JS002 = RuleMetadata(
    "JS002",
    "Unused Variable",
    "A variable is declared but never read.",
    "warning",
    "javascript",
    "Remove the declaration or use the variable.",
    (
        "Simple let, const, and var declarators are checked; "
        "destructuring is handled when binding names are identifiers.",
        "Exported bindings are ignored.",
    ),
)
JS003 = RuleMetadata(
    "JS003",
    "Unreachable Code",
    "Statements follow a terminating statement in the same block.",
    "warning",
    "javascript",
    "Remove the unreachable statements or adjust the control flow.",
)
JS004 = RuleMetadata(
    "JS004",
    "Duplicate Variable Declaration",
    "A name is declared more than once in one lexical scope.",
    "error",
    "javascript",
    "Remove the repeated declaration.",
    (
        "Only let, const, and var declarators are checked; plain "
        "assignment is not a declaration.",
    ),
)
JS005 = RuleMetadata(
    "JS005",
    "Unused Import",
    "An imported binding is not used in the file.",
    "warning",
    "javascript",
    "Remove the import or use the imported binding.",
    (
        "Side-effect imports are not bindings and are not reported.",
    ),
)
JS006 = RuleMetadata(
    "JS006",
    "Unused Function Parameter",
    "A function parameter is not used in the function body.",
    "warning",
    "javascript",
    "Remove the parameter or use it in the function.",
    (
        "Uses in nested functions count as uses of the parameter.",
    ),
)
JS007 = RuleMetadata(
    "JS007",
    "Potential Null Access",
    "A name bound to null is dereferenced without a visible guard.",
    "warning",
    "javascript",
    "Check that the value is not null before accessing it.",
    (
        "The rule is intra-scope, flow-insensitive for loops, and "
        "does not follow call chains.",
    ),
)
JS008 = RuleMetadata(
    "JS008",
    "Empty Exception Handler",
    "A catch clause silently swallows the exception.",
    "warning",
    "javascript",
    "Handle the exception, log it, or re-raise it.",
)
JS009 = RuleMetadata(
    "JS009",
    "Suspicious Function Call",
    "A call uses a dynamic or string-driven builtin.",
    "warning",
    "javascript",
    "Avoid dynamic execution in production code.",
)
JS010 = RuleMetadata(
    "JS010",
    "Dangerous Function Usage",
    "A call can execute commands or dynamic code.",
    "error",
    "javascript",
    "Use a safer API and validate untrusted input.",
    ("The rule does not perform taint analysis.",),
)


JS_GLOBALS = {
    "console", "Math", "JSON", "Object", "Array", "String", "Number",
    "Boolean", "Promise", "Date", "RegExp", "Error", "require", "module",
    "exports", "process", "window", "document", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "undefined", "NaN", "Infinity",
    "eval", "Function",
}

SUSPICIOUS_CALLS = {"eval", "Function", "document.write"}

TIMER_CALLS = {
    "setTimeout", "setInterval",
    "window.setTimeout", "window.setInterval",
}

DANGEROUS_CALLS = {
    "child_process.exec", "child_process.execSync",
    "exec", "execSync", "eval", "Function",
}

SHELL_CALLS = {"child_process.spawn", "spawn"}

USE_TYPES = {"identifier", "shorthand_property_identifier"}

FUNCTION_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "constructor_declaration",
}

SCOPE_TYPES = {"program", "statement_block"}

TYPE_NODES = {
    "type_annotation", "type_arguments", "type_parameter",
    "type_predicate", "type_query", "generic_type",
    "type_alias_declaration", "interface_declaration",
}

BINDING_PATTERN_TYPES = {
    "assignment_pattern", "required_parameter", "optional_parameter",
    "default_parameter", "typed_parameter", "rest_pattern",
    "object_pattern", "array_pattern", "list_pattern",
    "object_assignment_pattern", "array_assignment_pattern",
}


@dataclass(frozen=True)
class _Symbol:
    name: str
    node: Node
    kind: str
    scope: Node


def _key(node: Node | None) -> tuple[int, int, str]:
    if node is None:
        return (-1, -1, "")
    return (node.start_byte, node.end_byte, node.type)


def _same(node: Node | None, other: Node) -> bool:
    return _key(node) == _key(other)


def _parent_map(context: AnalysisContext):
    parents: dict[tuple[int, int, str], Node] = {}
    for node in context.walk():
        for child in node.children:
            parents[_key(child)] = node
    return parents


def _parent(
    context: AnalysisContext,
    node: Node,
    parents: dict[tuple[int, int, str], Node],
) -> Node | None:
    return parents.get(_key(node))


def _has_ancestor(
    context: AnalysisContext,
    node: Node,
    parents: dict[tuple[int, int, str], Node],
    *types: str,
) -> bool:
    wanted = set(types)
    current = _parent(context, node, parents)
    while current is not None:
        if current.type in wanted:
            return True
        current = parents.get(_key(current))
    return False


def _enclosing_function(
    context: AnalysisContext,
    node: Node,
    parents: dict[tuple[int, int, str], Node],
) -> Node | None:
    current = _parent(context, node, parents)
    while current is not None:
        if current.type in FUNCTION_TYPES:
            return current
        current = parents.get(_key(current))
    return None


def _binding_names(node: Node | None):
    if node is None:
        return
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        yield node
        return
    if node.type == "pair_pattern":
        yield from _binding_names(node.child_by_field_name("value"))
        return
    if node.type in BINDING_PATTERN_TYPES:
        target = (
            node.child_by_field_name("left")
            or node.child_by_field_name("name")
            or node.child_by_field_name("pattern")
        )
        if target is not None:
            yield from _binding_names(target)
            return
        for child in node.named_children:
            if child.type in {
                "property_identifier", "computed_property_name",
                "string", "number", "true", "false", "null",
            }:
                continue
            yield from _binding_names(child)
        return
    if node.type in {"formal_parameters", "parameters"}:
        for child in node.named_children:
            yield from _binding_names(child)


def _scope_owner(
    context: AnalysisContext,
    node: Node,
    parents: dict[tuple[int, int, str], Node],
) -> Node:
    current = _parent(context, node, parents)
    while current is not None:
        if current.type in SCOPE_TYPES:
            return current
        current = parents.get(_key(current))
    return context.root


def _import_bindings(context: AnalysisContext):
    for node in context.nodes_of_type("import_statement"):
        clause = next(
            (
                child for child in node.named_children
                if child.type == "import_clause"
            ),
            None,
        )
        if clause is None:
            continue
        for child in clause.named_children:
            if child.type in {"identifier", "statement_identifier"}:
                yield context.text(child), child
            elif child.type == "named_imports":
                for specifier in child.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    name_node = (
                        context.field(specifier, "alias")
                        or context.field(specifier, "name")
                    )
                    if name_node is not None:
                        yield context.text(name_node), name_node
            elif child.type == "namespace_import":
                for name_node in walk_identifiers(context, child):
                    yield context.text(name_node), name_node


def _declarations(context: AnalysisContext, parents):
    symbols: list[_Symbol] = []
    declared_ids: set[tuple[int, int, str]] = set()

    for node in context.nodes_of_type("variable_declarator"):
        scope = _scope_owner(context, node, parents)
        for name_node in _binding_names(context.field(node, "name")):
            name = context.text(name_node)
            symbols.append(_Symbol(name, name_node, "variable", scope))
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type(
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "class_declaration",
        "class_expression",
    ):
        name_node = context.field(node, "name")
        if name_node is not None:
            name = context.text(name_node)
            symbols.append(_Symbol(name, name_node, "function", context.root))
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type("formal_parameters"):
        scope = _parent(context, node, parents) or context.root
        for name_node in _binding_names(node):
            name = context.text(name_node)
            symbols.append(_Symbol(name, name_node, "parameter", scope))
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type("catch_clause"):
        scope = _scope_owner(context, node, parents)
        for name_node in _binding_names(context.field(node, "parameter")):
            name = context.text(name_node)
            symbols.append(
                _Symbol(name, name_node, "catch_parameter", scope)
            )
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type("import_statement"):
        for child in walk_identifiers(context, node):
            declared_ids.add(_key(child))
    for name, node in _import_bindings(context):
        symbols.append(_Symbol(name, node, "import", context.root))

    return symbols, declared_ids


def _uses(context: AnalysisContext, declared_ids, parents):
    for node in context.nodes_of_type(*USE_TYPES):
        if _key(node) in declared_ids:
            continue
        name = identifier_name(node)
        if name is None and node.type == "shorthand_property_identifier":
            name = context.text(node)
        if name is None:
            continue

        parent = _parent(context, node, parents)
        if parent is not None:
            if _same(context.field(parent, "property"), node):
                continue
            if _same(context.field(parent, "key"), node):
                continue
            if _same(context.field(parent, "label"), node):
                continue

        if _has_ancestor(
            context, node, parents, "import_statement", *TYPE_NODES
        ):
            continue

        yield name, node


def _walk_scope(context: AnalysisContext, scope: Node):
    def visit(node: Node, is_root: bool = False):
        yield node
        for child in node.children:
            if not is_root and child.type in FUNCTION_TYPES:
                continue
            yield from visit(child)

    return visit(scope, True)


def _dereferences(context: AnalysisContext, scope: Node):
    for node in _walk_scope(context, scope):
        if node.type == "call_expression":
            field_name = "function"
        elif node.type in {"member_expression", "subscript_expression"}:
            field_name = "object"
        else:
            continue
        target = context.field(node, field_name)
        if target is None or target.type != "identifier":
            continue
        yield context.text(target), node


def _is_null_guarded(
    context: AnalysisContext,
    node: Node,
    parents,
    name: str,
) -> bool:
    current = _parent(context, node, parents)
    while current is not None:
        if current.type in {"if_statement", "conditional_expression"}:
            condition = context.field_text(current, "condition")
            if condition and name in condition and (
                "!== null" in condition
                or "!= null" in condition
                or "!== undefined" in condition
                or "!= undefined" in condition
                or condition.strip() == name
            ):
                return True
        if current.type in FUNCTION_TYPES:
            break
        current = parents.get(_key(current))
    return False


class JavaScriptUndefinedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(JS001)

    def check(self, context: AnalysisContext):
        parents = _parent_map(context)
        symbols, declared_ids = _declarations(context, parents)
        defined = {symbol.name for symbol in symbols} | JS_GLOBALS
        seen: set[str] = set()

        for name, node in _uses(context, declared_ids, parents):
            if name in defined or name.startswith("__"):
                continue
            if name in seen:
                continue
            seen.add(name)
            yield self.report(
                context,
                node,
                f"Variable '{name}' is not defined.",
            )


class JavaScriptUnusedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(JS002)

    def check(self, context: AnalysisContext):
        parents = _parent_map(context)
        symbols, declared_ids = _declarations(context, parents)
        used = {
            name for name, _ in _uses(context, declared_ids, parents)
        }
        reported: set[tuple[str, tuple[int, int, str]]] = set()

        for symbol in symbols:
            if symbol.kind != "variable":
                continue
            if symbol.scope is context.root:
                if symbol.node.type != "identifier":
                    continue
                if _has_ancestor(
                    context, symbol.node, parents, "export_statement"
                ):
                    continue
            elif _enclosing_function(context, symbol.node, parents) is None:
                continue
            if symbol.name.startswith("_"):
                continue
            if symbol.name in used:
                continue
            key = (symbol.name, _key(symbol.scope))
            if key in reported:
                continue
            reported.add(key)
            yield self.report(
                context,
                symbol.node,
                f"Variable '{symbol.name}' is declared but never used.",
            )


class JavaScriptUnreachableCodeRule(BaseRule):
    def __init__(self):
        super().__init__(JS003)

    def check(self, context: AnalysisContext):
        for block in context.nodes_of_type("statement_block"):
            statements = [
                child
                for child in block.named_children
                if child.type not in {"comment", "empty_statement"}
            ]
            terminated = False
            for statement in statements:
                if terminated:
                    yield self.report(
                        context,
                        statement,
                        "Statement is unreachable after a terminating statement.",
                    )
                    break
                if statement.type in {
                    "return_statement",
                    "throw_statement",
                    "break_statement",
                    "continue_statement",
                }:
                    terminated = True


class JavaScriptDuplicateDeclarationRule(BaseRule):
    def __init__(self):
        super().__init__(JS004)

    def check(self, context: AnalysisContext):
        parents = _parent_map(context)
        seen: set[tuple[str, tuple[int, int, str]]] = set()
        reported: set[tuple[str, tuple[int, int, str]]] = set()

        for node in context.nodes_of_type("variable_declarator"):
            scope = _scope_owner(context, node, parents)
            for name_node in _binding_names(context.field(node, "name")):
                name = context.text(name_node)
                key = (name, _key(scope))
                if key not in seen:
                    seen.add(key)
                    continue
                if key in reported:
                    continue
                reported.add(key)
                yield self.report(
                    context,
                    name_node,
                    f"Variable '{name}' is declared more than once in the same scope.",
                )


class JavaScriptUnusedImportRule(BaseRule):
    def __init__(self):
        super().__init__(JS005)

    def check(self, context: AnalysisContext):
        imports = list(_import_bindings(context))
        if not imports:
            return

        parents = _parent_map(context)
        _, declared_ids = _declarations(context, parents)
        used = {
            name for name, _ in _uses(context, declared_ids, parents)
        }
        reported: set[str] = set()

        for name, node in imports:
            if name in used or name in reported:
                continue
            reported.add(name)
            yield self.report(
                context,
                node,
                f"Imported binding '{name}' is not used.",
            )


class JavaScriptUnusedParameterRule(BaseRule):
    def __init__(self):
        super().__init__(JS006)

    def check(self, context: AnalysisContext):
        parents = _parent_map(context)
        _, declared_ids = _declarations(context, parents)
        used = {
            name for name, _ in _uses(context, declared_ids, parents)
        }
        reported: set[tuple[str, tuple[int, int, str]]] = set()

        for node in context.nodes_of_type("formal_parameters"):
            for name_node in _binding_names(node):
                name = context.text(name_node)
                if name.startswith("_"):
                    continue
                if name in used:
                    continue
                key = (name, _key(node))
                if key in reported:
                    continue
                reported.add(key)
                yield self.report(
                    context,
                    name_node,
                    f"Parameter '{name}' is not used in the function body.",
                )


class JavaScriptNullAccessRule(BaseRule):
    def __init__(self):
        super().__init__(JS007)

    def check(self, context: AnalysisContext):
        scopes = [context.root] + list(
            context.nodes_of_type(*FUNCTION_TYPES)
        )
        parents = _parent_map(context)
        reported: set[tuple[str, int]] = set()

        for scope in scopes:
            none_names: set[str] = set()
            dereferences = {
                _key(target): name
                for name, target in _dereferences(context, scope)
            }

            for node in _walk_scope(context, scope):
                if node.type == "variable_declarator":
                    value = context.field(node, "value")
                    names = {
                        context.text(name_node)
                        for name_node in _binding_names(
                            context.field(node, "name")
                        )
                    }
                    if is_none_literal(context, value):
                        none_names |= names
                    elif value is not None:
                        none_names -= names
                    continue

                if node.type == "assignment_expression":
                    left = context.field(node, "left")
                    if left is None or left.type != "identifier":
                        continue
                    name = context.text(left)
                    if is_none_literal(context, context.field(node, "right")):
                        none_names.add(name)
                    else:
                        none_names.discard(name)
                    continue

                name = dereferences.get(_key(node))
                if name is None or name not in none_names:
                    continue
                if context.field(node, "optional_chain") is not None:
                    continue
                if _is_null_guarded(context, node, parents, name):
                    continue
                key = (name, context.line(node))
                if key in reported:
                    continue
                reported.add(key)
                yield self.report(
                    context,
                    node,
                    f"Value '{name}' may be null when it is accessed.",
                )


class JavaScriptEmptyExceptionHandlerRule(BaseRule):
    def __init__(self):
        super().__init__(JS008)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("catch_clause"):
            if is_empty_block(
                context,
                context.field(node, "body"),
                pass_types=("empty_statement",),
            ):
                yield self.report(
                    context,
                    node,
                    "Exception handler is empty and silently ignores errors.",
                )


class JavaScriptSuspiciousCallRule(BaseRule):
    def __init__(self):
        super().__init__(JS009)

    def check(self, context: AnalysisContext):
        reported: set[tuple[int, int, str]] = set()
        for node in context.nodes_of_type(
            "call_expression", "call", "method_invocation"
        ):
            name = call_name(context, node)
            suspicious = (
                name in SUSPICIOUS_CALLS
                and name not in DANGEROUS_CALLS
            )
            if name in TIMER_CALLS:
                arguments = call_argument_nodes(context, node)
                if arguments and arguments[0].type in {
                    "string", "template_string",
                }:
                    suspicious = True
            if suspicious and _key(node) not in reported:
                reported.add(_key(node))
                yield self.report(
                    context,
                    node,
                    f"Call to '{name}' may execute dynamic code.",
                )


class JavaScriptDangerousCallRule(BaseRule):
    def __init__(self):
        super().__init__(JS010)

    def check(self, context: AnalysisContext):
        reported: set[tuple[int, int, str]] = set()
        for node in context.nodes_of_type(
            "call_expression", "call", "new_expression", "method_invocation"
        ):
            if node.type == "new_expression":
                constructor = context.field(node, "constructor")
                if constructor is None:
                    continue
                name = context.text(constructor)
            else:
                name = call_name(context, node)

            dangerous = name in DANGEROUS_CALLS
            if name in SHELL_CALLS:
                arguments = call_argument_nodes(context, node)
                if any(
                    "shell" in context.text(argument)
                    and "true" in context.text(argument)
                    for argument in arguments
                ):
                    dangerous = True

            if dangerous and _key(node) not in reported:
                reported.add(_key(node))
                yield self.report(
                    context,
                    node,
                    f"Potentially dangerous call to '{name}'.",
                )


JAVASCRIPT_RULES = [
    JavaScriptUndefinedVariableRule(),
    JavaScriptUnusedVariableRule(),
    JavaScriptUnreachableCodeRule(),
    JavaScriptDuplicateDeclarationRule(),
    JavaScriptUnusedImportRule(),
    JavaScriptUnusedParameterRule(),
    JavaScriptNullAccessRule(),
    JavaScriptEmptyExceptionHandlerRule(),
    JavaScriptSuspiciousCallRule(),
    JavaScriptDangerousCallRule(),
]
