from dataclasses import dataclass

from tree_sitter import Node

from ...engine import BugDhorASTEngine
from ..context import AnalysisContext
from ..models import RuleMetadata
from .base import BaseRule
from .common import (
    call_argument_nodes,
    call_keyword_arguments,
    call_name,
    identifier_name,
    is_empty_block,
    is_none_literal,
)


_ast = BugDhorASTEngine()

PY001 = RuleMetadata(
    "PY001",
    "Undefined Variable",
    "A variable is used without a visible definition.",
    "error",
    "python",
    "Define the variable before using it.",
    ("Name resolution is file-wide and does not model control flow.",),
)
PY002 = RuleMetadata(
    "PY002",
    "Unused Variable",
    "A local variable is assigned but never read.",
    "warning",
    "python",
    "Remove the assignment or use the variable.",
    ("Only function-local assignments are checked.",),
)
PY003 = RuleMetadata(
    "PY003",
    "Unreachable Code",
    "Statements follow a terminating statement in the same block.",
    "warning",
    "python",
    "Remove the unreachable statements or adjust the control flow.",
)
PY004 = RuleMetadata(
    "PY004",
    "Duplicate Variable Declaration",
    "A name is annotated or declared more than once in one scope.",
    "error",
    "python",
    "Remove the repeated declaration.",
    (
        "Plain reassignment is not a declaration and is not reported.",
    ),
)
PY005 = RuleMetadata(
    "PY005",
    "Unused Import",
    "An imported binding is not used in the file.",
    "warning",
    "python",
    "Remove the import or use the imported binding.",
    ("Wildcard imports are not checked.",),
)
PY006 = RuleMetadata(
    "PY006",
    "Unused Function Parameter",
    "A function parameter is not used in the function body.",
    "warning",
    "python",
    "Remove the parameter or use it in the function.",
    (
        "self and cls are ignored; uses in nested functions count.",
    ),
)
PY007 = RuleMetadata(
    "PY007",
    "Potential None Access",
    "A name bound to None is dereferenced without a visible guard.",
    "warning",
    "python",
    "Check that the value is not None before accessing it.",
    (
        "The rule is intra-scope, flow-insensitive for loops, and "
        "does not follow call chains.",
    ),
)
PY008 = RuleMetadata(
    "PY008",
    "Empty Exception Handler",
    "An except clause silently swallows the exception.",
    "warning",
    "python",
    "Handle the exception, log it, or re-raise it.",
)
PY009 = RuleMetadata(
    "PY009",
    "Suspicious Function Call",
    "A call uses a dynamic or interactive builtin.",
    "warning",
    "python",
    "Avoid dynamic execution or interactive input in production code.",
)
PY010 = RuleMetadata(
    "PY010",
    "Dangerous Function Usage",
    "A call can execute commands or dynamic code, or deserialize untrusted data.",
    "error",
    "python",
    "Use a safer API and validate untrusted input.",
    ("The rule does not perform taint analysis.",),
)


PYTHON_BUILTINS = {
    "abs", "all", "any", "ascii", "bin", "bool", "breakpoint",
    "bytearray", "bytes", "callable", "chr", "classmethod",
    "compile", "complex", "delattr", "dict", "dir", "divmod",
    "enumerate", "eval", "exec", "filter", "float", "format",
    "frozenset", "getattr", "globals", "hasattr", "hash", "help",
    "hex", "id", "input", "int", "isinstance", "issubclass",
    "iter", "len", "list", "locals", "map", "max", "memoryview",
    "min", "next", "object", "oct", "open", "ord", "pow", "print",
    "property", "range", "repr", "reversed", "round", "set",
    "setattr", "slice", "sorted", "staticmethod", "str", "sum",
    "super", "tuple", "type", "vars", "zip", "__import__",
    "Exception", "ValueError", "TypeError", "KeyError", "RuntimeError",
    "IndexError", "OSError", "IOError", "StopIteration", "True",
    "False", "None", "NotImplemented", "Ellipsis", "self", "cls",
}

SUSPICIOUS_CALLS = {
    "compile", "breakpoint", "input",
}

DANGEROUS_CALLS = {
    "eval", "exec", "os.system", "os.popen", "subprocess.getoutput",
    "subprocess.getstatusoutput", "pickle.loads", "pickle.load",
    "marshal.loads", "yaml.load",
}

SHELL_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "run",
    "Popen", "call",
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


def _scope_owner(context: AnalysisContext, node: Node) -> Node:
    current = context.parent(node)
    while current is not None:
        if current.type in {
            "function_definition",
            "lambda",
        }:
            return current
        current = context.parent(current)
    return context.root


def _import_bindings(context: AnalysisContext):
    for node in context.nodes_of_type(
        "import_statement", "import_from_statement"
    ):
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
            if child.type == "dotted_name":
                first = child.named_children[0]
                yield context.text(first), first
            elif child.type == "identifier":
                yield context.text(child), child


def _declarations(context: AnalysisContext):
    symbols: list[_Symbol] = []
    declared_ids: set[tuple[int, int, str]] = set()

    for node in context.nodes_of_type("function_definition"):
        name_node = context.field(node, "name")
        if name_node is not None:
            name = context.text(name_node)
            symbols.append(
                _Symbol(name, name_node, "function", context.root)
            )
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type("class_definition"):
        name_node = context.field(node, "name")
        if name_node is not None:
            name = context.text(name_node)
            symbols.append(
                _Symbol(name, name_node, "class", context.root)
            )
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type(
        "parameters", "lambda_parameters"
    ):
        scope = (
            context.parent(node) or context.root
        )
        for name_node, name in _ast.get_python_parameter_names(
            node, context.source_bytes
        ):
            symbols.append(
                _Symbol(name, name_node, "parameter", scope)
            )
            declared_ids.add(_key(name_node))

    for node in context.nodes_of_type(
        "assignment", "augmented_assignment", "named_expression"
    ):
        scope = _scope_owner(context, node)
        for name_node, name in _ast.get_python_variable_names(
            node, context.source_bytes
        ):
            symbols.append(
                _Symbol(name, name_node, "variable", scope)
            )
            declared_ids.add(_key(name_node))

    for name, node in _import_bindings(context):
        symbols.append(
            _Symbol(name, node, "import", context.root)
        )
        declared_ids.add(_key(node))

    for node in context.nodes_of_type("import_statement", "import_from_statement"):
        for child in context.walk(node):
            declared_ids.add(_key(child))

    return symbols, declared_ids


def _uses(
    context: AnalysisContext,
    declared_ids: set[tuple[int, int, str]],
):
    for node in context.nodes_of_type("identifier"):
        name = identifier_name(node)
        if name is None or _key(node) in declared_ids:
            continue

        parent = context.parent(node)
        if parent is not None:
            if parent.type in {
                "type", "generic_type", "type_parameter",
            }:
                continue
            if parent.type == "attribute" and (
                _key(context.field(parent, "attribute"))
                == _key(node)
            ):
                continue
            if parent.type == "keyword_argument" and (
                _key(context.field(parent, "name"))
                == _key(node)
            ):
                continue

        if context.has_ancestor(
            node, "import_statement", "import_from_statement"
        ):
            continue

        yield name, node


def _dereferences(context: AnalysisContext):
    for node in context.nodes_of_type(
        "attribute", "subscript", "call"
    ):
        field_name = {
            "attribute": "object",
            "subscript": "value",
            "call": "function",
        }[node.type]
        target = context.field(node, field_name)
        if target is None or target.type != "identifier":
            continue
        yield context.text(target), node


def _is_guarded(context: AnalysisContext, node: Node, name: str) -> bool:
    current = context.parent(node)
    while current is not None:
        if current.type in {"if_statement", "assert_statement"}:
            condition = context.field_text(current, "condition")
            if condition and name in condition and (
                "is not None" in condition
                or "!= None" in condition
                or condition.strip() == name
            ):
                return True
        current = context.parent(current)
    return False


class PythonUndefinedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(PY001)

    def check(self, context: AnalysisContext):
        symbols, declared_ids = _declarations(context)
        defined = {symbol.name for symbol in symbols} | PYTHON_BUILTINS
        seen: set[str] = set()

        for name, node in _uses(context, declared_ids):
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


class PythonUnusedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(PY002)

    def check(self, context: AnalysisContext):
        symbols, declared_ids = _declarations(context)
        used = {name for name, _ in _uses(context, declared_ids)}
        reported: set[tuple[str, tuple[int, int, str]]] = set()

        for symbol in symbols:
            if symbol.kind != "variable":
                continue
            if symbol.scope is context.root:
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
                f"Variable '{symbol.name}' is assigned but never used.",
            )


class PythonUnreachableCodeRule(BaseRule):
    def __init__(self):
        super().__init__(PY003)

    def check(self, context: AnalysisContext):
        for block in context.nodes_of_type("block"):
            statements = [
                child
                for child in block.named_children
                if child.type != "comment"
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
                    "raise_statement",
                    "break_statement",
                    "continue_statement",
                }:
                    terminated = True


class PythonDuplicateDeclarationRule(BaseRule):
    def __init__(self):
        super().__init__(PY004)

    def check(self, context: AnalysisContext):
        seen: set[tuple[str, tuple[int, int, str]]] = set()

        for node in context.nodes_of_type("assignment"):
            if context.field(node, "type") is None:
                continue
            scope = _scope_owner(context, node)
            for name_node, name in _ast.get_python_variable_names(
                node, context.source_bytes
            ):
                key = (name, _key(scope))
                if key in seen:
                    yield self.report(
                        context,
                        name_node,
                        f"Variable '{name}' is declared more than once in the same scope.",
                    )
                else:
                    seen.add(key)


class PythonUnusedImportRule(BaseRule):
    def __init__(self):
        super().__init__(PY005)

    def check(self, context: AnalysisContext):
        imports = list(_import_bindings(context))
        if not imports:
            return

        _, declared_ids = _declarations(context)
        used = {name for name, _ in _uses(context, declared_ids)}

        for name, node in imports:
            if name not in used:
                yield self.report(
                    context,
                    node,
                    f"Imported binding '{name}' is not used.",
                )


class PythonUnusedParameterRule(BaseRule):
    def __init__(self):
        super().__init__(PY006)

    def check(self, context: AnalysisContext):
        _, declared_ids = _declarations(context)
        used = {name for name, _ in _uses(context, declared_ids)}

        for node in context.nodes_of_type(
            "parameters", "lambda_parameters"
        ):
            for name_node, name in _ast.get_python_parameter_names(
                node, context.source_bytes
            ):
                if name in {"self", "cls"} or name.startswith("_"):
                    continue
                if name not in used:
                    yield self.report(
                        context,
                        name_node,
                        f"Parameter '{name}' is not used in the function body.",
                    )


class PythonNoneAccessRule(BaseRule):
    def __init__(self):
        super().__init__(PY007)

    def check(self, context: AnalysisContext):
        scopes = [context.root] + list(
            context.nodes_of_type("function_definition")
        )
        reported: set[tuple[str, int]] = set()

        for scope in scopes:
            none_names: set[str] = set()
            dereferences = {
                _key(target): name
                for name, target in _dereferences(context)
            }

            for node in context.walk(scope):
                if node.type == "assignment" and context.field(
                    node, "right"
                ) is not None:
                    names = {
                        name
                        for _, name in _ast.get_python_variable_names(
                            node, context.source_bytes
                        )
                    }
                    if is_none_literal(
                        context, context.field(node, "right")
                    ):
                        none_names |= names
                    else:
                        none_names -= names

                name = dereferences.get(_key(node))
                if name is None or name not in none_names:
                    continue
                if _is_guarded(context, node, name):
                    continue
                key = (name, context.line(node))
                if key in reported:
                    continue
                reported.add(key)
                yield self.report(
                    context,
                    node,
                    f"Value '{name}' may be None when it is accessed.",
                )


class PythonEmptyExceptionHandlerRule(BaseRule):
    def __init__(self):
        super().__init__(PY008)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("except_clause"):
            block = next(
                (
                    child
                    for child in node.named_children
                    if child.type == "block"
                ),
                None,
            )
            if is_empty_block(
                context,
                block,
                pass_types=("pass_statement",),
            ):
                yield self.report(
                    context,
                    node,
                    "Exception handler is empty and silently ignores errors.",
                )


class PythonSuspiciousCallRule(BaseRule):
    def __init__(self):
        super().__init__(PY009)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("call"):
            name = call_name(context, node)
            if name in SUSPICIOUS_CALLS:
                yield self.report(
                    context,
                    node,
                    f"Call to '{name}' may execute dynamic code or require interaction.",
                )


class PythonDangerousCallRule(BaseRule):
    def __init__(self):
        super().__init__(PY010)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("call"):
            name = call_name(context, node)
            keywords = call_keyword_arguments(context, node)
            dangerous = name in DANGEROUS_CALLS

            if name in SHELL_CALLS and "shell" in keywords:
                value_node = context.field(
                    keywords["shell"], "value"
                )
                if context.text(value_node) == "True":
                    dangerous = True

            if name == "yaml.load":
                arguments = call_argument_nodes(context, node)
                dangerous = not any(
                    "SafeLoader" in context.text(argument)
                    for argument in arguments
                )

            if dangerous:
                yield self.report(
                    context,
                    node,
                    f"Potentially dangerous call to '{name}'.",
                )


PYTHON_RULES = [
    PythonUndefinedVariableRule(),
    PythonUnusedVariableRule(),
    PythonUnreachableCodeRule(),
    PythonDuplicateDeclarationRule(),
    PythonUnusedImportRule(),
    PythonUnusedParameterRule(),
    PythonNoneAccessRule(),
    PythonEmptyExceptionHandlerRule(),
    PythonSuspiciousCallRule(),
    PythonDangerousCallRule(),
]
