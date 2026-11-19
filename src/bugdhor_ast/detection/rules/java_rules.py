import re

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


JAVA001 = RuleMetadata(
    "JAVA001",
    "Undefined Variable",
    "A variable is used without a visible definition.",
    "error",
    "java",
    "Define the variable before using it.",
    (
        "Undefined-variable checking is deliberately conservative; "
        "type-aware resolution is not performed.",
        "Resolution is file-wide and does not model control flow.",
        "Only bare lower-camel identifiers are checked; type_identifier "
        "uses are skipped entirely.",
        "Fields, imports, methods, types, and JDK names are treated as "
        "known symbols.",
    ),
)
JAVA002 = RuleMetadata(
    "JAVA002",
    "Unused Variable",
    "A local variable is declared but never read.",
    "warning",
    "java",
    "Remove the declaration or use the variable.",
    (
        "Only local variable_declarator names inside method and "
        "constructor bodies are checked.",
        "Fields and underscore-prefixed names are skipped.",
    ),
)
JAVA003 = RuleMetadata(
    "JAVA003",
    "Unreachable Code",
    "Statements follow a terminating statement in the same block.",
    "warning",
    "java",
    "Remove the unreachable statements or adjust the control flow.",
    (
        "Only the first statement after a terminator in a Java block "
        "is reported.",
    ),
)
JAVA004 = RuleMetadata(
    "JAVA004",
    "Duplicate Variable Declaration",
    "A local variable is declared more than once in one scope.",
    "error",
    "java",
    "Remove the repeated declaration.",
    (
        "Only variable_declarator names in the same block or method "
        "scope are compared.",
        "Fields are skipped; invalid Java may parse with ERROR nodes "
        "that this rule does not interpret.",
    ),
)
JAVA005 = RuleMetadata(
    "JAVA005",
    "Unused Import",
    "An imported type or member is not used in the file.",
    "warning",
    "java",
    "Remove the import or use the imported name.",
    (
        "Wildcard and static imports are not checked.",
        "Usage is matched by simple name across identifier and "
        "type_identifier nodes.",
    ),
)
JAVA006 = RuleMetadata(
    "JAVA006",
    "Unused Function Parameter",
    "A method or constructor parameter is not used in the body.",
    "warning",
    "java",
    "Remove the parameter or use it in the body.",
    (
        "Only formal_parameter names of methods and constructors with "
        "bodies are checked.",
        "Underscore-prefixed names are skipped.",
    ),
)
JAVA007 = RuleMetadata(
    "JAVA007",
    "Potential Null Access",
    "A name bound to null is dereferenced without a visible guard.",
    "warning",
    "java",
    "Check that the value is not null before accessing it.",
    (
        "The rule is intra-method and does not follow call chains.",
        "Flow is approximated in source order; only simple != null and "
        "Objects.requireNonNull guards are recognized.",
    ),
)
JAVA008 = RuleMetadata(
    "JAVA008",
    "Empty Exception Handler",
    "A catch clause silently swallows the exception.",
    "warning",
    "java",
    "Handle the exception, log it, or re-throw it.",
    ("Comment-only catch blocks are treated as empty.",),
)
JAVA009 = RuleMetadata(
    "JAVA009",
    "Suspicious Function Call",
    "A call uses a process-control or diagnostic API.",
    "warning",
    "java",
    "Avoid abrupt process termination and swallowed stack traces.",
    ("Matches a fixed set of call names without receiver-type analysis.",),
)
JAVA010 = RuleMetadata(
    "JAVA010",
    "Dangerous Function Usage",
    "A call can execute commands, load classes, or deserialize data.",
    "error",
    "java",
    "Use a safer API and validate untrusted input.",
    (
        "No taint analysis is performed.",
        "Only a fixed set of call names, a few local receiver types, "
        "and ProcessBuilder creation are recognized.",
    ),
)


JAVA_JDK_NAMES = {
    "this", "super", "true", "false", "null", "var", "record",
    "Object", "String", "CharSequence", "StringBuilder", "StringBuffer",
    "Boolean", "Byte", "Short", "Integer", "Long", "Float", "Double",
    "Character", "Number", "Void", "Math", "System", "Runtime",
    "Thread", "ThreadLocal", "ThreadGroup", "Class", "ClassLoader",
    "Package", "Module", "Process", "ProcessBuilder", "Objects",
    "Optional", "Enum", "Comparable", "Iterable", "Cloneable",
    "Runnable", "Callable", "Exception", "RuntimeException", "Error",
    "Throwable", "IllegalArgumentException", "IllegalStateException",
    "NullPointerException", "IndexOutOfBoundsException",
    "UnsupportedOperationException", "ArithmeticException",
    "NumberFormatException", "ClassNotFoundException", "IOException",
    "FileNotFoundException", "InterruptedException", "SQLException",
    "List", "ArrayList", "LinkedList", "Set", "HashSet", "LinkedHashSet",
    "TreeSet", "SortedSet", "Map", "HashMap", "LinkedHashMap", "TreeMap",
    "SortedMap", "Queue", "Deque", "ArrayDeque", "LinkedList",
    "PriorityQueue", "Collection", "Collections", "Arrays", "Iterator",
    "ListIterator", "Spliterator", "Stream", "IntStream", "LongStream",
    "DoubleStream", "Collectors", "Function", "BiFunction", "Predicate",
    "BiPredicate", "Supplier", "Consumer", "BiConsumer", "File", "Path",
    "Paths", "Files", "InputStream", "OutputStream", "FileInputStream",
    "FileOutputStream", "ByteArrayInputStream", "ByteArrayOutputStream",
    "ObjectInputStream", "ObjectOutputStream", "BufferedReader",
    "BufferedWriter", "InputStreamReader", "OutputStreamWriter",
    "PrintStream", "PrintWriter", "Scanner", "Reader", "Writer",
    "Serializable", "Externalizable", "Date", "Calendar", "UUID",
    "Random", "SecureRandom", "Base64", "TimeUnit", "Duration", "Period",
    "LocalDate", "LocalTime", "LocalDateTime", "ZonedDateTime",
    "Instant", "Executor", "ExecutorService", "Executors", "Future",
    "CompletableFuture", "CountDownLatch", "Semaphore", "CyclicBarrier",
    "ConcurrentHashMap", "AtomicInteger", "AtomicLong", "AtomicBoolean",
    "ScriptEngine", "ScriptEngineManager", "Bindings", "Logger", "Level",
}

SUSPICIOUS_CALLS = {
    "System.exit",
    "printStackTrace",
    "Thread.stop",
}

DANGEROUS_CALLS = {
    "Runtime.getRuntime().exec",
    "Runtime.exec",
    "ObjectInputStream.readObject",
    "Class.forName",
    "ScriptEngine.eval",
}

DANGEROUS_CREATIONS = {"ProcessBuilder"}

_JAVA_DECLARATION_PARENTS = {
    "variable_declarator",
    "formal_parameter",
    "catch_formal_parameter",
    "enhanced_for_statement",
    "resource",
    "method_declaration",
    "constructor_declaration",
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "enum_constant",
    "annotation_type_declaration",
    "record_declaration",
    "annotation",
    "marker_annotation",
    "element_value_pair",
}

_JAVA_TYPE_DECLARATIONS = {
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "annotation_type_declaration",
    "record_declaration",
}

_JAVA_BODY_TYPES = {"block", "constructor_body"}


@dataclass(frozen=True)
class _Symbol:
    name: str
    node: Node
    kind: str
    scope: Node


def _node_key(node: Node) -> tuple[int, int, str]:
    return (node.start_byte, node.end_byte, node.type)


def _same_node(left: Node | None, right: Node | None) -> bool:
    return (
        left is not None
        and right is not None
        and _node_key(left) == _node_key(right)
    )


def _parent(context: AnalysisContext, node: Node) -> Node | None:
    parents = getattr(context, "_java_parents", None)
    if parents is None:
        parents = {}
        for current in context.walk(context.root):
            for child in current.children:
                parents[_node_key(child)] = current
        setattr(context, "_java_parents", parents)
    return parents.get(_node_key(node))


def _has_ancestor(
    context: AnalysisContext, node: Node, *types: str
) -> bool:
    wanted = set(types)
    current = _parent(context, node)
    while current is not None:
        if current.type in wanted:
            return True
        current = _parent(context, current)
    return False


def _nearest_scope(context: AnalysisContext, node: Node) -> Node:
    current = _parent(context, node)
    while current is not None:
        if current.type in _JAVA_BODY_TYPES:
            return current
        if current.type in {
            "method_declaration",
            "constructor_declaration",
            "static_initializer",
        }:
            return current
        current = _parent(context, current)
    return context.root


def _simple_type_name(text: str) -> str:
    name = text.split("<", 1)[0].strip()
    return name.rsplit(".", 1)[-1]


def _java_import_bindings(context: AnalysisContext):
    for node in context.nodes_of_type("import_declaration"):
        source = context.text(node)
        if source.lstrip().startswith("import static"):
            continue
        if any(child.type == "asterisk" for child in context.walk(node)):
            continue

        target = None
        for child in node.named_children:
            if child.type in {"scoped_identifier", "identifier"}:
                target = child
                break

        while target is not None and target.type == "scoped_identifier":
            target = context.field(target, "name")

        if target is not None and target.type == "identifier":
            yield context.text(target), target


def _collect_declarations(context: AnalysisContext):
    symbols: list[_Symbol] = []
    declared_ids: set[tuple[int, int, str]] = set()

    def add(node: Node | None, kind: str,
            scope: Node | None = None) -> None:
        name = identifier_name(node)
        if name is None:
            return
        symbols.append(
            _Symbol(name, node, kind, scope or context.root)
        )
        declared_ids.add(_node_key(node))

    for node in context.nodes_of_type(*_JAVA_TYPE_DECLARATIONS):
        add(context.field(node, "name"), "type")

    for node in context.nodes_of_type(
        "method_declaration", "constructor_declaration"
    ):
        add(context.field(node, "name"), "method")

    for node in context.nodes_of_type("enum_constant"):
        add(context.field(node, "name"), "field")

    for node in context.nodes_of_type("formal_parameter"):
        owner = _parent(context, node)
        scope = _parent(context, owner) if owner is not None else None
        add(context.field(node, "name"), "parameter", scope)

    for node in context.nodes_of_type("catch_formal_parameter"):
        add(context.field(node, "name"), "parameter")

    for node in context.nodes_of_type(
        "enhanced_for_statement", "resource"
    ):
        add(context.field(node, "name"), "variable",
            _nearest_scope(context, node))

    for node in context.nodes_of_type(
        "lambda_expression", "inferred_parameters"
    ):
        for child in node.named_children:
            if child.type == "identifier":
                add(child, "parameter", node)

    for node in context.nodes_of_type("variable_declarator"):
        parent = _parent(context, node)
        name_node = context.field(node, "name")
        if parent is not None and parent.type in {
            "field_declaration",
            "constant_declaration",
        }:
            add(name_node, "field")
        elif (
            parent is not None
            and parent.type == "local_variable_declaration"
        ):
            add(name_node, "variable", _nearest_scope(context, node))
        else:
            add(name_node, "variable")

    for name, node in _java_import_bindings(context):
        add(node, "import")

    return symbols, declared_ids


def _is_member_selector(context: AnalysisContext, node: Node) -> bool:
    parent = _parent(context, node)
    if parent is None:
        return False

    if parent.type in {"field_access", "method_invocation"}:
        if (
            _same_node(context.field(parent, "field"), node)
            or _same_node(context.field(parent, "name"), node)
        ):
            return True

    if parent.type in {
        "labeled_statement",
        "break_statement",
        "continue_statement",
        "method_reference",
    }:
        return True

    if parent.type in {
        "scoped_identifier",
        "scoped_type_identifier",
        "element_value_pair",
    } and _same_node(context.field(parent, "name"), node):
        return True

    return False


def _uses(
    context: AnalysisContext,
    declared_ids: set[tuple[int, int, str]],
):
    for node in context.walk():
        if (
            node.type != "identifier"
            or _node_key(node) in declared_ids
        ):
            continue
        if _has_ancestor(context,
            node, "import_declaration", "package_declaration"
        ):
            continue
        if _is_member_selector(context, node):
            continue
        name = identifier_name(node)
        if name is not None:
            yield name, node


def _all_used_names(context: AnalysisContext) -> set[str]:
    used: set[str] = set()
    for node in walk_identifiers(context):
        if _has_ancestor(context,
            node, "import_declaration", "package_declaration"
        ):
            continue
        name = identifier_name(node)
        if name is not None:
            used.add(name)
    return used


def _dereference_target(
    context: AnalysisContext, node: Node
) -> str | None:
    if node.type in {"method_invocation", "field_access"}:
        target = context.field(node, "object")
    elif node.type == "array_access":
        target = context.field(node, "array")
    else:
        return None

    if target is None or target.type != "identifier":
        return None
    return context.text(target)


def _child_on_path(
    context: AnalysisContext, ancestor: Node, node: Node
) -> Node:
    child = node
    while True:
        parent = _parent(context, child)
        if parent is None or parent is ancestor:
            return child
        child = parent


def _field_on_path(
    context: AnalysisContext, ancestor: Node, node: Node
) -> str | None:
    child = _child_on_path(context, ancestor, node)
    for index, candidate in enumerate(ancestor.children):
        if _same_node(candidate, child):
            return ancestor.field_name_for_child(index)
    return None


def _condition_has_guard(condition: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = (
        rf"\b{escaped}\s*!=\s*null\b",
        rf"\bnull\s*!=\s*{escaped}\b",
        rf"requireNonNull\s*\(\s*{escaped}\s*\)",
    )
    return any(re.search(pattern, condition) for pattern in patterns)


def _has_preceding_guard(
    context: AnalysisContext, node: Node, name: str
) -> bool:
    current = _parent(context, node)
    while current is not None:
        if current.type in _JAVA_BODY_TYPES:
            for statement in current.named_children:
                if statement.start_byte >= node.start_byte:
                    break
                if statement.type != "expression_statement":
                    continue
                expression = None
                for child in statement.named_children:
                    if child.type == "method_invocation":
                        expression = child
                        break
                if expression is None:
                    continue
                call = call_name(context, expression)
                if call == "Objects.requireNonNull" or call.endswith(
                    ".requireNonNull"
                ):
                    arguments = call_argument_nodes(context, expression)
                    if any(
                        context.text(argument) == name
                        for argument in arguments
                    ):
                        return True
        current = _parent(context, current)
    return False


def _is_guarded(
    context: AnalysisContext, node: Node, name: str
) -> bool:
    current = _parent(context, node)
    while current is not None:
        if current.type in {"if_statement", "assert_statement"}:
            condition = context.field_text(current, "condition") or ""
            if _condition_has_guard(condition, name):
                if current.type == "assert_statement":
                    return True
                field = _field_on_path(context, current, node)
                if field in {"condition", "consequence"}:
                    return True
        current = _parent(context, current)
    return _has_preceding_guard(context, node, name)


def _local_variables(context: AnalysisContext):
    for node in context.nodes_of_type("local_variable_declaration"):
        type_node = context.field(node, "type")
        type_name = _simple_type_name(context.text(type_node))
        for child in node.named_children:
            if child.type != "variable_declarator":
                continue
            name = identifier_name(context.field(child, "name"))
            if name is not None:
                yield name, type_name, child


def _typed_local_variables(context: AnalysisContext) -> dict[str, str]:
    return {
        name: type_name
        for name, type_name, _ in _local_variables(context)
    }


def _created_type_name(context: AnalysisContext, node: Node) -> str:
    return _simple_type_name(context.field_text(node, "type") or "")


class JavaUndefinedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA001)

    def check(self, context: AnalysisContext):
        symbols, declared_ids = _collect_declarations(context)
        defined = {symbol.name for symbol in symbols} | JAVA_JDK_NAMES
        seen: set[str] = set()

        for name, node in _uses(context, declared_ids):
            if name in defined:
                continue
            if not name or not name[0].islower() or name.startswith("_"):
                continue
            if name in seen:
                continue
            seen.add(name)
            yield self.report(
                context,
                node,
                f"Variable '{name}' is not defined.",
            )


class JavaUnusedVariableRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA002)

    def check(self, context: AnalysisContext):
        symbols, declared_ids = _collect_declarations(context)
        used = {name for name, _ in _uses(context, declared_ids)}
        reported: set[tuple[str, tuple[int, int, str]]] = set()

        for symbol in symbols:
            if symbol.kind != "variable":
                continue
            declarator = _parent(context, symbol.node)
            parent = (
                _parent(context, declarator)
                if declarator is not None
                else None
            )
            if (
                declarator is None
                or declarator.type != "variable_declarator"
                or parent is None
                or parent.type != "local_variable_declaration"
            ):
                continue
            if not _has_ancestor(context,
                symbol.node,
                "method_declaration",
                "constructor_declaration",
            ):
                continue
            if symbol.name.startswith("_") or symbol.name in used:
                continue
            key = (symbol.name, _node_key(symbol.scope))
            if key in reported:
                continue
            reported.add(key)
            yield self.report(
                context,
                symbol.node,
                f"Variable '{symbol.name}' is declared but never used.",
            )


class JavaUnreachableCodeRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA003)

    def check(self, context: AnalysisContext):
        for block in context.nodes_of_type("block"):
            statements = [
                child
                for child in block.named_children
                if child.type not in {
                    "comment",
                    "line_comment",
                    "block_comment",
                }
            ]
            terminated = False
            for statement in statements:
                if terminated:
                    text = context.text(statement).strip().splitlines()[0]
                    yield self.report(
                        context,
                        statement,
                        f"Statement '{text}' is unreachable after a "
                        "terminating statement.",
                    )
                    break
                if statement.type in {
                    "return_statement",
                    "throw_statement",
                    "break_statement",
                    "continue_statement",
                }:
                    terminated = True


class JavaDuplicateDeclarationRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA004)

    def check(self, context: AnalysisContext):
        seen: set[tuple[str, tuple[int, int, str]]] = set()

        for name, type_name, node in _local_variables(context):
            if type_name == "":
                continue
            scope = _nearest_scope(context, node)
            name_node = context.field(node, "name")
            if not _has_ancestor(context,
                node, "method_declaration", "constructor_declaration"
            ):
                continue
            key = (name, _node_key(scope))
            if key in seen:
                yield self.report(
                    context,
                    name_node,
                    f"Variable '{name}' is declared more than once in "
                    "the same scope.",
                )
            else:
                seen.add(key)


class JavaUnusedImportRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA005)

    def check(self, context: AnalysisContext):
        imports = list(_java_import_bindings(context))
        if not imports:
            return

        used = _all_used_names(context)
        reported: set[str] = set()

        for name, node in imports:
            if name in used or name in reported:
                continue
            reported.add(name)
            yield self.report(
                context,
                node,
                f"Imported name '{name}' is not used.",
            )


class JavaUnusedParameterRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA006)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("formal_parameters"):
            owner = _parent(context, node)
            if owner is None or owner.type not in {
                "method_declaration",
                "constructor_declaration",
            }:
                continue
            body = context.field(owner, "body")
            if body is None or body.type not in _JAVA_BODY_TYPES:
                continue

            used: set[str] = set()
            for child in context.walk(body):
                if child.type != "identifier":
                    continue
                name = identifier_name(child)
                if name is not None:
                    used.add(name)

            for parameter in node.named_children:
                if parameter.type != "formal_parameter":
                    continue
                name_node = context.field(parameter, "name")
                name = identifier_name(name_node)
                if name is None or name.startswith("_"):
                    continue
                if name not in used:
                    owner_name = (
                        context.field_text(owner, "name") or "constructor"
                    )
                    yield self.report(
                        context,
                        name_node,
                        f"Parameter '{name}' is not used in the body "
                        f"of '{owner_name}'.",
                    )


class JavaNullAccessRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA007)

    def check(self, context: AnalysisContext):
        scopes = list(
            context.nodes_of_type(
                "method_declaration", "constructor_declaration"
            )
        )
        reported: set[tuple[str, int]] = set()
        declarators_by_declaration: dict[
            tuple[int, int, str], list[tuple[str, Node]]
        ] = {}
        for name, _, declarator in _local_variables(context):
            declaration = _parent(context, declarator)
            if declaration is None:
                continue
            declarators_by_declaration.setdefault(
                _node_key(declaration), []
            ).append((name, declarator))

        for scope in scopes:
            body = context.field(scope, "body")
            if body is None or body.type not in _JAVA_BODY_TYPES:
                continue

            null_names: set[str] = set()
            for node in context.walk(body):
                if node.type == "local_variable_declaration":
                    for name, declarator in declarators_by_declaration.get(
                        _node_key(node), []
                    ):
                        value = context.field(declarator, "value")
                        if is_none_literal(context, value):
                            null_names.add(name)
                        elif value is not None:
                            null_names.discard(name)

                if node.type == "assignment_expression":
                    left = context.field(node, "left")
                    right = context.field(node, "right")
                    name = (
                        identifier_name(left)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    if name is not None:
                        if is_none_literal(context, right):
                            null_names.add(name)
                        elif right is not None:
                            null_names.discard(name)

                target = _dereference_target(context, node)
                if target is None or target not in null_names:
                    continue
                if _is_guarded(context, node, target):
                    continue
                key = (target, context.line(node))
                if key in reported:
                    continue
                reported.add(key)
                yield self.report(
                    context,
                    node,
                    f"Value '{target}' may be null when it is accessed.",
                )


class JavaEmptyExceptionHandlerRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA008)

    def check(self, context: AnalysisContext):
        for node in context.nodes_of_type("catch_clause"):
            body = context.field(node, "body")
            if not is_empty_block(context, body):
                continue

            exception_type = "exception"
            for child in node.named_children:
                if child.type == "catch_formal_parameter":
                    for nested in child.named_children:
                        if nested.type == "catch_type":
                            exception_type = context.text(nested)
                        break
                    break

            yield self.report(
                context,
                node,
                f"Exception handler for '{exception_type}' is empty "
                "and silently ignores errors.",
            )


class JavaSuspiciousCallRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA009)

    def check(self, context: AnalysisContext):
        seen: set[tuple[str, int]] = set()

        for node in context.nodes_of_type("method_invocation"):
            name = call_name(context, node)
            match = name if name in SUSPICIOUS_CALLS else None
            if match is None and name.endswith(".printStackTrace"):
                match = "printStackTrace"
            if match is None and name.endswith(".stop"):
                receiver = name.rsplit(".", 1)[0]
                if "thread" in receiver.lower():
                    match = "Thread.stop"
            if match is None:
                continue

            key = (match, context.line(node))
            if key in seen:
                continue
            seen.add(key)
            yield self.report(
                context,
                node,
                f"Call to '{name}' may terminate a process or hide an error.",
            )


class JavaDangerousCallRule(BaseRule):
    def __init__(self):
        super().__init__(JAVA010)

    def check(self, context: AnalysisContext):
        typed_locals = _typed_local_variables(context)
        seen: set[tuple[str, int]] = set()

        for node in context.nodes_of_type("method_invocation"):
            name = call_name(context, node)
            dangerous = name in DANGEROUS_CALLS

            if not dangerous and "." in name:
                receiver, method = name.rsplit(".", 1)
                receiver_type = typed_locals.get(receiver, "")
                dangerous = (
                    receiver_type == "ObjectInputStream"
                    and method == "readObject"
                ) or (
                    receiver_type == "ScriptEngine"
                    and method == "eval"
                ) or (
                    receiver_type == "Runtime"
                    and method == "exec"
                )

            if not dangerous:
                continue
            key = (name, context.line(node))
            if key in seen:
                continue
            seen.add(key)
            yield self.report(
                context,
                node,
                f"Potentially dangerous call to '{name}'.",
            )

        for node in context.nodes_of_type("object_creation_expression"):
            name = _created_type_name(context, node)
            if name not in DANGEROUS_CREATIONS:
                continue
            key = (name, context.line(node))
            if key in seen:
                continue
            seen.add(key)
            yield self.report(
                context,
                node,
                f"Potentially dangerous call to '{name}' constructor.",
            )


JAVA_RULES = [
    JavaUndefinedVariableRule(),
    JavaUnusedVariableRule(),
    JavaUnreachableCodeRule(),
    JavaDuplicateDeclarationRule(),
    JavaUnusedImportRule(),
    JavaUnusedParameterRule(),
    JavaNullAccessRule(),
    JavaEmptyExceptionHandlerRule(),
    JavaSuspiciousCallRule(),
    JavaDangerousCallRule(),
]
