"""Conservative AST evidence for general code defects.

Every match is tied to a concrete syntax node or parser diagnostic. The rules
never claim that a value is attacker-controlled, that a type checker ran, or
that a path is runtime-reachable. Findings are therefore potential defects with
explicit limitations; external linters and type checkers remain separate layers.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from tree_sitter import Node

from bugdhor.detection.ast_analysis import StructuralMatch
from bugdhor.detection.classification import CATEGORY_INFO
from bugdhor.detection.models import EvidenceType, VulnerabilityCategory
from bugdhor.parsing.models import SourceSpan, SupportedLanguage
from bugdhor.parsing.parser import ParsedSource

_MAX_MATCHES_PER_RULE = 20

_PYTHON_BUILTINS = frozenset(
    {
        "abs",
        "all",
        "any",
        "bool",
        "bytes",
        "dict",
        "dir",
        "enumerate",
        "Exception",
        "filter",
        "float",
        "format",
        "frozenset",
        "getattr",
        "hasattr",
        "hash",
        "int",
        "isinstance",
        "issubclass",
        "len",
        "list",
        "map",
        "max",
        "min",
        "next",
        "object",
        "open",
        "print",
        "range",
        "repr",
        "set",
        "setattr",
        "sorted",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "ValueError",
        "TypeError",
        "RuntimeError",
        "KeyError",
        "self",
        "cls",
        "True",
        "False",
        "None",
    }
)
_JAVASCRIPT_GLOBALS = frozenset(
    {
        "Array",
        "Boolean",
        "Buffer",
        "console",
        "Date",
        "Error",
        "fetch",
        "Function",
        "JSON",
        "Map",
        "Math",
        "Number",
        "Object",
        "Promise",
        "process",
        "RegExp",
        "require",
        "Set",
        "String",
        "Symbol",
        "URL",
        "window",
        "document",
        "globalThis",
        "undefined",
        "null",
        "true",
        "false",
        "module",
        "exports",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "encodeURIComponent",
        "decodeURIComponent",
        "parseInt",
        "parseFloat",
        "isNaN",
    }
)
_SENSITIVE_NAME = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SSRF_CALL_SUFFIXES = (
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "urllib.request.urlopen",
    "httpx.get",
    "httpx.post",
    "axios.get",
    "axios.post",
    "fetch",
    "http.get",
)
_UPLOAD_MARKERS = ("request.files", "req.files", "ctx.request.files")


@dataclass(frozen=True, slots=True)
class _Occurrence:
    name: str
    span: SourceSpan


def analyze_general_bugs(parsed: ParsedSource) -> tuple[StructuralMatch, ...]:
    """Return conservative general-bug evidence for a parsed source file."""
    matches: list[StructuralMatch] = []
    matches.extend(_syntax_matches(parsed))
    if parsed.language in {
        SupportedLanguage.PYTHON,
        SupportedLanguage.JAVASCRIPT,
        SupportedLanguage.TYPESCRIPT,
    }:
        definitions, uses = _identifier_occurrences(parsed)
        matches.extend(_undefined_variable_matches(parsed, definitions, uses))
        matches.extend(_unused_variable_matches(parsed, definitions, uses))
        matches.extend(_null_reference_matches(parsed))
        matches.extend(_suspicious_control_flow_matches(parsed))
        matches.extend(_runtime_error_matches(parsed))
        matches.extend(_exposure_matches(parsed))
        matches.extend(_ssrf_matches(parsed))
        matches.extend(_upload_matches(parsed))
    if parsed.language is SupportedLanguage.PYTHON:
        matches.extend(_python_type_error_matches(parsed))
        matches.extend(_python_unhandled_exception_matches(parsed))
        matches.extend(_python_resource_matches(parsed))
        matches.extend(_python_common_mistake_matches(parsed))
    elif parsed.language in {SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT}:
        matches.extend(_javascript_common_mistake_matches(parsed))
        matches.extend(_javascript_unhandled_exception_matches(parsed))
    return tuple(_limit(matches))


def _limit(matches: list[StructuralMatch]) -> list[StructuralMatch]:
    counts: Counter[str] = Counter()
    limited: list[StructuralMatch] = []
    for match in matches:
        if counts[match.rule_id] >= _MAX_MATCHES_PER_RULE:
            continue
        counts[match.rule_id] += 1
        limited.append(match)
    return limited


def _syntax_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.SYNTAX_ERROR]
    return [
        StructuralMatch(
            rule_id="parser.syntax-error",
            category=VulnerabilityCategory.SYNTAX_ERROR,
            cwe=info.default_cwe,
            title=f"Syntax error: {diagnostic.message}",
            span=diagnostic.span,
            detail=(
                f"Tree-sitter reported a {diagnostic.kind} node ({diagnostic.node_type}) at "
                f"line {diagnostic.line + 1}: {diagnostic.message}."
            ),
            severity_hint="high",
            strength=0.9,
            reliability=0.95,
            remediation=info.remediation,
            limitations=(
                "Parser recovery is syntactic; later analysis coverage may be incomplete.",
            ),
            evidence_type=EvidenceType.PARSER,
        )
        for diagnostic in parsed.diagnostics
    ]


def _walk(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(parsed: ParsedSource, node: Node) -> str:
    return parsed.text_for_node(node).strip()


def _identifier_occurrences(
    parsed: ParsedSource,
) -> tuple[dict[str, list[_Occurrence]], dict[str, list[_Occurrence]]]:
    definitions: dict[str, list[_Occurrence]] = {}
    uses: dict[str, list[_Occurrence]] = {}
    for node in _walk(parsed.root_node):
        definition = _definition_name(parsed, node)
        if definition is not None:
            definitions.setdefault(definition.name, []).append(definition)
        if _is_identifier_use(parsed, node):
            name = _text(parsed, node)
            uses.setdefault(name, []).append(_Occurrence(name, parsed.span_for_node(node)))
    return definitions, uses


def _definition_name(parsed: ParsedSource, node: Node) -> _Occurrence | None:
    language = parsed.language
    if language is SupportedLanguage.PYTHON:
        if node.type in {"function_definition", "class_definition"}:
            return None
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            if left is not None:
                return _first_from_target(parsed, left)
        if node.type in {"for_statement", "with_item", "except_clause"}:
            target = (
                node.child_by_field_name("left")
                or node.child_by_field_name("name")
                or node.child_by_field_name("target")
            )
            if target is not None:
                return _first_from_target(parsed, target)
        if node.type in {"import_statement", "import_from_statement"}:
            for child in node.named_children:
                if child.type in {"identifier", "dotted_name", "aliased_import"}:
                    text = _text(parsed, child).split(" as ")[-1].split(".")[0]
                    if text:
                        return _Occurrence(text, parsed.span_for_node(child))
        if node.type in {"parameters", "lambda_parameters"}:
            return None
        if node.type == "identifier" and _has_ancestor_type(
            node, {"parameters", "lambda_parameters"}
        ):
            return _Occurrence(_text(parsed, node), parsed.span_for_node(node))
        return None

    if node.type in {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "method_definition",
    }:
        return None
    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _first_from_target(parsed, name_node)
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        if left is not None:
            return _first_from_target(parsed, left)
    if node.type == "identifier" and _has_ancestor_type(node, {"formal_parameters"}):
        return _Occurrence(_text(parsed, node), parsed.span_for_node(node))
    if node.type in {"import_clause", "import_specifier", "namespace_import"}:
        name_node = node.child_by_field_name("name") or node.child_by_field_name("alias")
        if name_node is not None:
            return _Occurrence(_text(parsed, name_node), parsed.span_for_node(name_node))
    return None


def _first_from_target(parsed: ParsedSource, node: Node) -> _Occurrence | None:
    if node.type == "identifier":
        return _Occurrence(_text(parsed, node), parsed.span_for_node(node))
    for child in node.named_children:
        result = _first_from_target(parsed, child)
        if result is not None:
            return result
    return None


def _is_identifier_use(parsed: ParsedSource, node: Node) -> bool:
    if node.type != "identifier":
        return False
    parent = node.parent
    if parent is None:
        return False
    if parent.type in {"attribute", "member_expression"}:
        attribute = parent.child_by_field_name("attribute") or parent.child_by_field_name(
            "property"
        )
        if _same_node(attribute, node):
            return False
    if parent.type in {"pair", "object_pattern", "field_definition", "property_signature"}:
        key = parent.child_by_field_name("key") or parent.child_by_field_name("name")
        if _same_node(key, node):
            return False
    if parent.type in {"assignment", "variable_declarator", "assignment_expression"}:
        target = parent.child_by_field_name("left") or parent.child_by_field_name("name")
        if _same_node(target, node):
            return False
    if _has_ancestor_type(node, {"parameters", "lambda_parameters", "formal_parameters"}):
        return False
    if parent.type in {
        "function_definition",
        "class_definition",
        "function_declaration",
        "class_declaration",
    }:
        return False
    if parent.type in {
        "import_statement",
        "import_from_statement",
        "import_clause",
        "import_specifier",
    }:
        return False
    return True


def _same_node(left: Node | None, right: Node | None) -> bool:
    return (
        left is not None
        and right is not None
        and left.start_byte == right.start_byte
        and left.end_byte == right.end_byte
    )


def _has_ancestor_type(node: Node, types: set[str]) -> bool:
    current = node.parent
    while current is not None:
        if current.type in types:
            return True
        current = current.parent
    return False


def _undefined_variable_matches(
    parsed: ParsedSource,
    definitions: dict[str, list[_Occurrence]],
    uses: dict[str, list[_Occurrence]],
) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.UNDEFINED_VARIABLE]
    builtins = (
        _PYTHON_BUILTINS if parsed.language is SupportedLanguage.PYTHON else _JAVASCRIPT_GLOBALS
    )
    matches: list[StructuralMatch] = []
    for name, occurrences in sorted(uses.items()):
        if name in definitions or name in builtins or name.startswith("__"):
            continue
        occurrence = occurrences[0]
        matches.append(
            StructuralMatch(
                rule_id="ast.undefined-variable",
                category=VulnerabilityCategory.UNDEFINED_VARIABLE,
                cwe=info.default_cwe,
                title=f"Identifier {name!r} has no definition in this file",
                span=occurrence.span,
                detail=(
                    f"The AST reads identifier {name!r}, but no declaration, assignment, "
                    "parameter, or import with that name was observed in this file."
                ),
                severity_hint="medium",
                strength=0.58,
                reliability=0.65,
                remediation=info.remediation,
                limitations=(
                    "Globals, dynamic bindings, runtime injection, and other files are not resolved.",
                ),
            )
        )
    return matches


def _unused_variable_matches(
    parsed: ParsedSource,
    definitions: dict[str, list[_Occurrence]],
    uses: dict[str, list[_Occurrence]],
) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.UNUSED_VARIABLE]
    builtins = (
        _PYTHON_BUILTINS if parsed.language is SupportedLanguage.PYTHON else _JAVASCRIPT_GLOBALS
    )
    matches: list[StructuralMatch] = []
    for name, occurrences in sorted(definitions.items()):
        if name in builtins or name.startswith("_"):
            continue
        total = len(occurrences) + len(uses.get(name, ()))
        if total > 1:
            continue
        occurrence = occurrences[0]
        matches.append(
            StructuralMatch(
                rule_id="ast.unused-variable",
                category=VulnerabilityCategory.UNUSED_VARIABLE,
                cwe=info.default_cwe,
                title=f"Binding {name!r} is not read in this file",
                span=occurrence.span,
                detail=(
                    f"The AST observed a binding for {name!r} and no other identifier with "
                    "that name in the parsed file."
                ),
                severity_hint="low",
                strength=0.62,
                reliability=0.65,
                remediation=info.remediation,
                limitations=(
                    "Cross-file use, reflection, dynamic scope, and exported bindings are not resolved.",
                ),
            )
        )
    return matches


def _null_reference_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.NULL_REFERENCE]
    null_text = "None" if parsed.language is SupportedLanguage.PYTHON else "null"
    null_names: set[str] = set()
    for node in _walk(parsed.root_node):
        if node.type == "assignment":
            right = node.child_by_field_name("right")
            left = node.child_by_field_name("left")
            if right is not None and _text(parsed, right) == null_text and left is not None:
                target = _first_from_target(parsed, left)
                if target is not None:
                    null_names.add(target.name)
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None and _text(parsed, value) == null_text:
                target = _first_from_target(parsed, name)
                if target is not None:
                    null_names.add(target.name)
    matches: list[StructuralMatch] = []
    if not null_names:
        return matches
    for node in _walk(parsed.root_node):
        if node.type not in {"attribute", "member_expression"}:
            continue
        if _has_ancestor_type(node, {"optional_chain"}):
            continue
        object_node = node.child_by_field_name("object")
        if object_node is None or object_node.type != "identifier":
            continue
        name = _text(parsed, object_node)
        if name not in null_names:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.null-reference-risk",
                category=VulnerabilityCategory.NULL_REFERENCE,
                cwe=info.default_cwe,
                title=f"Member access on a value assigned {null_text}",
                span=parsed.span_for_node(node),
                detail=(
                    f"The AST observed {name!r} assigned {null_text} and later dereferenced. "
                    "Control flow between the assignment and access was not proven."
                ),
                severity_hint="high",
                strength=0.64,
                reliability=0.7,
                remediation=info.remediation,
                limitations=(
                    "No path feasibility or interprocedural control-flow analysis is implied.",
                ),
            )
        )
    return matches


def _python_type_error_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.TYPE_ERROR]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "binary_operator":
            continue
        operator = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if operator is None or left is None or right is None or _text(parsed, operator) != "+":
            continue
        left_kind = _literal_kind(left)
        right_kind = _literal_kind(right)
        if {left_kind, right_kind} != {"string", "number"}:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.string-number-addition",
                category=VulnerabilityCategory.TYPE_ERROR,
                cwe=info.default_cwe,
                title="String and numeric literals are added",
                span=parsed.span_for_node(node),
                detail=(
                    "The AST shows a '+' binary operation between a string literal and a "
                    "numeric literal, which raises TypeError in Python."
                ),
                severity_hint="medium",
                strength=0.86,
                reliability=0.9,
                remediation=info.remediation,
                limitations=(
                    "Only literal operands are evaluated; implicit conversion is not inferred.",
                ),
            )
        )
    return matches


def _python_unhandled_exception_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.UNHANDLED_EXCEPTION]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "except_clause":
            continue
        body = next((child for child in node.children if child.type == "block"), None)
        if body is None or [child.type for child in body.named_children] != ["pass_statement"]:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.silent-exception-handler",
                category=VulnerabilityCategory.UNHANDLED_EXCEPTION,
                cwe=info.default_cwe,
                title="Exception handler silently ignores the failure",
                span=parsed.span_for_node(node),
                detail=(
                    "The AST observed an exception clause whose body only contains 'pass', "
                    "so failures are discarded without recovery or reporting."
                ),
                severity_hint="medium",
                strength=0.72,
                reliability=0.85,
                remediation=info.remediation,
                limitations=("This rule reports silent handlers, not every uncaught exception.",),
            )
        )
    return matches


def _javascript_unhandled_exception_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.UNHANDLED_EXCEPTION]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "try_statement":
            continue
        if node.child_by_field_name("handler") is not None:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.try-without-catch",
                category=VulnerabilityCategory.UNHANDLED_EXCEPTION,
                cwe=info.default_cwe,
                title="try statement has no catch handler",
                span=parsed.span_for_node(node),
                detail="The AST observed a try statement without a catch handler.",
                severity_hint="medium",
                strength=0.68,
                reliability=0.8,
                remediation=info.remediation,
                limitations=("A finalizer may still run; recovery behavior is not evaluated.",),
            )
        )
    return matches


def _python_resource_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.RESOURCE_HANDLE]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "call":
            continue
        function = node.child_by_field_name("function")
        if function is None or _text(parsed, function) not in {"open", "io.open"}:
            continue
        if _has_ancestor_type(node, {"with_statement", "with_item"}):
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.unmanaged-open",
                category=VulnerabilityCategory.RESOURCE_HANDLE,
                cwe=info.default_cwe,
                title="File is opened outside a context manager",
                span=parsed.span_for_node(node),
                detail=(
                    "The AST observed open(...) outside a with statement. Deterministic cleanup "
                    "was not observed in the same construct."
                ),
                severity_hint="medium",
                strength=0.6,
                reliability=0.72,
                remediation=info.remediation,
                limitations=("Cleanup in a separate finally block is not tracked by this rule.",),
            )
        )
    return matches


def _suspicious_control_flow_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.SUSPICIOUS_CONTROL_FLOW]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type not in {"if_statement", "while_statement"}:
            continue
        condition = node.child_by_field_name("condition")
        if condition is None:
            continue
        value = _text(parsed, condition).lower()
        if value not in {"true", "false", "1", "0"}:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.constant-condition",
                category=VulnerabilityCategory.SUSPICIOUS_CONTROL_FLOW,
                cwe=info.default_cwe,
                title=f"Control flow uses a constant condition ({value})",
                span=parsed.span_for_node(node),
                detail=(
                    f"The AST observed a {node.type} whose condition is the literal {value}. "
                    "One branch is statically unreachable."
                ),
                severity_hint="medium",
                strength=0.7,
                reliability=0.85,
                remediation=info.remediation,
                limitations=("Dead code elimination and generated-code intent are not evaluated.",),
            )
        )
    return matches


def _runtime_error_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.RUNTIME_ERROR]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type not in {"binary_operator", "binary_expression"}:
            continue
        operator = node.child_by_field_name("operator")
        right = node.child_by_field_name("right")
        if operator is None or right is None:
            continue
        operator_text = _text(parsed, operator)
        if operator_text not in {"/", "//"} or _literal_kind(right) != "number":
            continue
        if _text(parsed, right).lstrip("-") != "0":
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.division-by-zero",
                category=VulnerabilityCategory.RUNTIME_ERROR,
                cwe=info.default_cwe,
                title="Division by a literal zero",
                span=parsed.span_for_node(node),
                detail="The AST observed a division whose divisor is the numeric literal 0.",
                severity_hint="medium",
                strength=0.9,
                reliability=0.92,
                remediation=info.remediation,
                limitations=("Only literal divisors are reported; computed zero is not inferred.",),
            )
        )
    return matches


def _python_common_mistake_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.COMMON_MISTAKE]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "default_parameter":
            continue
        value = node.child_by_field_name("value")
        if value is None or value.type not in {"list", "dictionary", "set"}:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.mutable-default-argument",
                category=VulnerabilityCategory.COMMON_MISTAKE,
                cwe=info.default_cwe,
                title="Mutable literal used as a default argument",
                span=parsed.span_for_node(node),
                detail=(
                    f"A mutable {value.type} literal is used as a default parameter value, "
                    "which shares state across calls."
                ),
                severity_hint="low",
                strength=0.85,
                reliability=0.88,
                remediation=info.remediation,
                limitations=(
                    "Runtime mutation is not simulated; the pattern itself is observable.",
                ),
            )
        )
    return matches


def _javascript_common_mistake_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.COMMON_MISTAKE]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type != "binary_expression":
            continue
        operator = node.child_by_field_name("operator")
        if operator is None or _text(parsed, operator) not in {"==", "!="}:
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.loose-equality",
                category=VulnerabilityCategory.COMMON_MISTAKE,
                cwe=info.default_cwe,
                title="Loose equality operator is used",
                span=parsed.span_for_node(node),
                detail=f"The AST observed the loose equality operator {_text(parsed, operator)}.",
                severity_hint="low",
                strength=0.6,
                reliability=0.8,
                remediation=info.remediation,
                limitations=(
                    "Intentional coercion is not distinguished from an accidental mistake.",
                ),
            )
        )
    return matches


def _exposure_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.SENSITIVE_EXPOSURE]
    log_names = {"print", "console.log", "console.debug", "logger.debug", "logger.info"}
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type not in {"call", "call_expression"}:
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or _text(parsed, function) not in log_names:
            continue
        for argument in arguments.named_children:
            if argument.type != "identifier" or not _SENSITIVE_NAME.search(_text(parsed, argument)):
                continue
            matches.append(
                StructuralMatch(
                    rule_id="ast.sensitive-value-in-log",
                    category=VulnerabilityCategory.SENSITIVE_EXPOSURE,
                    cwe=info.default_cwe,
                    title="Sensitive-looking identifier is written to output",
                    span=parsed.span_for_node(node),
                    detail=(
                        f"A call to {_text(parsed, function)} receives a sensitive-looking "
                        "identifier. The literal value is not reproduced here."
                    ),
                    severity_hint="high",
                    strength=0.66,
                    reliability=0.72,
                    remediation=info.remediation,
                    limitations=("Value contents and output destination are not evaluated.",),
                )
            )
            break
    return matches


def _ssrf_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.SSRF]
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type not in {"call", "call_expression"}:
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        name = _text(parsed, function).lower()
        if not any(name == suffix or name.endswith("." + suffix) for suffix in _SSRF_CALL_SUFFIXES):
            continue
        positional = [
            child
            for child in arguments.named_children
            if child.type not in {"comment", "keyword_argument", "pair"}
        ]
        if not positional or _literal_kind(positional[0]) != "string":
            matches.append(
                StructuralMatch(
                    rule_id="ast.outbound-request-dynamic-url",
                    category=VulnerabilityCategory.SSRF,
                    cwe=info.default_cwe,
                    title="Outbound HTTP request uses a non-literal destination",
                    span=parsed.span_for_node(node),
                    detail=(
                        f"The AST observed {name} called without a literal destination. "
                        "Destination provenance and allowlisting are not established."
                    ),
                    severity_hint="high",
                    strength=0.56,
                    reliability=0.7,
                    remediation=info.remediation,
                    limitations=(
                        "No attacker control, DNS resolution, or redirect behavior is proven.",
                    ),
                )
            )
    return matches


def _upload_matches(parsed: ParsedSource) -> list[StructuralMatch]:
    info = CATEGORY_INFO[VulnerabilityCategory.UNSAFE_FILE_UPLOAD]
    if not any(marker in parsed.text for marker in _UPLOAD_MARKERS):
        return []
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type not in {"call", "call_expression"}:
            continue
        function = node.child_by_field_name("function")
        if function is None:
            continue
        name = _text(parsed, function).lower()
        if not (name.endswith(".save") or name.endswith(".mv")):
            continue
        matches.append(
            StructuralMatch(
                rule_id="ast.upload-save-call",
                category=VulnerabilityCategory.UNSAFE_FILE_UPLOAD,
                cwe=info.default_cwe,
                title="Uploaded file is persisted without an observed validation step",
                span=parsed.span_for_node(node),
                detail=(
                    f"The AST observed an upload source marker and a call to {name}. "
                    "Type, size, destination, and filename validation were not observed."
                ),
                severity_hint="high",
                strength=0.6,
                reliability=0.68,
                remediation=info.remediation,
                limitations=("Validation in another function or framework is not resolved.",),
            )
        )
    return matches


def _literal_kind(node: Node) -> str | None:
    node_type = node.type.lower()
    if node_type in {"string", "string_literal", "template_string"}:
        return "string"
    if node_type in {"integer", "float", "number", "decimal_integer_literal"}:
        return "number"
    if node_type in {"true", "false", "true_literal", "false_literal"}:
        return "boolean"
    if node_type in {"none", "null", "null_literal"}:
        return "null"
    return None


__all__ = ["analyze_general_bugs"]
