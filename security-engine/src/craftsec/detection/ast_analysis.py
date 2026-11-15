"""Syntactic AST evidence for vulnerable constructs.

This is deliberately conservative structural analysis. It reports observable
patterns such as dynamic SQL construction, shell execution, unsafe loaders,
weak hashes, disabled TLS verification, and credential-like literals. It does
not claim that a value is attacker-controlled; taint and external analyzers
supply that evidence. Each match records the exact node span and the rule that
produced it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from tree_sitter import Node

from craftsec.detection.classification import CATEGORY_INFO
from craftsec.detection.models import EvidenceLocation, VulnerabilityCategory
from craftsec.parsing.models import SourceSpan
from craftsec.parsing.parser import ParsedSource

_CALL_TYPES = {"call", "call_expression"}
_ASSIGNMENT_TYPES = {
    "assignment",
    "variable_declarator",
    "assignment_expression",
    "pair",
}
_SENSITIVE_NAME = re.compile(
    r"(^|[._\-])(password|passwd|pwd|secret|client_secret|api_key|apikey|"
    r"access_key|auth_token|private_key|token)([._\-]|$)",
    re.IGNORECASE,
)
_SECRET_PLACEHOLDERS = (
    "changeme",
    "change_me",
    "change-me",
    "password",
    "secret",
    "example",
    "dummy",
    "placeholder",
    "redacted",
    "todo",
    "your_",
    "your-",
    "process.env",
    "os.environ",
    "getenv",
    "****",
)
_SECRET_PLACEHOLDER_TOKENS = (
    "process.env",
    "os.environ",
    "getenv",
    "your_",
    "your-",
    "****",
    "xxxx",
    "<password>",
    "<secret>",
    "{{",
    "}}",
    "%(",
)
_SQL_SINK_SUFFIXES = (
    "execute",
    "executemany",
    "executescript",
    "rawquery",
    "queryrawunsafe",
    "executerawunsafe",
    "query",
    "raw",
)
_HASH_NAMES = {
    "hashlib.md5",
    "hashlib.sha1",
    "crypto.createhash",
    "cryptography.hazmat.primitives.hashes.md5",
    "cryptography.hazmat.primitives.hashes.sha1",
    "crypto.hash.md5",
    "crypto.hash.sha1",
}
_DESERIALIZATION_SUFFIXES = (
    "pickle.loads",
    "pickle.load",
    "cpickle.loads",
    "cpickle.load",
    "dill.loads",
    "dill.load",
    "marshal.loads",
    "marshal.load",
    "yaml.load",
    "yaml.unsafe_load",
)
_COMMAND_NAMES = {
    "os.system",
    "os.popen",
    "commands.getoutput",
    "pty.spawn",
    "child_process.exec",
    "child_process.execsync",
    "child_process.spawn",
    "child_process.spawnsync",
}
_CODE_NAMES = {"eval", "exec", "function", "vm.runinthiscontext", "vm.runinnewcontext"}
_XSS_PROPERTIES = {"innerhtml", "outerhtml", "srcdoc"}


@dataclass(frozen=True, slots=True)
class StructuralMatch:
    """One AST rule match before conversion into shared evidence."""

    rule_id: str
    category: VulnerabilityCategory
    cwe: str
    title: str
    span: SourceSpan
    detail: str
    severity_hint: str
    strength: float
    reliability: float
    remediation: str = ""
    limitations: tuple[str, ...] = ()

    def to_location(self, path: str) -> EvidenceLocation:
        return EvidenceLocation.from_source(self.span, path)


def analyze_ast(parsed: ParsedSource, *, path: str | None = None) -> tuple[StructuralMatch, ...]:
    """Return conservative structural matches for one parsed file."""
    file_path = path or parsed.path or "<memory>"
    matches: list[StructuralMatch] = []
    for node in _walk(parsed.root_node):
        if node.type in _CALL_TYPES:
            matches.extend(_call_matches(parsed, node, file_path))
        if node.type in _ASSIGNMENT_TYPES:
            match = _hardcoded_secret(parsed, node)
            if match is not None:
                matches.append(match)
        if node.type == "pair":
            match = _object_pair_match(parsed, node)
            if match is not None:
                matches.append(match)
        if node.type == "assignment_expression":
            match = _tls_assignment(parsed, node)
            if match is not None:
                matches.append(match)
            match = _xss_assignment(parsed, node)
            if match is not None:
                matches.append(match)
    return tuple(_deduplicate(matches))


def _walk(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _call_matches(
    parsed: ParsedSource,
    node: Node,
    path: str,
) -> list[StructuralMatch]:
    del path
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None:
        return []
    name = _dotted_name(parsed, function)
    if not name:
        return []
    normalized = name.lower().replace("-", ".")
    positional = [
        child
        for child in arguments.named_children
        if child.type not in {"comment", "keyword_argument", "pair"}
    ]
    keywords = _keyword_arguments(parsed, arguments)
    first = positional[0] if positional else None
    first_dynamic = first is not None and _is_dynamic(parsed, first)
    span = parsed.span_for_node(node)
    results: list[StructuralMatch] = []

    # Dynamic code execution.
    if normalized in _CODE_NAMES or normalized.endswith(".eval"):
        if first_dynamic:
            info = CATEGORY_INFO[VulnerabilityCategory.CODE_INJECTION]
            results.append(
                StructuralMatch(
                    rule_id="ast.dynamic-code-execution",
                    category=VulnerabilityCategory.CODE_INJECTION,
                    cwe=info.default_cwe,
                    title=f"Dynamic code execution through {name}",
                    span=span,
                    detail=(
                        f"Call to {name} receives a non-literal argument. The AST "
                        "observation does not establish control by an attacker."
                    ),
                    severity_hint="critical",
                    strength=0.72,
                    reliability=0.82,
                    remediation=info.remediation,
                    limitations=(
                        "AST evidence is syntactic; value provenance requires taint or "
                        "external analyzer evidence.",
                    ),
                )
            )

    # Shell execution.
    if normalized in _COMMAND_NAMES:
        if first_dynamic:
            info = CATEGORY_INFO[VulnerabilityCategory.COMMAND_INJECTION]
            results.append(
                StructuralMatch(
                    rule_id="ast.shell-execution",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    cwe=info.default_cwe,
                    title=f"Dynamic command execution through {name}",
                    span=span,
                    detail=(
                        f"Call to {name} receives a non-literal command argument. "
                        "AST evidence alone does not prove attacker control."
                    ),
                    severity_hint="critical",
                    strength=0.74,
                    reliability=0.82,
                    remediation=info.remediation,
                    limitations=("No shell escape or provenance analysis is implied.",),
                )
            )

    if normalized.startswith("subprocess."):
        shell = _keyword_bool(parsed, keywords.get("shell"))
        if shell is True:
            info = CATEGORY_INFO[VulnerabilityCategory.COMMAND_INJECTION]
            strength = 0.78 if first_dynamic else 0.5
            results.append(
                StructuralMatch(
                    rule_id="ast.subprocess-shell-true",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    cwe=info.default_cwe,
                    title="Subprocess runs with shell interpretation enabled",
                    span=span,
                    detail=(
                        "subprocess is called with shell=True"
                        + (", and the command argument is not a literal." if first_dynamic else ".")
                    ),
                    severity_hint="high",
                    strength=strength,
                    reliability=0.85,
                    remediation=info.remediation,
                    limitations=(
                        "A literal command with shell=True is still fragile but may not "
                        "be directly injectable.",
                    ),
                )
            )

    # Unsafe deserialization.
    if any(normalized.endswith(suffix) for suffix in _DESERIALIZATION_SUFFIXES):
        safe_yaml = False
        if normalized.endswith("yaml.load"):
            loader = keywords.get("loader")
            safe_yaml = loader is not None and "safeloader" in _node_text(parsed, loader).lower()
            if not safe_yaml and len(positional) > 1:
                safe_yaml = "safeloader" in _node_text(parsed, positional[1]).lower()
        if not safe_yaml and not (first is not None and _is_literal(parsed, first)):
            info = CATEGORY_INFO[VulnerabilityCategory.UNSAFE_DESERIALIZATION]
            results.append(
                StructuralMatch(
                    rule_id="ast.unsafe-deserialization",
                    category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
                    cwe=info.default_cwe,
                    title=f"Unsafe deserialization through {name}",
                    span=span,
                    detail=(
                        f"Call to {name} deserializes a non-literal value with a "
                        "loader that can execute or construct arbitrary objects."
                    ),
                    severity_hint="critical",
                    strength=0.8,
                    reliability=0.85,
                    remediation=info.remediation,
                )
            )

    # Weak hash or signature.
    weak_hash = normalized in _HASH_NAMES
    if normalized in {"hashlib.new", "crypto.createhash", "messagedigest.getinstance"}:
        algorithm = _literal_text(parsed, first).lower() if first is not None else ""
        weak_hash = algorithm in {"md5", "sha1"}
    if weak_hash:
        info = CATEGORY_INFO[VulnerabilityCategory.WEAK_CRYPTOGRAPHY]
        results.append(
            StructuralMatch(
                rule_id="ast.weak-cryptography",
                category=VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
                cwe=info.default_cwe,
                title="Weak cryptographic algorithm",
                span=span,
                detail=f"{name} uses MD5 or SHA-1, which are unsuitable for security decisions.",
                severity_hint="medium",
                strength=0.83,
                reliability=0.88,
                remediation=info.remediation,
            )
        )

    # Disabled TLS verification.
    verify = keywords.get("verify")
    reject_unauthorized = keywords.get("rejectunauthorized")
    if (
        _keyword_bool(parsed, verify) is False
        or _keyword_bool(parsed, reject_unauthorized) is False
    ):
        info = CATEGORY_INFO[VulnerabilityCategory.INSECURE_TLS]
        results.append(
            StructuralMatch(
                rule_id="ast.insecure-tls-verification",
                category=VulnerabilityCategory.INSECURE_TLS,
                cwe=info.default_cwe,
                title="TLS certificate verification is disabled",
                span=span,
                detail=(
                    f"{name} is called with certificate verification disabled "
                    "(verify=false or rejectUnauthorized=false)."
                ),
                severity_hint="high",
                strength=0.86,
                reliability=0.9,
                remediation=info.remediation,
            )
        )
    if normalized == "ssl._create_unverified_context":
        info = CATEGORY_INFO[VulnerabilityCategory.INSECURE_TLS]
        results.append(
            StructuralMatch(
                rule_id="ast.insecure-tls-context",
                category=VulnerabilityCategory.INSECURE_TLS,
                cwe=info.default_cwe,
                title="TLS context is created without certificate verification",
                span=span,
                detail="ssl._create_unverified_context disables certificate validation.",
                severity_hint="high",
                strength=0.9,
                reliability=0.92,
                remediation=info.remediation,
            )
        )

    # Dynamic SQL construction at a query sink.
    if first_dynamic and any(normalized.endswith(suffix) for suffix in _SQL_SINK_SUFFIXES):
        info = CATEGORY_INFO[VulnerabilityCategory.SQL_INJECTION]
        results.append(
            StructuralMatch(
                rule_id="ast.dynamic-sql-query",
                category=VulnerabilityCategory.SQL_INJECTION,
                cwe=info.default_cwe,
                title="SQL text is built dynamically at a query sink",
                span=span,
                detail=(
                    f"{name} receives interpolated, formatted, or concatenated SQL "
                    "text. Provenance of the interpolated value is not established "
                    "by this AST observation."
                ),
                severity_hint="medium",
                strength=0.6,
                reliability=0.8,
                remediation=info.remediation,
                limitations=(
                    "A dynamic SQL string is a risk indicator, not proof of an "
                    "attacker-controlled value.",
                ),
            )
        )

    # XSS sinks.
    if normalized.endswith("render_template_string") or normalized in {
        "markup",
        "document.write",
    }:
        if first_dynamic:
            info = CATEGORY_INFO[VulnerabilityCategory.XSS]
            results.append(
                StructuralMatch(
                    rule_id="ast.dynamic-html-sink",
                    category=VulnerabilityCategory.XSS,
                    cwe=info.default_cwe,
                    title="Untrusted-looking value reaches an HTML sink",
                    span=span,
                    detail=f"{name} renders a non-literal value without an observed escaping step.",
                    severity_hint="high",
                    strength=0.58,
                    reliability=0.78,
                    remediation=info.remediation,
                )
            )

    return results


def _hardcoded_secret(parsed: ParsedSource, node: Node) -> StructuralMatch | None:
    if node.type == "pair":
        return None
    target = None
    value = None
    if node.type == "assignment":
        target = node.child_by_field_name("left")
        value = node.child_by_field_name("right")
    elif node.type == "variable_declarator":
        target = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
    elif node.type == "assignment_expression":
        target = node.child_by_field_name("left")
        value = node.child_by_field_name("right")
    if target is None or value is None:
        return None
    name = _target_name(parsed, target)
    if not name or not _SENSITIVE_NAME.search(name):
        return None
    secret = _literal_text(parsed, value)
    if len(secret) < 8 or _looks_like_placeholder(secret):
        return None
    info = CATEGORY_INFO[VulnerabilityCategory.HARDCODED_SECRET]
    return StructuralMatch(
        rule_id="ast.hardcoded-secret",
        category=VulnerabilityCategory.HARDCODED_SECRET,
        cwe=info.default_cwe,
        title="Credential-like value is hardcoded in source",
        span=parsed.span_for_node(target),
        detail=(
            f"Variable {name!r} is assigned a non-placeholder string literal. "
            "The value is redacted from this record."
        ),
        severity_hint="high",
        strength=0.88,
        reliability=0.86,
        remediation=info.remediation,
        limitations=("A credential-looking name and literal can still be a test fixture.",),
    )


def _object_pair_match(parsed: ParsedSource, node: Node) -> StructuralMatch | None:
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None:
        return None
    name = _target_name(parsed, key)
    if name and _SENSITIVE_NAME.search(name):
        secret = _literal_text(parsed, value)
        if len(secret) >= 8 and not _looks_like_placeholder(secret):
            info = CATEGORY_INFO[VulnerabilityCategory.HARDCODED_SECRET]
            return StructuralMatch(
                rule_id="ast.hardcoded-secret",
                category=VulnerabilityCategory.HARDCODED_SECRET,
                cwe=info.default_cwe,
                title="Credential-like value is hardcoded in an object literal",
                span=parsed.span_for_node(key),
                detail=(
                    f"Property {name!r} has a non-placeholder string literal. "
                    "The value is redacted from this record."
                ),
                severity_hint="high",
                strength=0.86,
                reliability=0.84,
                remediation=info.remediation,
                limitations=("A credential-looking property can still be a test fixture.",),
            )
    if name and name.lower() == "rejectunauthorized" and _keyword_bool(parsed, value) is False:
        info = CATEGORY_INFO[VulnerabilityCategory.INSECURE_TLS]
        return StructuralMatch(
            rule_id="ast.insecure-tls-verification",
            category=VulnerabilityCategory.INSECURE_TLS,
            cwe=info.default_cwe,
            title="TLS certificate verification is disabled in an options object",
            span=parsed.span_for_node(key),
            detail="An options object sets rejectUnauthorized=false.",
            severity_hint="high",
            strength=0.86,
            reliability=0.9,
            remediation=info.remediation,
        )
    return None


def _xss_assignment(parsed: ParsedSource, node: Node) -> StructuralMatch | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or left.type != "member_expression":
        return None
    property_node = left.child_by_field_name("property")
    if property_node is None:
        return None
    property_name = _node_text(parsed, property_node).strip().lower()
    if property_name not in _XSS_PROPERTIES:
        return None
    if not _is_dynamic(parsed, right):
        return None
    info = CATEGORY_INFO[VulnerabilityCategory.XSS]
    return StructuralMatch(
        rule_id="ast.dynamic-html-assignment",
        category=VulnerabilityCategory.XSS,
        cwe=info.default_cwe,
        title=f"Non-literal value is assigned to {property_name}",
        span=parsed.span_for_node(node),
        detail=(
            f"{property_name} receives a non-literal value. AST evidence does not "
            "establish that the value is untrusted or unescaped."
        ),
        severity_hint="high",
        strength=0.55,
        reliability=0.8,
        remediation=info.remediation,
        limitations=("Escaping and trust-boundary behavior are not evaluated.",),
    )


def _tls_assignment(parsed: ParsedSource, node: Node) -> StructuralMatch | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    name = _target_name(parsed, left)
    if name and name.upper() == "NODE_TLS_REJECT_UNAUTHORIZED":
        value = _node_text(parsed, right).strip().strip("\"'")
        if value in {"0", "false", "False"}:
            info = CATEGORY_INFO[VulnerabilityCategory.INSECURE_TLS]
            return StructuralMatch(
                rule_id="ast.tls-verification-disabled",
                category=VulnerabilityCategory.INSECURE_TLS,
                cwe=info.default_cwe,
                title="Node.js TLS certificate verification is disabled",
                span=parsed.span_for_node(node),
                detail="NODE_TLS_REJECT_UNAUTHORIZED is set to a disabled value.",
                severity_hint="high",
                strength=0.9,
                reliability=0.9,
                remediation=info.remediation,
            )
    return None


def _keyword_arguments(parsed: ParsedSource, arguments: Node) -> dict[str, Node]:
    result: dict[str, Node] = {}
    for child in arguments.named_children:
        if child.type == "keyword_argument":
            name = child.child_by_field_name("name")
            value = child.child_by_field_name("value")
            if name is not None and value is not None:
                result[_node_text(parsed, name).strip().lower()] = value
        elif child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is not None and value is not None:
                result[_target_name(parsed, key).lower()] = value
    return result


def _keyword_bool(parsed: ParsedSource, node: Node | None) -> bool | None:
    if node is None:
        return None
    value = _node_text(parsed, node).strip().lower()
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    return None


def _target_name(parsed: ParsedSource, node: Node) -> str:
    if node.type in {"identifier", "property_identifier", "string"}:
        return _node_text(parsed, node).strip().strip("\"'")
    name = _dotted_name(parsed, node)
    return name.strip("\"'")


def _dotted_name(parsed: ParsedSource, node: Node) -> str:
    if node.type in {"identifier", "property_identifier", "type_identifier"}:
        return _node_text(parsed, node).strip()
    if node.type in {"attribute", "member_expression"}:
        base = node.child_by_field_name("object")
        attribute = node.child_by_field_name("attribute") or node.child_by_field_name("property")
        if base is None or attribute is None:
            return ""
        left = _dotted_name(parsed, base)
        right = _dotted_name(parsed, attribute)
        if left and right:
            return f"{left}.{right}"
    if node.type == "subscript":
        value = node.child_by_field_name("value")
        return _dotted_name(parsed, value) if value is not None else ""
    if node.type in {"string", "template_string"}:
        return _literal_text(parsed, node)
    return ""


def _node_text(parsed: ParsedSource, node: Node) -> str:
    return parsed.text_for_node(node)


def _literal_text(parsed: ParsedSource, node: Node) -> str:
    text = _node_text(parsed, node).strip()
    if node.type not in {"string", "template_string"}:
        return text
    for index, char in enumerate(text):
        if char in {"'", '"', "`"}:
            body = text[index + 1 :]
            if body.endswith(char):
                body = body[:-1]
            return body
    return text


def _is_literal(parsed: ParsedSource, node: Node) -> bool:
    if node.type in {"string", "template_string"}:
        return not _is_dynamic(parsed, node)
    if node.type in {"integer", "float", "true", "false", "none", "null", "boolean"}:
        return True
    if node.type in {"list", "tuple", "array", "dictionary", "object"}:
        return all(_is_literal(parsed, child) for child in node.named_children)
    return False


def _is_dynamic(parsed: ParsedSource, node: Node) -> bool:
    if node.type in {"string", "template_string"}:
        text = _node_text(parsed, node)
        if node.type == "template_string" and "${" in text:
            return True
        if any(child.type in {"interpolation", "template_substitution"} for child in node.children):
            return True
        stripped = text.lstrip()
        prefix = stripped[:3].lower()
        return "f" in prefix and prefix[:1] == "f"
    if node.type in {"binary_operator", "binary_expression", "concatenated_string"}:
        return True
    if node.type in _CALL_TYPES:
        return True
    if node.type in {"identifier", "attribute", "member_expression", "subscript", "call"}:
        return True
    return not _is_literal(parsed, node)


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if len(lowered) < 8:
        return True
    if lowered in _SECRET_PLACEHOLDERS:
        return True
    return any(token in lowered for token in _SECRET_PLACEHOLDER_TOKENS)


def _deduplicate(matches: list[StructuralMatch]) -> list[StructuralMatch]:
    seen: set[tuple[str, int, int, int, int]] = set()
    result: list[StructuralMatch] = []
    for match in matches:
        key = (
            match.rule_id,
            match.span.start.line,
            match.span.start.character,
            match.span.end.line,
            match.span.end.character,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(match)
    return result


__all__ = ["StructuralMatch", "analyze_ast"]
