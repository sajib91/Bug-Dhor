"""Deterministic, context-specific repair recommendation strategies.

These strategies read source text and existing analysis evidence only. They do
not execute source code, do not modify files, and never claim that a proposal
is functionally or security-correct without verification.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ...languages import detect_language
from ..evidence import _finding_location, _matching_taint, finding_id_for
from ..schema import ConfidenceLevel, ExplanationLocation, FindingExplanation
from .recommendation import (
    RepairRecommendation,
    RepairStatus,
    RepairTarget,
)

DEFAULT_TESTS: tuple[str, ...] = (
    "Reparse the modified source.",
    "Rerun detection and taint analysis for the original finding.",
    "Run relevant unit or integration tests for the affected call site.",
    "Review the final diff and source context manually.",
)

_SQL_MARKER_PREFIX = "__BUGDHOR_SQL_PARAM_"
_COMMAND_MARKER_PREFIX = "__BUGDHOR_DYN_"
_SHELL_METACHARACTERS = frozenset(";&|><`$*?")

_PYTHON_COMMAND_SINK_RULES = frozenset(
    {"PY-SNK-003", "PY-SNK-004", "PY-SNK-005", "PY-SNK-006"}
)
_JAVASCRIPT_HTML_SINK_RULES = frozenset({"JS-SNK-003", "JS-SNK-004"})
_JAVA_SQL_SINK_RULES = frozenset({"JAVA-SNK-003", "JAVA-SNK-004"})


@dataclass(frozen=True)
class _Context:
    finding: dict[str, Any]
    analysis: dict[str, Any]
    explanation: FindingExplanation | None
    finding_id: str
    language: str
    location: ExplanationLocation
    file: str
    sink_rule: str | None
    source_code: str
    snippet: str | None
    indent: str


def _as_dict(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return dict(value)


def _normalize_explanation(value: Any) -> FindingExplanation | None:
    if value is None:
        return None
    if isinstance(value, FindingExplanation):
        return value
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, Mapping):
        return FindingExplanation.from_dict(value)
    raise TypeError("explanation must be a FindingExplanation or mapping")


def _extract_snippet(
    source_code: str, location: ExplanationLocation
) -> tuple[str | None, str]:
    if not source_code:
        return None, ""
    lines = source_code.splitlines(keepends=True)
    if not lines or location.start_line < 1 or location.end_line > len(lines):
        return None, ""
    if location.end_line < location.start_line:
        return None, ""
    if location.start_column < 1 or location.end_column < location.start_column:
        return None, ""

    start_line = lines[location.start_line - 1].encode("utf-8")
    end_line = lines[location.end_line - 1].encode("utf-8")
    start_index = location.start_column - 1
    end_index = location.end_column - 1
    if start_index > len(start_line) or end_index > len(end_line):
        return None, ""

    if location.start_line == location.end_line:
        raw = start_line[start_index:end_index]
    else:
        chunks = [start_line[start_index:]]
        chunks.extend(
            lines[index].encode("utf-8")
            for index in range(location.start_line, location.end_line - 1)
        )
        chunks.append(end_line[:end_index])
        raw = b"".join(chunks)

    try:
        snippet = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, ""

    prefix = start_line[:start_index]
    indent = prefix.decode("utf-8") if prefix.strip() == b"" else ""
    return snippet, indent


def _resolve_sink_rule(
    finding: dict[str, Any],
    analysis: dict[str, Any],
    location: ExplanationLocation,
    explanation: FindingExplanation | None,
) -> str | None:
    if str(finding.get("rule_id", "")).endswith("-TAINT001"):
        raw, _, _ = _matching_taint(
            analysis,
            finding,
            (
                (location.start_line, location.start_column),
                (location.end_line, location.end_column),
            ),
        )
        if raw is not None and raw.get("sink_rule"):
            return str(raw["sink_rule"])
    if explanation is not None and isinstance(explanation.trigger, Mapping):
        trigger = explanation.trigger
        if trigger.get("kind") == "taint_sink" and trigger.get("text"):
            return str(trigger["text"])
    return None


def _build_context(
    finding: Any,
    analysis: Any,
    explanation: Any,
    source_code: Any,
    file: Any,
) -> _Context:
    finding_dict = _as_dict(finding, "finding")
    analysis_dict = _as_dict(analysis, "analysis")
    if not isinstance(source_code, str):
        raise TypeError("source_code must be a string")
    if file is not None and not isinstance(file, str):
        raise TypeError("file must be a string or None")

    parsed_explanation = _normalize_explanation(explanation)
    location = _finding_location(finding_dict)
    target_file = file or str(finding_dict.get("file") or location.file or "<source>")
    language = str(
        finding_dict.get("language")
        or analysis_dict.get("language")
        or (parsed_explanation.language if parsed_explanation else "")
        or detect_language(target_file)
        or detect_language(str(finding_dict.get("file", "")))
        or "unknown"
    )
    snippet, indent = _extract_snippet(source_code, location)
    finding_id = str(
        finding_dict.get("finding_id") or finding_id_for(finding_dict)
    )
    return _Context(
        finding=finding_dict,
        analysis=analysis_dict,
        explanation=parsed_explanation,
        finding_id=finding_id,
        language=language,
        location=location,
        file=target_file,
        sink_rule=_resolve_sink_rule(
            finding_dict, analysis_dict, location, parsed_explanation
        ),
        source_code=source_code,
        snippet=snippet,
        indent=indent,
    )


def _target(context: _Context) -> RepairTarget:
    return RepairTarget(
        file=context.file,
        language=context.language,
        start_line=context.location.start_line,
        start_column=context.location.start_column,
        end_line=context.location.end_line,
        end_column=context.location.end_column,
    )


def _tests(*specific: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*specific, *DEFAULT_TESTS)))


def _unsupported(
    context: _Context,
    reason: str,
    *,
    original_code: str | None = None,
) -> RepairRecommendation:
    return RepairRecommendation(
        finding_id=context.finding_id,
        rule_id=str(context.finding.get("rule_id", "unknown")),
        strategy="unsupported",
        status=RepairStatus.UNSUPPORTED,
        original_code=context.snippet if original_code is None else original_code,
        proposed_code=None,
        target=_target(context),
        explanation=reason,
        security_rationale=(
            "No security control was applied because the repair context was "
            "not confidently recognized."
        ),
        functional_considerations="No source change was proposed.",
        confidence=ConfidenceLevel.LOW,
        required_tests=("Review the finding and surrounding source manually.",),
        known_limitations=(
            reason,
            "No deterministic repair was proposed for this finding.",
        ),
        requires_approval=True,
    )


def _ready(
    context: _Context,
    *,
    strategy: str,
    proposed_code: str,
    explanation: str,
    security_rationale: str,
    functional_considerations: str,
    confidence: ConfidenceLevel,
    required_tests: tuple[str, ...],
    known_limitations: tuple[str, ...],
    status: RepairStatus = RepairStatus.READY,
) -> RepairRecommendation:
    if context.snippet is None:
        return _unsupported(context, "The exact source span was unavailable.")
    if context.snippet == proposed_code:
        return _unsupported(context, "The proposed code did not change the source.")
    return RepairRecommendation(
        finding_id=context.finding_id,
        rule_id=str(context.finding.get("rule_id", "unknown")),
        strategy=strategy,
        status=status,
        original_code=context.snippet,
        proposed_code=proposed_code,
        target=_target(context),
        explanation=explanation,
        security_rationale=security_rationale,
        functional_considerations=functional_considerations,
        confidence=confidence,
        required_tests=_tests(*required_tests),
        known_limitations=tuple(dict.fromkeys(known_limitations)),
        requires_approval=True,
    )


def _matches(context: _Context, sink_rules: set[str], source_pattern: str) -> bool:
    if context.sink_rule in sink_rules:
        return True
    return bool(re.search(source_pattern, context.snippet or ""))


def _span(location: ExplanationLocation) -> tuple[tuple[int, int], tuple[int, int]]:
    return (
        (location.start_line, location.start_column),
        (location.end_line, location.end_column),
    )


def _python_call(
    context: _Context,
) -> tuple[ast.Call | None, str | None]:
    try:
        tree = ast.parse(context.source_code)
    except (SyntaxError, ValueError) as error:
        return None, f"Python source could not be parsed: {error.msg}"
    target = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            node.lineno == context.location.start_line
            and node.col_offset == context.location.start_column - 1
        ):
            target = node
            break
    if target is None:
        return None, "No Python call node was found at the finding span."
    segment = ast.get_source_segment(context.source_code, target)
    if segment != context.snippet:
        return None, "The Python call span did not match the exact source snippet."
    return target, None


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if not isinstance(func, ast.Attribute):
        return None
    parts: list[str] = []
    current: Any = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _flatten_add(node: ast.expr) -> list[ast.expr] | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _flatten_add(node.left)
        right = _flatten_add(node.right)
        if left is None or right is None:
            return None
        return [*left, *right]
    return [node]


def _marker(index: int, prefix: str) -> str:
    return f"{prefix}{index}__"


def _replace_markers(text: str, prefix: str) -> str:
    pattern = re.compile(rf"(['\"]){re.escape(prefix)}\d+__\1")
    replaced = pattern.sub("?", text)
    return re.sub(rf"{re.escape(prefix)}\d+__", "?", replaced)


def _python_parameter_expression(node: ast.expr) -> str:
    return ast.unparse(node)


def _python_argument_expression(node: ast.expr) -> str:
    text = _python_parameter_expression(node)
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Constant)):
        return text
    return f"({text})"


def _python_sql_template(
    expression: ast.expr,
) -> tuple[str, list[str]] | None:
    if isinstance(expression, ast.JoinedStr):
        text = ""
        parameters: list[str] = []
        for index, value in enumerate(expression.values):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text += value.value
            elif (
                isinstance(value, ast.FormattedValue)
                and value.conversion == -1
                and value.format_spec is None
            ):
                text += _marker(index, _SQL_MARKER_PREFIX)
                parameters.append(_python_parameter_expression(value.value))
            else:
                return None
        return _replace_markers(text, _SQL_MARKER_PREFIX), parameters

    if (
        isinstance(expression, ast.BinOp)
        and isinstance(expression.op, ast.Mod)
        and isinstance(expression.left, ast.Constant)
        and isinstance(expression.left.value, str)
        and isinstance(expression.right, (ast.Tuple, ast.List))
    ):
        placeholders = re.findall(
            r"%(?:[-+ #0]*\d*(?:\.\d+)?)[diouxXeEfFgGcrs]",
            expression.left.value,
        )
        args = list(expression.right.elts)
        if not placeholders or len(placeholders) != len(args):
            return None
        template = re.sub(
            r"%(?:[-+ #0]*\d*(?:\.\d+)?)[diouxXeEfFgGcrs]",
            "?",
            expression.left.value,
        )
        return template, [_python_parameter_expression(item) for item in args]

    if (
        isinstance(expression, ast.Call)
        and _call_name(expression) == "str.format"
        and isinstance(expression.func, ast.Attribute)
        and isinstance(expression.func.value, ast.Constant)
        and isinstance(expression.func.value.value, str)
        and not expression.keywords
    ):
        text = expression.func.value.value
        if "{{" in text or "}}" in text:
            return None
        placeholders = re.findall(r"\{[^{}]*\}", text)
        if not placeholders or len(placeholders) != len(expression.args):
            return None
        template = re.sub(r"\{[^{}]*\}", "?", text)
        return template, [
            _python_parameter_expression(item) for item in expression.args
        ]

    parts = _flatten_add(expression)
    if parts is None:
        return None
    text = ""
    parameters: list[str] = []
    for index, part in enumerate(parts):
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            text += part.value
        elif isinstance(part, ast.Constant):
            return None
        else:
            text += _marker(index, _SQL_MARKER_PREFIX)
            parameters.append(_python_parameter_expression(part))
    if not parameters:
        return None
    return _replace_markers(text, _SQL_MARKER_PREFIX), parameters


def _python_sql(context: _Context) -> RepairRecommendation:
    call, error = _python_call(context)
    if error is not None or call is None:
        return _unsupported(context, error or "No Python call node was available.")
    if _call_name(call) != "cursor.execute":
        return _unsupported(
            context,
            "Only cursor.execute SQL sinks are supported by the Python "
            "parameterization strategy.",
        )
    if len(call.args) != 1 or call.keywords:
        return _unsupported(
            context,
            "The SQL call must have exactly one positional statement argument.",
        )

    template_result = _python_sql_template(call.args[0])
    if template_result is None:
        return _unsupported(
            context,
            "The SQL statement structure was not confidently recognizable.",
        )
    template, parameters = template_result
    if not parameters or template.count("?") != len(parameters):
        return _unsupported(
            context,
            "The SQL placeholder count did not match the bound values.",
        )

    param_tuple = ", ".join(parameters)
    if len(parameters) == 1:
        param_tuple = f"{param_tuple},"
    proposed = f"cursor.execute({template!r}, ({param_tuple}))"

    evidence = (
        f"taint sink rule {context.sink_rule}"
        if context.sink_rule
        else "the cursor.execute call in the source"
    )
    return _ready(
        context,
        strategy="python_sql_parameterization",
        proposed_code=proposed,
        explanation=(
            f"Based on {evidence}, the statement text was separated from "
            "the tracked values and each value was converted to a bound parameter."
        ),
        security_rationale=(
            "Bound parameters keep untrusted values out of SQL statement text, "
            "preventing them from changing query structure."
        ),
        functional_considerations=(
            "Verify the database driver's placeholder style and parameter "
            "order; the recommendation assumes positional parameters."
        ),
        confidence=ConfidenceLevel.MEDIUM,
        required_tests=(
            "Verify identical query results for representative and edge-case inputs.",
            "Verify correct parameter binding with the configured database driver.",
        ),
        known_limitations=(
            "Database driver semantics and identifier quoting are not modeled.",
            "The proposal does not change dynamic table or column identifiers.",
            (
                "The current syntax-only taint engine may still report this "
                "finding because it does not model parameter binding."
            ),
        ),
    )


def _has_shell_metacharacters(text: str) -> bool:
    return any(character in _SHELL_METACHARACTERS for character in text)


def _python_argv(expression: ast.expr) -> list[str] | None:
    parts = _flatten_add(expression)
    if parts is None:
        return None
    command_text = ""
    dynamic: dict[str, str] = {}
    for index, part in enumerate(parts):
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            command_text += part.value
        elif isinstance(part, ast.Constant):
            return None
        else:
            marker = _marker(index, _COMMAND_MARKER_PREFIX)
            command_text += marker
            dynamic[marker] = _python_argument_expression(part)
    if not command_text or _has_shell_metacharacters(command_text):
        return None
    try:
        tokens = shlex.split(command_text)
    except ValueError:
        return None
    if not tokens:
        return None

    marker_pattern = re.compile(rf"{re.escape(_COMMAND_MARKER_PREFIX)}\d+__")
    argv: list[str] = []
    for token in tokens:
        matches = list(marker_pattern.finditer(token))
        if not matches:
            argv.append(repr(token))
            continue
        if token in dynamic:
            argv.append(dynamic[token])
            continue
        pieces: list[str] = []
        cursor = 0
        for match in matches:
            if match.start() > cursor:
                pieces.append(repr(token[cursor : match.start()]))
            pieces.append(dynamic[match.group()])
            cursor = match.end()
        if cursor < len(token):
            pieces.append(repr(token[cursor:]))
        argv.append("(" + " + ".join(pieces) + ")")
    return argv


def _subprocess_alias(source_code: str) -> str | None:
    for line in source_code.splitlines():
        alias_match = re.match(
            r"^\s*import\s+subprocess\s+as\s+([A-Za-z_]\w*)\b", line
        )
        if alias_match:
            return alias_match.group(1)
        if re.match(r"^\s*import\s+subprocess\b", line):
            return "subprocess"
    return None


def _python_command(context: _Context) -> RepairRecommendation:
    call, error = _python_call(context)
    if error is not None or call is None:
        return _unsupported(context, error or "No Python call node was available.")
    name = _call_name(call)
    if name is None:
        return _unsupported(context, "The Python call target was not recognizable.")

    alias = _subprocess_alias(context.source_code)
    supported_names = {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}
    if alias:
        supported_names.update(
            {f"{alias}.run", f"{alias}.call", f"{alias}.Popen"}
        )
    if name not in supported_names or not call.args:
        return _unsupported(
            context,
            "Only os.system and subprocess.run/call/Popen string commands "
            "are supported by the argument-list strategy.",
        )

    argv = _python_argv(call.args[0])
    if argv is None:
        return _unsupported(
            context,
            "The command string was not confidently convertible to an argument list.",
        )

    if name == "os.system":
        if len(call.args) != 1 or call.keywords:
            return _unsupported(
                context, "os.system command examples must have one argument."
            )
        target_name = f"{alias or 'subprocess'}.call"
        other_kwargs: list[str] = []
    else:
        other_kwargs = []
        for keyword in call.keywords:
            if keyword.arg is None:
                return _unsupported(
                    context, "Star keyword arguments are not supported."
                )
            if keyword.arg == "shell":
                if (
                    not isinstance(keyword.value, ast.Constant)
                    or not isinstance(keyword.value.value, bool)
                ):
                    return _unsupported(
                        context,
                        "The shell option must be a literal boolean to transform safely.",
                    )
                continue
            other_kwargs.append(
                f"{keyword.arg}={_python_parameter_expression(keyword.value)}"
            )
        target_name = name

    arguments = ", ".join(argv)
    if other_kwargs:
        arguments = f"{arguments}, {', '.join(other_kwargs)}"
    proposed = f"{target_name}([{arguments}])"

    import_issue = name == "os.system" and alias is None
    status = RepairStatus.NEEDS_REVIEW if import_issue else RepairStatus.READY
    limitations = [
        (
            "Shell features such as pipes, redirection, globbing, and command "
            "chaining are not preserved."
        ),
        "Argument types and process return values must be reviewed.",
        (
            "The current syntax-only taint engine may still report this "
            "finding because it tracks values passed to process APIs."
        ),
    ]
    tests = (
        "Verify command arguments and output for representative inputs.",
        "Verify that no shell-only behavior is required at this call site.",
    )
    if import_issue:
        limitations.append(
            "No subprocess import was found; the proposed code needs an "
            "explicit import before it can be applied."
        )
        tests = (
            "Add or verify the subprocess import before applying this proposal.",
            *tests,
        )

    evidence = (
        f"taint sink rule {context.sink_rule}"
        if context.sink_rule
        else f"the {name} call in the source"
    )
    return _ready(
        context,
        strategy="python_process_argument_list",
        proposed_code=proposed,
        explanation=(
            f"Based on {evidence}, the shell command string was converted "
            "into an argument vector for a direct process API."
        ),
        security_rationale=(
            "Passing an argument list avoids shell parsing, so untrusted data "
            "cannot introduce additional commands or operators."
        ),
        functional_considerations=(
            "Shell metacharacter behavior is intentionally not preserved. "
            "Confirm process return values, arguments, and output handling."
        ),
        confidence=ConfidenceLevel.MEDIUM if not import_issue else ConfidenceLevel.LOW,
        required_tests=tests,
        known_limitations=tuple(limitations),
        status=status,
    )


def _javascript_dom(context: _Context) -> RepairRecommendation:
    pattern = re.compile(
        r"^(?P<target>.+?)\.(?P<property>innerHTML|outerHTML)"
        r"(?P<equals>\s*=\s*)(?P<value>.+?)(?P<semicolon>\s*;?\s*)$",
        re.DOTALL,
    )
    match = pattern.match(context.snippet or "")
    if match is None:
        return _unsupported(
            context,
            "The DOM HTML assignment was not confidently recognizable.",
        )
    value = match.group("value").strip()
    context_specific = (
        "DOMPurify.sanitize",
        "sanitizeHtml",
        "escapeHtml",
        "encodeURIComponent",
        "htmlspecialchars",
    )
    if any(token in value for token in context_specific):
        return _unsupported(
            context,
            "The HTML value uses a sanitizer or encoder whose output context "
            "must be preserved; textContent was not recommended.",
        )
    if re.search(r"<[A-Za-z/!]", value) or "innerHTML" in value or "outerHTML" in value:
        return _unsupported(
            context,
            "The assigned value appears to contain markup or nested HTML; "
            "textContent was not recommended.",
        )

    proposed = (
        f"{match.group('target')}.textContent{match.group('equals')}"
        f"{match.group('value')}{match.group('semicolon')}"
    )
    limitations = [
        "Whether markup is intentionally rendered cannot be proven statically.",
        (
            "DOM event handlers and layout behavior may change when markup is no "
            "longer parsed."
        ),
    ]
    if match.group("property") == "outerHTML":
        limitations.append(
            "outerHTML replaces the element itself; textContent changes only "
            "its child text."
        )
    evidence = (
        f"taint sink rule {context.sink_rule}"
        if context.sink_rule
        else "the HTML property assignment in the source"
    )
    return _ready(
        context,
        strategy="javascript_html_property_to_text_content",
        proposed_code=proposed,
        explanation=(
            f"Based on {evidence}, the HTML property assignment was converted "
            "to a text-only DOM assignment."
        ),
        security_rationale=(
            "textContent inserts the value as text and does not parse it as "
            "HTML markup."
        ),
        functional_considerations=(
            "Use this proposal only when the value must be displayed as plain "
            "text; intentional markup will no longer render."
        ),
        confidence=ConfidenceLevel.MEDIUM,
        required_tests=(
            "Verify expected text rendering and UI layout.",
            "Verify that no intentional HTML markup is required at this site.",
        ),
        known_limitations=tuple(limitations),
    )


def _split_top_level(expression: str, separator: str) -> list[str] | None:
    parts: list[str] = []
    buffer: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for character in expression:
        if quote is not None:
            buffer.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            buffer.append(character)
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
            if depth < 0:
                return None
        if character == separator and depth == 0:
            parts.append("".join(buffer).strip())
            buffer = []
            continue
        buffer.append(character)
    if quote is not None or depth != 0:
        return None
    parts.append("".join(buffer).strip())
    return parts


def _java_string_value(part: str) -> str | None:
    if len(part) < 2 or part[0] != '"' or part[-1] != '"':
        return None
    try:
        value = json.loads(part)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, str) else None


def _java_sql_template(argument: str) -> tuple[str, list[str]] | None:
    parts = _split_top_level(argument, "+")
    if parts is None or not parts:
        return None
    text = ""
    parameters: list[str] = []
    for index, part in enumerate(parts):
        literal = _java_string_value(part)
        if literal is not None:
            text += literal
        elif not part:
            return None
        else:
            text += _marker(index, _SQL_MARKER_PREFIX)
            parameters.append(part)
    if not parameters:
        return None
    template = _replace_markers(text, _SQL_MARKER_PREFIX)
    if template.count("?") != len(parameters):
        return None
    return template, parameters


def _unique_identifier(source_code: str, base: str, digest: str) -> str:
    candidate = f"__bugdhor{base}_{digest}"
    while candidate in source_code:
        candidate += "_x"
    return candidate


def _java_sql(context: _Context) -> RepairRecommendation:
    pattern = re.compile(
        r"^\s*(?P<receiver>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
        r"\s*\.\s*(?P<method>executeQuery|executeUpdate)\s*"
        r"\((?P<arguments>.*)\)\s*;?\s*$",
        re.DOTALL,
    )
    match = pattern.match(context.snippet or "")
    if match is None:
        return _unsupported(
            context,
            "The Java SQL execution statement was not confidently recognizable.",
        )
    arguments = _split_top_level(match.group("arguments"), ",")
    if arguments is None or len(arguments) != 1 or not arguments[0]:
        return _unsupported(
            context,
            "The Java SQL execution must have exactly one statement argument.",
        )
    template_result = _java_sql_template(arguments[0])
    if template_result is None:
        return _unsupported(
            context,
            "The Java SQL statement structure was not confidently recognizable.",
        )
    template, parameters = template_result

    digest = re.sub(r"[^A-Za-z0-9]", "", context.finding_id)[-8:] or "repair"
    query_name = _unique_identifier(context.source_code, "Query", digest)
    statement_name = _unique_identifier(context.source_code, "Statement", digest)
    receiver = match.group("receiver")
    if re.fullmatch(r"(?i)(conn|connection|con)", receiver):
        connection_expression = receiver
    else:
        connection_expression = f"{receiver}.getConnection()"
    method = match.group("method")

    lines = [
        f"String {query_name} = {json.dumps(template, ensure_ascii=False)};",
        (
            f"java.sql.PreparedStatement {statement_name} = "
            f"{connection_expression}.prepareStatement({query_name});"
        ),
    ]
    for index, parameter in enumerate(parameters, start=1):
        lines.append(f"{statement_name}.setString({index}, {parameter});")
    lines.append(f"{statement_name}.{method}();")
    proposed = ("\n" + context.indent).join(lines)

    evidence = (
        f"taint sink rule {context.sink_rule}"
        if context.sink_rule
        else f"the {method} call in the source"
    )
    return _ready(
        context,
        strategy="java_prepared_statement",
        proposed_code=proposed,
        explanation=(
            f"Based on {evidence}, the concatenated SQL statement was "
            "converted into a prepared statement with bound parameters."
        ),
        security_rationale=(
            "Prepared statement parameters are transmitted separately from "
            "SQL text, preventing tracked values from changing query structure."
        ),
        functional_considerations=(
            "Verify the JDBC driver's placeholder support, choose type-specific "
            "setter methods, and review resource lifetime and exception handling."
        ),
        confidence=ConfidenceLevel.MEDIUM,
        required_tests=(
            "Verify identical query results with representative and edge-case inputs.",
            "Verify correct JDBC parameter indexes and setter types.",
        ),
        known_limitations=(
            "setString is used for all values because types are not modeled.",
            "Dynamic table or column identifiers are not parameterized.",
            "Resource cleanup and transaction behavior are not changed.",
        ),
    )


def recommend_repair(
    finding: Any,
    analysis: Any = None,
    explanation: Any = None,
    source_code: str = "",
    file: str | None = None,
) -> RepairRecommendation:
    """Recommend a deterministic repair without modifying any source file."""

    context = _build_context(
        finding, analysis, explanation, source_code, file
    )
    if context.snippet is None:
        return _unsupported(
            context,
            "The exact one-based source span could not be extracted from the "
            "supplied source code.",
        )

    if context.language == "python":
        if _matches(context, {"PY-SNK-007"}, r"\.execute\s*\("):
            return _python_sql(context)
        if _matches(
            context,
            _PYTHON_COMMAND_SINK_RULES,
            r"\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen)\s*\(",
        ):
            return _python_command(context)
    elif context.language == "javascript":
        if _matches(context, _JAVASCRIPT_HTML_SINK_RULES, r"innerHTML|outerHTML"):
            return _javascript_dom(context)
    elif context.language == "java" and _matches(
        context, _JAVA_SQL_SINK_RULES, r"\bexecuteQuery\s*\(|\bexecuteUpdate\s*\("
    ):
        return _java_sql(context)

    return _unsupported(
        context,
        "No deterministic repair strategy applies to this rule and source context.",
    )


__all__ = ["recommend_repair"]
