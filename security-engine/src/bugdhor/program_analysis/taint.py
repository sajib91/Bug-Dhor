"""Explicit, configuration-driven taint analysis for Python and JavaScript.

The taint layer reuses the CFG and DFG products for one file. It adds value-flow
edges for expressions, direct same-file interprocedural call/parameter/return
edges, and explicit source, sanitizer, validator, propagator, and sink rules.
Every reported item is a *potential* source-to-sink flow; no runtime
exploitability, authentication, framework routing, or path feasibility is
claimed.

Known approximations are documented in ``docs/program-analysis.md`` and tracked
by the ``LIM-PA-*`` limitation identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import networkx as nx
from tree_sitter import Node

from bugdhor.parsing.models import SourceSpan, SupportedLanguage
from bugdhor.parsing.parser import ParsedSource, parse_source
from bugdhor.program_analysis.analysis import ProgramAnalysis, analyze_parsed
from bugdhor.program_analysis.cfg import (
    ControlFlowAnalysis,
    ControlFlowGraph,
    _collect_function_nodes,
)
from bugdhor.program_analysis.dfg import DataFlowAnalysis, DataFlowGraph
from bugdhor.program_analysis.models import (
    DFGNode,
    DFGNodeKind,
    span_to_dict,
)


class TaintKind(StrEnum):
    """The vulnerability class a source-to-sink flow is relevant to."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"

    @property
    def title(self) -> str:
        return {
            TaintKind.SQL_INJECTION: "SQL injection",
            TaintKind.COMMAND_INJECTION: "Command injection",
            TaintKind.XSS: "Cross-site scripting",
            TaintKind.PATH_TRAVERSAL: "Path traversal",
            TaintKind.UNSAFE_DESERIALIZATION: "Unsafe deserialization",
        }[self]


_ALL_KINDS = frozenset(TaintKind)


def _kind_order(kind: TaintKind) -> int:
    order = {
        TaintKind.SQL_INJECTION: 0,
        TaintKind.COMMAND_INJECTION: 1,
        TaintKind.XSS: 2,
        TaintKind.PATH_TRAVERSAL: 3,
        TaintKind.UNSAFE_DESERIALIZATION: 4,
    }
    return order[kind]


def _require_name(value: str) -> str:
    name = value.strip()
    if not name:
        raise ValueError("rule name must not be empty")
    return name


def _require_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    result = tuple(pattern.strip() for pattern in patterns if pattern.strip())
    if not result:
        raise ValueError("at least one non-empty pattern is required")
    return result


def _kinds(values: Iterable[TaintKind | str]) -> frozenset[TaintKind]:
    result = frozenset(TaintKind(value) for value in values)
    if not result:
        raise ValueError("at least one taint kind is required")
    return result


class NameMatch(StrEnum):
    """How a configured name matches source text.

    ``EXACT`` requires the complete normalized text. ``SUFFIX`` also accepts a
    dotted suffix, so ``execute`` matches ``cursor.execute``. ``PREFIX`` accepts
    a dotted or indexed continuation, so ``request.args`` matches both
    ``request.args`` and ``request.args["q"]``.
    """

    EXACT = "exact"
    SUFFIX = "suffix"
    PREFIX = "prefix"


class SiteRole(StrEnum):
    """The role of one matched taint site."""

    SOURCE = "source"
    SANITIZER = "sanitizer"
    VALIDATOR = "validator"
    SINK = "sink"


class TaintNodeKind(StrEnum):
    """The kind of value represented by a taint graph node."""

    PARAMETER = "parameter"
    DEFINITION = "definition"
    USE = "use"
    CALL = "call"
    RETURN = "return"
    RAISE = "raise"
    EXPRESSION = "expression"


class TaintEdgeKind(StrEnum):
    """Why taint can move between two values."""

    DEF_USE = "def_use"
    CLOSURE = "closure"
    VALUE = "value"
    ARGUMENT = "argument"
    RECEIVER = "receiver"
    PARAMETER = "parameter"
    RETURN = "return"
    INTERPROCEDURAL_CALL = "interprocedural_call"
    PROPAGATOR = "propagator"


class TaintConfidence(StrEnum):
    """Analysis confidence, not exploitability or probability."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SinkTarget(StrEnum):
    """Where a sink consumes its value."""

    CALL_ARGUMENT = "call_argument"
    ATTRIBUTE_ASSIGNMENT = "attribute_assignment"


class SanitizerCategory(StrEnum):
    """Whether a configured neutralizing call sanitizes or validates."""

    SANITIZER = "sanitizer"
    VALIDATOR = "validator"


class PropagatorMode(StrEnum):
    """Which call inputs a configured propagator carries to its result."""

    ARGUMENTS = "arguments"
    RECEIVER = "receiver"
    BOTH = "both"


@dataclass(frozen=True, slots=True)
class SourceRule:
    """One explicit source of untrusted input."""

    name: str
    patterns: Sequence[str]
    kinds: frozenset[TaintKind] | Sequence[TaintKind | str] = _ALL_KINDS
    match: NameMatch | str = NameMatch.PREFIX
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_name(self.name))
        object.__setattr__(self, "patterns", _require_patterns(self.patterns))
        object.__setattr__(self, "kinds", _kinds(self.kinds))
        object.__setattr__(self, "match", NameMatch(self.match))
        object.__setattr__(self, "description", self.description.strip())

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "patterns": list(self.patterns),
            "kinds": [kind.value for kind in sorted(self.kinds, key=_kind_order)],
            "match": self.match.value,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class SanitizerRule:
    """One sanitizer or validator call.

    A validator is identified in the result but does not clear taint by itself.
    Use ``SanitizerRule`` with ``category=SANITIZER`` when a validator returns a
    value that is safe for a vulnerability class.
    """

    name: str
    patterns: Sequence[str]
    kinds: frozenset[TaintKind] | Sequence[TaintKind | str] = _ALL_KINDS
    match: NameMatch | str = NameMatch.SUFFIX
    category: SanitizerCategory | str = SanitizerCategory.SANITIZER
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_name(self.name))
        object.__setattr__(self, "patterns", _require_patterns(self.patterns))
        object.__setattr__(self, "kinds", _kinds(self.kinds))
        object.__setattr__(self, "match", NameMatch(self.match))
        object.__setattr__(self, "category", SanitizerCategory(self.category))
        object.__setattr__(self, "description", self.description.strip())

    @property
    def sanitizes(self) -> bool:
        return self.category is SanitizerCategory.SANITIZER

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "patterns": list(self.patterns),
            "kinds": [kind.value for kind in sorted(self.kinds, key=_kind_order)],
            "match": self.match.value,
            "category": self.category.value,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class PropagatorRule:
    """An unresolved call that carries taint from its inputs to its result."""

    name: str
    patterns: Sequence[str]
    mode: PropagatorMode | str = PropagatorMode.BOTH
    kinds: frozenset[TaintKind] | Sequence[TaintKind | str] = _ALL_KINDS
    match: NameMatch | str = NameMatch.SUFFIX
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_name(self.name))
        object.__setattr__(self, "patterns", _require_patterns(self.patterns))
        object.__setattr__(self, "mode", PropagatorMode(self.mode))
        object.__setattr__(self, "kinds", _kinds(self.kinds))
        object.__setattr__(self, "match", NameMatch(self.match))
        object.__setattr__(self, "description", self.description.strip())

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "patterns": list(self.patterns),
            "mode": self.mode.value,
            "kinds": [kind.value for kind in sorted(self.kinds, key=_kind_order)],
            "match": self.match.value,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class SinkRule:
    """One explicit sensitive sink."""

    name: str
    kind: TaintKind | str
    patterns: Sequence[str]
    argument: int | str = 0
    target: SinkTarget | str = SinkTarget.CALL_ARGUMENT
    match: NameMatch | str = NameMatch.SUFFIX
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_name(self.name))
        object.__setattr__(self, "kind", TaintKind(self.kind))
        object.__setattr__(self, "patterns", _require_patterns(self.patterns))
        object.__setattr__(self, "target", SinkTarget(self.target))
        object.__setattr__(self, "match", NameMatch(self.match))
        if isinstance(self.argument, int) and self.argument < 0:
            raise ValueError("sink argument index must be non-negative")
        if isinstance(self.argument, str) and not self.argument.strip():
            raise ValueError("sink argument name must not be empty")
        object.__setattr__(self, "description", self.description.strip())

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "patterns": list(self.patterns),
            "argument": self.argument,
            "target": self.target.value,
            "match": self.match.value,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class TaintConfig:
    """Explicit rules that define what taint means for one analysis run."""

    sources: Sequence[SourceRule] = ()
    sanitizers: Sequence[SanitizerRule] = ()
    propagators: Sequence[PropagatorRule] = ()
    sinks: Sequence[SinkRule] = ()
    interprocedural: bool = True
    max_paths_per_sink: int = 3
    max_findings: int = 200

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(self, "sanitizers", tuple(self.sanitizers))
        object.__setattr__(self, "propagators", tuple(self.propagators))
        object.__setattr__(self, "sinks", tuple(self.sinks))
        for collection_name in ("sources", "sanitizers", "propagators", "sinks"):
            collection = getattr(self, collection_name)
            names = [item.name for item in collection]
            if len(names) != len(set(names)):
                raise ValueError(f"{collection_name} rule names must be unique")
        if self.max_paths_per_sink < 1:
            raise ValueError("max_paths_per_sink must be at least 1")
        if self.max_findings < 1:
            raise ValueError("max_findings must be at least 1")

    def to_dict(self) -> dict[str, object]:
        return {
            "sources": [rule.to_dict() for rule in self.sources],
            "sanitizers": [rule.to_dict() for rule in self.sanitizers],
            "propagators": [rule.to_dict() for rule in self.propagators],
            "sinks": [rule.to_dict() for rule in self.sinks],
            "interprocedural": self.interprocedural,
            "max_paths_per_sink": self.max_paths_per_sink,
            "max_findings": self.max_findings,
        }


@dataclass(frozen=True, slots=True)
class TaintSite:
    """One matched source, sanitizer, validator, or sink site."""

    site_id: str
    role: SiteRole
    rule: str
    kinds: tuple[TaintKind, ...]
    span: SourceSpan
    text: str
    scope_id: str
    resolved: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "site_id": self.site_id,
            "role": self.role.value,
            "rule": self.rule,
            "kinds": [kind.value for kind in self.kinds],
            "span": span_to_dict(self.span),
            "text": self.text,
            "scope_id": self.scope_id,
            "resolved": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class TaintPathStep:
    """One node in an evidence path."""

    node_id: str
    role: str
    span: SourceSpan
    text: str
    scope_id: str
    name: str | None = None
    via: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "span": span_to_dict(self.span),
            "text": self.text,
            "scope_id": self.scope_id,
            "name": self.name,
            "via": self.via,
        }


@dataclass(frozen=True, slots=True)
class TaintFinding:
    """A potential source-to-sink path.

    ``confidence`` describes confidence in the syntactic flow, never confidence
    that an attacker can exploit it. ``limitations`` repeats the applicable
    limitation disclosures so a serialized finding remains self-describing.
    """

    finding_id: str
    kind: TaintKind
    title: str
    source_rule: str
    sink_rule: str
    source_span: SourceSpan
    source_text: str
    sink_span: SourceSpan
    sink_text: str
    path: tuple[TaintPathStep, ...]
    confidence: TaintConfidence
    confidence_notes: tuple[str, ...]
    limitations: tuple[str, ...]
    argument_span: SourceSpan | None = None
    argument_text: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "kind": self.kind.value,
            "title": self.title,
            "potential": True,
            "source_rule": self.source_rule,
            "sink_rule": self.sink_rule,
            "source": {
                "span": span_to_dict(self.source_span),
                "text": self.source_text,
            },
            "sink": {
                "span": span_to_dict(self.sink_span),
                "text": self.sink_text,
            },
            "argument": (
                {
                    "span": span_to_dict(self.argument_span),
                    "text": self.argument_text,
                }
                if self.argument_span is not None
                else None
            ),
            "path": [step.to_dict() for step in self.path],
            "confidence": {
                "level": self.confidence.value,
                "notes": list(self.confidence_notes),
            },
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class TaintAnalysis:
    """Taint graph, matched configuration sites, and potential findings."""

    parsed: ParsedSource
    cfg: ControlFlowAnalysis = field(repr=False)
    dfg: DataFlowAnalysis = field(repr=False)
    config: TaintConfig = field(repr=False)
    graph: nx.DiGraph = field(repr=False)
    sources: tuple[TaintSite, ...] = ()
    sanitizers: tuple[TaintSite, ...] = ()
    validators: tuple[TaintSite, ...] = ()
    sinks: tuple[TaintSite, ...] = ()
    findings: tuple[TaintFinding, ...] = ()
    unresolved_calls: int = 0
    limitations: tuple[str, ...] = ()

    @property
    def source_sites(self) -> tuple[TaintSite, ...]:
        return self.sources

    @property
    def sanitizer_sites(self) -> tuple[TaintSite, ...]:
        return self.sanitizers

    @property
    def validator_sites(self) -> tuple[TaintSite, ...]:
        return self.validators

    @property
    def sink_sites(self) -> tuple[TaintSite, ...]:
        return self.sinks

    @property
    def unsanitized_findings(self) -> tuple[TaintFinding, ...]:
        return self.findings

    def findings_for(self, kind: TaintKind | str) -> tuple[TaintFinding, ...]:
        target = TaintKind(kind)
        return tuple(finding for finding in self.findings if finding.kind is target)

    def summary(self) -> dict[str, object]:
        by_kind = {
            kind.value: sum(1 for finding in self.findings if finding.kind is kind)
            for kind in TaintKind
        }
        return {
            "sources": len(self.sources),
            "sanitizers": len(self.sanitizers),
            "validators": len(self.validators),
            "sinks": len(self.sinks),
            "findings": len(self.findings),
            "findings_by_kind": by_kind,
            "unresolved_calls": self.unresolved_calls,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.parsed.path,
            "language": self.parsed.language.value,
            "summary": self.summary(),
            "config": self.config.to_dict(),
            "sources": [site.to_dict() for site in self.sources],
            "sanitizers": [site.to_dict() for site in self.sanitizers],
            "validators": [site.to_dict() for site in self.validators],
            "sinks": [site.to_dict() for site in self.sinks],
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
            "graph": _graph_to_dict(self.graph),
        }


# --------------------------------------------------------------------------- #
# Explicit default configuration
# --------------------------------------------------------------------------- #

_DEFAULT_SOURCES = (
    SourceRule(
        name="python.http_request",
        patterns=(
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "request.data",
            "request.GET",
            "request.POST",
            "request.body",
            "request.query_params",
            "request.cookies",
            "request.headers",
            "request.files",
        ),
        description="Flask/Django-style HTTP request values.",
    ),
    SourceRule(
        name="python.request_json",
        patterns=("request.get_json", "request.json"),
        description="Parsed HTTP JSON request body.",
    ),
    SourceRule(
        name="python.input",
        patterns=("input",),
        description="Python interactive input.",
    ),
    SourceRule(
        name="python.argv",
        patterns=("sys.argv",),
        description="Command-line arguments.",
    ),
    SourceRule(
        name="python.environment",
        patterns=("os.environ", "os.getenv"),
        description="Process environment values.",
    ),
    SourceRule(
        name="javascript.http_request",
        patterns=(
            "req.query",
            "req.body",
            "req.params",
            "req.headers",
            "req.cookies",
            "req.files",
        ),
        description="Express-style HTTP request values.",
    ),
    SourceRule(
        name="javascript.browser_url",
        patterns=(
            "location.search",
            "location.hash",
            "location.href",
            "window.location",
            "document.location",
            "document.URL",
            "document.referrer",
        ),
        description="Browser URL and referrer values.",
    ),
    SourceRule(
        name="javascript.process",
        patterns=("process.argv", "process.env"),
        description="Node.js process arguments and environment.",
    ),
)

_DEFAULT_SANITIZERS = (
    SanitizerRule(
        name="python.numeric_conversion",
        patterns=("int", "float"),
        kinds=(TaintKind.SQL_INJECTION, TaintKind.COMMAND_INJECTION),
        description="Numeric conversion for SQL and command contexts.",
    ),
    SanitizerRule(
        name="javascript.numeric_conversion",
        patterns=("parseInt", "parseFloat", "Number"),
        kinds=(TaintKind.SQL_INJECTION, TaintKind.COMMAND_INJECTION),
        description="Numeric conversion for SQL and command contexts.",
    ),
    SanitizerRule(
        name="python.shell_quote",
        patterns=("shlex.quote", "pipes.quote", "quote"),
        kinds=(TaintKind.COMMAND_INJECTION,),
        description="Shell quoting.",
    ),
    SanitizerRule(
        name="python.html_escape",
        patterns=("html.escape", "markupsafe.escape", "flask.escape", "escape", "bleach.clean"),
        kinds=(TaintKind.XSS,),
        description="HTML escaping or sanitization.",
    ),
    SanitizerRule(
        name="javascript.html_escape",
        patterns=("escapeHtml", "DOMPurify.sanitize", "sanitizeHtml"),
        kinds=(TaintKind.XSS,),
        description="HTML escaping or sanitization.",
    ),
    SanitizerRule(
        name="python.path_basename",
        patterns=(
            "os.path.basename",
            "path.basename",
            "secure_filename",
            "werkzeug.utils.secure_filename",
        ),
        kinds=(TaintKind.PATH_TRAVERSAL,),
        description="Basename-only or secure filename conversion.",
    ),
    SanitizerRule(
        name="javascript.path_basename",
        patterns=("path.basename", "basename", "sanitizeFilename", "safeJoin"),
        kinds=(TaintKind.PATH_TRAVERSAL,),
        description="Basename-only or configured safe path conversion.",
    ),
    SanitizerRule(
        name="python.path_validator",
        patterns=("is_safe_path", "is_safe_url", "validate_path", "validate_filename"),
        kinds=(TaintKind.PATH_TRAVERSAL, TaintKind.XSS),
        category=SanitizerCategory.VALIDATOR,
        description="Path/URL validator; recorded but not assumed to sanitize.",
    ),
    SanitizerRule(
        name="javascript.path_validator",
        patterns=("isSafePath", "isSafeUrl", "validatePath", "validateFilename"),
        kinds=(TaintKind.PATH_TRAVERSAL, TaintKind.XSS),
        category=SanitizerCategory.VALIDATOR,
        description="Path/URL validator; recorded but not assumed to sanitize.",
    ),
    SanitizerRule(
        name="python.input_validator",
        patterns=("validate_input", "is_valid_input"),
        category=SanitizerCategory.VALIDATOR,
        description="Input validator; recorded but not assumed to sanitize.",
    ),
)

_DEFAULT_PROPAGATORS = (
    PropagatorRule(
        name="python.string_operations",
        patterns=(
            "str",
            "repr",
            "format",
            "format_map",
            "join",
            "replace",
            "strip",
            "lstrip",
            "rstrip",
            "lower",
            "upper",
            "casefold",
            "title",
            "capitalize",
            "swapcase",
            "encode",
            "decode",
        ),
        mode=PropagatorMode.BOTH,
        description="String transformations that preserve their input.",
    ),
    PropagatorRule(
        name="python.path_operations",
        patterns=(
            "os.path.join",
            "os.fspath",
            "os.path.normpath",
            "os.path.abspath",
            "os.path.realpath",
            "pathlib.Path",
            "Path",
            "urllib.parse.urljoin",
            "urllib.parse.quote",
            "urllib.parse.unquote",
        ),
        mode=PropagatorMode.ARGUMENTS,
        description="Path and URL transformations that preserve their input.",
    ),
    PropagatorRule(
        name="javascript.string_operations",
        patterns=(
            "String",
            "toString",
            "trim",
            "trimStart",
            "trimEnd",
            "toLowerCase",
            "toUpperCase",
            "replace",
            "replaceAll",
            "concat",
            "join",
            "slice",
            "substring",
            "substr",
            "padStart",
            "padEnd",
        ),
        mode=PropagatorMode.BOTH,
        description="String transformations that preserve their input.",
    ),
    PropagatorRule(
        name="javascript.path_operations",
        patterns=("path.join", "path.resolve", "path.normalize"),
        mode=PropagatorMode.ARGUMENTS,
        description="Path transformations that preserve their input.",
    ),
)

_DEFAULT_SINKS = (
    SinkRule(
        name="sql.execute",
        kind=TaintKind.SQL_INJECTION,
        patterns=("execute", "executemany", "executescript"),
        argument=0,
        description="Database execute-family call.",
    ),
    SinkRule(
        name="sql.raw",
        kind=TaintKind.SQL_INJECTION,
        patterns=("raw", "rawQuery", "$queryRawUnsafe", "$executeRawUnsafe"),
        argument=0,
        description="Raw SQL API.",
    ),
    SinkRule(
        name="sql.query",
        kind=TaintKind.SQL_INJECTION,
        patterns=("query", "sequelize.query", "knex.raw", "text"),
        argument=0,
        description="Database query API.",
    ),
    SinkRule(
        name="command.system",
        kind=TaintKind.COMMAND_INJECTION,
        patterns=("os.system", "os.popen", "commands.getoutput", "pty.spawn"),
        argument=0,
        description="Operating-system command execution.",
    ),
    SinkRule(
        name="command.subprocess",
        kind=TaintKind.COMMAND_INJECTION,
        patterns=(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        ),
        argument=0,
        description="Subprocess execution.",
    ),
    SinkRule(
        name="command.eval",
        kind=TaintKind.COMMAND_INJECTION,
        patterns=("eval", "Function"),
        argument=0,
        description="Dynamic code or command execution.",
    ),
    SinkRule(
        name="command.python_exec",
        kind=TaintKind.COMMAND_INJECTION,
        patterns=("exec",),
        argument=0,
        match=NameMatch.EXACT,
        description="Python dynamic code execution.",
    ),
    SinkRule(
        name="command.node_child_process",
        kind=TaintKind.COMMAND_INJECTION,
        patterns=(
            "child_process.exec",
            "execSync",
            "spawn",
            "spawnSync",
            "vm.runInNewContext",
            "vm.runInThisContext",
        ),
        argument=0,
        description="Node.js child-process or VM execution.",
    ),
    SinkRule(
        name="xss.python_response",
        kind=TaintKind.XSS,
        patterns=(
            "render_template_string",
            "Markup",
            "HttpResponse",
            "make_response",
            "Response",
        ),
        argument=0,
        description="HTML response construction.",
    ),
    SinkRule(
        name="xss.document_write",
        kind=TaintKind.XSS,
        patterns=("document.write", "document.writeln", "res.send", "res.write", "res.end"),
        argument=0,
        description="DOM or HTTP response write.",
    ),
    SinkRule(
        name="xss.insert_adjacent_html",
        kind=TaintKind.XSS,
        patterns=("insertAdjacentHTML",),
        argument=1,
        description="DOM HTML insertion.",
    ),
    SinkRule(
        name="xss.dom_assignment",
        kind=TaintKind.XSS,
        patterns=("innerHTML", "outerHTML", "srcdoc", "dangerouslySetInnerHTML"),
        target=SinkTarget.ATTRIBUTE_ASSIGNMENT,
        description="DOM HTML property assignment.",
    ),
    SinkRule(
        name="path.open",
        kind=TaintKind.PATH_TRAVERSAL,
        patterns=("open", "Path", "os.open", "io.open"),
        argument=0,
        description="Path-opening API.",
    ),
    SinkRule(
        name="path.file_operations",
        kind=TaintKind.PATH_TRAVERSAL,
        patterns=(
            "os.remove",
            "os.unlink",
            "shutil.copy",
            "shutil.copyfile",
            "shutil.move",
            "send_file",
            "FileResponse",
            "readFile",
            "readFileSync",
            "writeFile",
            "writeFileSync",
            "createReadStream",
            "createWriteStream",
            "sendFile",
            "unlink",
            "rm",
            "rmSync",
        ),
        argument=0,
        description="Filesystem read, write, copy, or delete API.",
    ),
    SinkRule(
        name="deserialization.pickle",
        kind=TaintKind.UNSAFE_DESERIALIZATION,
        patterns=(
            "pickle.load",
            "pickle.loads",
            "cPickle.load",
            "cPickle.loads",
            "dill.load",
            "dill.loads",
            "marshal.load",
            "marshal.loads",
        ),
        argument=0,
        description="Unsafe Python deserialization.",
    ),
    SinkRule(
        name="deserialization.yaml",
        kind=TaintKind.UNSAFE_DESERIALIZATION,
        patterns=("yaml.load", "yaml.unsafe_load", "yaml.full_load"),
        argument=0,
        description="Unsafe YAML loading.",
    ),
    SinkRule(
        name="deserialization.generic",
        kind=TaintKind.UNSAFE_DESERIALIZATION,
        patterns=("jsonpickle.decode", "unserialize", "deserialize", "nodeSerialize.unserialize"),
        argument=0,
        description="Generic object deserialization.",
    ),
)


def default_taint_config() -> TaintConfig:
    """Return the explicit default rule set for the five supported classes.

    The rules favor understandable, configurable coverage over soundness. A
    caller can replace any part of the configuration and only the supplied rules
    are applied.
    """
    return TaintConfig(
        sources=_DEFAULT_SOURCES,
        sanitizers=_DEFAULT_SANITIZERS,
        propagators=_DEFAULT_PROPAGATORS,
        sinks=_DEFAULT_SINKS,
    )


DEFAULT_TAINT_CONFIG = default_taint_config()


TAINT_LIMITATIONS = (
    "LIM-PA-09: Interprocedural taint is limited to direct, same-file calls "
    "resolved by declaration name or self/this method name. Imports, re-exports, "
    "aliases, dynamic dispatch, callbacks, and cross-file summaries are not resolved.",
    "LIM-PA-10: Findings are potential syntactic source-to-sink flows, not "
    "confirmed vulnerabilities. Path feasibility, runtime values, types, "
    "authentication, authorization, and framework routing are not evaluated.",
    "LIM-PA-11: Sanitizers, validators, propagators, and sinks are explicit "
    "configuration. Validators are identified but do not clear taint by "
    "themselves, and an unconfigured unknown call is assumed to block value flow.",
)


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def analyze_taint(
    source: ParsedSource | str,
    *,
    config: TaintConfig | None = None,
    path: str | Path | None = None,
    language: SupportedLanguage | str | None = None,
    language_id: str | None = None,
    analysis: ProgramAnalysis | None = None,
) -> TaintAnalysis:
    """Analyse Python or JavaScript source with explicit taint rules.

    ``config`` defaults to :data:`DEFAULT_TAINT_CONFIG`. Pass a custom
    :class:`TaintConfig` to apply only caller-supplied source, sanitizer,
    propagator, and sink rules.
    """
    resolved_config = config or DEFAULT_TAINT_CONFIG
    if analysis is None:
        if isinstance(source, ParsedSource):
            parsed = source
        else:
            parsed = parse_source(
                source,
                path=path,
                language=language,
                language_id=language_id,
            )
        analysis = analyze_parsed(parsed)
    return _TaintBuilder(analysis, resolved_config).build()


def analyze_taint_file(
    path: str | Path,
    *,
    config: TaintConfig | None = None,
    language_id: str | None = None,
) -> TaintAnalysis:
    """Read a UTF-8 file and run taint analysis.

    Callers handling untrusted paths must apply workspace containment first.
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    return analyze_taint(
        text,
        config=config,
        path=file_path,
        language_id=language_id,
    )


build_taint = analyze_taint
analyze_taint_source = analyze_taint


# --------------------------------------------------------------------------- #
# Internal graph construction
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _ScopeContext:
    scope_id: str
    graph: ControlFlowGraph
    dfg: DataFlowGraph
    body: Node
    function_node: Node | None
    defs: tuple[DFGNode, ...]
    uses: tuple[DFGNode, ...]
    parameters: tuple[DFGNode, ...]
    calls: tuple[DFGNode, ...]
    returns: tuple[DFGNode, ...]
    defs_by_span: dict[tuple[int, int], tuple[DFGNode, ...]]
    uses_by_span: dict[tuple[int, int], tuple[DFGNode, ...]]
    calls_by_span: dict[tuple[int, int], DFGNode]
    returns_by_span: dict[tuple[int, int], DFGNode]
    expression_body: str | None = None


@dataclass(frozen=True, slots=True)
class _Argument:
    position: int
    keyword: str | None
    node_id: str | None
    node: Node | None
    span: SourceSpan


@dataclass(slots=True)
class _CallRecord:
    node_id: str
    callee: str
    scope_id: str
    span: SourceSpan
    arguments: tuple[_Argument, ...]
    receiver_id: str | None = None
    propagator: PropagatorRule | None = None


@dataclass(slots=True)
class _SinkOccurrence:
    rule: SinkRule
    scope_id: str
    sink_node_id: str
    sink_span: SourceSpan
    sink_text: str
    argument_node_id: str | None
    argument_span: SourceSpan | None
    argument_text: str | None


@dataclass(frozen=True, slots=True)
class _EdgeRecord:
    source: str
    target: str
    kind: TaintEdgeKind
    span: SourceSpan


_FUNCTION_TYPES = frozenset(
    {
        "function_definition",
        "lambda",
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_CLASS_TYPES = frozenset({"class_definition", "class", "class_declaration"})
_BLOCK_TYPES = frozenset({"block", "statement_block", "switch_body", "module", "program"})
_ASSIGNMENT_TYPES = frozenset(
    {
        "assignment",
        "augmented_assignment",
        "named_expression",
        "assignment_expression",
        "augmented_assignment_expression",
    }
)
_SKIP_TYPES = frozenset(
    {
        "comment",
        "type",
        "type_parameter",
        "type_parameter_list",
        "type_parameters",
        "string_content",
        "string_fragment",
        "string_start",
        "string_end",
        "escape_sequence",
    }
)
_COMPARISON_TYPES = frozenset(
    {
        "comparison_operator",
        "comparison_expression",
        "not_operator",
        "unary_operator",
    }
)
_CONTAINER_TYPES = frozenset(
    {
        "argument_list",
        "arguments",
        "array",
        "list",
        "tuple",
        "set",
        "dictionary",
        "object",
        "object_pattern",
        "array_pattern",
        "pair",
        "spread_element",
        "list_splat",
        "dictionary_splat",
        "yield",
        "yield_expression",
    }
)
_SIMPLE_TERMINAL_TYPES = frozenset(
    {
        "integer",
        "float",
        "true",
        "false",
        "none",
        "null",
        "undefined",
        "this",
        "super",
        "ellipsis",
        "regex",
        "regex_pattern",
    }
)
_IMPORT_TYPES = frozenset(
    {
        "import_statement",
        "import_from_statement",
        "future_import_statement",
        "import_clause",
    }
)
_DECLARATION_TYPES = frozenset({"lexical_declaration", "variable_declaration"})


def _normalize_name(value: str) -> str:
    return re.sub(r"\s+", "", value).replace("?.", ".")


def _matches(text: str, pattern: str, mode: NameMatch) -> bool:
    candidate = _normalize_name(text)
    expected = _normalize_name(pattern)
    if not candidate or not expected:
        return False
    if mode is NameMatch.EXACT:
        return candidate == expected
    if mode is NameMatch.SUFFIX:
        return candidate == expected or candidate.endswith("." + expected)
    return (
        candidate == expected
        or candidate.startswith(expected + ".")
        or candidate.startswith(expected + "[")
        or candidate.startswith(expected + "(")
    )


def _matching_sources(text: str, config: TaintConfig) -> tuple[SourceRule, ...]:
    return tuple(
        rule
        for rule in config.sources
        if any(_matches(text, pattern, rule.match) for pattern in rule.patterns)
    )


def _matching_sanitizers(text: str, config: TaintConfig) -> tuple[SanitizerRule, ...]:
    return tuple(
        rule
        for rule in config.sanitizers
        if any(_matches(text, pattern, rule.match) for pattern in rule.patterns)
    )


def _matching_propagator(text: str, config: TaintConfig) -> PropagatorRule | None:
    for rule in config.propagators:
        if any(_matches(text, pattern, rule.match) for pattern in rule.patterns):
            return rule
    return None


def _matching_sinks(text: str, config: TaintConfig, target: SinkTarget) -> tuple[SinkRule, ...]:
    return tuple(
        rule
        for rule in config.sinks
        if rule.target is target
        and any(_matches(text, pattern, rule.match) for pattern in rule.patterns)
    )


def _span_key(span: SourceSpan) -> tuple[int, int]:
    return (span.start.byte_offset, span.end.byte_offset)


def _contains(outer: SourceSpan, inner: SourceSpan) -> bool:
    return (
        outer.start.byte_offset <= inner.start.byte_offset
        and outer.end.byte_offset >= inner.end.byte_offset
    )


def _first_named(node: Node | None) -> Node | None:
    if node is None:
        return None
    return next((child for child in node.named_children if child.type != "comment"), None)


def _function_body(node: Node) -> Node:
    body = node.child_by_field_name("body")
    if body is None:
        for child in node.named_children:
            if child.type in {"block", "statement_block"}:
                body = child
                break
    return body or node


class _TaintBuilder:
    def __init__(self, analysis: ProgramAnalysis, config: TaintConfig) -> None:
        self.analysis = analysis
        self.parsed = analysis.parsed
        self.cfg = analysis.cfg
        self.dfg = analysis.dfg
        self.config = config
        self.graph = nx.DiGraph()
        self._edges: list[_EdgeRecord] = []
        self._edge_keys: set[tuple[str, str, TaintEdgeKind]] = set()
        self._contexts: dict[str, _ScopeContext] = {}
        self._call_records: list[_CallRecord] = []
        self._sink_occurrences: list[_SinkOccurrence] = []
        self._sites: list[TaintSite] = []
        self._configured_calls: set[str] = set()
        self._unresolved_calls = 0

    def build(self) -> TaintAnalysis:
        self._build_contexts()
        self._copy_dfg()
        self._visit_all_scopes()
        if self.config.interprocedural:
            self._connect_calls()
        findings = self._find_findings()
        kept_source_pairs = {
            (rule, _span_key(self.graph.nodes[node_id]["span"]))
            for node_id in self._source_nodes()
            for rule in self.graph.nodes[node_id].get("source_rules", ())
        }
        sites = tuple(
            sorted(
                (
                    site
                    for site in self._sites
                    if site.role is not SiteRole.SOURCE
                    or (site.rule, _span_key(site.span)) in kept_source_pairs
                ),
                key=lambda site: (
                    site.span.start.byte_offset,
                    site.role.value,
                    site.rule,
                ),
            )
        )
        return TaintAnalysis(
            parsed=self.parsed,
            cfg=self.cfg,
            dfg=self.dfg,
            config=self.config,
            graph=self.graph,
            sources=tuple(site for site in sites if site.role is SiteRole.SOURCE),
            sanitizers=tuple(site for site in sites if site.role is SiteRole.SANITIZER),
            validators=tuple(site for site in sites if site.role is SiteRole.VALIDATOR),
            sinks=tuple(site for site in sites if site.role is SiteRole.SINK),
            findings=findings,
            unresolved_calls=self._unresolved_calls,
            limitations=TAINT_LIMITATIONS,
        )

    # ------------------------------------------------------------- contexts

    def _build_contexts(self) -> None:
        module = self._make_context(self.cfg.module, self.dfg.module, self.parsed.root_node, None)
        self._contexts[module.scope_id] = module
        function_nodes = _collect_function_nodes(self.parsed)
        for graph, dfg_graph, node in zip(
            self.cfg.functions,
            self.dfg.functions,
            function_nodes,
            strict=False,
        ):
            context = self._make_context(graph, dfg_graph, _function_body(node), node)
            self._contexts[context.scope_id] = context

    def _make_context(
        self,
        graph: ControlFlowGraph,
        dfg_graph: DataFlowGraph,
        body: Node,
        function_node: Node | None,
    ) -> _ScopeContext:
        defs_by_span: dict[tuple[int, int], list[DFGNode]] = {}
        uses_by_span: dict[tuple[int, int], list[DFGNode]] = {}
        calls_by_span: dict[tuple[int, int], DFGNode] = {}
        returns_by_span: dict[tuple[int, int], DFGNode] = {}
        defs: list[DFGNode] = []
        uses: list[DFGNode] = []
        parameters: list[DFGNode] = []
        calls: list[DFGNode] = []
        returns: list[DFGNode] = []
        for node in dfg_graph.nodes:
            if node.kind is DFGNodeKind.DEFINITION:
                defs.append(node)
                defs_by_span.setdefault(_span_key(node.span), []).append(node)
            elif node.kind is DFGNodeKind.PARAMETER:
                parameters.append(node)
                defs.append(node)
                defs_by_span.setdefault(_span_key(node.span), []).append(node)
            elif node.kind is DFGNodeKind.USE:
                uses.append(node)
                uses_by_span.setdefault(_span_key(node.span), []).append(node)
            elif node.kind is DFGNodeKind.CALL:
                calls.append(node)
                calls_by_span[_span_key(node.span)] = node
            elif node.kind is DFGNodeKind.RETURN:
                returns.append(node)
                returns_by_span[_span_key(node.span)] = node
        return _ScopeContext(
            scope_id=graph.scope_id,
            graph=graph,
            dfg=dfg_graph,
            body=body,
            function_node=function_node,
            defs=tuple(defs),
            uses=tuple(uses),
            parameters=tuple(parameters),
            calls=tuple(calls),
            returns=tuple(returns),
            defs_by_span={key: tuple(value) for key, value in defs_by_span.items()},
            uses_by_span={key: tuple(value) for key, value in uses_by_span.items()},
            calls_by_span=calls_by_span,
            returns_by_span=returns_by_span,
        )

    def _copy_dfg(self) -> None:
        kind_map = {
            DFGNodeKind.PARAMETER: TaintNodeKind.PARAMETER,
            DFGNodeKind.DEFINITION: TaintNodeKind.DEFINITION,
            DFGNodeKind.USE: TaintNodeKind.USE,
            DFGNodeKind.CALL: TaintNodeKind.CALL,
            DFGNodeKind.RETURN: TaintNodeKind.RETURN,
            DFGNodeKind.RAISE: TaintNodeKind.RAISE,
        }
        for context in self._contexts.values():
            for node in context.dfg.nodes:
                kind = kind_map.get(node.kind)
                if kind is None:
                    continue
                self._add_node(
                    node.node_id,
                    kind,
                    node.span,
                    node.text,
                    node.scope_id,
                    name=node.name,
                    instruction_id=node.instruction_id,
                    block_id=node.block_id,
                    call_id=node.call_id,
                    resolved=bool(node.resolved) if kind is not TaintNodeKind.CALL else False,
                )
            for edge in context.dfg.edges:
                if edge.kind.value in {"def_use", "closure"} and self.graph.has_node(edge.source):
                    if self.graph.has_node(edge.target):
                        self._add_edge(
                            edge.source,
                            edge.target,
                            TaintEdgeKind(edge.kind.value),
                            edge.span,
                        )

    # -------------------------------------------------------------- traversal

    def _visit_all_scopes(self) -> None:
        module = self._contexts["module"]
        self._visit_statement(module.body, module)
        for context in self._contexts.values():
            if context.scope_id == "module":
                continue
            if context.body.type in _BLOCK_TYPES:
                self._visit_statement(context.body, context)
            else:
                value = self._visit_expression(context.body, context)
                if value is not None:
                    context.expression_body = value
                    for return_node in context.returns:
                        self._add_edge(
                            value,
                            return_node.node_id,
                            TaintEdgeKind.RETURN,
                            self.parsed.span_for_node(context.body),
                        )

    def _visit_statement(self, node: Node | None, context: _ScopeContext) -> None:
        if node is None:
            return
        node_type = node.type
        if node_type in _FUNCTION_TYPES or node_type in _CLASS_TYPES:
            return
        if node_type in _SKIP_TYPES:
            return
        if node_type in _BLOCK_TYPES:
            for child in node.named_children:
                self._visit_statement(child, context)
            return
        if node_type == "decorated_definition":
            return
        if node_type == "expression_statement":
            self._visit_expression(_first_named(node), context)
            return
        if node_type in _DECLARATION_TYPES:
            self._visit_declaration(node, context)
            return
        if node_type == "variable_declarator":
            self._visit_declarator(node, context)
            return
        if node_type == "return_statement":
            self._visit_return(node, context)
            return
        if node_type in {"for_statement", "for_in_statement"}:
            self._visit_for(node, context)
            return
        if node_type == "with_statement":
            self._visit_with(node, context)
            return
        if node_type == "if_statement":
            condition = node.child_by_field_name("condition")
            self._visit_expression(condition, context)
            self._visit_statement(node.child_by_field_name("consequence"), context)
            alternative = node.child_by_field_name("alternative")
            if alternative is None:
                alternative = next(
                    (child for child in node.named_children if child.type == "else_clause"),
                    None,
                )
            self._visit_statement(alternative, context)
            return
        if node_type in {"while_statement", "do_statement"}:
            self._visit_expression(node.child_by_field_name("condition"), context)
            self._visit_statement(node.child_by_field_name("body"), context)
            alternative = next(
                (child for child in node.named_children if child.type == "else_clause"),
                None,
            )
            self._visit_statement(alternative, context)
            return
        if node_type == "switch_statement":
            self._visit_expression(node.child_by_field_name("value"), context)
            body = node.child_by_field_name("body")
            if body is not None:
                for case in body.named_children:
                    self._visit_statement(case, context)
            return
        if node_type == "match_statement":
            self._visit_expression(node.child_by_field_name("subject"), context)
            body = node.child_by_field_name("body")
            if body is not None:
                for case in body.named_children:
                    self._visit_statement(case, context)
            return
        if node_type in {"switch_case", "switch_default", "case_clause"}:
            for child in node.named_children:
                if child.type in _BLOCK_TYPES:
                    self._visit_statement(child, context)
                elif child.type.endswith("_statement") or child.type in {
                    "expression_statement",
                    "lexical_declaration",
                    "variable_declaration",
                }:
                    self._visit_statement(child, context)
                elif child.type in {"case_pattern", "else_clause"}:
                    self._visit_statement(child, context)
            return
        if node_type == "try_statement":
            self._visit_statement(node.child_by_field_name("body"), context)
            for child in node.named_children:
                if child.type in {
                    "except_clause",
                    "catch_clause",
                    "else_clause",
                    "finally_clause",
                }:
                    self._visit_statement(child, context)
            return
        if node_type in {"except_clause", "catch_clause", "else_clause", "finally_clause"}:
            body = node.child_by_field_name("body") or _first_named(node)
            if body is not None and body.type not in {"identifier", "as_pattern_target"}:
                self._visit_statement(body, context)
            return
        if node_type == "labeled_statement":
            self._visit_statement(node.child_by_field_name("body"), context)
            return
        if node_type == "export_statement":
            declaration = node.child_by_field_name("declaration")
            if declaration is not None:
                self._visit_statement(declaration, context)
            return
        if node_type in {"raise_statement", "throw_statement"}:
            self._visit_expression(_first_named(node), context)
            return
        if node_type == "assert_statement":
            self._visit_expression(_first_named(node), context)
            return
        if node_type in _IMPORT_TYPES:
            return
        if node_type in {
            "pass_statement",
            "break_statement",
            "continue_statement",
            "global_statement",
            "nonlocal_statement",
            "empty_statement",
            "delete_statement",
        }:
            return
        for child in node.named_children:
            self._visit_statement(child, context)

    def _visit_declaration(self, node: Node, context: _ScopeContext) -> None:
        for child in node.named_children:
            if child.type == "variable_declarator":
                self._visit_declarator(child, context)
            elif child.type not in _SKIP_TYPES:
                self._visit_statement(child, context)

    def _visit_declarator(self, node: Node, context: _ScopeContext) -> None:
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        value_id = self._visit_expression(value, context) if value is not None else None
        if value_id is not None and name is not None:
            self._link_targets(context, name, value_id)

    def _visit_return(self, node: Node, context: _ScopeContext) -> None:
        value = _first_named(node)
        value_id = self._visit_expression(value, context) if value is not None else None
        if value_id is None:
            return
        target = context.returns_by_span.get(_span_key(self.parsed.span_for_node(node)))
        targets = (target,) if target is not None else context.returns
        for return_node in targets:
            self._add_edge(
                value_id,
                return_node.node_id,
                TaintEdgeKind.RETURN,
                self.parsed.span_for_node(node),
            )

    def _visit_for(self, node: Node, context: _ScopeContext) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        initializer = node.child_by_field_name("initializer")
        condition = node.child_by_field_name("condition")
        increment = node.child_by_field_name("increment")
        if initializer is not None:
            self._visit_statement(initializer, context)
        iterable = right if right is not None else condition
        if iterable is not None:
            value_id = self._visit_expression(iterable, context)
            if value_id is not None and left is not None:
                self._link_targets(context, left, value_id)
        if increment is not None:
            self._visit_expression(increment, context)
        self._visit_statement(node.child_by_field_name("body"), context)
        alternative = next(
            (child for child in node.named_children if child.type == "else_clause"),
            None,
        )
        self._visit_statement(alternative, context)

    def _visit_with(self, node: Node, context: _ScopeContext) -> None:
        for child in node.named_children:
            if child.type == "with_clause":
                for item in child.named_children:
                    if item.type == "with_item":
                        self._visit_with_item(item, context)
            elif child.type in _BLOCK_TYPES:
                self._visit_statement(child, context)

    def _visit_with_item(self, node: Node, context: _ScopeContext) -> None:
        pattern = next(
            (child for child in node.named_children if child.type == "as_pattern"),
            None,
        )
        if pattern is not None:
            value = next(
                (child for child in pattern.named_children if child.type != "as_pattern_target"),
                None,
            )
            target = next(
                (child for child in pattern.named_children if child.type == "as_pattern_target"),
                None,
            )
            value_id = self._visit_expression(value, context)
            if value_id is not None and target is not None:
                self._link_targets(context, target, value_id)
            return
        for child in node.named_children:
            self._visit_expression(child, context)

    # ------------------------------------------------------------- expressions

    def _visit_expression(self, node: Node | None, context: _ScopeContext) -> str | None:
        if node is None:
            return None
        node_type = node.type
        if node_type in _SKIP_TYPES:
            return None
        if node_type in _FUNCTION_TYPES or node_type in _CLASS_TYPES:
            return None
        if node_type == "identifier":
            return self._identifier_value(node, context)
        if node_type in {"attribute", "member_expression"}:
            return self._attribute_value(node, context)
        if node_type in {"subscript", "subscript_expression"}:
            return self._subscript_value(node, context)
        if node_type in {"call", "call_expression", "new_expression"}:
            return self._visit_call(node, context)
        if node_type in _ASSIGNMENT_TYPES:
            return self._visit_assignment(node, context)
        if node_type == "update_expression":
            return self._visit_update(node, context)
        if node_type == "string":
            return self._interpolated_string(node, context)
        if node_type == "template_string":
            return self._template_string(node, context)
        if node_type in _COMPARISON_TYPES:
            for child in node.named_children:
                self._visit_expression(child, context)
            return None
        if node_type in {
            "binary_operator",
            "binary_expression",
            "boolean_operator",
            "conditional_expression",
            "ternary_expression",
            "await_expression",
            "parenthesized_expression",
            "concatenated_string",
        }:
            return self._combine_children(node, context)
        if node_type in _CONTAINER_TYPES:
            return self._combine_children(node, context)
        if node_type in {"interpolation", "template_substitution"}:
            return self._combine_children(node, context)
        if node_type in _SIMPLE_TERMINAL_TYPES:
            return None
        if node_type in {"delete_statement", "import_statement"}:
            return None
        return self._combine_children(node, context)

    def _identifier_value(self, node: Node, context: _ScopeContext) -> str | None:
        key = _span_key(self.parsed.span_for_node(node))
        uses = context.uses_by_span.get(key, ())
        if uses:
            node_id = uses[0].node_id
        else:
            node_id = self._value_node(node, context)
            name = self.parsed.text_for_node(node)
            parameter = next(
                (item for item in context.parameters if item.name == name),
                None,
            )
            if parameter is not None:
                self._add_edge(
                    parameter.node_id,
                    node_id,
                    TaintEdgeKind.VALUE,
                    self.parsed.span_for_node(node),
                )
        self._match_source_text(node_id, self.parsed.text_for_node(node), context)
        return node_id

    def _attribute_value(self, node: Node, context: _ScopeContext) -> str | None:
        object_node = node.child_by_field_name("object")
        object_id = self._visit_expression(object_node, context)
        node_id = self._value_node(node, context)
        if object_id is not None:
            self._add_edge(
                object_id,
                node_id,
                TaintEdgeKind.VALUE,
                self.parsed.span_for_node(node),
            )
        self._match_source_text(node_id, self.parsed.text_for_node(node), context)
        return node_id

    def _subscript_value(self, node: Node, context: _ScopeContext) -> str | None:
        value_node = node.child_by_field_name("value") or node.child_by_field_name("object")
        value_id = self._visit_expression(value_node, context)
        node_id = self._value_node(node, context)
        if value_id is not None:
            self._add_edge(
                value_id,
                node_id,
                TaintEdgeKind.VALUE,
                self.parsed.span_for_node(node),
            )
        self._match_source_text(node_id, self.parsed.text_for_node(node), context)
        return node_id

    def _visit_call(self, node: Node, context: _ScopeContext) -> str | None:
        callee_field = "constructor" if node.type == "new_expression" else "function"
        callee_node = node.child_by_field_name(callee_field)
        callee_text = self.parsed.text_for_node(callee_node).strip() if callee_node else ""
        arguments = self._call_arguments(node, context)
        call_node = context.calls_by_span.get(_span_key(self.parsed.span_for_node(node)))
        if call_node is not None:
            call_node_id = call_node.node_id
        else:
            call_node_id = self._call_value_node(node, context, callee_text)

        source_rules = _matching_sources(callee_text, self.config)
        for rule in source_rules:
            self._mark_source(
                call_node_id,
                rule,
                self.parsed.span_for_node(node),
                callee_text,
                context,
            )

        sanitizers = _matching_sanitizers(callee_text, self.config)
        for rule in sanitizers:
            self._mark_sanitizer(
                call_node_id,
                rule,
                self.parsed.span_for_node(node),
                self.parsed.text_for_node(node),
                context,
            )
        if sanitizers:
            # A sanitizer or validator returns a value derived from its inputs.
            # Sanitized kinds are blocked by removing this node from that kind's
            # graph; other kinds continue through it. Validators never clear
            # taint, so their call node is never marked sanitized.
            receiver = self._receiver_value(callee_node, context)
            for argument in arguments:
                if argument.node_id is not None:
                    self._add_edge(
                        argument.node_id,
                        call_node_id,
                        TaintEdgeKind.VALUE,
                        argument.span,
                    )
            if receiver is not None:
                self._add_edge(
                    receiver,
                    call_node_id,
                    TaintEdgeKind.VALUE,
                    self.parsed.span_for_node(node),
                )
        propagator = _matching_propagator(callee_text, self.config)
        if (
            propagator is not None
            and not source_rules
            and not any(rule.sanitizes for rule in sanitizers)
        ):
            receiver = self._receiver_value(callee_node, context)
            self._call_records.append(
                _CallRecord(
                    node_id=call_node_id,
                    callee=callee_text,
                    scope_id=context.scope_id,
                    span=self.parsed.span_for_node(node),
                    arguments=arguments,
                    receiver_id=receiver,
                    propagator=propagator,
                )
            )
        else:
            self._call_records.append(
                _CallRecord(
                    node_id=call_node_id,
                    callee=callee_text,
                    scope_id=context.scope_id,
                    span=self.parsed.span_for_node(node),
                    arguments=arguments,
                )
            )

        sink_rules = _matching_sinks(callee_text, self.config, SinkTarget.CALL_ARGUMENT)
        for rule in sink_rules:
            selected = _select_argument(arguments, rule.argument)
            self._record_sink(
                rule=rule,
                context=context,
                sink_node_id=call_node_id,
                sink_span=self.parsed.span_for_node(node),
                sink_text=self.parsed.text_for_node(node),
                argument=selected,
            )
        if source_rules or sanitizers or propagator is not None or sink_rules:
            self._configured_calls.add(call_node_id)
        return call_node_id

    def _visit_assignment(self, node: Node, context: _ScopeContext) -> str | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        value_id = self._visit_expression(right, context)
        if left is not None:
            if node.type in {"augmented_assignment", "augmented_assignment_expression"}:
                for use in self._uses_within(context, left):
                    self._link_targets(context, left, use.node_id)
                if value_id is not None:
                    self._link_targets(context, left, value_id)
            elif value_id is not None:
                self._link_targets(context, left, value_id)
            property_name = _assignment_property(left)
            if property_name is not None:
                for rule in _matching_sinks(
                    property_name,
                    self.config,
                    SinkTarget.ATTRIBUTE_ASSIGNMENT,
                ):
                    self._record_sink(
                        rule=rule,
                        context=context,
                        sink_node_id=f"{context.scope_id}:sink@" + str(left.start_byte),
                        sink_span=self.parsed.span_for_node(left),
                        sink_text=self.parsed.text_for_node(left),
                        argument=_Argument(
                            position=0,
                            keyword=None,
                            node_id=value_id,
                            node=right,
                            span=(
                                self.parsed.span_for_node(right)
                                if right is not None
                                else self.parsed.span_for_node(node)
                            ),
                        ),
                    )
        return value_id

    def _visit_update(self, node: Node, context: _ScopeContext) -> str | None:
        argument = node.child_by_field_name("argument") or _first_named(node)
        value_id = self._visit_expression(argument, context)
        if argument is not None:
            for use in self._uses_within(context, argument):
                self._link_targets(context, argument, use.node_id)
        return value_id

    def _interpolated_string(self, node: Node, context: _ScopeContext) -> str | None:
        values = [
            value
            for child in node.named_children
            if child.type == "interpolation"
            for value in (self._visit_expression(child, context),)
            if value is not None
        ]
        return self._combine_values(node, context, values)

    def _template_string(self, node: Node, context: _ScopeContext) -> str | None:
        values = [
            value
            for child in node.named_children
            if child.type == "template_substitution"
            for value in (self._visit_expression(child, context),)
            if value is not None
        ]
        return self._combine_values(node, context, values)

    def _combine_children(self, node: Node, context: _ScopeContext) -> str | None:
        values: list[str] = []
        for child in node.named_children:
            if child.type in _SKIP_TYPES:
                continue
            value = self._visit_expression(child, context)
            if value is not None:
                values.append(value)
        return self._combine_values(node, context, values)

    def _combine_values(
        self,
        node: Node,
        context: _ScopeContext,
        values: list[str],
    ) -> str | None:
        if not values:
            return None
        node_id = self._value_node(node, context)
        for value in values:
            self._add_edge(
                value,
                node_id,
                TaintEdgeKind.VALUE,
                self.parsed.span_for_node(node),
            )
        return node_id

    def _call_arguments(self, node: Node, context: _ScopeContext) -> tuple[_Argument, ...]:
        container = node.child_by_field_name("arguments")
        if container is None:
            return ()
        arguments: list[_Argument] = []
        position = 0
        for child in container.named_children:
            if child.type in _SKIP_TYPES:
                continue
            keyword = None
            value_node = child
            if child.type == "keyword_argument":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value") or child
                keyword = self.parsed.text_for_node(name_node).strip() if name_node else None
            elif child.type in {"spread_element", "list_splat", "dictionary_splat"}:
                value_node = _first_named(child) or child
            value_id = self._visit_expression(value_node, context)
            arguments.append(
                _Argument(
                    position=position,
                    keyword=keyword,
                    node_id=value_id,
                    node=value_node,
                    span=self.parsed.span_for_node(value_node),
                )
            )
            if keyword is None:
                position += 1
        return tuple(arguments)

    def _receiver_value(
        self,
        callee: Node | None,
        context: _ScopeContext,
    ) -> str | None:
        if callee is None:
            return None
        object_node = callee.child_by_field_name("object")
        if object_node is None:
            return None
        return self._visit_expression(object_node, context)

    # --------------------------------------------------------------- targets

    def _link_targets(self, context: _ScopeContext, target: Node, value_id: str) -> None:
        span = self.parsed.span_for_node(target)
        for definition in context.defs:
            if _contains(span, definition.span):
                self._add_edge(
                    value_id,
                    definition.node_id,
                    TaintEdgeKind.VALUE,
                    span,
                )

    def _uses_within(self, context: _ScopeContext, target: Node) -> tuple[DFGNode, ...]:
        span = self.parsed.span_for_node(target)
        return tuple(use for use in context.uses if _contains(span, use.span))

    # ---------------------------------------------------------------- nodes

    def _value_node(self, node: Node, context: _ScopeContext) -> str:
        node_id = f"{context.scope_id}:expr:{node.start_byte}:{node.end_byte}"
        self._add_node(
            node_id,
            TaintNodeKind.EXPRESSION,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            context.scope_id,
        )
        return node_id

    def _call_value_node(self, node: Node, context: _ScopeContext, text: str) -> str:
        node_id = f"{context.scope_id}:call:{node.start_byte}:{node.end_byte}"
        self._add_node(
            node_id,
            TaintNodeKind.CALL,
            self.parsed.span_for_node(node),
            self.parsed.text_for_node(node),
            context.scope_id,
            name=text or None,
            resolved=False,
        )
        return node_id

    def _add_node(
        self,
        node_id: str,
        kind: TaintNodeKind,
        span: SourceSpan,
        text: str,
        scope_id: str,
        *,
        name: str | None = None,
        instruction_id: str | None = None,
        block_id: str | None = None,
        call_id: str | None = None,
        resolved: bool = True,
    ) -> None:
        if self.graph.has_node(node_id):
            return
        self.graph.add_node(
            node_id,
            kind=kind.value,
            span=span,
            span_dict=span_to_dict(span),
            text=text,
            scope_id=scope_id,
            name=name,
            instruction_id=instruction_id,
            block_id=block_id,
            call_id=call_id,
            resolved=resolved,
            source_rules=(),
            sanitized_for=frozenset(),
            target_scopes=(),
            resolution=None,
        )

    def _add_edge(
        self,
        source: str,
        target: str,
        kind: TaintEdgeKind,
        span: SourceSpan,
    ) -> None:
        if source not in self.graph or target not in self.graph:
            return
        key = (source, target, kind)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._edges.append(_EdgeRecord(source, target, kind, span))
        if self.graph.has_edge(source, target):
            attributes = self.graph[source][target]
            attributes["kinds"] = tuple(dict.fromkeys(attributes["kinds"] + (kind.value,)))
            attributes["count"] += 1
        else:
            self.graph.add_edge(
                source,
                target,
                kind=kind.value,
                kinds=(kind.value,),
                count=1,
                span=span,
                span_dict=span_to_dict(span),
            )

    # ------------------------------------------------------------- matching

    def _match_source_text(
        self,
        node_id: str,
        text: str,
        context: _ScopeContext,
    ) -> None:
        span = self.graph.nodes[node_id]["span"]
        for rule in _matching_sources(text, self.config):
            self._mark_source(node_id, rule, span, text, context)

    def _mark_source(
        self,
        node_id: str,
        rule: SourceRule,
        span: SourceSpan,
        text: str,
        context: _ScopeContext,
    ) -> None:
        rules = tuple(
            dict.fromkeys(self.graph.nodes[node_id].get("source_rules", ()) + (rule.name,))
        )
        self.graph.nodes[node_id]["source_rules"] = rules
        self._add_site(
            TaintSite(
                site_id=f"source:{rule.name}@{span.start.byte_offset}:{span.end.byte_offset}",
                role=SiteRole.SOURCE,
                rule=rule.name,
                kinds=tuple(sorted(rule.kinds, key=_kind_order)),
                span=span,
                text=text,
                scope_id=context.scope_id,
            )
        )

    def _mark_sanitizer(
        self,
        node_id: str,
        rule: SanitizerRule,
        span: SourceSpan,
        text: str,
        context: _ScopeContext,
    ) -> None:
        role = SiteRole.SANITIZER if rule.sanitizes else SiteRole.VALIDATOR
        if rule.sanitizes:
            sanitized = frozenset(self.graph.nodes[node_id].get("sanitized_for", ())) | rule.kinds
            self.graph.nodes[node_id]["sanitized_for"] = sanitized
        self._add_site(
            TaintSite(
                site_id=f"{role.value}:{rule.name}@{span.start.byte_offset}:{span.end.byte_offset}",
                role=role,
                rule=rule.name,
                kinds=tuple(sorted(rule.kinds, key=_kind_order)),
                span=span,
                text=text,
                scope_id=context.scope_id,
            )
        )

    def _record_sink(
        self,
        *,
        rule: SinkRule,
        context: _ScopeContext,
        sink_node_id: str,
        sink_span: SourceSpan,
        sink_text: str,
        argument: _Argument | None,
    ) -> None:
        self._add_site(
            TaintSite(
                site_id=f"sink:{rule.name}@{sink_span.start.byte_offset}:{sink_span.end.byte_offset}",
                role=SiteRole.SINK,
                rule=rule.name,
                kinds=(rule.kind,),
                span=sink_span,
                text=sink_text,
                scope_id=context.scope_id,
            )
        )
        argument_span = (
            argument.span if argument is not None and argument.node is not None else None
        )
        argument_text = (
            self.parsed.text_for_span(argument_span) if argument_span is not None else None
        )
        self._sink_occurrences.append(
            _SinkOccurrence(
                rule=rule,
                scope_id=context.scope_id,
                sink_node_id=sink_node_id,
                sink_span=sink_span,
                sink_text=sink_text,
                argument_node_id=argument.node_id if argument is not None else None,
                argument_span=argument_span,
                argument_text=argument_text,
            )
        )

    def _add_site(self, site: TaintSite) -> None:
        if any(existing.site_id == site.site_id for existing in self._sites):
            return
        self._sites.append(site)

    # ----------------------------------------------------- interprocedural

    def _connect_calls(self) -> None:
        for record in self._call_records:
            target = self._resolve_target(record)
            call_node = self.graph.nodes[record.node_id]
            if target is None:
                call_node["resolved"] = False
                if record.propagator is not None:
                    self._apply_propagator(record)
                if record.node_id not in self._configured_calls:
                    self._unresolved_calls += 1
                continue
            target_context = self._contexts[target.scope_id]
            call_node["resolved"] = True
            call_node["target_scopes"] = (target.scope_id,)
            call_node["resolution"] = "same_file"
            self._bind_arguments(record, target_context)
            for return_node in target_context.returns:
                self._add_edge(
                    return_node.node_id,
                    record.node_id,
                    TaintEdgeKind.INTERPROCEDURAL_CALL,
                    record.span,
                )
            if target_context.expression_body is not None:
                self._add_edge(
                    target_context.expression_body,
                    record.node_id,
                    TaintEdgeKind.INTERPROCEDURAL_CALL,
                    record.span,
                )

    def _resolve_target(self, record: _CallRecord) -> ControlFlowGraph | None:
        callee = _normalize_name(record.callee)
        if not callee:
            return None
        functions = [graph for graph in self.cfg.functions if graph.function is not None]
        by_qualified: dict[str, list[ControlFlowGraph]] = {}
        by_name: dict[str, list[ControlFlowGraph]] = {}
        for graph in functions:
            function = graph.function
            assert function is not None
            if function.qualified_name:
                by_qualified.setdefault(function.qualified_name, []).append(graph)
            if function.name:
                by_name.setdefault(function.name, []).append(graph)

        exact = by_qualified.get(callee, ())
        if len(exact) == 1:
            return exact[0]
        if "." not in callee:
            candidates = by_name.get(callee, ())
            if len(candidates) == 1:
                return candidates[0]
            return None
        receiver, _separator, method_name = callee.rpartition(".")
        source_context = self._contexts[record.scope_id]
        if receiver in {"self", "this"}:
            container = (
                source_context.graph.function.container_name
                if source_context.graph.function is not None
                else None
            )
            candidates = [
                graph
                for graph in functions
                if graph.function is not None
                and graph.function.name == method_name
                and graph.function.container_name == container
            ]
            if len(candidates) == 1:
                return candidates[0]
        return None

    def _bind_arguments(self, record: _CallRecord, target: _ScopeContext) -> None:
        parameters = list(target.parameters)
        if (
            target.graph.function is not None
            and target.graph.function.is_method
            and parameters
            and parameters[0].name in {"self", "this"}
        ):
            parameters = parameters[1:]
        for argument in record.arguments:
            if argument.node_id is None:
                continue
            parameter: DFGNode | None = None
            if argument.keyword is not None:
                parameter = next(
                    (item for item in parameters if item.name == argument.keyword),
                    None,
                )
            elif argument.position < len(parameters):
                parameter = parameters[argument.position]
            if parameter is not None:
                self._add_edge(
                    argument.node_id,
                    parameter.node_id,
                    TaintEdgeKind.PARAMETER,
                    argument.span,
                )

    def _apply_propagator(self, record: _CallRecord) -> None:
        propagator = record.propagator
        if propagator is None:
            return
        if propagator.mode in {PropagatorMode.ARGUMENTS, PropagatorMode.BOTH}:
            for argument in record.arguments:
                if argument.node_id is not None:
                    self._add_edge(
                        argument.node_id,
                        record.node_id,
                        TaintEdgeKind.PROPAGATOR,
                        argument.span,
                    )
        if propagator.mode in {PropagatorMode.RECEIVER, PropagatorMode.BOTH}:
            if record.receiver_id is not None:
                self._add_edge(
                    record.receiver_id,
                    record.node_id,
                    TaintEdgeKind.PROPAGATOR,
                    record.span,
                )

    # -------------------------------------------------------------- findings

    def _find_findings(self) -> tuple[TaintFinding, ...]:
        sources = self._source_nodes()
        findings: list[TaintFinding] = []
        seen: set[tuple[object, ...]] = set()
        for occurrence in self._sink_occurrences:
            if occurrence.argument_node_id is None:
                continue
            visible = self._graph_for_kind(occurrence.rule.kind)
            target_id = occurrence.argument_node_id
            if target_id not in visible:
                continue
            ancestors = nx.ancestors(visible, target_id) | {target_id}
            candidates = [
                source_id
                for source_id in sources
                if source_id in ancestors and source_id in visible
            ]
            candidates.sort(
                key=lambda node_id: (
                    visible.nodes[node_id]["span"].start.byte_offset,
                    node_id,
                )
            )
            emitted_for_sink = 0
            for source_id in candidates:
                if emitted_for_sink >= self.config.max_paths_per_sink:
                    break
                if len(findings) >= self.config.max_findings:
                    break
                path = nx.shortest_path(visible, source_id, target_id)
                key = (
                    occurrence.rule.kind,
                    occurrence.sink_span.start.byte_offset,
                    occurrence.sink_span.end.byte_offset,
                    source_id,
                    target_id,
                )
                if key in seen:
                    continue
                seen.add(key)
                finding = self._finding(occurrence, path, visible)
                findings.append(finding)
                emitted_for_sink += 1
            if len(findings) >= self.config.max_findings:
                break
        findings.sort(
            key=lambda finding: (
                finding.sink_span.start.byte_offset,
                finding.source_span.start.byte_offset,
                _kind_order(finding.kind),
                finding.finding_id,
            )
        )
        return tuple(findings)

    def _source_nodes(self) -> list[str]:
        raw = [
            node_id
            for node_id, attributes in self.graph.nodes(data=True)
            if attributes.get("source_rules")
        ]
        kept: list[str] = []
        for node_id in raw:
            span = self.graph.nodes[node_id]["span"]
            nested = False
            for other in raw:
                if other == node_id:
                    continue
                other_span = self.graph.nodes[other]["span"]
                if _contains(other_span, span) and nx.has_path(self.graph, node_id, other):
                    nested = True
                    break
            if not nested:
                kept.append(node_id)
        return kept

    def _graph_for_kind(self, kind: TaintKind) -> nx.DiGraph:
        allowed = [
            node_id
            for node_id, attributes in self.graph.nodes(data=True)
            if kind not in attributes.get("sanitized_for", ())
        ]
        return self.graph.subgraph(allowed).copy()

    def _finding(
        self,
        occurrence: _SinkOccurrence,
        path: list[str],
        graph: nx.DiGraph,
    ) -> TaintFinding:
        steps = self._path_steps(path, graph)
        source_step = steps[0]
        sink_step = TaintPathStep(
            node_id=occurrence.sink_node_id,
            role="sink",
            span=occurrence.sink_span,
            text=occurrence.sink_text,
            scope_id=occurrence.scope_id,
            name=occurrence.rule.name,
            via="sink",
        )
        steps.append(sink_step)
        confidence, notes = self._confidence(path, graph, occurrence)
        source_rule = graph.nodes[path[0]].get("source_rules", ())
        finding_id = (
            f"taint:{occurrence.rule.kind.value}:"
            f"{occurrence.sink_span.start.byte_offset}:"
            f"{source_step.span.start.byte_offset}:"
            f"{occurrence.rule.name}"
        )
        return TaintFinding(
            finding_id=finding_id,
            kind=occurrence.rule.kind,
            title=f"Potential {occurrence.rule.kind.title} flow",
            source_rule=source_rule[0] if source_rule else "unknown",
            sink_rule=occurrence.rule.name,
            source_span=source_step.span,
            source_text=source_step.text,
            sink_span=occurrence.sink_span,
            sink_text=occurrence.sink_text,
            path=tuple(steps),
            confidence=confidence,
            confidence_notes=notes,
            limitations=TAINT_LIMITATIONS,
            argument_span=occurrence.argument_span,
            argument_text=occurrence.argument_text,
        )

    def _path_steps(self, path: list[str], graph: nx.DiGraph) -> list[TaintPathStep]:
        steps: list[TaintPathStep] = []
        for index, node_id in enumerate(path):
            attributes = graph.nodes[node_id]
            role = "source" if attributes.get("source_rules") else attributes.get("kind", "value")
            via = None
            if index > 0:
                edge = graph[path[index - 1]][node_id]
                via = edge.get("kind")
            steps.append(
                TaintPathStep(
                    node_id=node_id,
                    role=role,
                    span=attributes["span"],
                    text=attributes.get("text", ""),
                    scope_id=attributes.get("scope_id", ""),
                    name=attributes.get("name"),
                    via=via,
                )
            )
        return steps

    def _confidence(
        self,
        path: list[str],
        graph: nx.DiGraph,
        occurrence: _SinkOccurrence,
    ) -> tuple[TaintConfidence, tuple[str, ...]]:
        notes: list[str] = [
            "Potential syntactic flow only; exploitability, runtime values, and "
            "blocking validation were not evaluated."
        ]
        if any(site.role is SiteRole.VALIDATOR for site in self._sites):
            notes.append(
                "Validator calls are recorded but do not clear taint unless the "
                "caller configured them as sanitizers."
            )
        edge_kinds = {
            graph[path[index - 1]][node_id].get("kind")
            for index, node_id in enumerate(path)
            if index > 0
        }
        scopes = {graph.nodes[node_id].get("scope_id") for node_id in path}
        confidence = TaintConfidence.HIGH
        if len(scopes) > 1 or edge_kinds & {
            TaintEdgeKind.PARAMETER.value,
            TaintEdgeKind.INTERPROCEDURAL_CALL.value,
            TaintEdgeKind.CLOSURE.value,
        }:
            confidence = TaintConfidence.MEDIUM
            notes.append(
                "Flow crosses a same-file function or closure boundary via syntactic "
                "resolution; imported and dynamic targets are not followed."
            )
        if TaintEdgeKind.PROPAGATOR.value in edge_kinds:
            confidence = TaintConfidence.MEDIUM
            notes.append(
                "Flow passes through an unresolved call covered by an explicit propagator rule."
            )
        if occurrence.rule.target is SinkTarget.ATTRIBUTE_ASSIGNMENT:
            confidence = TaintConfidence.MEDIUM
            notes.append(
                "The sink is a syntactic property assignment; object types and DOM "
                "semantics were not resolved."
            )
        return confidence, tuple(notes)


def _select_argument(arguments: tuple[_Argument, ...], selector: int | str) -> _Argument | None:
    if isinstance(selector, int):
        return next(
            (
                argument
                for argument in arguments
                if argument.keyword is None and argument.position == selector
            ),
            None,
        )
    return next((argument for argument in arguments if argument.keyword == selector), None)


def _assignment_property(node: Node) -> str | None:
    if node.type == "attribute":
        attribute = node.child_by_field_name("attribute")
        if attribute is not None:
            return attribute.text.decode("utf-8", "replace")
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop is not None:
            return prop.text.decode("utf-8", "replace")
    return None


def _graph_to_dict(graph: nx.DiGraph) -> dict[str, object]:
    nodes: list[dict[str, object]] = []
    for node_id, attributes in graph.nodes(data=True):
        nodes.append(
            {
                "node_id": node_id,
                "kind": attributes.get("kind"),
                "span": attributes["span_dict"],
                "text": attributes.get("text", ""),
                "scope_id": attributes.get("scope_id"),
                "name": attributes.get("name"),
                "instruction_id": attributes.get("instruction_id"),
                "block_id": attributes.get("block_id"),
                "call_id": attributes.get("call_id"),
                "resolved": attributes.get("resolved"),
                "source_rules": list(attributes.get("source_rules", ())),
                "sanitized_for": [
                    kind.value
                    for kind in sorted(
                        attributes.get("sanitized_for", ()),
                        key=_kind_order,
                    )
                ],
                "target_scopes": list(attributes.get("target_scopes", ())),
                "resolution": attributes.get("resolution"),
            }
        )
    edges: list[dict[str, object]] = []
    for source, target, attributes in graph.edges(data=True):
        edges.append(
            {
                "source": source,
                "target": target,
                "kind": attributes.get("kind"),
                "kinds": list(attributes.get("kinds", ())),
                "count": attributes.get("count", 1),
                "span": attributes["span_dict"],
            }
        )
    return {"nodes": nodes, "edges": edges}
