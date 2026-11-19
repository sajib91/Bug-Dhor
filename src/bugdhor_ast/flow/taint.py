import re

from dataclasses import dataclass, field
from typing import Any, Iterable

from .ir import IRProgram
from .models import (
    DataFlowResult,
    Definition,
    SourceLocation,
    TaintFinding,
    TaintResult,
    TaintRule,
    Use,
)
from .scopes import ScopeAnalysis


DEFAULT_SOURCES: tuple[TaintRule, ...] = (
    TaintRule(
        "PY-SRC-001", "source", "User input", "input", "python",
        description="Builtin input() reads untrusted user input.",
    ),
    TaintRule(
        "PY-SRC-002", "source", "HTTP query parameter",
        "request.args.get", "python",
        description="HTTP query parameters are untrusted.",
    ),
    TaintRule(
        "PY-SRC-003", "source", "HTTP form parameter",
        "request.form.get", "python",
        description="HTTP form values are untrusted.",
    ),
    TaintRule(
        "PY-SRC-004", "source", "Environment variable",
        "os.getenv", "python",
        description="Environment values are externally controlled.",
    ),
    TaintRule(
        "PY-SRC-005", "source", "Environment mapping",
        "os.environ.get", "python",
        description="Environment values are externally controlled.",
    ),
    TaintRule(
        "PY-SRC-006", "source", "External file input", "open",
        "python",
        description="File contents are treated as external input.",
    ),
    TaintRule(
        "PY-SRC-007", "source", "Standard input",
        "sys.stdin.readline", "python",
        description="Standard input is untrusted.",
    ),
)

DEFAULT_SANITIZERS: tuple[TaintRule, ...] = (
    TaintRule(
        "PY-SAN-001", "sanitizer", "Integer coercion", "int",
        "python",
    ),
    TaintRule(
        "PY-SAN-002", "sanitizer", "Float coercion", "float",
        "python",
    ),
    TaintRule(
        "PY-SAN-003", "sanitizer", "Shell quoting", "shlex.quote",
        "python",
    ),
    TaintRule(
        "PY-SAN-004", "sanitizer", "HTML escaping", "html.escape",
        "python",
    ),
)

DEFAULT_SINKS: tuple[TaintRule, ...] = (
    TaintRule(
        "PY-SNK-001", "sink", "Dynamic evaluation", "eval",
        "python",
    ),
    TaintRule(
        "PY-SNK-002", "sink", "Dynamic execution", "exec",
        "python",
    ),
    TaintRule(
        "PY-SNK-003", "sink", "Operating system command",
        "os.system", "python",
    ),
    TaintRule(
        "PY-SNK-004", "sink", "Subprocess execution",
        "subprocess.run", "python",
    ),
    TaintRule(
        "PY-SNK-005", "sink", "Subprocess execution",
        "subprocess.call", "python",
    ),
    TaintRule(
        "PY-SNK-006", "sink", "Subprocess execution",
        "subprocess.Popen", "python",
    ),
    TaintRule(
        "PY-SNK-007", "sink", "Database query",
        "cursor.execute", "python",
    ),
)


JS_SOURCES: tuple[TaintRule, ...] = (
    TaintRule("JS-SRC-001", "source", "Express query", "req.query",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-002", "source", "Request query", "request.query",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-003", "source", "Express route params", "req.params",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-004", "source", "Express body", "req.body",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-005", "source", "URL query string", "location.search",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-006", "source", "Window URL query",
              "window.location.search", "javascript", confidence="medium"),
    TaintRule("JS-SRC-007", "source", "Document URL", "document.URL",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-008", "source", "Document referrer",
              "document.referrer", "javascript", confidence="medium"),
    TaintRule("JS-SRC-009", "source", "DOM input value",
              "document.getElementById", "javascript", confidence="low"),
    TaintRule("JS-SRC-010", "source", "Prompt input", "prompt",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-011", "source", "Process environment", "process.env",
              "javascript", confidence="medium"),
    TaintRule("JS-SRC-012", "source", "Local storage data",
              "localStorage.getItem", "javascript", confidence="medium"),
    TaintRule("JS-SRC-013", "source", "URL search params",
              "URLSearchParams", "javascript", confidence="medium"),
    TaintRule("JS-SRC-014", "source", "User agent", "navigator.userAgent",
              "javascript", confidence="low"),
)

JS_SANITIZERS: tuple[TaintRule, ...] = (
    TaintRule("JS-SAN-001", "sanitizer", "URI encoding",
              "encodeURIComponent", "javascript"),
    TaintRule("JS-SAN-002", "sanitizer", "DOMPurify sanitizer",
              "DOMPurify.sanitize", "javascript"),
    TaintRule("JS-SAN-003", "sanitizer", "Numeric coercion", "Number",
              "javascript"),
    TaintRule("JS-SAN-004", "sanitizer", "Integer parsing", "parseInt",
              "javascript"),
    TaintRule("JS-SAN-005", "sanitizer", "Float parsing", "parseFloat",
              "javascript"),
    TaintRule("JS-SAN-006", "sanitizer", "Project HTML sanitizer",
              "sanitizeHtml", "javascript"),
)

JS_SINKS: tuple[TaintRule, ...] = (
    TaintRule("JS-SNK-001", "sink", "Dynamic evaluation", "eval",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-002", "sink", "Dynamic function construction",
              "Function", "javascript", confidence="high"),
    TaintRule("JS-SNK-003", "sink", "DOM HTML injection", "innerHTML",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-004", "sink", "DOM outer HTML injection",
              "outerHTML", "javascript", confidence="high"),
    TaintRule("JS-SNK-005", "sink", "Document write", "document.write",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-006", "sink", "Child process execution",
              "child_process.exec", "javascript", confidence="high"),
    TaintRule("JS-SNK-007", "sink", "Child process execution",
              "execSync", "javascript", confidence="high"),
    TaintRule("JS-SNK-008", "sink", "Child process spawn", "spawn",
              "javascript", confidence="medium"),
    TaintRule("JS-SNK-009", "sink", "Database query", "db.query",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-010", "sink", "Database query", "connection.query",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-011", "sink", "Database query", "stmt.executeQuery",
              "javascript", confidence="high"),
    TaintRule("JS-SNK-012", "sink", "SQL query", "sql.query",
              "javascript", confidence="high"),
)

JAVA_SOURCES: tuple[TaintRule, ...] = (
    TaintRule("JAVA-SRC-001", "source", "Servlet request parameter",
              "request.getParameter", "java", confidence="medium"),
    TaintRule("JAVA-SRC-002", "source", "Request parameter",
              "req.getParameter", "java", confidence="medium"),
    TaintRule("JAVA-SRC-003", "source", "Request parameter values",
              "getParameterValues", "java", confidence="medium"),
    TaintRule("JAVA-SRC-004", "source", "HTTP header", "getHeader",
              "java", confidence="medium"),
    TaintRule("JAVA-SRC-005", "source", "HTTP query string",
              "getQueryString", "java", confidence="medium"),
    TaintRule("JAVA-SRC-006", "source", "Environment variable",
              "System.getenv", "java", confidence="medium"),
    TaintRule("JAVA-SRC-007", "source", "System property",
              "System.getProperty", "java", confidence="medium"),
    TaintRule("JAVA-SRC-008", "source", "File input stream",
              "FileInputStream", "java", confidence="medium"),
    TaintRule("JAVA-SRC-009", "source", "File lines", "Files.readAllLines",
              "java", confidence="medium"),
    TaintRule("JAVA-SRC-010", "source", "Scanner input", "Scanner",
              "java", confidence="low"),
    TaintRule("JAVA-SRC-011", "source", "Generic request parameter",
              "getParameter", "java", confidence="low"),
)

JAVA_SANITIZERS: tuple[TaintRule, ...] = (
    TaintRule("JAVA-SAN-001", "sanitizer", "Integer parsing",
              "Integer.parseInt", "java"),
    TaintRule("JAVA-SAN-002", "sanitizer", "Long parsing",
              "Long.parseLong", "java"),
    TaintRule("JAVA-SAN-003", "sanitizer", "Double parsing",
              "Double.parseDouble", "java"),
    TaintRule("JAVA-SAN-004", "sanitizer", "URL encoding",
              "URLEncoder.encode", "java"),
    TaintRule("JAVA-SAN-005", "sanitizer", "Project sanitizer",
              "sanitize", "java"),
    TaintRule("JAVA-SAN-006", "sanitizer", "HTML escaping",
              "escapeHtml", "java"),
)

JAVA_SINKS: tuple[TaintRule, ...] = (
    TaintRule("JAVA-SNK-001", "sink", "Runtime command execution",
              "Runtime.getRuntime().exec", "java", confidence="high"),
    TaintRule("JAVA-SNK-002", "sink", "Process builder",
              "ProcessBuilder", "java", confidence="high"),
    TaintRule("JAVA-SNK-003", "sink", "SQL query execution",
              "executeQuery", "java", confidence="high"),
    TaintRule("JAVA-SNK-004", "sink", "SQL update execution",
              "executeUpdate", "java", confidence="high"),
    TaintRule("JAVA-SNK-005", "sink", "Object deserialization",
              "ObjectInputStream", "java", confidence="high"),
    TaintRule("JAVA-SNK-006", "sink", "Object read", "readObject",
              "java", confidence="high"),
    TaintRule("JAVA-SNK-007", "sink", "Script engine evaluation",
              "ScriptEngine.eval", "java", confidence="high"),
    TaintRule("JAVA-SNK-008", "sink", "Dynamic evaluation", "eval",
              "java", confidence="medium"),
)


TAINT_LIMITATIONS = (
    "Legacy note: Phase 3 taint analysis was implemented only for Python; "
    "Phase 4 adds JavaScript and Java rule packs without changing the "
    "original Python rule set.",
    "Matching is syntactic: rules match call names, property names, and "
    "variable definitions, not library semantics or string contents.",
    "Propagation covers assignments, call arguments, returns, simple "
    "expressions, and conservative Python slots; it does not model full "
    "heap layouts, dynamic dispatch, or reflection.",
    "Sanitizers are sink-agnostic and user-configurable; a sanitizer match "
    "removes taint for the matched rule set.",
    "Interprocedural taint uses bounded call-site mapping with recursion "
    "safeguards; unresolved calls do not receive argument-derived taint.",
    "Object and container flow is conservative and Python-first: object "
    "fields, dictionary/subscript values, simple aliases, and string "
    "concatenation are tracked textually, not through a heap model.",
)


@dataclass(frozen=True)
class LanguageRulePack:
    language: str
    sources: tuple[TaintRule, ...] = ()
    sanitizers: tuple[TaintRule, ...] = ()
    sinks: tuple[TaintRule, ...] = ()

    @classmethod
    def from_dict(
        cls,
        language: str,
        data: dict[str, Any] | None,
    ) -> "LanguageRulePack":
        defaults = DEFAULT_PACKS.get(
            language,
            LanguageRulePack(language),
        )
        if not data:
            return defaults
        rules: dict[str, tuple[TaintRule, ...]] = {}
        for kind in ("sources", "sanitizers", "sinks"):
            if kind in data:
                rules[kind] = _parse_rules(kind, data[kind], language)
            else:
                rules[kind] = getattr(defaults, kind)
        return cls(
            language=language,
            sources=rules["sources"],
            sanitizers=rules["sanitizers"],
            sinks=rules["sinks"],
        )

    def all_rules(self) -> tuple[TaintRule, ...]:
        return self.sources + self.sanitizers + self.sinks

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "sources": [rule.to_dict() for rule in self.sources],
            "sanitizers": [rule.to_dict() for rule in self.sanitizers],
            "sinks": [rule.to_dict() for rule in self.sinks],
        }


DEFAULT_PACKS: dict[str, LanguageRulePack] = {
    "python": LanguageRulePack(
        "python", DEFAULT_SOURCES, DEFAULT_SANITIZERS, DEFAULT_SINKS
    ),
    "javascript": LanguageRulePack(
        "javascript", JS_SOURCES, JS_SANITIZERS, JS_SINKS
    ),
    "java": LanguageRulePack(
        "java", JAVA_SOURCES, JAVA_SANITIZERS, JAVA_SINKS
    ),
}


def _parse_rules(
    kind: str,
    values: Any,
    language: str = "python",
) -> tuple[TaintRule, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"Taint {kind} must be a list")
    parsed: list[TaintRule] = []
    for index, item in enumerate(values):
        if isinstance(item, str):
            item = {"pattern": item}
        if not isinstance(item, dict):
            raise ValueError(
                f"Taint {kind} rule {index} must be a string or object"
            )
        pattern = str(item.get("pattern", "")).strip()
        if not pattern:
            raise ValueError(
                f"Taint {kind} rule {index} needs a pattern"
            )
        parsed.append(
            TaintRule(
                id=str(item.get("id", f"CUSTOM-{kind}-{index}")),
                kind=kind[:-1],
                name=str(item.get("name", pattern)),
                pattern=pattern,
                language=str(item.get("language", language)),
                argument_index=int(item.get("argument_index", 0)),
                description=str(item.get("description", "")),
                confidence=str(item.get("confidence", "medium")),
            )
        )
    return tuple(parsed)


@dataclass(frozen=True)
class TaintConfig:
    """Language-aware taint rules with Phase 3 field compatibility."""

    sources: tuple[TaintRule, ...] = DEFAULT_SOURCES
    sanitizers: tuple[TaintRule, ...] = DEFAULT_SANITIZERS
    sinks: tuple[TaintRule, ...] = DEFAULT_SINKS
    language_packs: dict[str, LanguageRulePack] = field(
        default_factory=lambda: dict(DEFAULT_PACKS)
    )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any] | None,
    ) -> "TaintConfig":
        if not data:
            return cls()
        if not isinstance(data, dict):
            raise ValueError("Taint configuration must be a JSON object")

        legacy: dict[str, tuple[TaintRule, ...] | None] = {}
        for kind in ("sources", "sanitizers", "sinks"):
            legacy[kind] = (
                _parse_rules(kind, data[kind]) if kind in data else None
            )

        packs = dict(DEFAULT_PACKS)
        raw_packs = data.get("language_packs", data.get("languages"))
        if raw_packs is not None:
            if not isinstance(raw_packs, dict):
                raise ValueError("language_packs must be a JSON object")
            for language, raw in raw_packs.items():
                if not isinstance(raw, dict):
                    raise ValueError(
                        f"Taint pack for {language} must be an object"
                    )
                packs[str(language)] = LanguageRulePack.from_dict(
                    str(language), raw
                )

        python_pack = packs.get("python", DEFAULT_PACKS["python"])
        python_pack = LanguageRulePack(
            language="python",
            sources=(
                legacy["sources"]
                if legacy["sources"] is not None
                else python_pack.sources
            ),
            sanitizers=(
                legacy["sanitizers"]
                if legacy["sanitizers"] is not None
                else python_pack.sanitizers
            ),
            sinks=(
                legacy["sinks"]
                if legacy["sinks"] is not None
                else python_pack.sinks
            ),
        )
        packs["python"] = python_pack
        return cls(
            sources=python_pack.sources,
            sanitizers=python_pack.sanitizers,
            sinks=python_pack.sinks,
            language_packs=packs,
        )

    @classmethod
    def from_json_file(cls, path: str) -> "TaintConfig":
        import json

        from pathlib import Path

        file_path = Path(path)
        text = file_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid taint configuration JSON: {error}"
            ) from error
        return cls.from_dict(data)

    def rules_for(self, language: str) -> LanguageRulePack:
        return self.language_packs.get(
            language,
            LanguageRulePack(language),
        )

    def all_rules(self) -> tuple[TaintRule, ...]:
        """Backward-compatible Python rule view."""
        return self.sources + self.sanitizers + self.sinks

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": [rule.to_dict() for rule in self.sources],
            "sanitizers": [rule.to_dict() for rule in self.sanitizers],
            "sinks": [rule.to_dict() for rule in self.sinks],
            "language_packs": {
                language: pack.to_dict()
                for language, pack in sorted(self.language_packs.items())
            },
        }


@dataclass(frozen=True)
class _TaintState:
    source_rule: str
    source_name: str
    source_location: SourceLocation
    path: tuple[dict[str, Any], ...]
    sanitizers: tuple[str, ...] = ()

    def extended(
        self,
        step: dict[str, Any],
    ) -> "_TaintState":
        return _TaintState(
            source_rule=self.source_rule,
            source_name=self.source_name,
            source_location=self.source_location,
            path=self.path + (step,),
            sanitizers=self.sanitizers,
        )


_QUALIFIED_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_STRING_RE = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")
_SLOT_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\[[^\]\n]+\])+"
)
_ALIAS_RE = re.compile(
    r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"
)

_CONTAINER_STATEMENT_KINDS = {
    "function",
    "class",
    "loop",
    "if",
    "else",
    "try",
    "handler",
    "finally",
    "params",
    "noop",
}


class TaintAnalyzer:
    """Language-aware taint analysis over a documented syntactic subset."""

    MAX_CALLEE_PASSES = 2
    MAX_ITERATION_FLOOR = 32
    MAX_ITERATION_CEILING = 500

    def __init__(
        self,
        scope_analysis: ScopeAnalysis,
        ir_program: IRProgram,
        data_flow: DataFlowResult,
        config: TaintConfig | None = None,
    ) -> None:
        self.scope_analysis = scope_analysis
        self.ir_program = ir_program
        self.data_flow = data_flow
        self.config = config or TaintConfig()
        self.language = scope_analysis.language
        self.rules = self.config.rules_for(self.language)
        self._tainted_defs: dict[str, _TaintState] = {}
        self._sanitized_defs: set[str] = set()
        self._tainted_statements: dict[str, _TaintState] = {}
        self._clean_statements: set[str] = set()
        self._return_taint: dict[str, _TaintState] = {}
        self._findings: dict[str, TaintFinding] = {}
        self._defs_by_statement: dict[str, list[str]] = {}
        self._uses_by_statement: dict[str, list[str]] = {}
        self._def_use: dict[str, list[str]] = {}
        self._definitions: dict[str, Definition] = {}
        self._uses: dict[str, Use] = {}
        self._slot_taint: dict[str, _TaintState] = {}
        self._aliases: dict[str, str] = {}
        self._param_taint: dict[tuple[str, str, str], _TaintState] = {}
        self._callee_passes: dict[tuple[int, str], int] = {}
        self._scope_by_id = {
            scope.id: scope for scope in scope_analysis.scopes
        }
        for scope in data_flow.scopes:
            for definition in scope.definitions:
                self._definitions[definition.id] = definition
                self._defs_by_statement.setdefault(
                    definition.statement_id, []
                ).append(definition.id)
            for use in scope.uses:
                self._uses[use.id] = use
                self._uses_by_statement.setdefault(
                    use.statement_id, []
                ).append(use.id)
            for use_id, def_ids in scope.def_use_chains.items():
                self._def_use[use_id] = list(def_ids)
        self._function_keys = self._build_function_keys()
        self._scope_by_function_key = {
            key: scope_id for scope_id, key in self._function_keys.items()
        }
        self._summaries = {
            item.symbol_id: item
            for item in data_flow.function_summaries
            if item.symbol_id
        }
        self._params_by_key = self._build_parameter_map()
        self._calls = list(scope_analysis.calls)
        self._call_by_statement = {
            call.statement_id: call for call in self._calls
        }
        statements = ir_program.statements
        self._max_iterations = min(
            max(
                len(statements) * 2 + 8,
                self.MAX_ITERATION_FLOOR,
            ),
            self.MAX_ITERATION_CEILING,
        )

    def analyze(self) -> TaintResult:
        statements = sorted(
            self.ir_program.statements,
            key=lambda item: (
                item.location.line,
                item.location.column,
                item.id,
            ),
        )
        for iteration in range(self._max_iterations):
            changed = False
            self._callee_passes = {}
            for statement in statements:
                if self._visit_statement(statement, iteration):
                    changed = True
            if not changed:
                break

        return TaintResult(
            language=self.language,
            findings=sorted(
                self._findings.values(),
                key=lambda item: (
                    item.sink_location.line,
                    item.sink_location.column,
                    item.id,
                ),
            ),
            rules=list(self.rules.all_rules()),
            limitations=TAINT_LIMITATIONS,
        )

    def _build_function_keys(self) -> dict[str, str]:
        keys: dict[str, str] = {}
        for scope in self.scope_analysis.scopes:
            if scope.kind not in {"function", "lambda"}:
                continue
            symbol = next(
                (
                    item
                    for item in self.scope_analysis.symbols
                    if item.name == scope.name
                    and item.scope_id == scope.parent_id
                    and item.symbol_type == "function"
                ),
                None,
            )
            keys[scope.id] = (
                symbol.id if symbol else f"scope:{scope.id}"
            )
        return keys

    def _build_parameter_map(
        self,
    ) -> dict[str, tuple[tuple[int, str, str], ...]]:
        result: dict[str, tuple[tuple[int, str, str], ...]] = {}
        for summary in self.data_flow.function_summaries:
            key = summary.symbol_id or f"name:{summary.name}"
            scope_id = self._scope_by_function_key.get(key, "")
            params: list[tuple[int, str, str]] = []
            for index, name in enumerate(summary.parameters):
                symbol = next(
                    (
                        item
                        for item in self.scope_analysis.symbols
                        if item.scope_id == scope_id
                        and item.name == name
                        and item.symbol_type == "parameter"
                    ),
                    None,
                )
                params.append((index, symbol.id if symbol else "", name))
            result[key] = tuple(params)
        return result

    @staticmethod
    def _normalize_call_name(name: str) -> str:
        normalized = name.strip()
        if normalized.startswith("new "):
            normalized = normalized[4:]
        previous = None
        while previous != normalized:
            previous = normalized
            normalized = re.sub(r"\([^()]*\)", "", normalized)
        return normalized

    @classmethod
    def _name_candidates(cls, name: str) -> tuple[str, ...]:
        candidates = [name.strip()]
        normalized = cls._normalize_call_name(name)
        if normalized and normalized not in candidates:
            candidates.append(normalized)
        return tuple(candidates)

    @classmethod
    def _expression_candidates(cls, text: str) -> tuple[str, ...]:
        cleaned = _STRING_RE.sub(" ", text)
        cleaned = re.sub(r"//[^\n]*", " ", cleaned)
        return tuple(_QUALIFIED_RE.findall(cleaned))

    def _candidates(self, statement) -> tuple[str, ...]:
        values: list[str] = []
        for call in statement.calls:
            values.extend(self._name_candidates(call))
        for argument in statement.call_arguments:
            values.extend(self._expression_candidates(argument))

        # Compound statements contain their body text. Scanning that text
        # here would duplicate findings at the enclosing function/loop line.
        if statement.kind not in _CONTAINER_STATEMENT_KINDS:
            values.extend(self._expression_candidates(statement.text))
            for use_id in self._uses_by_statement.get(statement.id, []):
                use = self._uses.get(use_id)
                if use is not None and use.name:
                    values.append(use.name)
        return tuple(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _matches_candidate(candidate: str, pattern: str) -> bool:
        parts = candidate.split(".")
        return (
            candidate == pattern
            or candidate.startswith(pattern + ".")
            or candidate.endswith("." + pattern)
            or pattern in parts
        )

    def _match(
        self,
        names: str | Iterable[str],
        rules: tuple[TaintRule, ...],
    ) -> TaintRule | None:
        candidates = [names] if isinstance(names, str) else list(names)
        for rule in rules:
            if rule.language not in {"", "*", self.language}:
                continue
            for candidate in candidates:
                for variant in self._name_candidates(candidate):
                    if self._matches_candidate(variant, rule.pattern):
                        return rule
        return None

    def _source_state(
        self,
        statement,
        candidates: tuple[str, ...],
    ) -> _TaintState | None:
        for call_name in statement.calls:
            rule = self._match(call_name, self.rules.sources)
            if rule is not None:
                return self._new_source_state(
                    rule, call_name, statement
                )
        for candidate in candidates:
            rule = self._match(candidate, self.rules.sources)
            if rule is not None:
                return self._new_source_state(
                    rule, candidate, statement
                )
        return None

    def _new_source_state(
        self,
        rule: TaintRule,
        name: str,
        statement,
    ) -> _TaintState:
        return _TaintState(
            source_rule=rule.id,
            source_name=name,
            source_location=statement.location,
            path=(
                {
                    "kind": "source",
                    "rule": rule.id,
                    "name": name,
                    "location": statement.location.to_dict(),
                    "statement_id": statement.id,
                },
            ),
        )

    def _normalize_slot(self, slot: str) -> str:
        normalized = re.sub(r"\s+", "", slot)
        match = _IDENTIFIER_RE.match(normalized)
        if match is None:
            return normalized
        base = match.group(0)
        seen: set[str] = set()
        while base in self._aliases and base not in seen:
            seen.add(base)
            base = self._aliases[base]
        remainder = normalized[len(match.group(0)):]
        # A bracketed slot names one contained value. Collapsing keys and
        # indexes is conservative: data["a"] and data["b"] share a slot.
        remainder = re.sub(r"\[[^\]\n]*\]", "[]", remainder)
        return base + remainder

    def _slot_writes(self, statement) -> list[str]:
        if self.language != "python":
            return []
        slots = [
            match.group(0)
            for match in _SLOT_RE.finditer(statement.text)
            if re.match(
                r"\s*(?<![=!<>])=\s*(?!=)",
                statement.text[match.end():],
            )
        ]
        slots.extend(self._append_slots(statement.text))
        return list(dict.fromkeys(slots))

    @staticmethod
    def _append_slots(text: str) -> list[str]:
        slots: list[str] = []
        pattern = r"([A-Za-z_$][A-Za-z0-9_$]*)\.append\s*\("
        for match in re.finditer(pattern, text):
            start = match.end()
            depth = 1
            index = start
            while index < len(text) and depth:
                if text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                index += 1
            if depth:
                continue
            argument = text[start:index - 1].strip()
            if argument:
                slots.append(f"{match.group(1)}[]")
        return slots

    def _slot_reads(self, statement) -> list[str]:
        if self.language != "python":
            return []
        return list(
            dict.fromkeys(
                match.group(0)
                for match in _SLOT_RE.finditer(statement.text)
            )
        )

    @staticmethod
    def _same_source(
        left: _TaintState,
        right: _TaintState,
    ) -> bool:
        return (
            left.source_rule == right.source_rule
            and left.source_name == right.source_name
            and left.source_location.line == right.source_location.line
            and left.source_location.column == right.source_location.column
        )

    @classmethod
    def _is_better_state(
        cls,
        existing: _TaintState | None,
        candidate: _TaintState,
    ) -> bool:
        if existing is None or not cls._same_source(existing, candidate):
            return True
        return len(candidate.path) < len(existing.path)

    def _taint_definitions(
        self,
        statement,
        state: _TaintState,
    ) -> bool:
        changed = False
        for definition_id in self._defs_by_statement.get(
            statement.id, []
        ):
            if definition_id in self._sanitized_defs:
                continue
            definition = self._definitions[definition_id]
            step = {
                "kind": "assignment",
                "name": definition.name,
                "location": definition.location.to_dict(),
                "statement_id": statement.id,
            }
            new_state = state.extended(step)
            existing = self._tainted_defs.get(definition_id)
            if not self._is_better_state(existing, new_state):
                continue
            self._tainted_defs[definition_id] = new_state
            changed = True
        return changed

    def _taint_slots(
        self,
        statement,
        state: _TaintState,
    ) -> bool:
        changed = False
        for slot in self._slot_writes(statement):
            key = self._normalize_slot(slot)
            step = {
                "kind": "slot_write",
                "name": slot,
                "location": statement.location.to_dict(),
                "statement_id": statement.id,
            }
            new_state = state.extended(step)
            existing = self._slot_taint.get(key)
            if not self._is_better_state(existing, new_state):
                continue
            self._slot_taint[key] = new_state
            changed = True
        return changed

    def _clean_targets(self, statement) -> bool:
        changed = False
        for definition_id in self._defs_by_statement.get(
            statement.id, []
        ):
            self._sanitized_defs.add(definition_id)
            if definition_id in self._tainted_defs:
                del self._tainted_defs[definition_id]
                changed = True
        for slot in self._slot_writes(statement):
            key = self._normalize_slot(slot)
            if key in self._slot_taint:
                del self._slot_taint[key]
                changed = True
        return changed

    def _serialize_alias(self, statement) -> bool:
        if self.language != "python":
            return False
        match = _ALIAS_RE.fullmatch(statement.text)
        if match is None:
            return False
        source = self._normalize_slot(match.group(2))
        if self._aliases.get(match.group(1)) == source:
            return False
        self._aliases[match.group(1)] = source
        return True

    def _dedupe_states(
        self,
        states: list[_TaintState],
    ) -> list[_TaintState]:
        # Keep the shortest path per source occurrence. Including path length
        # in the key lets re-visiting a source statement extend its own path
        # on every pass, which prevents the fixpoint loop from converging.
        best: dict[tuple[str, str, int, int], _TaintState] = {}
        for state in states:
            key = (
                state.source_rule,
                state.source_name,
                state.source_location.line,
                state.source_location.column,
            )
            current = best.get(key)
            if current is None or len(state.path) < len(current.path):
                best[key] = state
        return list(best.values())

    def _source_states(
        self,
        statement,
        candidates: tuple[str, ...],
    ) -> list[_TaintState]:
        states: list[_TaintState] = []
        for use_id in self._uses_by_statement.get(statement.id, []):
            for def_id in self._def_use.get(use_id, []):
                state = self._tainted_defs.get(def_id)
                if state is not None:
                    states.append(state)
        statement_state = self._tainted_statements.get(
            statement.id
        )
        if (
            statement_state is not None
            and statement_id_clean(statement.id, self._clean_statements)
        ):
            states.append(statement_state)
        for slot in self._slot_reads(statement):
            state = self._slot_taint.get(self._normalize_slot(slot))
            if state is not None:
                step = {
                    "kind": "slot_read",
                    "name": slot,
                    "location": statement.location.to_dict(),
                    "statement_id": statement.id,
                }
                states.append(state.extended(step))
        for candidate in candidates:
            for def_id, state in self._tainted_defs.items():
                definition = self._definitions.get(def_id)
                if definition is not None and definition.name == candidate:
                    states.append(state)
        return self._dedupe_states(states)

    def _resolve_name(
        self,
        scope_id: str,
        name: str,
    ) -> str | None:
        current: str | None = scope_id
        while current is not None:
            scope = self._scope_by_id.get(current)
            if scope is None:
                return None
            symbol_id = scope.symbol_ids.get(name)
            if symbol_id:
                return symbol_id
            current = scope.parent_id
        return None

    def _states_for_argument(
        self,
        statement,
        argument: str,
    ) -> list[_TaintState]:
        argument = argument.strip()
        states: list[_TaintState] = []
        if self.language == "python":
            for slot in self._slot_reads_from_text(argument):
                state = self._slot_taint.get(
                    self._normalize_slot(slot)
                )
                if state is not None:
                    states.append(state)
        symbol_id = self._resolve_name(statement.scope_id, argument)
        for definition_id, state in self._tainted_defs.items():
            definition = self._definitions[definition_id]
            if (
                symbol_id and definition.symbol_id == symbol_id
            ) or definition.name == argument:
                states.append(state)
        return self._dedupe_states(states)

    def _slot_reads_from_text(self, text: str) -> list[str]:
        return list(
            dict.fromkeys(
                match.group(0) for match in _SLOT_RE.finditer(text)
            )
        )

    def _resolve_callee(self, call) -> str | None:
        if call.symbol_id and call.symbol_id in self._params_by_key:
            return call.symbol_id
        base_name = call.name.rsplit(".", 1)[-1]
        normalized = self._normalize_call_name(base_name)
        for key, summary in self._summaries.items():
            if summary.name in {base_name, normalized, call.name}:
                return key
        return None

    def _allow_callee(
        self,
        iteration: int,
        key: str,
    ) -> bool:
        cache_key = (iteration, key)
        passes = self._callee_passes.get(cache_key, 0)
        if passes >= self.MAX_CALLEE_PASSES:
            return False
        self._callee_passes[cache_key] = passes + 1
        return True

    def _map_arguments(
        self,
        statement,
        call,
        callee_key: str,
    ) -> bool:
        params = self._params_by_key.get(callee_key, ())
        changed = False
        for index, argument in enumerate(call.arguments):
            if index >= len(params):
                break
            _, param_id, param_name = params[index]
            if not param_id:
                continue
            for state in self._states_for_argument(statement, argument):
                cache_key = (callee_key, param_id, call.statement_id)
                new_state = state.extended(
                    {
                        "kind": "argument",
                        "name": argument.strip(),
                        "parameter": param_name,
                        "location": call.location.to_dict(),
                        "statement_id": call.statement_id,
                    }
                )
                existing = self._param_taint.get(cache_key)
                if self._is_better_state(existing, new_state):
                    self._param_taint[cache_key] = new_state
                    changed = True
        return changed

    def _seed_parameters(self, statement) -> bool:
        changed = False
        for definition_id in self._defs_by_statement.get(
            statement.id, []
        ):
            definition = self._definitions[definition_id]
            if not definition.symbol_id:
                continue
            states = [
                state
                for (_, param_id, _), state in self._param_taint.items()
                if param_id == definition.symbol_id
            ]
            if not states:
                continue
            merged = self._merge_states(statement, states)
            if definition_id in self._sanitized_defs:
                continue
            step = {
                "kind": "parameter",
                "name": definition.name,
                "location": definition.location.to_dict(),
                "statement_id": statement.id,
            }
            new_state = merged.extended(step)
            if self._tainted_defs.get(definition_id) != new_state:
                self._tainted_defs[definition_id] = new_state
                changed = True
        return changed

    def _visit_statement(self, statement, iteration: int) -> bool:
        changed = False
        candidates = self._candidates(statement)
        source_state = self._source_state(statement, candidates)
        sanitizer_rule = self._match(
            candidates, self.rules.sanitizers
        )
        sink_rule = self._match(candidates, self.rules.sinks)

        if source_state is not None:
            if self._tainted_statements.get(
                statement.id
            ) != source_state:
                self._tainted_statements[statement.id] = source_state
                changed = True
            if self._taint_definitions(statement, source_state):
                changed = True
            if self._taint_slots(statement, source_state):
                changed = True

        if sanitizer_rule is not None:
            self._clean_statements.add(statement.id)
            if self._clean_targets(statement):
                changed = True
            return changed

        if self._serialize_alias(statement):
            changed = True
        if self._seed_parameters(statement):
            changed = True

        call = self._call_by_statement.get(statement.id)
        if call is not None:
            callee_key = self._resolve_callee(call)
            if callee_key is not None:
                if self._map_arguments(statement, call, callee_key):
                    changed = True
                returned = self._return_taint.get(callee_key)
                if (
                    returned is not None
                    and self._allow_callee(iteration, callee_key)
                ):
                    step = {
                        "kind": "call",
                        "name": call.name,
                        "location": call.location.to_dict(),
                        "statement_id": call.statement_id,
                    }
                    if self._taint_definitions(
                        statement, returned.extended(step)
                    ):
                        changed = True

        states = self._source_states(statement, candidates)
        if states:
            merged = self._merge_states(statement, states)
            if statement.kind == "return":
                key = self._function_keys.get(statement.scope_id, "")
                existing = self._return_taint.get(key) if key else None
                if key and self._is_better_state(existing, merged):
                    self._return_taint[key] = merged
                    changed = True
            if self._taint_definitions(statement, merged):
                changed = True
            if self._taint_slots(statement, merged):
                changed = True

        if sink_rule is not None:
            for state in states:
                self._record_finding(statement, sink_rule, state)
        return changed

    def _merge_states(
        self,
        statement,
        states: list[_TaintState],
    ) -> _TaintState:
        first = states[0]
        for state in states[1:]:
            if state.source_location.line < first.source_location.line:
                first = state
        return first

    def _record_finding(
        self,
        statement,
        sink_rule: TaintRule,
        state: _TaintState,
    ) -> None:
        finding_id = (
            f"taint:{state.source_location.line}:"
            f"{state.source_location.column}:"
            f"{statement.location.line}:{statement.location.column}:"
            f"{sink_rule.id}"
        )
        if finding_id in self._findings:
            return
        path = list(state.path) + [
            {
                "kind": "sink",
                "rule": sink_rule.id,
                "name": sink_rule.name,
                "location": statement.location.to_dict(),
                "statement_id": statement.id,
            }
        ]
        self._findings[finding_id] = TaintFinding(
            id=finding_id,
            source_rule=state.source_rule,
            source_name=state.source_name,
            source_location=state.source_location,
            sink_rule=sink_rule.id,
            sink_name=sink_rule.name,
            sink_location=statement.location,
            path=path,
            confidence=sink_rule.confidence or "medium",
            sanitizers=state.sanitizers,
            limitations=TAINT_LIMITATIONS,
        )


def statement_id_clean(
    statement_id: str,
    clean_statements: set[str],
) -> bool:
    return statement_id not in clean_statements
