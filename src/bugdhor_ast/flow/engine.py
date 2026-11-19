from pathlib import Path
from typing import Any

from ..detection.models import Diagnostic, RuleMetadata
from ..engine import BugDhorASTEngine
from ..languages import detect_language
from .cfg import build_cfgs
from .dataflow import DataFlowAnalyzer
from .ir import IRBuilder
from .models import FlowAnalysisResult, TaintResult
from .profiles import get_profile
from .scopes import ScopeAnalyzer
from .taint import TaintAnalyzer, TaintConfig
from .tree import FlowContext


ENGINE_LIMITATIONS = (
    "Scope and data-flow facts are syntax-scoped and do not model "
    "dynamic dispatch, reflection, heap aliasing, or string contents.",
    "Control-flow graphs are generated for module, function, and class "
    "scopes; block and comprehension scopes remain symbol/data-flow "
    "scopes only.",
    "Syntax-error files return empty analysis sections rather than "
    "partial or fabricated flow facts.",
)

TAINT_DIAGNOSTIC_RULE = RuleMetadata(
    "PY-TAINT001",
    "Potential tainted data flow",
    "Untrusted data reaches a sensitive sink through tracked flow.",
    "warning",
    "python",
    "Validate, constrain, or sanitize the value before using it at "
    "the sink.",
    limitations=(
        "Syntactic Python subset; medium confidence and manual review "
        "required.",
    ),
)

JS_TAINT_DIAGNOSTIC_RULE = RuleMetadata(
    "JS-TAINT001",
    "Potential tainted data flow",
    "Untrusted data reaches a sensitive JavaScript sink.",
    "warning",
    "javascript",
    "Validate, encode, or sanitize the value before using it at "
    "the sink.",
    limitations=(
        "Syntactic JavaScript subset; manual review required.",
    ),
)

JAVA_TAINT_DIAGNOSTIC_RULE = RuleMetadata(
    "JAVA-TAINT001",
    "Potential tainted data flow",
    "Untrusted data reaches a sensitive Java sink.",
    "warning",
    "java",
    "Validate, encode, or sanitize the value before using it at "
    "the sink.",
    limitations=(
        "Syntactic Java subset; not a complete Java security analysis.",
    ),
)


def _diagnostic_rule(finding):
    if finding.sink_rule.startswith("JS-"):
        return JS_TAINT_DIAGNOSTIC_RULE
    if finding.sink_rule.startswith("JAVA-"):
        return JAVA_TAINT_DIAGNOSTIC_RULE
    return TAINT_DIAGNOSTIC_RULE


class FlowEngine:
    """Public facade for scope, CFG, data-flow, and taint analysis."""

    def __init__(
        self,
        taint_config: TaintConfig | dict[str, Any] | None = None,
    ) -> None:
        self.ast_engine = BugDhorASTEngine()
        if isinstance(taint_config, dict):
            self.taint_config = TaintConfig.from_dict(taint_config)
        else:
            self.taint_config = taint_config or TaintConfig()

    def analyze_source(
        self,
        source_code: str,
        language_name: str,
        *,
        file: str = "<source>",
        taint_config: TaintConfig | dict[str, Any] | None = None,
    ) -> FlowAnalysisResult:
        profile = get_profile(language_name)
        root = self.ast_engine.get_parser(
            language_name
        ).parse(source_code.encode("utf-8")).root_node
        result = FlowAnalysisResult(
            file=file,
            language=language_name,
            has_syntax_errors=root.has_error,
            limitations=ENGINE_LIMITATIONS,
        )
        if root.has_error:
            result.taint_analysis = TaintResult(
                language=language_name,
                limitations=ENGINE_LIMITATIONS,
            )
            return result

        context = FlowContext(
            source_code, language_name, file, root
        )
        scope_analysis = ScopeAnalyzer(context, profile).analyze()
        ir_program = IRBuilder(
            context, profile, scope_analysis
        ).build()
        cfgs = build_cfgs(
            context, profile, scope_analysis, ir_program
        )
        data_flow = DataFlowAnalyzer(
            scope_analysis, ir_program, cfgs, profile
        ).analyze()

        config = self._resolve_config(taint_config)
        taint = TaintAnalyzer(
            scope_analysis,
            ir_program,
            data_flow,
            config,
        ).analyze()

        result.scopes = scope_analysis.scopes
        result.symbols = scope_analysis.symbols
        result.control_flow_graphs = cfgs
        result.data_flow = data_flow
        result.taint_analysis = taint
        result.unresolved_references = (
            scope_analysis.unresolved_references
        )
        result.limitations = (
            ENGINE_LIMITATIONS
            + tuple(scope_analysis.limitations)
        )
        return result

    def analyze_file(
        self,
        file_path: str | Path,
        *,
        taint_config: TaintConfig | dict[str, Any] | None = None,
    ) -> FlowAnalysisResult:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )
        language = detect_language(str(path))
        if language is None:
            raise ValueError(
                f"Unsupported file extension: {path.suffix}"
            )
        source_code = path.read_text(encoding="utf-8")
        return self.analyze_source(
            source_code,
            language,
            file=str(path),
            taint_config=taint_config,
        )

    def _resolve_config(
        self,
        value: TaintConfig | dict[str, Any] | None,
    ) -> TaintConfig:
        if isinstance(value, dict):
            return TaintConfig.from_dict(value)
        return value or self.taint_config


def taint_diagnostics(
    result: FlowAnalysisResult,
) -> list[Diagnostic]:
    """Convert taint findings into the existing diagnostic schema."""
    if result.taint_analysis is None:
        return []
    diagnostics: list[Diagnostic] = []
    for finding in result.taint_analysis.findings:
        rule = _diagnostic_rule(finding)
        location = finding.sink_location
        path_summary = " -> ".join(
            " ".join(
                part
                for part in (
                    f"{step.get('kind')}:{step.get('name', '')}",
                    (
                        f"[{step['rule']}]"
                        if step.get("rule")
                        else ""
                    ),
                )
                if part
            )
            for step in finding.path
        )
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                message=(
                    f"Untrusted data from {finding.source_name} "
                    f"reaches {finding.sink_name}."
                ),
                file=location.file,
                line=location.line,
                column=location.column,
                end_line=location.end_line,
                end_column=location.end_column,
                explanation=(
                    f"Tracked path: {path_summary}. "
                    f"Syntactic finding ({finding.confidence} "
                    "confidence); review the surrounding code."
                ),
                suggestion=rule.suggestion,
                language=result.language,
            )
        )
    return diagnostics
