from pathlib import Path

from ..engine import BugDhorASTEngine
from ..languages import detect_language
from .context import AnalysisContext
from .models import (
    DetectionResult,
    Diagnostic,
    RuleMetadata,
)
from .registry import DEFAULT_REGISTRY, RuleRegistry


SYNTAX_ERROR_RULE = RuleMetadata(
    "AST001",
    "Syntax Error",
    "The source contains a parse error.",
    "error",
    "all",
    "Fix the syntax error before running static detection.",
)


class BugDhorDetectionEngine:
    """Rule-based static bug detection over tree-sitter parse trees."""

    def __init__(
        self, registry: RuleRegistry | None = None
    ) -> None:
        self.ast_engine = BugDhorASTEngine()
        self.registry = registry or DEFAULT_REGISTRY

    def analyze_source(
        self,
        source_code: str,
        language_name: str,
        *,
        file: str = "<source>",
        rule_ids: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> DetectionResult:
        parser = self.ast_engine.get_parser(language_name)
        root = parser.parse(source_code.encode("utf-8")).root_node
        context = AnalysisContext(
            source_code, language_name, file, root
        )

        if root.has_error:
            diagnostics = self._syntax_diagnostics(context)
            return DetectionResult(
                file=file,
                language=language_name,
                diagnostics=diagnostics,
                rules_executed=[SYNTAX_ERROR_RULE.rule_id],
                has_syntax_errors=True,
            )

        rules = self.registry.select(
            language=language_name,
            rule_ids=rule_ids,
            severities=severities,
        )
        diagnostics: list[Diagnostic] = []
        for rule in rules:
            diagnostics.extend(rule.check(context))

        return DetectionResult(
            file=file,
            language=language_name,
            diagnostics=self._finalize(diagnostics),
            rules_executed=[rule.rule_id for rule in rules],
            has_syntax_errors=False,
        )

    def analyze_file(
        self,
        file_path: str | Path,
        *,
        rule_ids: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> DetectionResult:
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
            rule_ids=rule_ids,
            severities=severities,
        )

    def list_rules(
        self, language: str | None = None
    ) -> list[dict]:
        return [
            metadata.to_dict()
            for metadata in self.registry.metadata(language)
        ]

    @staticmethod
    def _syntax_diagnostics(
        context: AnalysisContext,
    ) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for node in context.walk():
            if node.type == "ERROR":
                message = "Syntax error"
            elif node.is_missing:
                message = "Missing syntax node"
            else:
                continue
            diagnostics.append(
                context.diagnostic(
                    SYNTAX_ERROR_RULE, node, message
                )
            )
        return BugDhorDetectionEngine._finalize(diagnostics)

    @staticmethod
    def _finalize(
        diagnostics: list[Diagnostic],
    ) -> list[Diagnostic]:
        unique: dict[tuple, Diagnostic] = {}
        for diagnostic in diagnostics:
            key = (
                diagnostic.rule_id,
                diagnostic.line,
                diagnostic.column,
                diagnostic.end_line,
                diagnostic.end_column,
                diagnostic.message,
            )
            unique.setdefault(key, diagnostic)
        return sorted(
            unique.values(),
            key=lambda item: (
                item.line,
                item.column,
                item.rule_id,
            ),
        )
