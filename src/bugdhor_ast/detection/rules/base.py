from abc import ABC, abstractmethod

from ..context import AnalysisContext
from ..models import Diagnostic, RuleMetadata


class BaseRule(ABC):
    """Base class for all static detection rules."""

    def __init__(self, metadata: RuleMetadata) -> None:
        self.metadata = metadata

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def severity(self) -> str:
        return self.metadata.severity

    def report(
        self,
        context: AnalysisContext,
        node,
        message: str,
        suggestion: str | None = None,
    ) -> Diagnostic:
        return context.diagnostic(
            self.metadata, node, message, suggestion
        )

    @abstractmethod
    def check(
        self, context: AnalysisContext
    ) -> list[Diagnostic]:
        """Return diagnostics produced by this rule."""

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.rule_id}, "
            f"{self.metadata.language})"
        )
