from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("error", "warning", "info")


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    name: str
    description: str
    severity: str
    language: str
    suggestion: str = ""
    limitations: tuple[str, ...] = ()

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Unsupported severity: {self.severity}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "description": self.description,
            "severity": self.severity,
            "language": self.language,
            "suggestion": self.suggestion,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class Diagnostic:
    rule_id: str
    rule_name: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    end_line: int
    end_column: int
    explanation: str
    suggestion: str = ""
    language: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def location_key(self) -> tuple[int, int, int, int, str]:
        return (
            self.line,
            self.column,
            self.end_line,
            self.end_column,
            self.rule_id,
        )


@dataclass
class DetectionResult:
    file: str
    language: str
    diagnostics: list[Diagnostic] = field(default_factory=list)
    rules_executed: list[str] = field(default_factory=list)
    has_syntax_errors: bool = False

    @property
    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for diagnostic in self.diagnostics:
            counts[diagnostic.severity] += 1
        return {"total": len(self.diagnostics), **counts}

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "has_syntax_errors": self.has_syntax_errors,
            "summary": self.summary,
            "rules_executed": list(self.rules_executed),
            "diagnostics": [
                diagnostic.to_dict()
                for diagnostic in self.diagnostics
            ],
        }
