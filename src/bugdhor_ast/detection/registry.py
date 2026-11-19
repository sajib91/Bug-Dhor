from .models import RuleMetadata
from .rules.base import BaseRule
from .rules.java_rules import JAVA_RULES
from .rules.javascript_rules import JAVASCRIPT_RULES
from .rules.python_rules import PYTHON_RULES


class RuleRegistry:
    """Registry of static detection rules."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self._rules: dict[str, BaseRule] = {}
        for rule in (
            rules
            if rules is not None
            else PYTHON_RULES + JAVASCRIPT_RULES + JAVA_RULES
        ):
            self.register(rule)

    def register(self, rule: BaseRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(
                f"Duplicate rule id: {rule.rule_id}"
            )
        self._rules[rule.rule_id] = rule

    def all_rules(self) -> list[BaseRule]:
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> BaseRule:
        return self._rules[rule_id.upper()]

    def select(
        self,
        language: str | None = None,
        rule_ids: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> list[BaseRule]:
        wanted_ids = (
            {rule_id.upper() for rule_id in rule_ids}
            if rule_ids
            else None
        )
        wanted_severities = (
            {severity.lower() for severity in severities}
            if severities
            else None
        )

        selected = []
        for rule in self._rules.values():
            if language is not None and (
                rule.metadata.language != language
            ):
                continue
            if wanted_ids is not None and (
                rule.rule_id not in wanted_ids
            ):
                continue
            if wanted_severities is not None and (
                rule.severity not in wanted_severities
            ):
                continue
            selected.append(rule)
        return selected

    def metadata(
        self, language: str | None = None
    ) -> list[RuleMetadata]:
        return [
            rule.metadata
            for rule in self.select(language=language)
        ]


DEFAULT_REGISTRY = RuleRegistry()
