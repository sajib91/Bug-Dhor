from __future__ import annotations

import pytest

from craftsec.steering import (
    FunctionalConstraintEvaluator,
    FunctionalConstraints,
    FunctionalEvidence,
    python_syntax_validator,
)


def test_functional_constraints_reject_missing_functional_evidence() -> None:
    evaluator = FunctionalConstraintEvaluator(
        FunctionalConstraints(
            require_unit_test_result=True,
            require_behavioral_consistency=True,
        ),
        syntax_validator=python_syntax_validator,
    )

    result = evaluator.evaluate("def safe():\n    return 1", baseline="def safe():\n    return 0")

    assert result.accepted is False
    assert "unit-test pass rate is unavailable" in result.rejection_reasons
    assert "behavioral consistency is unavailable" in result.rejection_reasons
    assert result.evidence.syntax_valid is True


def test_functional_constraints_compare_security_and_functionality_tradeoff() -> None:
    evaluator = FunctionalConstraintEvaluator(
        FunctionalConstraints(
            require_compilation_success=True,
            require_unit_test_result=True,
            require_behavioral_consistency=True,
            min_unit_test_pass_rate=1.0,
            min_behavioral_consistency=0.9,
            max_functional_regression=0.0,
            min_security_improvement=0.2,
            max_generation_overhead=0.5,
        )
    )
    evidence = FunctionalEvidence(
        syntax_valid=True,
        compilation_success=True,
        unit_test_pass_rate=1.0,
        behavioral_consistency=0.95,
        functional_regression=0.0,
        security_improvement=0.3,
        generation_seconds=1.5,
        baseline_generation_seconds=1.0,
    )

    result = evaluator.evaluate("candidate", baseline="baseline", evidence=evidence)

    assert result.accepted is True
    assert result.tradeoff == {
        "security_improvement": 0.3,
        "functional_regression": 0.0,
        "generation_overhead": 0.5,
    }


def test_syntax_is_not_functional_equivalence() -> None:
    evaluator = FunctionalConstraintEvaluator(
        FunctionalConstraints(max_functional_regression=0.0),
        syntax_validator=python_syntax_validator,
    )

    result = evaluator.evaluate("def safe():\n    return 2", baseline="def safe():\n    return 1")

    assert result.accepted is False
    assert "functional regression evidence is unavailable" in result.rejection_reasons


def test_constraints_validate_metric_ranges() -> None:
    with pytest.raises(ValueError, match="min_behavioral_consistency"):
        FunctionalConstraints(min_behavioral_consistency=1.1)
