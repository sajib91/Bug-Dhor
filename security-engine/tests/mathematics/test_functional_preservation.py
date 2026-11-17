from __future__ import annotations

import math

import numpy as np
import pytest
from mathematics.functional_preservation import (
    PredicateState,
    accept_patch,
    conjunction,
    evaluate_preservation,
    functional_pass_rate,
    functional_predicate,
    hoare_triple_predicate,
    no_new_vulnerabilities_predicate,
    regression_predicate,
    security_predicate,
    targeted_removal_predicate,
)


def test_equation_34_exact_pass_rate():
    result = functional_pass_rate([1, 2, 3], [1, 2, 3])
    assert result.passed == 3
    assert result.failed == 0
    assert result.inconclusive == 0
    assert result.total == 3
    assert result.pass_rate == pytest.approx(1.0)
    assert result.state is PredicateState.PASS
    assert result.predicate.state is PredicateState.PASS

    failed = functional_pass_rate([1, 2, 3], [1, 2, 4])
    assert failed.passed == 2
    assert failed.failed == 1
    assert failed.pass_rate == pytest.approx(2.0 / 3.0)
    assert failed.state is PredicateState.FAIL
    assert "1 of 3 tests failed" in failed.reasons


def test_inconclusive_is_never_a_pass_and_remains_in_the_denominator():
    result = functional_pass_rate([1, 2, None], [1, 2, 3])
    assert result.passed == 2
    assert result.inconclusive == 1
    assert result.total == 3
    assert result.pass_rate == pytest.approx(2.0 / 3.0)
    assert result.state is PredicateState.INCONCLUSIVE
    assert not result.predicate.passed

    nan_result = functional_pass_rate([1.0, np.nan], [1.0, 2.0])
    assert nan_result.inconclusive == 1
    assert nan_result.state is PredicateState.INCONCLUSIVE

    fail_dominates = functional_pass_rate([1, 2, None], [1, 9, 3])
    assert fail_dominates.state is PredicateState.FAIL


def test_empty_test_set_and_functional_predicate():
    empty = functional_pass_rate([], [])
    assert empty.total == 0
    assert math.isnan(empty.pass_rate)
    assert empty.state is PredicateState.INCONCLUSIVE
    assert functional_predicate(empty).state is PredicateState.INCONCLUSIVE
    with pytest.raises(ValueError):
        functional_pass_rate([1], [1, 2])
    with pytest.raises(ValueError):
        functional_pass_rate([1], [1], atol=-1.0)


def test_output_comparison_supports_numeric_tolerance_and_arrays():
    assert functional_pass_rate([1.0], [1.0001], atol=1e-3).state is PredicateState.PASS
    assert functional_pass_rate([1.0], [1.0001]).state is PredicateState.FAIL
    arrays = functional_pass_rate(
        [np.asarray([1.0, 2.0])],
        [np.asarray([1.0, 2.01])],
        atol=0.1,
    )
    assert arrays.state is PredicateState.PASS
    different_shapes = functional_pass_rate([np.asarray([1.0, 2.0])], [np.asarray([1.0])])
    assert different_shapes.state is PredicateState.FAIL


def test_three_valued_conjunction():
    assert conjunction(PredicateState.PASS, PredicateState.PASS).state is PredicateState.PASS
    assert (
        conjunction(PredicateState.PASS, PredicateState.INCONCLUSIVE).state
        is PredicateState.INCONCLUSIVE
    )
    assert (
        conjunction(PredicateState.PASS, PredicateState.INCONCLUSIVE, PredicateState.FAIL).state
        is PredicateState.FAIL
    )
    with pytest.raises(ValueError):
        conjunction()
    with pytest.raises(TypeError):
        conjunction(True)  # type: ignore[arg-type]


def test_equation_36_requires_a_real_verifier():
    absent = hoare_triple_predicate("{x=0} x:=1 {x=1}", "x=0", "x=1")
    assert absent.state is PredicateState.INCONCLUSIVE
    assert "not decidable" in absent.reasons[0]
    passed = hoare_triple_predicate("program", "pre", "post", verifier=lambda p, a, b: True)
    assert passed.state is PredicateState.PASS
    failed = hoare_triple_predicate("program", "pre", "post", verifier=lambda p, a, b: False)
    assert failed.state is PredicateState.FAIL
    unknown = hoare_triple_predicate(
        "program",
        "pre",
        "post",
        verifier=lambda p, a, b: PredicateState.INCONCLUSIVE,
    )
    assert unknown.state is PredicateState.INCONCLUSIVE
    with pytest.raises(TypeError):
        hoare_triple_predicate("program", "pre", "post", verifier=lambda p, a, b: "yes")
    with pytest.raises(ValueError):
        hoare_triple_predicate(" ", "pre", "post")


def test_equation_37_targeted_removal():
    original = ["CWE-89@a.py:10", "CWE-79@b.py:4"]
    assert targeted_removal_predicate(original, ["CWE-79@b.py:4"]).state is PredicateState.FAIL
    assert targeted_removal_predicate(original, []).state is PredicateState.PASS
    assert (
        targeted_removal_predicate(
            original, ["CWE-89@a.py:10"], correspondence_complete=False
        ).state
        is PredicateState.INCONCLUSIVE
    )
    assert targeted_removal_predicate([[1, 2]], [np.asarray([1, 2])]).state is PredicateState.FAIL


def test_equation_38_no_new_vulnerabilities():
    original = ["CWE-89@a.py:10"]
    assert (
        no_new_vulnerabilities_predicate(original, ["CWE-89@a.py:10", "CWE-79@c.py:1"]).state
        is PredicateState.FAIL
    )
    assert (
        no_new_vulnerabilities_predicate(original, ["CWE-89@a.py:10"], scan_complete=False).state
        is PredicateState.INCONCLUSIVE
    )
    assert (
        no_new_vulnerabilities_predicate(original, ["CWE-89@a.py:10"]).state is PredicateState.PASS
    )


def test_security_predicate_combines_equations_37_and_38():
    assert security_predicate(PredicateState.PASS, PredicateState.PASS).state is PredicateState.PASS
    assert security_predicate(PredicateState.PASS, PredicateState.FAIL).state is PredicateState.FAIL
    assert (
        security_predicate(PredicateState.INCONCLUSIVE, PredicateState.PASS).state
        is PredicateState.INCONCLUSIVE
    )


def test_regression_predicate_ignores_never_passing_tests():
    assert (
        regression_predicate({"a": True, "b": False}, {"a": True, "b": False}).state
        is PredicateState.PASS
    )
    assert regression_predicate({"a": True}, {"a": False}).state is PredicateState.FAIL
    assert regression_predicate({"a": True}, {}).state is PredicateState.INCONCLUSIVE
    assert regression_predicate({"a": None}, {"a": True}).state is PredicateState.INCONCLUSIVE
    assert regression_predicate({}, {}).state is PredicateState.INCONCLUSIVE


def test_equation_39_acceptance_conjunction():
    accepted = accept_patch(syntax=True, functional=True, regression=True, security=True)
    assert accepted.accepted
    assert accepted.state is PredicateState.PASS
    assert accepted.inconclusive_count == 0
    assert accepted.to_dict()["accepted"] is True

    failed = accept_patch(syntax=True, functional=False, regression=True, security=True)
    assert not failed.accepted
    assert failed.state is PredicateState.FAIL

    unknown = accept_patch(
        syntax=True,
        functional=PredicateState.INCONCLUSIVE,
        regression=True,
        security=True,
    )
    assert not unknown.accepted
    assert unknown.state is PredicateState.INCONCLUSIVE
    assert unknown.inconclusive_count == 1
    assert unknown.to_dict()["accepted"] is False

    required = accept_patch(
        syntax=True,
        functional=True,
        regression=True,
        security=True,
        require_hoare=True,
    )
    assert required.state is PredicateState.INCONCLUSIVE
    assert required.predicates["V_hoare"] is PredicateState.INCONCLUSIVE

    with_hoare = accept_patch(
        syntax=True,
        functional=True,
        regression=True,
        security=True,
        hoare=True,
        require_hoare=True,
    )
    assert with_hoare.accepted
    with pytest.raises(TypeError):
        accept_patch(
            syntax="yes",  # type: ignore[arg-type]
            functional=True,
            regression=True,
            security=True,
        )


def test_evaluate_preservation_end_to_end():
    accepted = evaluate_preservation(
        expected=[1, 2, 3.0],
        actual=[1, 2, 3.0],
        syntax=True,
        baseline_tests={"test_api": True},
        candidate_tests={"test_api": True},
        original_vulnerabilities={"CWE-89@a.py:10"},
        candidate_vulnerabilities=set(),
        targeted={"CWE-89@a.py:10"},
    )
    assert accepted.accepted
    assert accepted.predicates == {
        "V_syntax": PredicateState.PASS,
        "V_func": PredicateState.PASS,
        "V_reg": PredicateState.PASS,
        "V_security": PredicateState.PASS,
    }

    absent = evaluate_preservation(syntax=True)
    assert not absent.accepted
    assert absent.state is PredicateState.INCONCLUSIVE
    assert absent.predicates["V_func"] is PredicateState.INCONCLUSIVE
    assert absent.predicates["V_reg"] is PredicateState.INCONCLUSIVE
    assert absent.inconclusive_count >= 2

    security_failure = evaluate_preservation(
        expected=[1],
        actual=[1],
        syntax=True,
        baseline_tests={"t": True},
        candidate_tests={"t": True},
        original_vulnerabilities={"CWE-89@a.py:10"},
        candidate_vulnerabilities={"CWE-89@a.py:10"},
        targeted={"CWE-89@a.py:10"},
    )
    assert security_failure.state is PredicateState.FAIL
    assert security_failure.predicates["V_security"] is PredicateState.FAIL


def test_evaluate_preservation_with_hoare_verifier():
    result = evaluate_preservation(
        expected=[1],
        actual=[1],
        syntax=True,
        baseline_tests={"t": True},
        candidate_tests={"t": True},
        program="x := x + 1",
        precondition="x >= 0",
        postcondition="x >= 1",
        verifier=lambda p, pre, post: True,
        require_hoare=True,
    )
    assert result.accepted
    assert result.predicates["V_hoare"] is PredicateState.PASS

    missing_spec = evaluate_preservation(syntax=True, require_hoare=True)
    assert missing_spec.predicates["V_hoare"] is PredicateState.INCONCLUSIVE
    assert not missing_spec.accepted
