"""Patch correctness and security preservation (Eq. 34-39).

Equations and operational meaning
---------------------------------
Eq. (34)::

    Pass_func(P', T) = (sum_{t in T} 1[P'(t) = o_t]) / |T|

Eq. (35)::

    V_func(P') = 1[ Pass_func(P', T) = 1 ]

Eq. (36)::

    {P} P' {Q}                        (Hoare triple; not computable here)

Eq. (37)::

    V_target(P') intersect V_target(P) = empty

Eq. (38)::

    V(P') \\ V(P) = empty

Eq. (39)::

    Accept(P') = V_syntax(P') and V_func(P') and V_reg(P') and V_security(P')

Three-valued semantics
----------------------
Eq. (34)-(35) are binary in the paper.  A test runner can fail to execute, time
out, or lack a baseline; those cases are ``inconclusive``.  This module uses
``pass`` / ``fail`` / ``inconclusive`` for every predicate:

* any conclusive failure makes the predicate ``fail``;
* otherwise any missing or inconclusive input makes it ``inconclusive``;
* only complete, all-passing evidence makes it ``pass``.

``inconclusive`` is never treated as ``pass`` and is counted in the report.
Eq. (36) is returned as ``inconclusive`` unless a caller supplies a verifier
result; this module does not invent a formal proof.  Eqs. (37)-(38) are
detector-relative: an incomplete scan cannot establish a clean result.

Complexity
----------
Eq. (34): O(|T|).  Eqs. (37)-(39): O(|V|) average set operations.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import numpy as np

Array = np.ndarray


class PredicateState(StrEnum):
    """Three-valued predicate outcome."""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class PredicateResult:
    """One named predicate with its state and explanatory reasons."""

    name: str
    state: PredicateState
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("predicate name must not be empty")
        if self.state is PredicateState.PASS and self.reasons:
            raise ValueError("a passing predicate cannot carry failure reasons")

    @property
    def passed(self) -> bool:
        return self.state is PredicateState.PASS


@dataclass(frozen=True, slots=True)
class FunctionalPassResult:
    """Result of Eq. (34) with explicit inconclusive accounting."""

    passed: int
    failed: int
    inconclusive: int
    total: int
    pass_rate: float
    state: PredicateState
    reasons: tuple[str, ...] = ()

    @property
    def predicate(self) -> PredicateResult:
        return PredicateResult("V_func", self.state, self.reasons)


@dataclass(frozen=True, slots=True)
class AcceptanceDecision:
    """Eq. (39) under three-valued logic."""

    state: PredicateState
    predicates: Mapping[str, PredicateState]
    reasons: tuple[str, ...]
    inconclusive_count: int

    @property
    def accepted(self) -> bool:
        """True only for a complete, all-pass conjunction."""
        return self.state is PredicateState.PASS

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "accepted": self.accepted,
            "predicates": {name: state.value for name, state in self.predicates.items()},
            "reasons": list(self.reasons),
            "inconclusive_count": self.inconclusive_count,
        }


def conjunction(*states: PredicateState, reasons: Sequence[str] = ()) -> PredicateResult:
    """Three-valued conjunction: fail dominates, then inconclusive, then pass."""
    if not states:
        raise ValueError("at least one predicate state is required")
    for state in states:
        if not isinstance(state, PredicateState):
            raise TypeError("states must be PredicateState values")
    if PredicateState.FAIL in states:
        return PredicateResult("conjunction", PredicateState.FAIL, tuple(reasons))
    if PredicateState.INCONCLUSIVE in states:
        return PredicateResult("conjunction", PredicateState.INCONCLUSIVE, tuple(reasons))
    return PredicateResult("conjunction", PredicateState.PASS)


# --------------------------------------------------------------------------- #
# Eq. (34)-(35): functional pass rate and predicate
# --------------------------------------------------------------------------- #
def functional_pass_rate(
    expected: Sequence[Any],
    actual: Sequence[Any],
    *,
    atol: float = 0.0,
    rtol: float = 0.0,
) -> FunctionalPassResult:
    """Compute Eq. (34) with exact or tolerance-based output comparison.

    ``None`` and ``NaN`` entries are inconclusive, not failures.  The
    denominator is ``|T|`` including inconclusive tests, exactly as in Eq. (34);
    the pass rate is therefore not inflated when a test cannot be executed.
    """
    if len(expected) != len(actual):
        raise ValueError(
            f"expected and actual must have the same length, got {len(expected)} and {len(actual)}"
        )
    if not math.isfinite(atol) or atol < 0 or not math.isfinite(rtol) or rtol < 0:
        raise ValueError("atol and rtol must be finite and non-negative")
    total = len(expected)
    if total == 0:
        return FunctionalPassResult(
            passed=0,
            failed=0,
            inconclusive=0,
            total=0,
            pass_rate=math.nan,
            state=PredicateState.INCONCLUSIVE,
            reasons=("the test set is empty",),
        )
    passed = failed = inconclusive = 0
    for want, got in zip(expected, actual, strict=True):
        if _is_missing(want) or _is_missing(got):
            inconclusive += 1
            continue
        equal = _outputs_equal(want, got, atol=atol, rtol=rtol)
        passed += int(equal)
        failed += int(not equal)
    rate = passed / total
    reasons: list[str] = []
    if failed:
        reasons.append(f"{failed} of {total} tests failed")
    if inconclusive:
        reasons.append(f"{inconclusive} of {total} tests were inconclusive")
    if failed:
        state = PredicateState.FAIL
    elif inconclusive:
        state = PredicateState.INCONCLUSIVE
    else:
        state = PredicateState.PASS
    return FunctionalPassResult(
        passed=passed,
        failed=failed,
        inconclusive=inconclusive,
        total=total,
        pass_rate=rate,
        state=state,
        reasons=tuple(reasons),
    )


def functional_predicate(result: FunctionalPassResult) -> PredicateResult:
    """Return Eq. (35) as a three-valued predicate."""
    if result.total == 0:
        return PredicateResult("V_func", PredicateState.INCONCLUSIVE, ("no tests were supplied",))
    if result.state is not PredicateState.PASS:
        return PredicateResult("V_func", result.state, result.reasons)
    return PredicateResult("V_func", PredicateState.PASS)


# --------------------------------------------------------------------------- #
# Eq. (36): Hoare triple
# --------------------------------------------------------------------------- #
HoareVerifier = Callable[[str, str, str], bool | PredicateState]


def hoare_triple_predicate(
    program: str,
    precondition: str,
    postcondition: str,
    *,
    verifier: HoareVerifier | None = None,
) -> PredicateResult:
    """Evaluate Eq. (36) only when a real verifier is supplied.

    Without a verifier the honest result is ``inconclusive``.  A syntactic check
    of the program is not a proof of the triple.
    """
    for name, value in (
        ("program", program),
        ("precondition", precondition),
        ("postcondition", postcondition),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if verifier is None:
        return PredicateResult(
            "V_hoare",
            PredicateState.INCONCLUSIVE,
            ("no formal verifier was supplied; a Hoare triple is not decidable here",),
        )
    verdict = verifier(program, precondition, postcondition)
    if isinstance(verdict, PredicateState):
        state = verdict
    elif isinstance(verdict, (bool, np.bool_)):
        state = PredicateState.PASS if bool(verdict) else PredicateState.FAIL
    else:
        raise TypeError("verifier must return bool or PredicateState")
    return PredicateResult("V_hoare", state)


# --------------------------------------------------------------------------- #
# Eq. (37)-(38): targeted removal and no new vulnerabilities
# --------------------------------------------------------------------------- #
def targeted_removal_predicate(
    original: Sequence[Any],
    candidate: Sequence[Any],
    *,
    correspondence_complete: bool = True,
) -> PredicateResult:
    """Evaluate Eq. (37): no original targeted finding remains in the patch.

    Findings must use a stable identity (for example ``CWE + normalized
    location``); otherwise the intersection is not evaluable and the result is
    ``inconclusive``.
    """
    if not correspondence_complete:
        return PredicateResult(
            "V_target_removed",
            PredicateState.INCONCLUSIVE,
            ("finding correspondence across versions is incomplete",),
        )
    remaining = _identity_set(original) & _identity_set(candidate)
    if remaining:
        return PredicateResult(
            "V_target_removed",
            PredicateState.FAIL,
            (f"{len(remaining)} targeted finding(s) remain after the patch",),
        )
    return PredicateResult("V_target_removed", PredicateState.PASS)


def no_new_vulnerabilities_predicate(
    original: Sequence[Any],
    candidate: Sequence[Any],
    *,
    scan_complete: bool = True,
) -> PredicateResult:
    """Evaluate Eq. (38): ``V(P') \\ V(P)`` is empty.

    A new finding is a conclusive failure even if the scan is incomplete.  An
    empty difference on an incomplete scan is only ``inconclusive`` because the
    detector may have missed the new vulnerability.
    """
    new_findings = _identity_set(candidate) - _identity_set(original)
    if new_findings:
        return PredicateResult(
            "V_no_new",
            PredicateState.FAIL,
            (f"{len(new_findings)} new finding(s) were introduced",),
        )
    if not scan_complete:
        return PredicateResult(
            "V_no_new",
            PredicateState.INCONCLUSIVE,
            ("no new findings were observed, but the post-patch scan was incomplete",),
        )
    return PredicateResult("V_no_new", PredicateState.PASS)


def security_predicate(
    targeted_removed: PredicateState,
    no_new_findings: PredicateState,
) -> PredicateResult:
    """Combine Eq. (37)-(38) into ``V_security``."""
    result = conjunction(targeted_removed, no_new_findings)
    return PredicateResult("V_security", result.state, result.reasons)


# --------------------------------------------------------------------------- #
# Regression predicate
# --------------------------------------------------------------------------- #
def regression_predicate(
    baseline: Mapping[str, bool | None],
    candidate: Mapping[str, bool | None],
) -> PredicateResult:
    """Evaluate ``V_reg``: no baseline-passing test may fail after the patch.

    Missing candidate results or missing baseline results are inconclusive, not
    failures and not passes.
    """
    if not baseline:
        return PredicateResult(
            "V_reg", PredicateState.INCONCLUSIVE, ("no baseline test results were supplied",)
        )
    failures: list[str] = []
    unknown: list[str] = []
    for test_id, baseline_passed in baseline.items():
        if baseline_passed is None:
            unknown.append(f"{test_id}: baseline result is unavailable")
            continue
        if not baseline_passed:
            continue
        candidate_passed = candidate.get(test_id)
        if candidate_passed is None:
            unknown.append(f"{test_id}: candidate result is unavailable")
        elif not candidate_passed:
            failures.append(f"{test_id}: passed before the patch and fails after it")
    if failures:
        return PredicateResult("V_reg", PredicateState.FAIL, tuple(failures))
    if unknown:
        return PredicateResult("V_reg", PredicateState.INCONCLUSIVE, tuple(unknown))
    return PredicateResult("V_reg", PredicateState.PASS)


# --------------------------------------------------------------------------- #
# Eq. (39): acceptance
# --------------------------------------------------------------------------- #
def accept_patch(
    *,
    syntax: bool | PredicateState | PredicateResult,
    functional: bool | PredicateState | PredicateResult,
    regression: bool | PredicateState | PredicateResult,
    security: bool | PredicateState | PredicateResult,
    hoare: bool | PredicateState | PredicateResult | None = None,
    require_hoare: bool = False,
) -> AcceptanceDecision:
    """Evaluate Eq. (39) with three-valued predicates.

    ``accepted`` is true only when every required predicate is ``pass``.
    """
    named: dict[str, PredicateResult] = {
        "V_syntax": _as_predicate("V_syntax", syntax),
        "V_func": _as_predicate("V_func", functional),
        "V_reg": _as_predicate("V_reg", regression),
        "V_security": _as_predicate("V_security", security),
    }
    if require_hoare:
        named["V_hoare"] = (
            _as_predicate("V_hoare", hoare)
            if hoare is not None
            else PredicateResult(
                "V_hoare",
                PredicateState.INCONCLUSIVE,
                ("a Hoare triple is required but no verifier result was supplied",),
            )
        )
    elif hoare is not None:
        named["V_hoare"] = _as_predicate("V_hoare", hoare)
    states = tuple(result.state for result in named.values())
    reasons = tuple(
        f"{name}: {reason}" for name, result in named.items() for reason in result.reasons
    )
    combined = conjunction(*states, reasons=reasons)
    return AcceptanceDecision(
        state=combined.state,
        predicates={name: result.state for name, result in named.items()},
        reasons=combined.reasons,
        inconclusive_count=sum(state is PredicateState.INCONCLUSIVE for state in states),
    )


def evaluate_preservation(
    *,
    expected: Sequence[Any] | None = None,
    actual: Sequence[Any] | None = None,
    syntax: bool | PredicateState | PredicateResult,
    baseline_tests: Mapping[str, bool | None] | None = None,
    candidate_tests: Mapping[str, bool | None] | None = None,
    original_vulnerabilities: Sequence[Any] = (),
    candidate_vulnerabilities: Sequence[Any] = (),
    targeted: Sequence[Any] = (),
    correspondence_complete: bool = True,
    scan_complete: bool = True,
    program: str | None = None,
    precondition: str | None = None,
    postcondition: str | None = None,
    verifier: HoareVerifier | None = None,
    require_hoare: bool = False,
    atol: float = 0.0,
    rtol: float = 0.0,
) -> AcceptanceDecision:
    """Evaluate Eq. (34)-(39) end to end from measured evidence.

    Every input is evidence supplied by a validator, test runner, or scanner.
    Nothing is inferred: absent tests, scans, or specifications become
    ``inconclusive`` rather than ``pass``.
    """
    if expected is None or actual is None:
        functional = PredicateResult(
            "V_func", PredicateState.INCONCLUSIVE, ("no test outputs were supplied",)
        )
    else:
        functional = functional_predicate(
            functional_pass_rate(expected, actual, atol=atol, rtol=rtol)
        )
    regression = (
        regression_predicate(baseline_tests, candidate_tests)
        if baseline_tests is not None
        else PredicateResult(
            "V_reg", PredicateState.INCONCLUSIVE, ("no baseline tests were supplied",)
        )
    )
    targeted_removed = targeted_removal_predicate(
        targeted,
        candidate_vulnerabilities,
        correspondence_complete=correspondence_complete,
    )
    no_new = no_new_vulnerabilities_predicate(
        original_vulnerabilities,
        candidate_vulnerabilities,
        scan_complete=scan_complete,
    )
    security = security_predicate(targeted_removed.state, no_new.state)
    hoare = None
    if require_hoare or program is not None:
        if program is None or precondition is None or postcondition is None:
            hoare = PredicateResult(
                "V_hoare",
                PredicateState.INCONCLUSIVE,
                ("program, precondition, and postcondition are all required",),
            )
        else:
            hoare = hoare_triple_predicate(
                program,
                precondition,
                postcondition,
                verifier=verifier,
            )
    return accept_patch(
        syntax=syntax,
        functional=functional,
        regression=regression,
        security=security,
        hoare=hoare,
        require_hoare=require_hoare,
    )


def _as_predicate(
    name: str,
    value: bool | PredicateState | PredicateResult,
) -> PredicateResult:
    if isinstance(value, PredicateResult):
        return value
    if isinstance(value, PredicateState):
        return PredicateResult(name, value)
    if isinstance(value, (bool, np.bool_)):
        return PredicateResult(name, PredicateState.PASS if value else PredicateState.FAIL)
    raise TypeError(f"{name} must be bool, PredicateState, or PredicateResult")


def _identity_set(values: Sequence[Any]) -> set[Any]:
    output = set()
    for value in values:
        if isinstance(value, (np.ndarray, list)):
            output.add(tuple(np.asarray(value).reshape(-1).tolist()))
        else:
            output.add(value)
    return output


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (float, np.floating)) and math.isnan(float(value)):
        return True
    return False


def _outputs_equal(expected: Any, actual: Any, *, atol: float, rtol: float) -> bool:
    if isinstance(expected, (np.ndarray, list, tuple)) or isinstance(
        actual, (np.ndarray, list, tuple)
    ):
        left = np.asarray(expected, dtype=np.float64)
        right = np.asarray(actual, dtype=np.float64)
        if left.shape != right.shape:
            return False
        return bool(np.allclose(left, right, atol=atol, rtol=rtol, equal_nan=False))
    if isinstance(expected, (bool, np.bool_)) or isinstance(actual, (bool, np.bool_)):
        return bool(expected) == bool(actual)
    if isinstance(expected, (int, float, np.number)) and isinstance(
        actual, (int, float, np.number)
    ):
        return bool(math.isclose(float(expected), float(actual), abs_tol=atol, rel_tol=rtol))
    return bool(expected == actual)


__all__ = [
    "AcceptanceDecision",
    "FunctionalPassResult",
    "HoareVerifier",
    "PredicateResult",
    "PredicateState",
    "accept_patch",
    "conjunction",
    "evaluate_preservation",
    "functional_pass_rate",
    "functional_predicate",
    "hoare_triple_predicate",
    "no_new_vulnerabilities_predicate",
    "regression_predicate",
    "security_predicate",
    "targeted_removal_predicate",
]
