"""Synthetic validation of CRAFT-Sec counterfactual interaction mathematics.

This script is model-independent.  It emits a machine-readable record of
analytical checks, scale-dependence checks, confounding demonstrations, and a
bootstrap coverage simulation.  It complements
``tests/unit/test_counterfactual_mathematical_validation.py`` by recording the
observed numbers rather than only pass/fail assertions.

Run from the repository root:

    .venv/bin/python research/experiments/counterfactual_validation/run_synthetic_validation.py
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from craftsec.counterfactual.validation import (
    bootstrap_mean_interval,
    estimate_higher_order_contrast,
    estimate_pairwise_contrast,
    factorial_unit_contrasts,
    interaction_on_scale,
    logit,
    sigmoid,
    stability_summary,
)

OUT_DIR = Path(__file__).resolve().parent / "results"


def _pairwise_cells(
    baseline: np.ndarray,
    a_effect: np.ndarray | float,
    b_effect: np.ndarray | float,
    interaction: np.ndarray | float,
) -> dict[tuple[int, ...], np.ndarray]:
    return {
        (): np.asarray(baseline, dtype=np.float64),
        (0,): np.asarray(baseline, dtype=np.float64) + np.asarray(a_effect),
        (1,): np.asarray(baseline, dtype=np.float64) + np.asarray(b_effect),
        (0, 1): (
            np.asarray(baseline, dtype=np.float64)
            + np.asarray(a_effect)
            + np.asarray(b_effect)
            + np.asarray(interaction)
        ),
    }


def _triple_cells() -> dict[tuple[int, ...], np.ndarray]:
    ones = np.ones(8, dtype=np.float64)
    cells: dict[tuple[int, ...], np.ndarray] = {}
    for mask in range(8):
        active = tuple(index for index in range(3) if mask & (1 << index))
        a = ones if 0 in active else np.zeros(8)
        b = ones if 1 in active else np.zeros(8)
        c = ones if 2 in active else np.zeros(8)
        cells[active] = 2.0 + a + 2.0 * b + 3.0 * c + 7.0 * a * b * c
    return cells


def _coverage_simulation() -> dict[str, Any]:
    generator = np.random.default_rng(2026)
    true_effect = 2.0
    replications = 1000
    covered = 0
    widths: list[float] = []
    for replication in range(replications):
        n = 50
        paired_noise = generator.normal(0.0, 1.0, size=n)
        cells = {
            (): np.zeros(n),
            (0,): np.zeros(n),
            (1,): np.zeros(n),
            (0, 1): true_effect + paired_noise,
        }
        result = estimate_higher_order_contrast(
            cells, (0, 1), n_boot=500, seed=replication
        )
        covered += int(result.confidence_low <= true_effect <= result.confidence_high)
        widths.append(result.confidence_high - result.confidence_low)
    return {
        "true_contrast": true_effect,
        "replications": replications,
        "nominal_confidence": 0.95,
        "empirical_coverage": covered / replications,
        "mean_interval_width": float(np.mean(widths)),
        "note": (
            "Coverage is for the declared paired contrast with i.i.d. unit noise. "
            "It is not a guarantee under dependent or misspecified sampling."
        ),
    }


def _null_containment() -> dict[str, Any]:
    generator = np.random.default_rng(44)
    replications = 1000
    contained = 0
    for replication in range(replications):
        n = 60
        cells = {
            (): np.zeros(n),
            (0,): np.zeros(n),
            (1,): np.zeros(n),
            (0, 1): generator.normal(0.0, 1.0, size=n),
        }
        result = estimate_higher_order_contrast(
            cells, (0, 1), n_boot=500, seed=replication
        )
        contained += int(result.confidence_low <= 0.0 <= result.confidence_high)
    return {
        "true_contrast": 0.0,
        "replications": replications,
        "nominal_confidence": 0.95,
        "empirical_zero_containment": contained / replications,
    }


def _finite_sample_coverage() -> dict[str, Any]:
    """Coverage of the percentile bootstrap at several unit counts."""
    results: dict[str, Any] = {}
    for n in (24, 60, 120, 240):
        generator = np.random.default_rng(44)
        replications = 1000
        contained = 0
        for replication in range(replications):
            sample = generator.normal(0.0, 1.0, size=n)
            _, _, low, high = bootstrap_mean_interval(
                sample, confidence=0.95, n_boot=600, seed=replication
            )
            contained += int(low <= 0.0 <= high)
        results[f"n_{n}"] = {
            "n_units": n,
            "replications": replications,
            "empirical_zero_containment": contained / replications,
        }
    return {
        "nominal_confidence": 0.95,
        "results": results,
        "note": (
            "Percentile bootstrap intervals undercover in small samples.  The "
            "real-model run uses 24 evaluation units, so intervals are descriptive "
            "and should be read together with the normal-approximation interval."
        ),
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scenarios: dict[str, Any] = {}

    # 1. Baseline is the reference cell, not zero; constant shifts cancel.
    baseline = np.array([10.0, 12.0, 14.0])
    cells = _pairwise_cells(baseline, 2.0, 3.0, 5.0)
    result = estimate_pairwise_contrast(
        cells[()], cells[(0,)], cells[(1,)], cells[(0, 1)], n_boot=500, seed=1
    )
    scenarios["baseline_and_constant_shift"] = {
        "baseline_values": baseline.tolist(),
        "observed_contrast": result.contrast,
        "expected_contrast": 5.0,
        "passed": math.isclose(result.contrast, 5.0),
    }

    # 2. Single-feature interventions and additive null.
    additive = _pairwise_cells(np.array([1.0, 4.0, 9.0]), 2.0, 3.0, 0.0)
    additive_contrast = float(np.mean(factorial_unit_contrasts(additive, (0, 1))))
    scenarios["additive_null"] = {
        "observed_contrast": additive_contrast,
        "expected_contrast": 0.0,
        "passed": math.isclose(additive_contrast, 0.0),
    }

    # 3. Ablation: state 1 removes a feature's contribution.
    # Y = 10 - 2*I(A active) - 3*I(B active) + 4*I(A active)*I(B active)
    baseline_value = np.full(6, 10.0)
    ablation = {
        (): baseline_value.copy(),
        (0,): baseline_value - 2.0,
        (1,): baseline_value - 3.0,
        (0, 1): baseline_value - 2.0 - 3.0 + 4.0,
    }
    ablation_contrast = float(np.mean(factorial_unit_contrasts(ablation, (0, 1))))
    scenarios["ablation_binary_states"] = {
        "observed_contrast": ablation_contrast,
        "expected_contrast": 4.0,
        "passed": math.isclose(ablation_contrast, 4.0),
    }

    # 4. Joint intervention is simultaneous, not sequential.
    simultaneous = {
        (): np.zeros(2),
        (0,): np.full(2, 1.0),
        (1,): np.full(2, 2.0),
        (0, 1): np.full(2, 3.0),
    }
    scenarios["joint_simultaneous"] = {
        "joint_mean": float(np.mean(simultaneous[(0, 1)])),
        "expected_joint_mean": 3.0,
        "passed": math.isclose(float(np.mean(simultaneous[(0, 1)])), 3.0),
    }

    # 5. Higher-order inclusion-exclusion.
    triple = _triple_cells()
    triple_result = estimate_higher_order_contrast(
        triple, (0, 1, 2), n_boot=500, seed=2
    )
    scenarios["higher_order_inclusion_exclusion"] = {
        "observed_contrast": triple_result.contrast,
        "expected_contrast": 7.0,
        "passed": math.isclose(triple_result.contrast, 7.0),
    }

    # 6. Interaction direction under outcome negation.
    positive_cells = _pairwise_cells(np.zeros(5), 1.0, 1.0, 2.0)
    negative_cells = {key: -value for key, value in positive_cells.items()}
    positive = estimate_higher_order_contrast(
        positive_cells, (0, 1), n_boot=200, seed=3
    )
    negative = estimate_higher_order_contrast(
        negative_cells, (0, 1), n_boot=200, seed=3
    )
    scenarios["direction_under_negation"] = {
        "positive_contrast": positive.contrast,
        "negative_contrast": negative.contrast,
        "passed": math.isclose(positive.contrast, -negative.contrast),
    }

    # 7. Outcome-scale dependence: probability vs logit.
    baseline_logit = -1.5
    a_effect = 1.2
    b_effect = 0.8
    interaction = 2.0

    def probability_cell(a: float, b: float) -> float:
        return float(
            sigmoid(baseline_logit + a_effect * a + b_effect * b + interaction * a * b)
        )

    probability_cells = {
        (): np.array([probability_cell(0.0, 0.0)]),
        (0,): np.array([probability_cell(1.0, 0.0)]),
        (1,): np.array([probability_cell(0.0, 1.0)]),
        (0, 1): np.array([probability_cell(1.0, 1.0)]),
    }
    probability_contrast = estimate_higher_order_contrast(
        probability_cells, (0, 1), n_boot=50, seed=4
    ).contrast
    logit_contrast = interaction_on_scale(probability_cells, (0, 1), logit)
    scenarios["outcome_scale_dependence"] = {
        "probability_scale_contrast": probability_contrast,
        "logit_scale_contrast": logit_contrast,
        "expected_logit_contrast": interaction,
        "passed": not math.isclose(probability_contrast, logit_contrast)
        and math.isclose(logit_contrast, interaction),
    }

    # 8. Confounding: paired design cancels a unit-level baseline; an unpaired
    # comparison with imbalanced groups manufactures a contrast.
    paired_baseline = np.array([0.0, 10.0, 20.0, 100.0])
    paired_cells = _pairwise_cells(paired_baseline, 2.0, 3.0, 0.0)
    paired_contrast = float(np.mean(factorial_unit_contrasts(paired_cells, (0, 1))))
    unpaired_means = {
        (): np.mean([0.0, 1.0]),
        (0,): np.mean([10.0, 11.0]) + 2.0,
        (1,): np.mean([10.0, 11.0]) + 3.0,
        (0, 1): np.mean([10.0, 11.0]) + 2.0 + 3.0,
    }
    unpaired_contrast = (
        unpaired_means[(0, 1)]
        - unpaired_means[(0,)]
        - unpaired_means[(1,)]
        + unpaired_means[()]
    )
    scenarios["confounding_paired_vs_unpaired"] = {
        "paired_contrast": paired_contrast,
        "unpaired_spurious_contrast": float(unpaired_contrast),
        "passed": math.isclose(paired_contrast, 0.0)
        and math.isclose(unpaired_contrast, -10.0),
    }

    # 9. Off-target change in a single cell masquerades as an interaction.
    off_target = {
        (): np.ones(3),
        (0,): np.ones(3) + 1.0,
        (1,): np.ones(3) + 1.0,
        (0, 1): np.ones(3) + 1.0 + 1.0 + 4.0,
    }
    off_target_contrast = estimate_higher_order_contrast(
        off_target, (0, 1), n_boot=50, seed=5
    ).contrast
    scenarios["off_target_change"] = {
        "observed_contrast": off_target_contrast,
        "expected_contrast": 4.0,
        "passed": math.isclose(off_target_contrast, 4.0),
    }

    # 10. Bootstrap reproducibility and paired standard error.
    values = np.array([1.0, 2.0, 3.0, 4.0, 10.0])
    first = bootstrap_mean_interval(values, n_boot=800, seed=17)
    second = bootstrap_mean_interval(values, n_boot=800, seed=17)
    paired_se = float(values.std(ddof=1) / math.sqrt(values.size))
    scenarios["bootstrap_reproducibility"] = {
        "first": first,
        "second": second,
        "paired_standard_error": paired_se,
        "passed": first == second and math.isclose(first[1], paired_se),
    }

    # 11. Stability summary across groups.
    zeros = np.zeros(24)
    group_noise = np.random.default_rng(9).normal(0.0, 1.5, size=24)
    stable = {
        "cwe-89": estimate_pairwise_contrast(
            zeros, zeros, zeros, 2.0 + group_noise, n_boot=400, seed=6
        ),
        "cwe-79": estimate_pairwise_contrast(
            zeros, zeros, zeros, 1.6 + group_noise, n_boot=400, seed=7
        ),
        "cwe-78": estimate_pairwise_contrast(
            zeros, zeros, zeros, 2.4 + group_noise, n_boot=400, seed=8
        ),
    }
    unstable = {
        **stable,
        "cwe-22": estimate_pairwise_contrast(
            zeros, zeros, zeros, -2.0 + group_noise, n_boot=400, seed=9
        ),
    }
    stable_summary = stability_summary(stable)
    unstable_summary = stability_summary(unstable)
    scenarios["stability_summary"] = {
        "stable": {
            "same_sign": stable_summary.same_sign,
            "sign_consistency": stable_summary.sign_consistency,
            "all_intervals_overlap": stable_summary.all_intervals_overlap,
        },
        "unstable": {
            "same_sign": unstable_summary.same_sign,
            "sign_consistency": unstable_summary.sign_consistency,
            "all_intervals_overlap": unstable_summary.all_intervals_overlap,
        },
        "passed": stable_summary.same_sign
        and not unstable_summary.same_sign
        and math.isclose(unstable_summary.sign_consistency, 0.75),
    }

    # 12. Bootstrap coverage and null containment.
    scenarios["bootstrap_coverage"] = _coverage_simulation()
    scenarios["bootstrap_null_containment"] = _null_containment()
    scenarios["bootstrap_finite_sample_coverage"] = _finite_sample_coverage()

    payload = {
        "experiment": "synthetic_counterfactual_mathematics_validation",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "estimand": (
            "Delta(S) = sum_{T subset S} (-1)^(|S|-|T|) Y(T) on the declared "
            "outcome scale, where Y(T) is the outcome under the simultaneous "
            "intervention that sets every feature in T to its active state."
        ),
        "pairwise_estimand": "Y(1,1) - Y(1,0) - Y(0,1) + Y(0,0)",
        "higher_order_estimand": (
            "sum_{T subset S} (-1)^(|S|-|T|) Y(T) (inclusion-exclusion / Mobius)"
        ),
        "scenarios": scenarios,
        "all_passed": all(
            scenario.get("passed", True) for scenario in scenarios.values()
        ),
    }
    output = OUT_DIR / "synthetic_validation.json"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
