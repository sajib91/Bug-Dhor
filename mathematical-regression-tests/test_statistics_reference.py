"""Independent checks of the evaluation statistics, including corrected edge cases."""

from __future__ import annotations

import math

import pytest
import reference as ref
from craftsec.evaluation.statistics import (
    benjamini_hochberg,
    bootstrap_ci,
    cliffs_delta,
    cohens_d_paired,
    holm_bonferroni,
    mann_whitney_u,
    mean_difference_ci,
    paired_comparison,
    paired_permutation_test,
    paired_t_test,
    wilcoxon_signed_rank,
)


def test_paired_t_statistic_and_df1_p_value_match_closed_form() -> None:
    x = [10.0, 12.0]
    y = [9.0, 10.0]
    expected_t, expected_df = ref.paired_t(ref.paired_differences(x, y))
    result = paired_t_test(x, y)
    assert result["statistic"] == pytest.approx(expected_t)
    assert result["df"] == expected_df
    assert result["p_value"] == pytest.approx(ref.paired_t_p_value_df1(expected_t))
    assert result["n"] == 2


def test_paired_effect_size_matches_reference() -> None:
    x = [10.0, 12.0, 11.0]
    y = [9.0, 10.0, 9.0]
    expected = ref.cohens_d(ref.paired_differences(x, y))
    result = cohens_d_paired(x, y)
    assert result["value"] == pytest.approx(expected)
    assert result["n"] == 3


def test_nan_and_non_finite_observations_are_dropped_pairwise() -> None:
    x = [1.0, float("nan"), 3.0, float("inf")]
    y = [0.0, 0.0, 2.0, 1.0]
    result = paired_t_test(x, y)
    assert result["n"] == 2
    assert result["missing"] == 2
    # The two retained differences are both 1.0, so the variance is zero and the
    # t statistic is unbounded rather than a finite number.
    assert result["statistic"] == math.inf
    assert result["p_value"] == 0.0
    assert result["reason"] == "zero_variance_nonzero_mean"

    permutation = paired_permutation_test(x, y, n_perm=100, seed=1)
    assert permutation["n"] == 2
    assert permutation["missing"] == 2

    wilcoxon = wilcoxon_signed_rank(x, y)
    assert wilcoxon["n"] == 2
    assert wilcoxon["missing"] == 2


def test_unequal_paired_lengths_raise_instead_of_truncating() -> None:
    for function in (
        paired_t_test,
        cohens_d_paired,
        mean_difference_ci,
        paired_permutation_test,
        wilcoxon_signed_rank,
    ):
        with pytest.raises(ValueError, match="equal length"):
            function([1.0, 2.0, 3.0], [1.0, 2.0])
    with pytest.raises(ValueError, match="equal length"):
        paired_comparison([1.0, 2.0, 3.0], [1.0, 2.0])


def test_zero_variance_is_distinguished_from_no_difference() -> None:
    nonzero = paired_t_test([1.0, 1.0], [2.0, 2.0])
    assert nonzero["p_value"] == 0.0
    assert nonzero["statistic"] == -math.inf
    assert nonzero["reason"] == "zero_variance_nonzero_mean"

    zero = paired_t_test([1.0, 1.0], [1.0, 1.0])
    assert zero["p_value"] is None
    assert zero["statistic"] is None
    assert zero["reason"] == "zero_variance_no_difference"


def test_paired_comparison_means_use_the_same_aligned_pairs() -> None:
    result = paired_comparison(
        [1.0, float("nan"), 3.0],
        [0.0, 0.0, 100.0],
        n_boot=100,
        n_perm=100,
    )
    assert result.n_pairs == 2
    assert result.missing == 1
    assert result.mean_a == pytest.approx(2.0)
    assert result.mean_b == pytest.approx(50.0)
    assert result.mean_difference == pytest.approx(-48.0)


def test_bootstrap_cluster_alignment_is_enforced_and_none_is_excluded() -> None:
    with pytest.raises(ValueError, match="cluster_ids"):
        bootstrap_ci([1.0, 2.0], cluster_ids=["a"], n_boot=10)

    result = bootstrap_ci([1.0, 2.0, 3.0], cluster_ids=["a", None, "b"], n_boot=50, seed=2)
    assert result.estimate == pytest.approx(2.0)
    assert result.n == 2
    assert result.missing == 1
    assert result.assumptions[0]["nEffectiveClustersOrUnits"] == 2


def test_bootstrap_drops_non_finite_values_and_is_reproducible() -> None:
    values = [1.0, float("inf"), float("nan"), 3.0]
    first = bootstrap_ci(values, n_boot=100, seed=4)
    second = bootstrap_ci(values, n_boot=100, seed=4)
    assert first.to_dict() == second.to_dict()
    assert first.estimate == pytest.approx(2.0)
    assert first.n == 2
    assert first.missing == 2


def test_holm_and_bh_match_hand_computation_and_skip_missing_p_values() -> None:
    holm = holm_bonferroni([0.01, 0.04, 0.03, None])
    assert [row["adjusted_p_value"] for row in holm] == pytest.approx([0.03, 0.06, 0.06, None])
    assert [row["reject"] for row in holm] == [True, False, False, None]
    assert [row["adjusted_p_value"] for row in holm] == pytest.approx(
        ref.holm([0.01, 0.04, 0.03, None])
    )

    bh = benjamini_hochberg([0.01, 0.04, 0.03, float("nan")])
    assert [row["adjusted_p_value"] for row in bh] == pytest.approx([0.03, 0.04, 0.04, None])
    assert [row["reject"] for row in bh] == [True, True, True, None]

    holm_nan = holm_bonferroni([0.01, float("nan"), 0.03])
    assert holm_nan[1]["adjusted_p_value"] is None


def test_empty_inputs_return_insufficient_results() -> None:
    result = bootstrap_ci([], n_boot=10)
    assert result.estimate is None
    assert result.n == 0
    comparison = paired_comparison([], [])
    assert comparison.n_pairs == 0
    assert comparison.mean_difference is None
    assert comparison.paired_t_test["p_value"] is None


def test_mann_whitney_u_matches_pairwise_definition_with_ties() -> None:
    x = [1.0, 2.0, 2.0, 3.0]
    y = [2.0, 3.0, 4.0]
    expected_u, expected_z, expected_p, _ = ref.mann_whitney_counts(x, y)
    result = mann_whitney_u(x, y)
    assert result["statistic"] == pytest.approx(expected_u)
    assert result["z"] == pytest.approx(expected_z)
    assert result["p_value"] == pytest.approx(expected_p)
    assert result["n1"] == 4
    assert result["n2"] == 3
    assert result["missing"] == 0

    # No ties: the statistic equals the hand-counted wins over the other group.
    clean_x = [1.0, 2.0, 3.0]
    clean_y = [4.0, 5.0]
    clean = mann_whitney_u(clean_x, clean_y)
    assert clean["statistic"] == pytest.approx(0.0)
    assert clean["p_value"] == pytest.approx(
        ref.two_sided_normal_p(
            (0.0 - 3.0) / math.sqrt(3 * 2 / 12.0 * (6))
        )
    )


def test_mann_whitney_and_cliffs_degenerate_inputs() -> None:
    empty = mann_whitney_u([], [1.0])
    assert empty["p_value"] is None
    assert empty["statistic"] is None
    assert empty["reason"] == "insufficient_observations"

    constant = mann_whitney_u([1.0, 1.0], [1.0, 1.0])
    assert constant["p_value"] is None
    assert constant["statistic"] == pytest.approx(2.0)
    assert constant["reason"] == "zero_variance"

    missing = mann_whitney_u([1.0, float("nan"), 3.0], [2.0, float("inf")])
    assert missing["n1"] == 2 and missing["n2"] == 1
    assert missing["missing"] == 2

    no_effect = cliffs_delta([], [1.0])
    assert no_effect["value"] is None
    assert no_effect["reason"] == "insufficient_observations"


def test_cliffs_delta_matches_pairwise_count_definition() -> None:
    x = [1.0, 2.0, 2.0, 4.0]
    y = [2.0, 3.0, 5.0]
    result = cliffs_delta(x, y)
    assert result["value"] == pytest.approx(ref.cliffs_delta_counts(x, y))
    assert result["n1"] == 4
    assert result["n2"] == 3
    # Ties contribute zero to the difference.
    assert result["value"] == pytest.approx((2 - 8) / 12.0)

    dropped = cliffs_delta([1.0, float("nan")], [0.0, float("inf"), 2.0])
    assert dropped["n1"] == 1 and dropped["n2"] == 2
    assert dropped["missing"] == 2
    assert dropped["value"] == pytest.approx(0.0)


def test_mean_difference_ci_matches_normal_approximation() -> None:
    small_x = [10.0, 12.0, 9.0, 11.0, 13.0]
    small_y = [9.0, 10.0, 8.0, 10.0, 11.0]
    expected = ref.mean_difference_interval(small_x, small_y)
    small = mean_difference_ci(small_x, small_y)
    assert small.estimate == pytest.approx(expected[0])
    assert small.ci_low == pytest.approx(expected[1])
    assert small.ci_high == pytest.approx(expected[2])
    assert small.method == "normal_approx_ci_small_n_caution"
    assert small.n == 5

    import random

    generator = random.Random(11)
    large_x = [generator.gauss(1.0, 0.5) for _ in range(40)]
    large_y = [generator.gauss(0.0, 0.5) for _ in range(40)]
    expected_large = ref.mean_difference_interval(large_x, large_y)
    large = mean_difference_ci(large_x, large_y)
    assert large.estimate == pytest.approx(expected_large[0])
    assert large.ci_low == pytest.approx(expected_large[1])
    assert large.ci_high == pytest.approx(expected_large[2])
    assert large.method == "normal_approx_ci"

    single = mean_difference_ci([1.0], [0.0])
    assert single.estimate == pytest.approx(1.0)
    assert single.ci_low is None
    assert single.n == 1
