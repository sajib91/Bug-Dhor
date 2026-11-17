"""Numerical validation of equations against independent calculations.

These tests do not duplicate the unit tests.  They check identities that must
hold for any valid implementation: Möbius inversion, discrete derivatives,
finite-difference gradients, linearity, exact budgets, and brute-force masked
averages.
"""

from __future__ import annotations

import itertools
import math

import numpy as np
import pytest
from mathematics.adaptive_steering import (
    AdaptiveSteeringConfig,
    apply_adaptive_steering,
    plan_adaptive_steering,
)
from mathematics.common import (
    bootstrap_ci,
    cohens_d,
    hedges_g,
    pooled_sd,
    stable_sigmoid,
)
from mathematics.cwe_risk import RiskComponents, RiskWeights, compute_risk_index
from mathematics.evidence_fusion import (
    LogisticFusionHead,
    fit_logistic_fusion_head,
    masked_weighted_fusion,
)
from mathematics.higher_order_interaction import mobius_contrast
from mathematics.pairwise_interaction import pairwise_contrast
from mathematics.sae_encoding import (
    SAEParameters,
    decode,
    encode,
    sae_loss,
)
from mathematics.sparse_representation import l0_norm


def powerset(features: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        combo
        for order in range(len(features) + 1)
        for combo in itertools.combinations(features, order)
    )


def random_sae(input_dim: int = 4, latent_dim: int = 3) -> SAEParameters:
    rng = np.random.default_rng(1234)
    return SAEParameters(
        encoder_weight=rng.normal(size=(latent_dim, input_dim)),
        encoder_bias=rng.normal(scale=0.1, size=latent_dim),
        decoder_weight=rng.normal(size=(input_dim, latent_dim)),
        decoder_bias=rng.normal(scale=0.1, size=input_dim),
    )


def test_mobius_inversion_reconstructs_every_cell_mean():
    features = (0, 1, 2)
    rng = np.random.default_rng(99)
    cells = {active: rng.normal(size=6) for active in powerset(features)}
    coefficients = {(): float(cells[()].mean())}
    coefficients.update(
        {active: mobius_contrast(cells, active) for active in powerset(features) if active}
    )
    for active in powerset(features):
        reconstructed = sum(
            coefficients[subset] for subset in powerset(features) if set(subset) <= set(active)
        )
        assert reconstructed == pytest.approx(float(cells[active].mean()), abs=1e-12)


def test_pairwise_contrast_is_a_discrete_mixed_second_derivative():
    def outcome(x: float, y: float) -> float:
        return 3.0 * x * y + 0.5 * x * x - 2.0 * y

    x0, y0, step = 1.3, -0.7, 1e-5
    mixed_difference = (
        outcome(x0 + step, y0 + step)
        - outcome(x0 + step, y0)
        - outcome(x0, y0 + step)
        + outcome(x0, y0)
    ) / (step * step)
    assert mixed_difference == pytest.approx(3.0, abs=1e-6)

    contrast = pairwise_contrast(
        [outcome(x0, y0)],
        [outcome(x0 + step, y0)],
        [outcome(x0, y0 + step)],
        [outcome(x0 + step, y0 + step)],
    )
    assert contrast == pytest.approx(3.0 * step * step, abs=1e-12)


def test_logistic_bce_gradient_matches_finite_differences():
    rng = np.random.default_rng(7)
    features = rng.normal(size=(9, 2))
    labels = np.asarray([0, 1, 1, 0, 1, 0, 1, 1, 0])
    weights = np.asarray([0.4, -0.7])
    bias = 0.2

    def loss(w: np.ndarray, b: float) -> float:
        return LogisticFusionHead(weights=w, bias=b).binary_cross_entropy(features, labels)

    probability = stable_sigmoid(features @ weights + bias)
    analytic_weights = features.T @ (probability - labels) / labels.size
    analytic_bias = float(np.mean(probability - labels))

    epsilon = 1e-6
    for index in range(weights.size):
        plus = weights.copy()
        minus = weights.copy()
        plus[index] += epsilon
        minus[index] -= epsilon
        numeric = (loss(plus, bias) - loss(minus, bias)) / (2.0 * epsilon)
        assert numeric == pytest.approx(analytic_weights[index], abs=1e-7)
    numeric_bias = (loss(weights, bias + epsilon) - loss(weights, bias - epsilon)) / (2.0 * epsilon)
    assert numeric_bias == pytest.approx(analytic_bias, abs=1e-7)


def test_fitted_logistic_head_has_a_near_zero_ridge_gradient():
    rng = np.random.default_rng(11)
    features = rng.normal(size=(300, 3))
    probability = stable_sigmoid(features @ np.asarray([1.2, -0.8, 0.3]) + 0.1)
    labels = (rng.random(300) < probability).astype(np.int8)
    l2 = 1e-5
    head = fit_logistic_fusion_head(features, labels, l2=l2, max_iterations=200, tolerance=1e-10)
    predicted = head.predict_proba(features)
    weight_gradient = features.T @ (predicted - labels) / labels.size + l2 * head.weights
    bias_gradient = float(np.mean(predicted - labels))
    assert np.linalg.norm(weight_gradient) < 1e-5
    assert abs(bias_gradient) < 1e-5


def test_adaptive_l2_budget_is_attained_exactly():
    importance = {index: float(index + 1) for index in range(6)}
    allocation = plan_adaptive_steering(
        importance,
        mean_differences={index: 0.5 for index in range(6)},
        config=AdaptiveSteeringConfig(
            max_features=6,
            l2_budget=2.0,
            max_strength=10.0,
        ),
    ).allocation
    strengths = np.asarray(list(allocation.strengths.values()))
    assert np.linalg.norm(strengths) == pytest.approx(2.0)
    assert allocation.l2_norm > 2.0
    assert allocation.l2_scale == pytest.approx(2.0 / allocation.l2_norm)


def test_risk_index_is_linear_in_the_component_vector():
    weights = RiskWeights(alpha=0.4, beta=0.3, gamma=0.2, delta=0.1)
    components = RiskComponents(0.71, 0.42, 0.63, 0.18)
    base, contributions, _ = compute_risk_index(components, weights)
    scaled, _, _ = compute_risk_index(
        RiskComponents(*(0.3 * value for value in components.as_tuple())),
        weights,
    )
    assert scaled == pytest.approx(0.3 * base)
    assert sum(contributions.values()) == pytest.approx(base)


def test_equation_26_matches_a_brute_force_masked_average():
    rng = np.random.default_rng(21)
    values = rng.uniform(0.0, 1.0, size=(30, 5))
    mask = rng.random((30, 5)) > 0.35
    values[~mask] = np.nan
    weights = rng.uniform(0.1, 1.0, size=5)
    result = masked_weighted_fusion(values, weights)
    assert result.missing_count == int((~mask).sum())
    for row in range(values.shape[0]):
        observed = mask[row]
        if not observed.any():
            assert math.isnan(result.scores[row])
            continue
        expected = float(
            np.sum(values[row, observed] * weights[observed]) / np.sum(weights[observed])
        )
        assert result.scores[row] == pytest.approx(expected, abs=1e-12)


def test_bootstrap_is_reproducible_for_a_seed():
    rng = np.random.default_rng(33)
    values = rng.normal(loc=2.0, scale=0.7, size=80)
    first = bootstrap_ci(np.mean, values, n_boot=400, seed=42)
    second = bootstrap_ci(np.mean, values, n_boot=400, seed=42)
    different = bootstrap_ci(np.mean, values, n_boot=400, seed=43)
    assert first == second
    assert first != different


def test_pooled_effect_sizes_match_their_definitions():
    rng = np.random.default_rng(44)
    vulnerable = rng.normal(1.0, 2.0, size=35)
    secure = rng.normal(-0.5, 1.5, size=27)
    manual_pooled = math.sqrt(
        ((vulnerable.size - 1) * vulnerable.var(ddof=1) + (secure.size - 1) * secure.var(ddof=1))
        / (vulnerable.size + secure.size - 2)
    )
    assert pooled_sd(vulnerable, secure) == pytest.approx(manual_pooled, rel=1e-12)
    d = (vulnerable.mean() - secure.mean()) / manual_pooled
    assert cohens_d(vulnerable, secure) == pytest.approx(d, rel=1e-12)
    total = vulnerable.size + secure.size
    assert hedges_g(vulnerable, secure) == pytest.approx(
        d * (1.0 - 3.0 / (4.0 * total - 9.0)), rel=1e-12
    )


def test_steering_delta_is_the_decoder_linear_combination():
    rng = np.random.default_rng(55)
    parameters = random_sae(input_dim=4, latent_dim=3)
    activations = rng.normal(size=(5, 4))
    plan = plan_adaptive_steering(
        {0: 1.0, 1: 0.6, 2: 0.3},
        config=AdaptiveSteeringConfig(max_features=3, direction_mode="positive"),
    )
    application = apply_adaptive_steering(activations, parameters, plan)
    expected_delta = sum(
        plan.strengths[feature] * parameters.decoder_weight[:, feature]
        for feature in plan.selected_features
    )
    np.testing.assert_allclose(application.delta, np.tile(expected_delta, (5, 1)))
    np.testing.assert_allclose(application.modified, activations + expected_delta)


def test_sae_objective_matches_equation_7_by_hand():
    rng = np.random.default_rng(66)
    parameters = random_sae(input_dim=3, latent_dim=2)
    activations = rng.normal(size=(7, 3))
    latents = encode(activations, parameters)
    reconstruction = decode(latents, parameters)
    expected_reconstruction = float(np.sum((activations - reconstruction) ** 2, axis=1).mean())
    expected_sparsity = float(np.sum(np.abs(latents), axis=1).mean())
    loss = sae_loss(activations, parameters, sparsity_coefficient=0.3)
    assert loss.reconstruction == pytest.approx(expected_reconstruction, rel=1e-12)
    assert loss.sparsity == pytest.approx(expected_sparsity, rel=1e-12)
    assert loss.total == pytest.approx(expected_reconstruction + 0.3 * expected_sparsity, rel=1e-12)


def test_l0_threshold_is_strict_while_encode_threshold_is_post_hoc():
    parameters = SAEParameters(
        encoder_weight=np.eye(3),
        encoder_bias=np.zeros(3),
        decoder_weight=np.eye(3),
        decoder_bias=np.zeros(3),
    )
    activations = np.asarray([[0.5, 0.7, 0.2]])
    encoded = encode(activations, parameters, threshold=0.5)
    np.testing.assert_allclose(encoded, [[0.5, 0.7, 0.0]])
    assert np.count_nonzero(encoded) == 2
    np.testing.assert_array_equal(l0_norm(encoded, threshold=0.5), [1])
