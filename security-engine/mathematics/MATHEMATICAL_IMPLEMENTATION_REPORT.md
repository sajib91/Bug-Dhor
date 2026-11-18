# Bug Dhor Mathematical Implementation Report

This report maps the implemented Bug Dhor mathematical formulations to their
Python functions, tests, numerical behaviour, and complexity. The authoritative
equation reference is [`research/mathematical-formulations.md`](../../research/mathematical-formulations.md);
the package described here is [`security-engine/mathematics/`](.).

The scope is the twelve requested components:

1. SAE encoding and decoding (Eq. 5-7)
2. Sparse activation representation (Eq. 8 support set)
3. Feature activation measurement
4. Feature association statistics (Eq. 9-11)
5. Single-feature intervention
6. Pairwise interaction effects (Eq. 12-13)
7. Higher-order interaction effects (Möbius generalisation of Eq. 12-13)
8. Counterfactual outcome estimation
9. Adaptive multi-feature steering
10. CWE-specific risk estimation (Eq. 28-29)
11. Multi-source evidence fusion (Eq. 24, 26, 27)
12. Functional preservation constraints (Eq. 34-39)

Everything is implemented from the stated estimand. No function returns a
hard-coded risk score, a fabricated interaction, or an invented outcome.
Outcomes, activations, labels, evidence scores, test results, and vulnerability
sets are always supplied by the caller.

## 1. Package layout

| File | Responsibility |
|---|---|
| `common.py` | float64 conversion, shape checks, masks, stable sigmoid/logit, Student-t and incomplete-beta numerics, means/SEs/CIs, bootstrap, effect sizes, correlations, Benjamini-Hochberg |
| `sae_encoding.py` | Eq. 5-7, reconstruction diagnostics, decoder-column normalization |
| `sparse_representation.py` | Eq. 8 per-feature activation, sparse support, L0/L1, dense round-trip |
| `feature_measurement.py` | Per-feature activation statistics and token pooling |
| `feature_association.py` | Eq. 9-11, Hedges' g, Welch inference, bootstrap, BH, permutation null |
| `single_feature_intervention.py` | `do(z_j = u)` operators, paired treatment effects, dose sweeps |
| `pairwise_interaction.py` | Eq. 12-13, paired/unpaired factorial contrasts |
| `higher_order_interaction.py` | Möbius contrasts, exhaustive/sampled subsets, cost accounting |
| `counterfactual_estimation.py` | Paired counterfactual deltas and cell means |
| `adaptive_steering.py` | Importance ranking, interaction-aware allocation, L2 budget, position schedule, decoder-direction application |
| `cwe_risk.py` | Eq. 28-29, weights, bands, CWE policy registry, missing policies |
| `evidence_fusion.py` | Eq. 24 assembly, Eq. 26 masked mean, Eq. 27 logistic head, documented noisy-OR baseline |
| `functional_preservation.py` | Eq. 34-39 with three-valued predicates |
| `examples.py` | Deterministic end-to-end example for every component |
| `tests/mathematics/` | Unit tests plus cross-module numerical validation |

The unit and numerical suites are run with:

```bash
cd security-engine
./.venv/bin/python -m pytest tests/mathematics -q
```

Current result: **108 passed**. The reproducible example runner is:

```bash
cd security-engine
./.venv/bin/python -m mathematics.examples
```

## 2. Shared numerical conventions

### 2.1 Inputs and tensor validation

`common.as_float_array` converts array-like input and detached PyTorch tensors to
NumPy `float64`. A tensor must be detached and on CPU; gradients are not
retained. Empty arrays are rejected. Shape helpers (`require_2d`,
`require_same_shape`, `require_same_length`, `require_ndim`) are called at every
public boundary, so a mismatched latent width, outcome length, mask shape, or
weight vector fails with an explicit `ValueError` instead of broadcasting
silently.

### 2.2 Missing values

The package distinguishes two cases.

* **Statistical missingness**: represented by `NaN` and/or an explicit boolean
  `observed` mask. Estimands drop the missing observation from numerator and
  denominator, report the observed count, and return `NaN` when no observation
  remains. Missing values are never silently zero-imputed.
* **Representation missingness**: non-finite latents in
  `sparse_representation.to_sparse` are treated as inactive and counted in
  `missing_count`. The dense form fills them with zero because a sparse support
  has no value there. This is an explicit representation choice, not an
  imputation used by any statistical estimand.

Methods that cannot estimate an effect from missing data return `NaN` for the
estimate and expose `missing_count`. Modules with a configurable missing policy
(`cwe_risk`, `evidence_fusion`) document each option below.

### 2.3 Numerical stability

* Sigmoid uses separate positive/negative branches to avoid overflow.
* Logit and probability validation clamp only through the explicit
  `stable_logit` epsilon; inputs outside `[0, 1]` are rejected elsewhere.
* Pooled variance `<= 0` yields `NaN` for Cohen's d rather than division by
  zero; Cliff's delta is available as the degenerate-variance fallback.
* Degenerate reconstruction R² is `NaN`, not an arbitrary number.
* Student-t tail probabilities use a continued-fraction incomplete beta
  implementation because SciPy is not installed. The normal approximation is
  used only where documented.
* The logistic fusion head is fitted by ridge-regularized IRLS with a
  least-squares fallback when the Hessian is singular.
* L2 steering budgets are attained by a global rescale of the clipped strength
  vector, not by per-feature truncation.

### 2.4 Reproducibility

Every stochastic procedure accepts `seed: int | None` or a
`numpy.random.Generator`: bootstrap confidence intervals, association bootstrap
intervals, permutation tests, and subset sampling. Library procedures obtain
their generators through `common.resolve_rng`; the example runner uses
`numpy.random.default_rng` with a fixed seed. Ties in feature ranking are broken
by ascending feature index. The example output is byte-for-byte deterministic
across runs (`test_examples.py::test_reproducible_examples_run_end_to_end`).

## 3. Equation-to-code matrix

| Equation / estimand | Implementation | Primary tests |
|---|---|---|
| Eq. 5 `z = ReLU(W_e h + b_e)` | `sae_encoding.encode` | `test_sae_encoding.py::test_encode_decode_equations`, `::test_encode_threshold_is_post_hoc` |
| Eq. 6 `h_hat = W_d z + b_d` | `sae_encoding.decode`, `forward` | `test_encode_decode_equations` |
| Eq. 7 `L_SAE` | `sae_encoding.sae_loss` | `test_sae_loss_paper_formula_is_exact`, `test_numerical_validation.py::test_sae_objective_matches_equation_7_by_hand` |
| Eq. 8 `z_ij = ReLU(w_j . h_i + b_j)` | `sparse_representation.feature_activation` | `test_sparse_representation.py::test_feature_activation_equation_8` |
| Sparse support `{j : \|z_ij\| > threshold}` | `to_sparse`, `l0_norm`, `l1_norm`, `SparseActivation` | `test_threshold_is_strict`, `test_top_k_and_dense_roundtrip`, `test_numerical_validation.py::test_l0_threshold_is_strict_while_encode_threshold_is_post_hoc` |
| Activation statistics | `feature_measurement.measure_feature_activations` | `test_feature_measurement.py::test_feature_statistics_match_definitions` |
| Token pooling | `feature_measurement.pool_token_activations` | `test_token_pooling_respects_attention_mask` |
| Eq. 9 `Delta mu_j` | `feature_association.analyze_feature_associations` | `test_feature_association.py::test_equations_9_and_10_are_exact` |
| Eq. 10 Cohen's d / Hedges' g | same, via `common.cohens_d`, `common.hedges_g` | `test_equations_9_and_10_are_exact`, `test_numerical_validation.py::test_pooled_effect_sizes_match_their_definitions` |
| Eq. 11 `rho_ij` | `feature_correlation_matrix`, `correlation_p_values` | `test_correlation_matrix_and_p_values`, `test_degenerate_correlation_is_nan` |
| Single-feature `do(z_j = u)` and `tau_j` | `apply_latent_intervention`, `apply_decoder_intervention`, `estimate_paired_effect`, `run_single_feature_experiment` | `test_single_feature_intervention.py::test_ablation_effect_is_exact`, `test_numerical_validation.py::test_steering_delta_is_the_decoder_linear_combination` |
| Eq. 12 `I_ij` | `pairwise_interaction.pairwise_contrast`, `estimate_pairwise_interaction` | `test_pairwise_interaction.py::test_equation_12_contrast`, `test_numerical_validation.py::test_pairwise_contrast_is_a_discrete_mixed_second_derivative` |
| Eq. 13 continuous `I_ij(a,b)` | `run_pairwise_experiment` with `value_a`, `value_b` | `test_run_pairwise_experiment_with_identity_sae` |
| Möbius higher-order contrast | `higher_order_interaction.mobius_contrast`, `estimate_higher_order_interaction` | `test_higher_order_interaction.py::test_mobius_contrast_recovers_the_triple_interaction`, `test_numerical_validation.py::test_mobius_inversion_reconstructs_every_cell_mean` |
| Counterfactual `Delta(T)` | `counterfactual_estimation.estimate_counterfactual_outcomes`, `CounterfactualEstimator` | `test_counterfactual_estimation.py::test_paired_estimand_is_exact`, `::test_estimator_applies_real_decoder_intervention` |
| Adaptive allocation and schedule | `adaptive_steering.rank_feature_importance`, `allocate_feature_strengths`, `build_position_schedule`, `plan_adaptive_steering`, `apply_adaptive_steering` | `test_adaptive_steering.py` (all), `test_numerical_validation.py::test_adaptive_l2_budget_is_attained_exactly` |
| Eq. 24 evidence assembly | `evidence_fusion.assemble_evidence_matrix` | `test_evidence_fusion.py::test_equation_24_assembly_preserves_columns_and_availability` |
| Eq. 26 masked weighted mean | `masked_weighted_fusion` | `test_equation_26_masked_weighted_mean_never_imputes`, `test_numerical_validation.py::test_equation_26_matches_a_brute_force_masked_average` |
| Eq. 27 logistic fusion | `fit_logistic_fusion_head`, `LogisticFusionHead` | `test_equation_27_logistic_head_is_deterministic_and_learns`, `test_numerical_validation.py::test_logistic_bce_gradient_matches_finite_differences`, `::test_fitted_logistic_head_has_a_near_zero_ridge_gradient` |
| Eq. 28 risk index | `cwe_risk.compute_risk_index`, `assess_cwe_risk` | `test_cwe_risk.py::test_equation_28_is_exact_and_contributions_sum_to_score`, `test_numerical_validation.py::test_risk_index_is_linear_in_the_component_vector` |
| Eq. 29 priority bands | `classify_risk_band` | `test_equation_29_band_boundaries_are_inclusive_at_the_lower_threshold` |
| Eq. 34 pass rate | `functional_preservation.functional_pass_rate` | `test_functional_preservation.py::test_equation_34_exact_pass_rate` |
| Eq. 35 functional predicate | `functional_predicate` | `test_empty_test_set_and_functional_predicate` |
| Eq. 36 Hoare triple | `hoare_triple_predicate` | `test_equation_36_requires_a_real_verifier` |
| Eq. 37 targeted removal | `targeted_removal_predicate` | `test_equation_37_targeted_removal` |
| Eq. 38 no new vulnerabilities | `no_new_vulnerabilities_predicate` | `test_equation_38_no_new_vulnerabilities` |
| Eq. 39 acceptance conjunction | `accept_patch`, `evaluate_preservation` | `test_equation_39_acceptance_conjunction`, `test_evaluate_preservation_end_to_end` |

## 4. Component details

### 4.1 SAE encoding, decoding, and objective (Eq. 5-7)

**Module:** `sae_encoding.py`

**Equations.** For `h ∈ R^d`, `W_e ∈ R^{d_s×d}`, `W_d ∈ R^{d×d_s}`:

```text
z       = ReLU(W_e h + b_e)                                            (5)
h_hat   = W_d z + b_d                                                  (6)
L_SAE   = (1/N) sum_i ||h_i - h_hat_i||^2
        + lambda * (1/N) sum_i ||z_i||_1                                (7)
```

**Functions.**

* `SAEParameters(encoder_weight, encoder_bias, decoder_weight, decoder_bias)`
  validates all four shapes and exposes `decoder_direction(j)`.
* `encode(activations, parameters, threshold=None)` evaluates Eq. 5. A
  `threshold` is an explicitly documented *post-hoc* sparsification
  (`|z| >= threshold`); it is not part of Eq. 5.
* `decode(latents, parameters)` and `forward(...)` evaluate Eq. 6.
* `sae_loss(..., sparsity_coefficient, reduction="paper")` evaluates Eq. 7 and
  returns total, reconstruction, and sparsity terms separately.
  `reduction="elementwise"` accepts an `observed` mask and excludes masked
  entries from the reconstruction numerator and denominator; it does not
  impute them.
* `reconstruction_metrics` returns R², per-sample L0, mean L0, and dead-feature
  fraction.
* `normalize_decoder_columns` applies the documented SAE convention
  `||W_d[:, j]||_2 = 1`.

**Missing values.** Eq. 7 is defined for complete activation vectors. NaN
activations are rejected. Partial observations require the explicit
`observed` mask with `reduction="elementwise"`.

**Numerical stability.** Latents are computed in float64. Degenerate R²
(`SS_tot = 0`) returns `NaN`. The L1 term uses `abs`, so it is differentiable
almost everywhere as expected.

**Complexity.** Encode/decode `O(N d d_s)`. Loss `O(N(d + d_s))`. Memory
`O(N d_s)`.

**Tests.** `test_sae_encoding.py`, and numerical checks in
`test_numerical_validation.py`.

### 4.2 Sparse activation representation (Eq. 8 and support set)

**Module:** `sparse_representation.py`

**Equations.** Per-feature activation is Eq. 8:

```text
z_ij = ReLU(w_j . h_i + b_j),    w_j = W_e[j, :]^T
```

The sparse representation is the thresholded support:

```text
support_i = { j : |z_ij| > threshold }        (optional top-k cap)
sparse_i  = { (j, z_ij) : j in support_i }
```

**Functions.**

* `feature_activation(activations, encoder_row, encoder_bias)` evaluates Eq. 8
  for one feature over a batch.
* `to_sparse(latents, threshold, top_k, observed)` builds padded index/value
  matrices. Padding is marked with `-1` in `indices`.
* `l0_norm`, `l1_norm`, `reconstruction_error`, and
  `SparseActivation.to_dense` provide representation diagnostics and round-trip.
* `SparseActivation.l0_per_sample` and `density` expose support statistics.

**Threshold semantics.** The statistical support definition uses the strict
predicate `|z| > threshold`. `encode(..., threshold=...)` uses `>=` because it
is a post-hoc truncation of the encoder output, not a support-set estimand.
This distinction is pinned by the numerical test
`test_l0_threshold_is_strict_while_encode_threshold_is_post_hoc`.

**Missing values.** Non-finite latents are inactive and counted in
`missing_count`; `to_dense` fills them with the requested `fill` value (default
zero). `observed` can only remove values from the support, never add them.

**Complexity.** Threshold sparsification `O(N d_s)`. Top-k uses `argpartition`
in `O(N d_s)` average plus `O(N k log k)` sorting. Dense conversion
`O(N d_s)`.

**Tests.** `test_sparse_representation.py`.

### 4.3 Feature activation measurement

**Module:** `feature_measurement.py`

**Definitions.** For feature `j` with observed values `{z_ij}`:

```text
mean_j        = (1/n_j) sum_i z_ij
sd_j          = sqrt((1/(n_j-1)) sum_i (z_ij - mean_j)^2)
freq_j        = (1/n_j) sum_i 1[|z_ij| > threshold]
active_mean_j = mean_i { z_ij : |z_ij| > threshold }
active_count_j= |{ i : |z_ij| > threshold }|
L0_i          = sum_j 1[|z_ij| > threshold]
```

Token pooling for one sample is the masked mean

```text
z_i = (1 / sum_t m_it) sum_t m_it z_it
```

**Functions.** `measure_feature_activations` returns per-feature means, sample
SDs, maxima, activation frequency, active means/counts, observed counts, and
requested quantiles. `FeatureMeasurement.to_records` produces serializable
records. `pool_token_activations` returns pooled latents and valid-token
counts.

**Missing values.** NaN entries and explicitly masked entries are excluded
per feature. A feature with no observation reports `NaN` statistics and
`observed_count == 0`. A sample with no valid token pools to `NaN`; it is not
silently dropped.

**Complexity.** Measurement `O(N F)`. Token pooling `O(N T d_s)`. Quantiles add
`O(N log N)` per selected feature.

**Tests.** `test_feature_measurement.py`.

### 4.4 Feature association statistics (Eq. 9-11)

**Module:** `feature_association.py`

**Equations.**

```text
Delta mu_j = E[z_j | y=1] - E[z_j | y=0]                                (9)
d_j        = (mu_j1 - mu_j0) / s_pool,j                                (10)
s_pool,j   = sqrt(((n1-1)s1^2 + (n0-1)s0^2) / (n1+n0-2))
rho_ij     = Cov(z_i, z_j) / (sigma_i sigma_j)                          (11)
```

**Functions.** `analyze_feature_associations` returns `Delta mu_j`, Cohen's d,
Hedges' g, group means/SDs, activation frequencies, Welch standard errors and
degrees of freedom, confidence intervals (normal or seeded bootstrap), p-values,
and BH q-values. `feature_correlation_matrix` computes Eq. 11 globally or
pairwise with an observed mask; `method="spearman"` is available for
zero-inflated or non-linear latents. `correlation_p_values` converts
correlations to two-sided p-values with multiplicity correction.
`permutation_association_test` provides a seeded label-permutation null.

**Audit additions (not paper equations).** Hedges' bias correction, Welch
inference, bootstrap intervals, Cliff's delta fallback when pooled variance is
degenerate, BH correction, and the permutation null are explicitly labelled as
audit additions in the module docstring.

**Missing values.** A missing feature observation is excluded from that
feature's group statistics. A group with no observations reports `NaN` for the
affected estimand. Missing labels are rejected. BH ignores `NaN` p-values and
never turns them into discoveries.

**Numerical stability.** A pooled variance `<= 0` gives `NaN` for Cohen's d and
activates Cliff's delta. A correlation with zero variance is `NaN`.
Satterthwaite degrees of freedom are used for Welch intervals.

**Complexity.** Association `O(N F)`. BH `O(F log F)`. Bootstrap
`O(B N F)`. Correlation matrix `O(N F^2)`.

**Tests.** `test_feature_association.py` plus effect-size checks in
`test_numerical_validation.py`.

### 4.5 Single-feature intervention

**Module:** `single_feature_intervention.py`

**Intervention operator.** For feature `j` and target latent value `u`:

```text
do(z_j = u):
    u = 0            ablation
    u = value        clamp
    u = z_j + value  additive shift

decoder-direction form:
    delta_z = u - z_j
    h'      = h + delta_z * W_d[:, j]
```

The per-feature effect is the paired average treatment effect

```text
tau_j = (1/N) sum_i [ g(h_i') - g(h_i) ]
```

with a standard error, confidence interval, and standardized paired effect
`tau_j / sd(g(h') - g(h))`.

**Functions.** `apply_latent_intervention`, `apply_decoder_intervention`,
`apply_multi_feature_decoder_intervention`, `estimate_paired_effect`,
`run_single_feature_experiment`, and `sweep_intervention_values`.

**Missing values.** Missing latents are left unchanged and counted. A unit with
a non-finite factual or interventional outcome is dropped pairwise from the
effect estimate and reported in `missing_count`.

**Complexity.** Latent intervention `O(N d_s)`. Decoder-direction intervention
`O(N d)`. Effect estimation `O(N)`, or `O(B N)` for a bootstrap interval.

**Tests.** `test_single_feature_intervention.py`, including the exact ablation
effect and the decoder linear-combination check in
`test_numerical_validation.py::test_steering_delta_is_the_decoder_linear_combination`.

### 4.6 Pairwise interaction effects (Eq. 12-13)

**Module:** `pairwise_interaction.py`

**Equations.**

```text
I_ij        = g(1,1) - g(1,0) - g(0,1) + g(0,0)                        (12)
I_ij(a,b)   = g(a,b) - g(a,0) - g(0,b) + g(0,0)                        (13)
```

Sign convention: `I > 0` is synergy on the declared outcome scale; `I < 0` is
antagonism. The contrast is scale-dependent and is not invariant to nonlinear
outcome transformations.

**Functions.** `pairwise_contrast` implements Eq. 12 from four cells.
`estimate_pairwise_interaction` computes the paired contrast (per-unit
difference-in-differences, then average) or the unpaired contrast, with
confidence intervals and provenance. `run_pairwise_experiment` builds the four
cells by applying real decoder-direction interventions through the SAE.
`rank_pairwise_interactions` orders measured experiments.

**Missing values.** In the paired design, a unit missing any cell is dropped
and counted. In the unpaired design, each cell drops its own missing values.
No cell is imputed.

**Complexity.** Estimate `O(N)` paired or `O(sum n_cells)` unpaired. Bootstrap
`O(B N)`. A full experiment evaluates four cells, each `O(N d)`.

**Tests.** `test_pairwise_interaction.py` and the discrete mixed-derivative
check in `test_numerical_validation.py`.

### 4.7 Higher-order interaction effects (Möbius generalisation)

**Module:** `higher_order_interaction.py`

**Equation.** For a sorted feature subset `S`, `|S| = k`:

```text
I_S = sum_{T subseteq S} (-1)^(k - |T|) g(T)
```

All `2^k` factorial cells are required. `g(T)` is the mean outcome under the
simultaneous intervention that clamps every feature in `T`. `I_S > 0` means
the joint effect exceeds the alternating lower-order combination; `I_S < 0`
means antagonism.

**Functions.** `mobius_contrast` applies the equation to supplied cell
outcomes. `estimate_higher_order_interaction` adds paired/unpaired uncertainty
and confidence intervals. `run_higher_order_experiment` evaluates cells with
the same decoder-direction operator as the lower-order modules and caches
repeated cells. `generate_subsets` produces exhaustive or seeded sampled
subsets. `complexity_report` counts cell evaluations.

**Missing values.** Paired design drops a unit if any required cell is
missing. Unpaired design drops missing values per cell. A missing cell raises
an error; it is never treated as zero. The empty subset is the baseline cell
mean; `mobius_contrast` requires a non-empty target subset.

**Complexity.** One subset `O(2^k N)`. Exhaustive subsets up to order `K` over
`F` features: `sum_{k=1..K} C(F,k) 2^k` cell evaluations. Caching means each
unique cell is evaluated once per experiment.

**Tests.** `test_higher_order_interaction.py`, plus the Möbius inversion
identity in `test_numerical_validation.py::test_mobius_inversion_reconstructs_every_cell_mean`.

### 4.8 Counterfactual outcome estimation

**Module:** `counterfactual_estimation.py`

**Estimand.** For an intervention set `T` with targets `u_T`:

```text
g(T)     = E_{x ~ D_eval}[ f(x ; do(z_j = u_j for j in T)) ]
Delta(T) = (1/N) sum_i [ f(x_i; do(z_T = u_T)) - f(x_i) ]
```

`f` is caller-supplied; it is never invented by the package.

**Functions.** `estimate_counterfactual_outcomes` computes the paired delta,
standard error, confidence interval, standardized effect, and missing count
from *measured* factual and counterfactual outcomes.
`CounterfactualEstimator.estimate` applies real decoder interventions to
activations, evaluates the caller's `outcome_fn`, then calls the same estimator.
`CounterfactualEstimator.expected_cell_means` returns cell means and reuses the
baseline cell rather than recomputing it. `make_decoder_intervention_function`
wraps a set of interventions as an outcome-transform callable.

**Missing values.** A unit with a missing factual or counterfactual outcome is
excluded from the paired estimate. Missing activations are rejected by the SAE
encoder, not silently dropped.

**Complexity.** Each intervention cell `O(N d)`. `M` cells `O(M N d)`. Effect
estimation `O(N)`, or `O(B N)` for the bootstrap.

**Tests.** `test_counterfactual_estimation.py`.

### 4.9 Adaptive multi-feature steering

**Module:** `adaptive_steering.py`

**Formulation.** This policy is a documented extension, not a single numbered
paper equation. For each selected feature `j`:

```text
i_j    = |a_j|                                  measured importance magnitude
d_j    = direction(Delta mu_j)                  +1 / -1
tau_j  = s_0 * w_individual * i_j * d_j         individual term

tau_j += sum_{S : j in S, |S| >= 2}
             s_0 * w_|S| * I_S / |S|            interaction term

tau_j *= context_multiplier
tau_j  = clip(tau_j, -s_max, +s_max)            per-feature bound

if ||tau||_2 > B:
    tau = (B / ||tau||_2) * tau                 global L2 budget

h'_i = h_i + sum_{j in selected} tau_j * W_d[:, j]
```

The per-position schedule uses only measured activations:

```text
active(p)   = { j : |z_{p,j}| > activation_threshold }
scale_{p,j} = |z_{p,j}| / activation_reference
tau_{p,j}   = clip(tau_j * scale_{p,j}, -s_max, +s_max) if j in active(p)
              0 otherwise
```

**Functions.** `rank_feature_importance` performs deterministic ranking
(descending magnitude, ties by ascending index) and resolves direction.
`allocate_feature_strengths` implements individual and interaction terms,
context adjustment, per-feature clipping, and the exact global L2 rescale.
`build_position_schedule` implements the position schedule.
`plan_adaptive_steering` returns the complete plan.
`apply_adaptive_steering` applies the same decoder-direction displacement to
every row in the batch, or uses a precomputed delta when available.

**Missing values and direction.** Non-finite importance, direction, contrast,
or activation values are rejected. A feature without importance is never
selected. A position without measured activations receives no scheduled
strength. With the default `direction_mode="association_reducing"`, every
candidate must have a finite mean difference; use `"positive"` or `"negative"`
when no association is measured.

**Complexity.** Ranking `O(F log F)`. Allocation `O(F + sum_S |S|)`. L2
clipping `O(F)`. Schedule `O(P F)` for `P` positions. Application `O(N d F)`,
or `O(N d + N F)` with a precomputed delta.

**Tests.** `test_adaptive_steering.py`, including direction semantics,
individual/interaction allocation, context and clipping, exact budget scaling,
strict schedule thresholds, decoder-direction application, and validation.
The budget invariant is independently checked in
`test_numerical_validation.py::test_adaptive_l2_budget_is_attained_exactly`.

### 4.10 CWE-specific risk estimation (Eq. 28-29)

**Module:** `cwe_risk.py`

**Equations.**

```text
R_index(v) = alpha P(v) + beta S(v) + gamma E(v) + delta I(v)          (28)

C(v) = Critical  if R_index(v) >= tau_3
       High      if tau_2 <= R_index(v) < tau_3
       Medium    if tau_1 <= R_index(v) < tau_2
       Low       if R_index(v) < tau_1                                  (29)
```

**Functions.** `compute_risk_index` returns the score, per-component
contributions, and the weights actually used. `classify_risk_band` implements
Eq. 29 with inclusive lower boundaries. `assess_cwe_risk` bundles the score,
band, components, policy, contributions, and missing diagnostics.
`CweRiskScorer` is a per-CWE registry with a documented default fallback and a
batch API keyed by identifier.

**Weights.** `RiskWeights` requires finite non-negative weights with a positive
sum. `normalize=True` (default) divides by the sum, keeping `R_index` in
`[0, 1]` when components are in `[0, 1]`. `normalize=False` preserves the
literal unnormalized Eq. 28 weights; callers must then interpret thresholds
accordingly.

**Not a probability.** `RiskAssessment.is_probability` is always `False`, and
the result carries an explicit interpretation statement. `P` is assumed
calibrated by the caller; this module performs no calibration.

**Missing values.** `NaN` marks an unavailable component. The policy chooses:

* `"nan"` (default): score `NaN`, band `"Unknown"`, no imputation.
* `"error"`: raise `ValueError` naming the missing component.
* `"renormalize"`: renormalize weights over available components. This is an
  explicit extension, not Eq. 28 as written, and is reported in the result.
  If every component is missing, the result is not a score.

**Complexity.** `O(1)` time and memory per finding; `O(K)` for a registry of
`K` CWE policies.

**Tests.** `test_cwe_risk.py`, plus the linearity check in
`test_numerical_validation.py::test_risk_index_is_linear_in_the_component_vector`.

### 4.11 Multi-source evidence fusion (Eq. 24, 26, 27)

**Module:** `evidence_fusion.py`

**Equations.**

```text
e_i = [e_neural ; e_SAE ; e_interaction ; e_AST ; e_CFG ;
       e_DFG ; e_taint ; e_dynamic]                                    (24)

S_i = (sum_j m_ij w_j q_ij) / (sum_j m_ij w_j)                         (26)

P_fusion(y_i = 1) = sigmoid(w_f^T h_fusion + b_f)                      (27)
```

**Functions.** `assemble_evidence_matrix` implements Eq. 24 as an aligned
`[N, J]` matrix with an availability mask and named columns; it rejects
unaligned lengths and empty evidence. `masked_weighted_fusion` implements
Eq. 26 directly. `fit_logistic_fusion_head` and `LogisticFusionHead` implement
Eq. 27 with ridge-regularized IRLS, `predict_proba`, `predict`,
`decision_function`, BCE, and Brier score. `noisy_or_fusion` reproduces the
project's family-wise noisy-OR heuristic and labels it as a prioritization
score, not a probability.

**Eq. 25 is intentionally not invented.** The paper does not specify the
architecture, output dimension, objective, or calibration of
`h_fusion = F_phi(e_i, m_i)`. Callers supply a fused representation to the
logistic head; this package provides the transparent Eq. 26 baseline instead.

**Missing values.** For Eq. 26, `m_ij = 0` or a `NaN` evidence value makes
modality `j` unavailable. It is excluded from both numerator and denominator;
it is never imputed with zero. A unit with no available modality gets `NaN`
(or raises under `on_missing="error"`). An explicit mask can only remove
availability, never restore a `NaN`. Eq. 27 rejects missing features rather than
imputing them.

**Numerical stability.** The sigmoid uses stable branches. IRLS uses a
ridge-regularized weighted least-squares solve with a least-squares fallback
when the Hessian is singular. The noisy-OR clamps the combined score and
refutation penalty to documented bounds.

**Complexity.** Eq. 26 `O(N J)`. Noisy-OR `O(J log J)` per unit for the damping
order. Eq. 27 `O(N D)` per prediction, `O(E (N D^2 + D^3))` for `E` IRLS
iterations, or `O(N D)` per iteration with a linear solve.

**Tests.** `test_evidence_fusion.py`, plus the brute-force Eq. 26 comparison,
BCE gradient check, and near-zero ridge-gradient check in
`test_numerical_validation.py`.

### 4.12 Functional preservation constraints (Eq. 34-39)

**Module:** `functional_preservation.py`

**Equations and operational meaning.**

```text
Pass_func(P', T) = (sum_{t in T} 1[P'(t) = o_t]) / |T|                 (34)
V_func(P')       = 1[ Pass_func(P', T) = 1 ]                           (35)
{P} P' {Q}                                                             (36)
V_target(P') intersect V_target(P) = empty                             (37)
V(P') \ V(P) = empty                                                   (38)
Accept(P') = V_syntax(P') and V_func(P')
             and V_reg(P') and V_security(P')                          (39)
```

**Functions.** `functional_pass_rate` implements Eq. 34 with exact,
`atol`/`rtol`, and array-aware comparison. `functional_predicate` implements
Eq. 35. `hoare_triple_predicate` implements Eq. 36. `targeted_removal_predicate`
implements Eq. 37. `no_new_vulnerabilities_predicate` implements Eq. 38.
`regression_predicate` and `security_predicate` implement the operational
definitions of `V_reg` and `V_security`. `conjunction` and `accept_patch`
implement Eq. 39. `evaluate_preservation` assembles the full workflow from
caller-supplied test results, vulnerability sets, scan completeness, syntax
status, and optional verifier.

**Three-valued semantics.** Every predicate is `pass`, `fail`, or
`inconclusive`:

* any conclusive failure makes the predicate `fail`;
* otherwise any missing or inconclusive input makes it `inconclusive`;
* only complete, all-passing evidence makes it `pass`.

Inconclusive is **never** treated as pass, and it remains in the Eq. 34
denominator `|T|`, so the pass rate is not inflated when a test cannot run.
An empty test set is `inconclusive`.

**Eq. 36.** Without a real caller-supplied verifier, the Hoare triple is
`inconclusive`; a syntactic check is not a proof. Eq. 36 is therefore never
silently accepted.

**Detector-relative caveat.** Eqs. 37-38 are relative to the configured
analyzers. `correspondence_complete=False` or `scan_complete=False` produces
`inconclusive`, because an incomplete scan cannot establish a clean result.

**Complexity.** Eq. 34 `O(|T|)`. Eqs. 37-39 `O(|V|)` average set operations.

**Tests.** `test_functional_preservation.py`, including the three-valued
conjunction, inconclusive denominator, Hoare verifier requirement, targeted
removal, no-new-vulnerabilities, regression, Eq. 39 acceptance, and end-to-end
acceptance with and without a verifier.

## 5. Numerical validation suite

`tests/mathematics/test_numerical_validation.py` checks identities that are
independent of any single implementation detail:

| Test | Invariant |
|---|---|
| `test_mobius_inversion_reconstructs_every_cell_mean` | every cell mean is reconstructed from its Möbius coefficients |
| `test_pairwise_contrast_is_a_discrete_mixed_second_derivative` | Eq. 12 equals the discrete mixed second difference |
| `test_logistic_bce_gradient_matches_finite_differences` | analytic BCE gradient matches central finite differences |
| `test_fitted_logistic_head_has_a_near_zero_ridge_gradient` | the IRLS solution is a stationary point of the ridge objective |
| `test_adaptive_l2_budget_is_attained_exactly` | the global rescale attains the L2 budget |
| `test_risk_index_is_linear_in_the_component_vector` | Eq. 28 is affine in the component vector |
| `test_equation_26_matches_a_brute_force_masked_average` | Eq. 26 equals a direct masked weighted mean |
| `test_bootstrap_is_reproducible_for_a_seed` | equal seeds produce equal bootstrap intervals |
| `test_pooled_effect_sizes_match_their_definitions` | Cohen's d, Hedges' g, and pooled SD match hand calculations |
| `test_steering_delta_is_the_decoder_linear_combination` | the applied edit is exactly `sum_j tau_j W_d[:, j]` |
| `test_sae_objective_matches_equation_7_by_hand` | Eq. 7 matches a direct per-sample calculation |
| `test_l0_threshold_is_strict_while_encode_threshold_is_post_hoc` | the documented threshold semantics differ as stated |

The remaining test modules validate each component's own equation, shape
validation, missing-value behaviour, deterministic seeds, and error paths.

## 6. Complexity summary

| Component | Time | Memory / notes |
|---|---|---|
| SAE encode/decode | `O(N d d_s)` | `O(N d_s)` |
| SAE loss | `O(N(d + d_s))` | `O(N d_s)` |
| Sparse support | `O(N d_s)`; top-k `O(N d_s + N k log k)` | `O(N k)` for padded support |
| Feature measurement | `O(N F)`; token pooling `O(N T d_s)` | `O(F)` statistics |
| Association | `O(N F)`; BH `O(F log F)`; bootstrap `O(B N F)` | full correlation matrix `O(N F^2)` time |
| Single intervention | `O(N d_s)` latent, `O(N d)` decoder; effect `O(N)` | `O(N d)` modified activations |
| Pairwise | `O(N)` paired; four cells each `O(N d)` | `O(N)` per cell |
| Higher order | `O(2^k N)` per subset; `sum C(F,k) 2^k` cells exhaustive | cell cache |
| Counterfactual | `O(M N d)` for `M` cells | `O(N)` outcomes per cell |
| Adaptive steering | ranking `O(F log F)`; allocation `O(F + sum\|S\|)`; schedule `O(P F)`; apply `O(N d F)` | `O(N d)` edited activations |
| CWE risk | `O(1)` per finding; `O(K)` registry | `O(1)` |
| Evidence Eq. 26 | `O(N J)` | `O(N J)` |
| Evidence Eq. 27 | `O(N D)` prediction; `O(E(N D^2 + D^3))` IRLS | `O(D^2)` Hessian |
| Functional preservation | `O(\|T\|)` tests; `O(\|V\|)` set operations | set storage |

## 7. Extensions and explicit non-claims

These items are implemented but are **not** paper equations as printed. They
are labelled in code and must not be reported as if they were derived from the
paper.

* Hedges' g bias correction, Welch inference, bootstrap intervals, Cliff's
  delta fallback, BH q-values, and the permutation null in
  `feature_association.py`.
* The adaptive steering allocation policy, position schedule, and L2 budget.
  The paper does not number a steering equation.
* The CWE risk `"renormalize"` missing policy.
* The family-wise noisy-OR fusion score. It is a heuristic prioritization
  score, not a probability and not Eq. 25-27.
* Three-valued functional and security predicates. The paper's Eq. 34-39 are
  binary; `inconclusive` is the honest third state when evidence is missing.
* Minimal Bayes/Student-t numerics implemented because SciPy is unavailable.

Explicit non-implementations:

* Eq. 25 `h_fusion = F_phi(e_i, m_i)`: the architecture, objective, and
  calibration are unspecified, so no model is invented. Callers supply
  `h_fusion` to the Eq. 27 head.
* Eq. 36 Hoare logic: no verifier is invented. The function returns
  `inconclusive` unless a real verifier is supplied.
* Any calibration of `P(v)` in Eq. 28: the caller must calibrate.
* Any replacement of a measured outcome with a hard-coded score.

## 8. Reproducibility and example

`mathematics/examples.py` builds a deterministic SAE and activation set,
measures every component end to end, and returns a JSON-serializable result.
It uses:

* a fixed `SEED`;
* measured encoder/decoder matrices and activations;
* an analytic outcome with a genuine pairwise interaction;
* measured feature associations, interventions, counterfactual outcomes,
  steering allocation, risk components, evidence scores, and test outcomes.

It does not use precomputed answer keys. Running the module twice produces the
same output, which is enforced by `test_examples.py`. The example is a smoke
test, not a substitute for the unit and numerical tests.

## 9. Limitations

* No trained SAE checkpoint or model artifact is part of this package. The
  functions consume caller-supplied activations, weights, outcomes, labels,
  evidence, test results, and vulnerability sets.
* The paper's intervention operator is under-specified. This package uses the
  explicit decoder-direction operator `h' = h + (u - z_j) W_d[:, j]` and
  documents it in every intervention module.
* Interaction contrasts are scale-dependent. The caller declares
  `outcome_scale`; the package does not reinterpret a probability-scale
  contrast as a logit-scale contrast.
* Eq. 38 is detector-relative. The implementation reports `inconclusive` when
  the scan is incomplete; it cannot guarantee the absence of vulnerabilities.
* SciPy is not required. Statistical tails use documented NumPy/math
  implementations; if SciPy is installed, results should agree within
  numerical tolerance, but this package does not switch implementations
  silently.
