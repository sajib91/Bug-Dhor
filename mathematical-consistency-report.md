# Mathematical Consistency Audit of CRAFT-Sec

**Status:** Audit complete for the implemented mathematics in
`security-engine/src/craftsec/`.
**Date:** 2026-11-17
**Scope:** Equation-to-code consistency, tensor dimensions, SAE reconstruction
and sparsity arithmetic, counterfactual contrasts, paired and unpaired
uncertainty estimators, association and stability statistics, steering and risk
arithmetic, and reproducibility of saved experiments.

This report is the audit record. The companion artifacts are:

- `equation-to-code-traceability.csv` — one row per equation or arithmetic
  operator, its production symbol, its independent reference test, and its
  status.
- `mathematical-regression-tests/` — an independent numerical suite that does
  not import `craftsec` in `reference.py`.
- `mathematical_validation_report.md` — the synthetic and real-model validation
  report.
- `research/mathematical-framework-audit.md`,
  `research/mathematical-implementation-mapping.md`, and
  `research/mathematical-formulations.md` — the prior paper-versus-code review.

The audit does **not** establish that an SAE feature is a vulnerability concept,
that a contrast is a real-world causal effect, or that the synthetic corpus is a
vulnerability benchmark. It establishes whether the implemented arithmetic
matches the declared equations and whether degenerate inputs are reported rather
than hidden.

---

## 1. Method

Three independent checks were used.

1. **Symbolic and dimensional review.** Every implemented equation was read
   against its code path: batch dimensions, cell ordering, inclusion-exclusion
   signs, strict versus inclusive thresholds, and the difference between a
   requested intervention value and a realized measurement.
2. **Independent numerical reference.** `mathematical-regression-tests/reference.py`
   re-derives each formula with NumPy or closed-form mathematics. The reference
   module deliberately does not import `craftsec`, so agreement is evidence
   about the implementation rather than a tautology.
3. **Artifact recomputation.** `test_artifact_recomputation.py` re-reads
   `research/experiments/counterfactual_validation/results/real_model_validation.json`
   and recomputes per-unit factorial contrasts, pooled standard errors, seeded
   percentile-bootstrap intervals, layer-stability counts, and cross-checkpoint
   decoder cosines from the stored cells and weights.

Boundary cases were treated as first-class findings. Empty samples, one-class
labels, constant differences, zero-variance tests, single-replicate cells,
missing cells, non-finite observations, one-group stability summaries, and
disabled steering specs are exercised explicitly.

---

## 2. Overall verdict

The implemented mathematics is consistent with the declared estimands after the
corrections listed in Section 4. The core factorial contrasts are correct:

- the four-cell pairwise contrast,
- the \(2^k\) inclusion-exclusion higher-order contrast,
- the paired per-unit contrast and its seeded percentile bootstrap,
- the SAE encode/decode/loss definitions,
- the association mean difference and selectivity definitions,
- the decoder-direction steering and norm clamp,
- the adaptive and risk-controller priority/strength arithmetic.

The audit found no silent reversal of an inclusion-exclusion sign, no
transposed decoder/encoder weight use, and no mismatch between the synthetic
reference contrasts and the production estimators. It did find several
degenerate-input and consistency defects that could have produced a wrong
number without an error. Those were corrected and are documented below.

The real-model results are internally reproducible from the saved artifact, but
they are descriptive: the corpus is synthetic, the outcome is a declared A/B
log-odds probe, the pooled 240 pair-unit rows share 24 prompts, and the per-CWE
cells contain four units. No real-world vulnerability claim is supported.

---

## 3. Severity scale

| Severity | Meaning |
|---|---|
| **High** | Could change a reported contrast, stability verdict, intervention path, or uncertainty interval without raising an error. |
| **Medium** | Could silently drop, pool, or misclassify observations in a way that changes a summary statistic or diagnostic. |
| **Low** | Boundary inconsistency or documentation defect with limited numerical impact, but still capable of confusing a reader or a downstream comparison. |

---

## 4. Corrections register

Each correction below was applied to production code and has a corresponding
reference test. "Before" describes the pre-correction behavior; "After"
describes the current behavior. No equation was changed silently.

### 4.1 Summary table

| ID | Severity | Area | Correction | Evidence |
|---|---|---|---|---|
| C-01 | High | Statistics | Non-finite observations now dropped as missing | `test_nan_and_non_finite_observations_are_dropped_pairwise` |
| C-02 | High | Statistics | Unequal paired lengths now raise instead of truncating | `test_unequal_paired_lengths_raise_instead_of_truncating` |
| C-03 | High | Statistics | Zero-variance paired t-test now distinguishes nonzero from zero mean | `test_zero_variance_is_distinguished_from_no_difference` |
| C-04 | Medium | Statistics | `paired_comparison` means now use the same aligned pairs | `test_paired_comparison_means_use_the_same_aligned_pairs` |
| C-05 | Medium | Statistics | Cluster bootstrap alignment enforced; `None` cluster ids dropped | `test_bootstrap_cluster_alignment_is_enforced_and_none_is_excluded` |
| C-06 | Medium | Statistics | Holm/BH treat NaN and infinities as missing | `test_holm_and_bh_match_hand_computation_and_skip_missing_p_values` |
| C-07 | Medium | Comparisons | Cross-model comparison drops non-finite values | Covered by C-01 and `tests/unit/test_statistics.py` |
| C-08 | Medium | SAE | One strict `>` activation threshold everywhere | `test_sparse_statistics_match_reference_and_agree_with_thresholding` |
| C-09 | High | Association | Stability uses majority sign and counts two-class datasets correctly | `test_stability_uses_majority_sign_and_counts_two_class_datasets` |
| C-10 | High | Association | CWE-specific ranking uses the CWE association with documented fallback | `test_cwe_specific_ranking_uses_the_cwe_association` |
| C-11 | Medium | Association | Cross-dataset direction transfer is measured, not inferred | `test_cross_dataset_metrics_record_direction_transfer` |
| C-12 | High | Counterfactual | Realized post-intervention latent is measured, not fabricated | `tests/unit/test_counterfactual_engine.py` |
| C-13 | Medium | Counterfactual | Invalid layer and hidden-size mismatch raise at construction | `tests/unit/test_counterfactual_engine.py` |
| C-14 | High | Counterfactual | `use_cache=False` for baseline and intervention alike | `tests/unit/test_counterfactual_engine.py` |
| C-15 | High | Steering | Missing/zero measured direction produces no steering sign | `test_adaptive_direction_modes_and_missing_difference_are_explicit` |
| C-16 | Low | Steering | Schedule uses the same strict `>` activation threshold | `test_adaptive_schedule_scales_by_observed_activation` |
| C-17 | Medium | Risk control | Direct `.contrast` records are accepted | `test_risk_controller_accepts_direct_contrast_objects_and_missing_policy` |
| C-18 | Medium | Steering | Baseline and steered generation share one decoding path | `test_run_applies_clamped_delta_and_uses_one_decoding_path` |

### 4.2 Detailed entries

#### C-01 — Non-finite observations were only partially excluded

**Before.** `_to_float_list` and several paired helpers dropped `None` and
`float('nan')`, but accepted `+inf` and `-inf`. An infinite observation could
therefore enter a mean, a variance, or a bootstrap resample.

**After.** `_is_missing` treats `None`, NaN, both infinities, and
non-convertible values as missing. Paired helpers use `_aligned_pairs`, which
drops the whole pair when either side is missing.

**Justification.** Non-finite outcomes are not measurements on the declared
scale. Dropping a pair preserves alignment; substituting a finite value would
invent data.

#### C-02 — Unequal paired lengths were silently truncated

**Before.** `zip(x, y)` stopped at the shorter sequence, so a misaligned paired
test could compare unrelated units without an error.

**After.** Every paired helper raises `ValueError` when the two sequences have
different lengths.

**Justification.** Pairing is a design requirement. Silent truncation changes
the estimand and can hide a data-construction bug.

#### C-03 — Zero variance was reported as “no effect”

**Before.** A zero-variance paired t-test returned `p_value=1.0` and
`statistic=0.0` even when the constant difference was nonzero.

**After.**

- constant nonzero difference: `statistic = ±inf`, `p_value = 0.0`,
  `reason = "zero_variance_nonzero_mean"`;
- constant zero difference: `statistic = None`, `p_value = None`,
  `reason = "zero_variance_no_difference"`.

**Justification.** A constant nonzero difference has an unbounded t statistic;
reporting it as no effect is arithmetically false. A constant zero difference
is degenerate and should not be reported as an exact affirmative p-value.

#### C-04 — Paired comparison means used different subsets

**Before.** `mean_a` and `mean_b` were computed from independently filtered
lists, while the difference was computed from aligned pairs. With missing values
the reported means and the reported difference could refer to different
observations.

**After.** `mean_a` and `mean_b` are computed from the surviving aligned pairs,
matching the difference and the tests.

**Justification.** The summary row must describe one common sample.

#### C-05 — Cluster bootstrap silently changed its design

**Before.** A cluster-id length mismatch silently disabled clustering, and
`None` cluster ids were pooled into an implicit cluster.

**After.** A length mismatch raises, and observations with `None` cluster ids
are dropped as unclustered/missing.

**Justification.** Silently switching from a cluster bootstrap to an
observation bootstrap understates dependence. `None` is not a cluster.

#### C-06 — Holm and Benjamini-Hochberg treated NaN as a valid p-value

**Before.** Only `None` was excluded. NaN could enter the sort and the adjusted
value computation.

**After.** `_is_missing` excludes `None`, NaN, and infinities; those rows keep
`adjusted_p_value=None` and `reject=None`.

**Justification.** A non-finite p-value is not evidence and cannot be ordered.

#### C-07 — Cross-model comparison used a `None`-only filter

**Before.** Non-finite values passed the `is None` check and entered the
comparison vectors.

**After.** `_is_missing` is used consistently.

**Justification.** Same as C-01, applied at the comparison layer.

#### C-08 — Two SAE activation thresholds disagreed at the boundary

**Before.** `SparseAutoencoder.feature_activations` used `abs(x) >= threshold`,
while `feature_statistics` used `abs(x) > threshold`. A latent exactly equal to
the threshold was active for one routine and inactive for the other.

**After.** Both use strict `>`.

**Justification.** L0, utilization, dead-feature counts, and activation
frequency must be computed from one definition. The strict form also makes
“threshold 0 means nonzero activation” true.

#### C-09 — Stability sign was anchored to the first dataset

**Before.** `sign_consistency` compared every dataset sign to the first sign,
and `datasets_with_both_classes` was set to the number of non-zero signs rather
than the number of datasets containing both classes.

**After.** Consistency is
`max(positive, negative) / number_of_nonzero_signs`, and
`datasets_with_both_classes` counts datasets whose labels contain both classes.

**Justification.** The stability statistic is a majority-agreement measure, not
an agreement-with-arbitrary-reference measure. The old count could exceed the
number of two-class datasets.

#### C-10 — CWE-specific ranking ignored the CWE association

**Before.** `select_association_pairs` and `preselect_features` ranked by the
entry's overall selectivity even when a `cwe` was supplied.

**After.** When a CWE is supplied, the CWE association's selectivity is used.
If that CWE subset has no two-class contrast (`None`), the overall selectivity
is used as an explicit documented fallback.

**Justification.** A CWE-specific analysis must rank by the CWE-specific
evidence. Falling back to zero would silently delete features with missing
two-class CWE data; falling back to the overall score keeps them selectable and
is visible in the code and tests.

#### C-11 — Cross-dataset direction fields were absent

**Before.** `CrossDatasetMetric` stored validation precision/recall but no
train/validation direction or agreement flag.

**After.** It stores `train_association_direction`,
`validation_association_direction`, and `direction_agrees`, and it skips pairs
where either direction is undefined.

**Justification.** Direction transfer is a different quantity from validation
precision/recall and must be measured, not inferred from the metrics.

#### C-12 — Intervention measurements were fabricated from the requested target

**Before.** `CounterfactualEngine` recorded
`intervention_values = full_like(baseline_values, spec.target_value)`. The
recorded “measurement” was the intervention request, not the SAE's reading of
the modified activation.

**After.** The intervention hook re-encodes the modified hidden states and
records the realized latent at the target positions. If the hook produces no
measurement, the engine raises.

**Justification.** The encoder and decoder are not exact inverses, and later
layers can change the activation. A requested ablation target of zero need not
be the realized latent. Recording a request as a measurement is a silent
fabrication.

#### C-13 — Invalid layer and hidden-size mismatches were accepted

**Before.** An unknown layer failed only when the hook was installed, and a
SAE whose input width did not match the model hidden size could reach the
intervention arithmetic.

**After.** The constructor checks that the layer exists and that
`sae.config.input_dim` matches the model's `hidden_size` when available. The
SAE is put in evaluation mode.

**Justification.** These are shape/identity errors, not runtime numerical
conditions. Failing early prevents a silently wrong activation slice.

#### C-14 — Baseline and intervention used different cache settings

**Before.** The steered generation forced `use_cache=False`, but the baseline
generation could use the default cache. A forward hook fires only on the prefill
pass under a KV cache, so the two conditions were not comparable.

**After.** Both calls use `use_cache=False`; the same decoding path is used in
both the counterfactual engine and the steering engine.

**Justification.** A contrast is only interpretable if the baseline and
intervention share the decoding configuration. This is the C-18 correction in
the steering path.

#### C-15 — Adaptive steering invented a sign when no direction was measured

**Before.** `difference is None` produced `+1.0`, i.e. a full positive steering
step even though no sign had been measured. A zero difference also produced
`+1.0`.

**After.** `None` or zero returns `0.0`; the feature receives no steering
contribution from that term.

**Justification.** A missing measurement is not evidence for a positive
direction. Inventing a sign is a silent semantic claim.

#### C-16 — Schedule activation used an inclusive threshold

**Before.** `abs(activation) >= activation_threshold` was active.
**After.** It is strictly `>`.

**Justification.** Consistency with C-08 and with the declared “active above
threshold” semantics.

#### C-17 — Risk controller ignored direct contrast records

**Before.** `_interaction_contrast` only read `interaction.estimate.contrast`.
A record exposing `.contrast` directly was treated as having no contrast.
**After.** It reads `.contrast` first and falls back to `.estimate.contrast`.

**Justification.** Both shapes are present in the repository's result records.
Ignoring one silently drops interaction evidence.

#### C-18 — Steering baseline and steered conditions were not cache-consistent

**Before.** Only the steered call disabled the KV cache.
**After.** Both calls disable it.

**Justification.** Same as C-14; the steering comparison must use one decoding
path.

---

## 5. Equation-to-code traceability

`equation-to-code-traceability.csv` contains 62 rows spanning:

- baselines and single-feature, pairwise, and higher-order contrasts;
- paired per-unit estimators and bootstrap uncertainty;
- scale transforms and stability summaries;
- SAE encoding, decoding, loss, L0, dead-feature counts, and reconstruction
  error;
- association means, frequencies, selectivity, stability, and cross-dataset
  transfer;
- CWE-specific pair ranking and higher-order preselection;
- natural ablation and fixed directional interventions;
- realized activation measurement and decoding-path consistency;
- decoder-direction steering and norm clamping;
- adaptive importance, direction, interaction allocation, and scheduling;
- risk priority, bands, component scores, context multiplier, and strength;
- paired t, Cohen's d, mean-difference interval, Mann-Whitney U, Cliffs delta,
  permutation, Wilcoxon, Holm, Benjamini-Hochberg, and bootstrap helpers;
- configuration hashing, checkpoint round-trip, seeded training, artifact
  recomputation, and cross-checkpoint cosine diagnostics.

Status values are `verified`, `verified-with-documented-correction`, or
`implemented-artifact-level`. The last value is used for the real-model probe
and step-size rows, whose numeric values are recorded in the artifact but whose
semantic validity is not claimed.

---

## 6. Verification evidence

### 6.1 Independent regression suite

Command:

```bash
.venv/bin/python -m pytest mathematical-regression-tests -q
```

Result at audit time: **80 passed**. The suite covers 10 test modules:

| File | Focus |
|---|---|
| `test_sae_reference.py` | Encode/decode/loss, strict threshold, L0, dead features, reconstruction metrics |
| `test_counterfactual_reference.py` | Four-cell contrast, independent-cell SE, Möbius contrast, ranking |
| `test_validation_reference.py` | Per-unit factorial contrasts, scale transforms, bootstrap, stability |
| `test_statistics_reference.py` | Paired t, Cohen's d, mean-difference CI, Mann-Whitney U, Cliffs delta, Holm/BH, NaN and pairing semantics |
| `test_steering_reference.py` | Decoder directions, norm clamp, single decoding path |
| `test_steering_policy_reference.py` | Adaptive importance/direction/allocation/schedule and risk priority/band/strength |
| `test_association_reference.py` | Association statistics, majority-sign stability, cross-dataset transfer, CWE ranking |
| `test_artifact_recomputation.py` | Recompute the saved real-model contrasts, intervals, stability counts, and cosines |
| `test_config_reproducibility.py` | Config hashing, checkpoint round-trip, seeded training |
| `test_boundary_degenerate.py` | Empty, constant, one-class, single-replicate, and invalid-shape cases |

### 6.2 Validation and reference-package tests

Command:

```bash
cd security-engine
../.venv/bin/python -m pytest \
  tests/unit/test_counterfactual_mathematical_validation.py \
  tests/unit/test_validation_corpus.py \
  tests/mathematics -q --import-mode=importlib
```

Result: **128 passed**.

### 6.3 Full backend suite

Command:

```bash
cd security-engine
../.venv/bin/python -m pytest tests -q --import-mode=importlib
```

Result at audit time: **577 passed, 6 failed**. The six failures are
pre-existing/environmental API and pipeline capability assertions:

- `tests/api/test_openapi.py` (2),
- `tests/api/test_scan.py` (3),
- `tests/unit/test_pipeline.py` (1).

They do not exercise the arithmetic covered by this audit. The full suite
requires `--import-mode=importlib` because `tests/unit` and `tests/mathematics`
contain files with the same basenames.

### 6.4 Artifact recomputation

`test_artifact_recomputation.py` confirms, for all eight configurations in
`real_model_validation.json`:

- the stored pairwise and triple contrasts equal the per-unit factorial means;
- the pooled standard error equals `std(unit_contrasts, ddof=1)/sqrt(n)`;
- the seeded percentile-bootstrap interval re-runs exactly;
- the layer-stability counts and cross-checkpoint decoder cosines recompute
  from the stored cells and checkpoints.

---

## 7. Residual risks

These are not implementation defects, but they limit what the mathematics can
support.

1. **Synthetic corpus.** The real-model corpus is six pattern pairs with lexical
   variants. It is not a vulnerability benchmark. Generator labels are not
   ground truth.
2. **Declared outcome probe.** \(Y\) is the A/B next-token log-odds at one
   position. It is not calibrated and is not compared with human or scanner
   labels.
3. **Non-independent pooled units.** The 240 pooled pairwise rows come from 24
   prompts × 10 pairs. The percentile bootstrap treats the 240 rows as
   exchangeable, so the pooled intervals are likely too narrow. The report
   states this limitation and the per-prompt paired estimator is the primary
   unit.
4. **Bootstrap undercoverage at small \(n\).** Synthetic coverage at \(n=24\)
   was approximately 0.927 for a nominal 0.95 interval. Intervals are
   descriptive.
5. **Layer-21 SAE quality.** Relative reconstruction error is
   \(1.0\times10^{-2}\) (base) and \(1.2\times10^{-2}\) (instruct), with 337 and
   193 dead latents. Layer-21 contrasts are reported but are the weakest
   evidence in the experiment.
6. **Unmatched feature identity.** Feature indices are SAE-specific. The
   cross-checkpoint cosine is a population-level diagnostic, not a matched
   feature comparison.
7. **No multiplicity control in the validation report.** Ten pairs and one
   triple are reported per configuration. The corrected Holm/BH helpers exist,
   but the report does not apply them and makes no ranking or selection claim.
8. **Operator dependence.** Directional activation and natural ablation produce
   different contrasts (for example, base layer 10: \(+0.0332\) directional,
   \(+0.3935\) ablation). Neither is the “true” effect; each is conditional on
   its declared operator.
9. **Threshold semantics differ by module.** The SAE statistics and adaptive
   schedule use strict `>` on activation magnitude; the risk controller uses
   inclusive `>=` on feature activation and static/interaction scores. This is
   documented in the traceability CSV, but a reader must not assume one global
   threshold convention.
10. **Semantic vulnerability claims remain unsupported.** No validated
    vulnerability benchmark, human feature labeling, or downstream repair
    experiment was run.

---

## 8. Reproduction

```bash
# Independent numerical regression suite
.venv/bin/python -m pytest mathematical-regression-tests -q

# Validation and reference-package tests
cd security-engine
../.venv/bin/python -m pytest \
  tests/unit/test_counterfactual_mathematical_validation.py \
  tests/unit/test_validation_corpus.py \
  tests/mathematics -q --import-mode=importlib

# Full backend suite
../.venv/bin/python -m pytest tests -q --import-mode=importlib

# Synthetic validation artifact
cd ..
.venv/bin/python research/experiments/counterfactual_validation/run_synthetic_validation.py

# Real-model artifact (requires the two Qwen checkpoints)
.venv/bin/python research/experiments/counterfactual_validation/run_real_model_validation.py \
  --layers 4,10,16,21 --top-k 5 --eval-variants 2 --train-variants 4 \
  --sae-epochs 8 --sparsity 0.3 --latent-multiplier 2 --n-boot 2000 \
  --direction-fraction 0.25 --checkpoints base,instruct \
  --output real_model_validation.json
```

The real-model artifact records the model revisions, corpus generator, SAE
configuration hashes, layer names, step sizes, feature indices, and bootstrap
seeds needed to reproduce the reported numbers.

---

## 9. Claim boundary

Supported:

- The implemented factorial, SAE, association, steering, and risk arithmetic
  matches independent numerical references, including the boundary cases listed
  in Section 4.
- Each saved real-model contrast can be recomputed from its stored cells and
  seeds.
- Degenerate inputs are either handled by a documented rule or rejected with an
  error; they are not silently converted into a plausible number.

Not supported:

- That any selected feature is a vulnerability concept.
- That any contrast is a causal effect in real software.
- That the synthetic labels are ground truth.
- That the pooled intervals are exact 95% confidence intervals for a broader
  code population.
- That layer, checkpoint, feature, or CWE rankings are established.
