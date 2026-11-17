# Mathematical and Experimental Validation of CRAFT-Sec Counterfactual Feature Interaction Analysis

**Status:** Validation report with synthetic ground-truth checks and a real-model
activation-intervention experiment.
**Date:** 2026-11-17
**Repository:** CRAFT-Sec
**Scope:** The arithmetic, estimands, intervention-cell construction, uncertainty
estimation, and stability behaviour of the counterfactual feature interaction
analysis. This report does **not** validate semantic claims that an SAE feature
represents a vulnerability, a secure behaviour, or a causal mechanism in real
software.

---

## 1. What is validated, and what is not

Two kinds of validation are reported.

1. **Synthetic ground truth.** Outcomes are generated from known algebraic
   functions, so the expected contrast is known exactly. These checks verify the
   estimator, the intervention-cell construction, direction, scale dependence,
   confounding behaviour, and bootstrap calibration.
2. **Real-model activation interventions.** Sparse autoencoders (SAEs) are
   trained on activations from `Qwen/Qwen2.5-Coder-0.5B` and
   `Qwen/Qwen2.5-Coder-0.5B-Instruct`. Declared decoder-direction interventions
   are applied at several residual-stream layers, and interaction contrasts are
   estimated on a declared next-token log-odds outcome.

The real-model experiment is a controlled study of **model-internal
interventions and a model-internal readout**. It is not a vulnerability
benchmark, and it does not establish that any feature is a vulnerability
feature. The code samples are synthetic, lexically varied snippets generated
from six insecure/secure pattern pairs. Their labels describe the generator, not
validated ground truth.

No p-values, significance stars, or "significant interaction" labels are
produced. All intervals are descriptive.

---

## 2. Definitions and estimands

### 2.1 Units, features, and intervention cells

Let:

- \(u \in \{1,\dots,n\}\) index an **experimental unit**: a code sample/prompt,
  together with the fixed token position, layer, checkpoint, and outcome probe.
- \(S\) be a declared set of features, \(|S| = k\).
- \(x \in \{0,1\}^{k}\) be a binary intervention-state vector for the features
  in \(S\).
- \(T(x) = \{i \in S : x_i = 1\}\) be the set of features in the active state.

The **cell** \(T \subseteq S\) is the simultaneous intervention that sets every
feature in \(T\) to state 1 and every feature in \(S \setminus T\) to state 0.
There are \(2^k\) cells. A cell is applied in a single forward pass; it is not a
sequence of one-feature edits.

Let \(Y_u(T)\) be the declared scalar outcome on unit \(u\) under cell \(T\).

### 2.2 Baseline outcome

The baseline is the empty cell:

\[
Y_u(\varnothing) = \text{outcome with no declared feature intervention.}
\]

It is estimated, not assumed to be zero. In a paired design, unit-level baseline
offsets cancel from every contrast:

\[
Y_u(T) = b_u + f(T) + \varepsilon_u(T)
\quad\Longrightarrow\quad
\text{any contrast in } T \text{ is free of } b_u.
\]

This is important because code samples differ substantially in their baseline
outcome.

### 2.3 Single-feature intervention

For one feature \(i\),

\[
\Delta_i = Y_u(\{i\}) - Y_u(\varnothing).
\]

In the engine this is represented as a 1-feature factorial contrast. It answers:
"what is the change in the declared outcome when feature \(i\) is switched from
state 0 to state 1, holding the other declared features at state 0?"

### 2.4 Pairwise interaction contrast

For features \(i,j\),

\[
\boxed{
\Delta_{ij}
= Y_u(1,1) - Y_u(1,0) - Y_u(0,1) + Y_u(0,0)
}
\]

where the arguments are the states of \((i,j)\), the empty cell is
\(Y_u(0,0) = Y_u(\varnothing)\), and \(Y_u(1,1)\) is the **joint** cell in which
both features are active. This is the difference-in-differences contrast on the
declared outcome scale.

Interpretation on the declared scale:

- \(\Delta_{ij} = 0\): the effect of activating \(i\) does not depend on the
  state of \(j\), within the measured cells.
- \(\Delta_{ij} > 0\): activating \(i\) and \(j\) together increases the outcome
  by more than the sum of their single activations.
- \(\Delta_{ij} < 0\): the joint activation increases the outcome by less than
  the sum (including possible antagonism).

The sign is relative to the orientation of \(Y\). It is not "good" or "bad" in
security terms unless the outcome has been explicitly oriented and validated.

### 2.5 Higher-order interaction contrast

For a declared feature set \(S\) with \(|S| = k\), the higher-order contrast is
the inclusion-exclusion (Möbius) coefficient

\[
\boxed{
\Delta_S
= \sum_{T \subseteq S} (-1)^{|S|-|T|} Y_u(T)
}
\]

Equivalently, writing \(Y_u(x_1,\dots,x_k)\) for the cell with state vector
\(x\),

\[
\Delta_S
= \sum_{x \in \{0,1\}^k}
(-1)^{k - \sum_i x_i} Y_u(x_1,\dots,x_k).
\]

For \(k=3\),

\[
\begin{aligned}
\Delta_{ijk}
={}& Y(1,1,1) \\
&- Y(1,1,0) - Y(1,0,1) - Y(0,1,1) \\
&+ Y(1,0,0) + Y(0,1,0) + Y(0,0,1) \\
&- Y(0,0,0).
\end{aligned}
\]

All \(2^k\) cells are required. If \(Y\) is additive over the declared features,
every contrast of order \(\ge 2\) is exactly zero.

### 2.6 Feature ablation and joint intervention

Two intervention operators are used in this validation.

**Natural feature ablation.** For a unit with residual activation \(h_u\), SAE
latent \(a_f(u) \ge 0\), and decoder direction \(d_f\),

\[
h_u' = h_u - a_f(u)\, d_f.
\]

This removes the feature's measured decoded contribution. The binary state is
"feature present" (0) versus "feature ablated" (1). The magnitude is
unit-dependent and can be a no-op when \(a_f(u) = 0\).

**Fixed directional activation.** For a fixed step \(\alpha > 0\),

\[
h_u' = h_u + \alpha\,\frac{d_f}{\lVert d_f\rVert}.
\]

This is a constant-size intervention along the feature direction. The binary
state is "no step" (0) versus "positive step" (1). The joint cell is
\(h_u + \alpha(d_i/\lVert d_i\rVert + d_j/\lVert d_j\rVert)\), applied
simultaneously.

Both operators are declared interventions. The estimand is conditional on the
operator, the step size, the layer, and the outcome probe. A contrast under
ablation need not equal a contrast under directional activation.

### 2.7 Outcome scale

If \(\phi\) is a nonlinear transformation, then in general

\[
\Delta_S(\phi(Y)) \ne \phi(\Delta_S(Y)).
\]

The engine reports contrasts on the scale supplied to it. The real-model probe
uses a log-odds scale; a probability-scale contrast is a different estimand. The
synthetic suite demonstrates this explicitly (Section 4.3).

---

## 3. Implementation map

| Concept | Location |
|---|---|
| Paired per-unit factorial contrasts | `security-engine/src/craftsec/counterfactual/validation.py::factorial_unit_contrasts` |
| Pairwise paired estimator | `.../validation.py::estimate_pairwise_contrast` |
| Higher-order paired estimator | `.../validation.py::estimate_higher_order_contrast` |
| Percentile bootstrap over units | `.../validation.py::bootstrap_mean_interval` |
| Scale-transformed contrast | `.../validation.py::interaction_on_scale` |
| Stability summary | `.../validation.py::stability_summary` |
| Controlled corpus and outcome prompt | `.../validation_corpus.py` |
| Existing pairwise engine (independent-cell delta method) | `.../pairwise.py` |
| Existing higher-order engine (inclusion-exclusion) | `.../higher_order.py` |
| Synthetic validation runner | `research/experiments/counterfactual_validation/run_synthetic_validation.py` |
| Real-model validation runner | `research/experiments/counterfactual_validation/run_real_model_validation.py` |
| Automated mathematics tests | `security-engine/tests/unit/test_counterfactual_mathematical_validation.py` |
| Automated corpus tests | `security-engine/tests/unit/test_validation_corpus.py` |

The production pairwise and higher-order engines are unchanged. The validation
module adds a **paired** estimator so that the same unit (code sample, token
position, layer, checkpoint) appears in all cells. The existing engine's
independent-cell standard error remains available for engine replicates, but it
does not exploit pairing and is not used for the real-model intervals in this
report.

---

## 4. Synthetic ground-truth validation

Command:

```bash
.venv/bin/python research/experiments/counterfactual_validation/run_synthetic_validation.py
```

Artifact: `research/experiments/counterfactual_validation/results/synthetic_validation.json`.

### 4.1 Deterministic scenarios

| Scenario | Expected | Observed | Result |
|---|---:|---:|---|
| Baseline nonzero; constant shift cancels | 5.0 | 5.0 | pass |
| Purely additive outcome (pairwise null) | 0.0 | 0.0 | pass |
| Binary ablation with interaction | 4.0 | 4.0 | pass |
| Simultaneous joint intervention | 3.0 | 3.0 | pass |
| Third-order inclusion-exclusion | 7.0 | 7.0 | pass |
| Direction under outcome negation | \(+2\), \(-2\) | \(+2\), \(-2\) | pass |
| Off-target change in one cell | 4.0 | 4.0 | pass |

The higher-order check used the outcome

\[
Y = 2 + A + 2B + 3C + 7ABC,
\]

for which the third-order contrast is exactly \(7\). The pairwise check used

\[
Y_u = b_u + 2A + 3B + 5AB,
\qquad b_u \in \{10, 12, 14\},
\]

for which the pairwise contrast is exactly \(5\) regardless of the unit-level
baseline \(b_u\). The additive-null check used the same form with the
interaction term set to zero and a different baseline vector, giving a contrast
of exactly \(0\).

### 4.2 Confounding demonstration

Paired cells with unit-level baselines \(0,10,20,100\) and additive effects
\(+2,+3\) gave a pairwise contrast of exactly \(0\). An unpaired construction in
which the baseline distribution differs between cells gave a spurious contrast
of \(-10\). This is not evidence that the engine is "wrong"; it demonstrates that
**pairing is part of the design**, and that unpaired cell means can manufacture
an interaction when unit composition differs across cells.

### 4.3 Outcome-scale dependence

With a logistic data-generating process whose log-odds interaction is \(2.0\):

- probability-scale contrast: \(0.3492\)
- logit-scale contrast: \(2.0000\)

The two numbers are different estimands. Neither is "the" interaction without a
declared scale. The report and engine must therefore carry the outcome scale as
metadata, which they do.

### 4.4 Uncertainty calibration

The paired bootstrap resamples **units**, not cells. Each resample preserves the
four-cell (or \(2^k\)-cell) structure for each unit.

| Check | Setting | Result |
|---|---|---:|
| Nominal 95% coverage, true contrast 2.0 | 1000 replications, \(n=50\) | 0.954 |
| Null containment, true contrast 0.0 | 1000 replications, \(n=60\) | 0.925 |
| Finite-sample null containment | \(n=24\) | 0.927 |
| Finite-sample null containment | \(n=60\) | 0.925 |
| Finite-sample null containment | \(n=120\) | 0.946 |
| Finite-sample null containment | \(n=240\) | 0.955 |

The percentile bootstrap undercovers in small samples. At the 24-unit scale used
in the real-model experiment, coverage was approximately 92.7% rather than 95%
in a Gaussian simulation. Intervals in this report are therefore **descriptive
uncertainty summaries**, not exact 95% confidence procedures. The real-model
results also report the paired standard error so that a normal-approximation
interval can be computed if desired.

### 4.5 Automated tests

`security-engine/tests/unit/test_counterfactual_mathematical_validation.py`
contains 16 tests covering:

- baseline definition and constant-shift cancellation;
- the four declared pairwise cells and their intervention dictionaries;
- single-feature ablation state;
- simultaneous (not sequential) joint intervention;
- additive null;
- higher-order inclusion-exclusion by hand;
- missing-cell rejection;
- direction reversal under outcome negation;
- probability-versus-logit scale dependence;
- paired versus unpaired confounding;
- off-target spurious interaction;
- bootstrap reproducibility and agreement with the paired standard error;
- bootstrap coverage and null containment;
- stability summaries;
- invalid shapes, missing values, and empty feature subsets.

`security-engine/tests/unit/test_validation_corpus.py` adds 4 tests for corpus
determinism, label balance, valid Python syntax, unique samples, prompt
construction, and single-token label resolution.

All 20 tests pass.

A separate independent suite, `mathematical-regression-tests/`, re-derives the
production arithmetic in NumPy/closed form (without importing `craftsec`),
exercises boundary and degenerate cases, and recomputes the saved real-model
artifact. It passes 80 tests and is summarised in
`mathematical-consistency-report.md`. The equation-to-symbol mapping is in
`equation-to-code-traceability.csv`.

---

## 5. Real-model experiment

Command:

```bash
.venv/bin/python research/experiments/counterfactual_validation/run_real_model_validation.py \
  --layers 4,10,16,21 \
  --top-k 5 \
  --eval-variants 2 \
  --train-variants 4 \
  --sae-epochs 8 \
  --sparsity 0.3 \
  --latent-multiplier 2 \
  --n-boot 2000 \
  --direction-fraction 0.25 \
  --checkpoints base,instruct \
  --output real_model_validation.json
```

Artifact: `research/experiments/counterfactual_validation/results/real_model_validation.json`.
SAE checkpoints: `research/experiments/counterfactual_validation/artifacts/`.

### 5.1 Models, layers, and provenance

- Base: `Qwen/Qwen2.5-Coder-0.5B`,
  revision `8123ea2e9354afb7ffcc6c8641d1b2f5ecf18301`.
- Instruct: `Qwen/Qwen2.5-Coder-0.5B-Instruct`,
  revision `ea3f2471cf1b1f0db85067f1ef93848e38e88c25`.
- Device: CPU, float32.
- Layers: 4, 10, 16, 21 of 24.
- The same layer indices are used for both checkpoints.

### 5.2 Corpus and units

The corpus generator creates six CWE-pattern categories (`CWE-89`, `CWE-79`,
`CWE-78`, `CWE-22`, `CWE-798`, `CWE-502`), each with one insecure template and
one secure counterpart. Six lexical variants per template are generated by
substituting function names, table names, routes, paths, and secret names.

- 24 evaluation units: four per category (two generated from the insecure
  template, two from the secure template).
- 48 additional training prompts used for SAE training.
- SAE training is unsupervised and does not use labels or outcomes.

The labels are generator labels, not validated vulnerability ground truth, and
they are not used by the interaction estimator.

### 5.3 Outcome \(Y\)

Each prompt is:

```text
Review the following Python code for security problems.

```python
<code>
```

If the code is unsafe, answer "A". If the code is safe, answer "B".
Answer:
```

The outcome is the next-token log-odds of the label pair ` A` versus ` B`:

\[
Y_u = \operatorname{logit}(A \mid \text{prompt}_u)
     - \operatorname{logit}(B \mid \text{prompt}_u)
\]

where the logits are read at the final non-padding position. Positive \(Y\)
means the model assigns more probability mass to the "unsafe" label.

This is a **declared model readout**, not a vulnerability label. It is not
assumed to be calibrated, and it is not compared with ground truth.

### 5.4 SAE training

For each checkpoint and layer:

- residual-stream output at the selected decoder block, all non-padding token
  positions of the 48 training prompts;
- input dimension 896, latent dimension 1792, ReLU encoder, linear decoder;
- sparsity coefficient 0.3, 8 epochs, Adam, learning rate \(10^{-3}\), seed
  fixed per layer;
- checkpoint saved with configuration hash and training history.

The sparsity coefficient was selected in a small calibration at layer 12:
0.02 left \(L_0 \approx 709\), 0.1 left \(L_0 \approx 390\), and 0.3 left
\(L_0 \approx 173\) with relative reconstruction error \(5.8\times 10^{-4}\).
The 0.3 setting was used for the reported run. This is a light-to-moderate
sparsity setting, not a claim of interpretable features.

### 5.5 Feature selection

Selection is outcome-blind:

1. Encode the 24 evaluation prompts at the final position.
2. Rank latents by mean activation over the 24 units.
3. Keep the top 5 positive, non-degenerate features.

All 10 feature pairs are evaluated, plus the triple formed by the top 3
features. This rule is fixed before looking at \(Y\). It can select generic
features; that is a limitation for semantic interpretation, not for the
arithmetic of the contrast.

### 5.6 Interventions

Primary factorial intervention (used for all pairwise and triple contrasts):

\[
h_u' = h_u + \alpha \sum_{f \in T} \frac{d_f}{\lVert d_f\rVert},
\qquad
\alpha = 0.25 \times \operatorname{median}_u \lVert h_u \rVert.
\]

State 0 for feature \(f\) means no step along \(d_f\); state 1 means the step.
The joint cell applies all declared steps simultaneously.

Natural ablation sensitivity check:

\[
h_u' = h_u - \sum_{f \in T} a_f(u)\, d_f.
\]

Single-feature ablation effects are reported for all selected features, and one
pairwise contrast is reported for the top two features under ablation.

The intervention step is a modeling choice. A different step size would produce
different magnitudes and potentially different signs; the report therefore
describes results as conditional on \(\alpha\).

### 5.7 Results

The following tables are descriptive. Every interval is a percentile bootstrap
over units with the seed and resample count recorded in the artifact. No
p-value, significance verdict, or population claim is attached to any cell.
"Pooled" means the per-unit contrast was averaged over the 24 evaluation units
and, for pairwise contrasts, over the 10 selected pairs; the 240 pooled
pair-unit rows are therefore **not independent** because each prompt contributes
ten pairs.

#### 5.7.1 SAE quality and intervention scale

| Checkpoint | Layer | SAE rel. recon. err. | SAE mean \(L_0\) | Dead latents | Step \(\alpha\) | Mean abs single effect | Pairwise range | Triple |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| base | 4 | \(1.77\times10^{-4}\) | 186.1 | 42 | 2.355 | 0.1081 | \(-0.0053\) to \(+0.1701\) | \(-0.0115\) |
| base | 10 | \(1.19\times10^{-3}\) | 187.9 | 50 | 3.276 | 0.1597 | \(-0.0040\) to \(+0.0768\) | \(-0.0262\) |
| base | 16 | \(5.01\times10^{-4}\) | 200.3 | 33 | 5.714 | 0.4141 | \(-0.1269\) to \(+0.0503\) | \(-0.0067\) |
| base | 21 | \(1.01\times10^{-2}\) | 338.3 | 337 | 16.468 | 0.4742 | \(-0.1868\) to \(+0.0099\) | \(+0.0200\) |
| instruct | 4 | \(3.85\times10^{-4}\) | 212.8 | 34 | 3.097 | 0.0545 | \(-0.0143\) to \(+0.0194\) | \(+0.0055\) |
| instruct | 10 | \(1.18\times10^{-3}\) | 188.8 | 34 | 4.425 | 0.1551 | \(+0.0038\) to \(+0.0716\) | \(+0.0007\) |
| instruct | 16 | \(5.64\times10^{-4}\) | 213.6 | 33 | 7.931 | 0.0511 | \(-0.0377\) to \(+0.0350\) | \(+0.0138\) |
| instruct | 21 | \(1.20\times10^{-2}\) | 450.9 | 193 | 20.531 | 0.1393 | \(-0.0141\) to \(+0.1422\) | \(+0.0049\) |

Layers 4, 10, and 16 reconstruct with relative error between
\(1.8\times10^{-4}\) and \(1.2\times10^{-3}\). Layer 21 is markedly worse
(\(1.0\times10^{-2}\) base, \(1.2\times10^{-2}\) instruct) and has 337 and 193
dead latents respectively. Layer-21 contrasts are reported for completeness but
should carry much less weight: the decoder is a poorer instrument at that layer,
and the intervention step is correspondingly larger.

#### 5.7.2 Pooled pairwise and triple contrasts

| Checkpoint | Layer | Pooled pairwise | SE | 95% interval | Triple | SE | 95% interval | Pair units | Triple units |
|---|---:|---:|---:|---|---:|---:|---|---:|---:|
| base | 4 | \(+0.0609\) | 0.00329 | \([+0.0546,+0.0675]\) | \(-0.0115\) | 0.00090 | \([-0.0133,-0.0098]\) | 240 | 24 |
| base | 10 | \(+0.0332\) | 0.00195 | \([+0.0294,+0.0370]\) | \(-0.0262\) | 0.00148 | \([-0.0289,-0.0234]\) | 240 | 24 |
| base | 16 | \(-0.0259\) | 0.00325 | \([-0.0321,-0.0195]\) | \(-0.0067\) | 0.00050 | \([-0.0077,-0.0057]\) | 240 | 24 |
| base | 21 | \(-0.1090\) | 0.00424 | \([-0.1170,-0.1006]\) | \(+0.0200\) | 0.00131 | \([+0.0175,+0.0224]\) | 240 | 24 |
| instruct | 4 | \(+0.0030\) | 0.00069 | \([+0.0017,+0.0043]\) | \(+0.0055\) | 0.00019 | \([+0.0052,+0.0059]\) | 240 | 24 |
| instruct | 10 | \(+0.0309\) | 0.00165 | \([+0.0278,+0.0342]\) | \(+0.0007\) | 0.00046 | \([-0.0002,+0.0016]\) | 240 | 24 |
| instruct | 16 | \(-0.0111\) | 0.00142 | \([-0.0139,-0.0085]\) | \(+0.0138\) | 0.00016 | \([+0.0135,+0.0141]\) | 240 | 24 |
| instruct | 21 | \(+0.0400\) | 0.00317 | \([+0.0337,+0.0461]\) | \(+0.0049\) | 0.00037 | \([+0.0043,+0.0056]\) | 240 | 24 |

The sign of the pooled pairwise contrast is not monotonic in layer and differs
between checkpoints: base is positive at layers 4 and 10, negative at 16 and 21;
instruct is small and positive at layer 4, positive at 10, negative at 16, and
positive again at 21. The triple contrast does not track the pairwise sign
(base layer 21 is the clearest case: pairwise \(-0.1090\), triple \(+0.0200\)).
This is expected for a higher-order Möbius coefficient; it is not evidence that
the arithmetic is wrong. The scale also varies substantially with the
checkpoint and layer, which is why contrasts are reported per configuration
rather than as one aggregate number.

The pairwise detail for base layer 4 illustrates the heterogeneity hidden by the
pooled average:

| Features | Contrast | 95% interval | Unit sign consistency | CWE sign consistency |
|---|---:|---|---:|---:|
| 475, 975 | \(+0.0608\) | \([+0.0552,+0.0665]\) | 1.00 | 1.00 |
| 743, 975 | \(+0.0063\) | \([+0.0022,+0.0102]\) | 0.79 | 0.83 |
| 975, 1145 | \(+0.0773\) | \([+0.0726,+0.0823]\) | 1.00 | 1.00 |
| 477, 975 | \(+0.0616\) | \([+0.0580,+0.0656]\) | 1.00 | 1.00 |
| 475, 743 | \(-0.0053\) | \([-0.0091,-0.0017]\) | 0.67 | 0.67 |
| 475, 1145 | \(+0.1009\) | \([+0.0952,+0.1066]\) | 1.00 | 1.00 |
| 475, 477 | \(+0.0499\) | \([+0.0459,+0.0538]\) | 1.00 | 1.00 |
| 743, 1145 | \(+0.0069\) | \([+0.0030,+0.0106]\) | 0.83 | 0.83 |
| 477, 743 | \(+0.1701\) | \([+0.1671,+0.1730]\) | 1.00 | 1.00 |
| 477, 1145 | \(+0.0811\) | \([+0.0765,+0.0862]\) | 1.00 | 1.00 |

Nine of ten pairs are positive at this config; one is slightly negative. The
selected feature indices differ across configurations, so these rows are not
matched features across layers or checkpoints.

#### 5.7.3 CWE-pattern breakdown

| Checkpoint | Layer | CWE-22 | CWE-502 | CWE-78 | CWE-79 | CWE-798 | CWE-89 | Same sign | Intervals overlap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| base | 4 | \(+0.0639\) | \(+0.0554\) | \(+0.0588\) | \(+0.0749\) | \(+0.0627\) | \(+0.0500\) | yes | yes |
| base | 10 | \(+0.0371\) | \(+0.0198\) | \(+0.0257\) | \(+0.0570\) | \(+0.0438\) | \(+0.0161\) | yes | no |
| base | 16 | \(-0.0264\) | \(-0.0245\) | \(-0.0244\) | \(-0.0337\) | \(-0.0232\) | \(-0.0228\) | yes | yes |
| base | 21 | \(-0.1092\) | \(-0.1132\) | \(-0.1124\) | \(-0.1012\) | \(-0.1007\) | \(-0.1173\) | yes | yes |
| instruct | 4 | \(+0.0020\) | \(+0.0026\) | \(+0.0021\) | \(+0.0052\) | \(+0.0030\) | \(+0.0032\) | yes | yes |
| instruct | 10 | \(+0.0306\) | \(+0.0300\) | \(+0.0329\) | \(+0.0295\) | \(+0.0323\) | \(+0.0300\) | yes | yes |
| instruct | 16 | \(-0.0121\) | \(-0.0100\) | \(-0.0112\) | \(-0.0114\) | \(-0.0114\) | \(-0.0108\) | yes | yes |
| instruct | 21 | \(+0.0402\) | \(+0.0456\) | \(+0.0431\) | \(+0.0321\) | \(+0.0391\) | \(+0.0401\) | yes | yes |

All six CWE categories have the same sign within every configuration. Only base
layer 10 has non-overlapping CWE intervals. Each CWE cell contains \(n=4\)
paired units, so these are coarse descriptive summaries, not category-level
estimates. No multiplicity correction is applied to the six categories.

#### 5.7.4 Layer and checkpoint stability

| Checkpoint | Same sign across layers | Sign consistency | All intervals overlap |
|---|---:|---:|---:|
| base | no | 0.50 | no |
| instruct | no | 0.75 | no |

| Layer | Base pooled | Instruct pooled | Same sign | Intervals overlap | Base triple | Instruct triple |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | \(+0.0609\) | \(+0.0030\) | yes | no | \(-0.0115\) | \(+0.0055\) |
| 10 | \(+0.0332\) | \(+0.0309\) | yes | yes | \(-0.0262\) | \(+0.0007\) |
| 16 | \(-0.0259\) | \(-0.0111\) | yes | no | \(-0.0067\) | \(+0.0138\) |
| 21 | \(-0.1090\) | \(+0.0400\) | no | no | \(+0.0200\) | \(+0.0049\) |

Across checkpoints, 3 of 4 layers share the pairwise sign, 1 of 4 has
overlapping intervals, and 1 of 4 shares the triple sign. The mean best decoder
cosine between base and instruct features is 0.246. Independently trained SAEs
do not define matched features, so this is a population-level stability check,
not feature-identity matching. The honest summary is that the pairwise contrast
is not stable in sign across layers and that the instruct model is the more
internally consistent of the two checkpoints (0.75 vs 0.50 sign consistency).

#### 5.7.5 Natural-ablation sensitivity check

| Checkpoint | Layer | Mean abs ablation effect | Ablation pairwise | 95% interval |
|---|---:|---:|---:|---|
| base | 4 | 0.1274 | \(-0.2986\) | \([-0.3220,-0.2756]\) |
| base | 10 | 0.1402 | \(+0.3935\) | \([+0.3647,+0.4202]\) |
| base | 16 | 0.2616 | \(-0.0043\) | \([-0.0070,-0.0013]\) |
| base | 21 | 0.1850 | \(+0.0193\) | \([+0.0030,+0.0348]\) |
| instruct | 4 | 0.0524 | \(+0.0040\) | \([+0.0027,+0.0054]\) |
| instruct | 10 | 0.0777 | \(+0.0252\) | \([+0.0195,+0.0308]\) |
| instruct | 16 | 0.0288 | \(-0.0048\) | \([-0.0055,-0.0041]\) |
| instruct | 21 | 0.0617 | \(-0.0002\) | \([-0.0006,+0.0002]\) |

The ablation operator does not reproduce the directional-intervention contrast.
At base layer 4 the directional contrast is \(+0.0609\) while the ablation
contrast is \(-0.2986\); at base layer 10 the directional contrast is \(+0.0332\)
while the ablation contrast is \(+0.3935\). The two operators answer different
questions (remove the decoded feature contribution versus add a fixed unit
step), so agreement was never required. The disagreement is a useful check that
the reported numbers are genuinely operator-dependent and that the pipeline is
not accidentally reusing one intervention for both.

#### 5.7.6 What these numbers do not show

- They do not show that a selected latent is a vulnerability feature, a secure
  feature, or a mechanism. Feature selection is outcome-blind and the labels are
  generator labels.
- They do not show a population effect for real code. The corpus is 24
  synthetic prompts, the intervals are percentile-bootstrap summaries, and the
  240 pooled pair-unit rows share prompts.
- They do not establish a ranking of layers, checkpoints, features, or CWE
  categories. The per-CWE sample size is 4 and no multiplicity correction is
  applied.
- They do not establish that the layer-21 results reflect the same feature
  structure as earlier layers; the layer-21 SAEs have high relative
  reconstruction error and many dead latents.

---

## 6. Assumptions and causal boundary

The contrasts in this report are causal contrasts **of the declared
activation intervention on the declared model readout**, under the stated
experimental design. They are not causal claims about real-world
vulnerabilities.

The interpretation requires, at minimum:

1. **Consistency.** The declared intervention is the intervention actually
   applied (same layer, position, direction, step, and simultaneous application).
2. **No undeclared interference.** Other features may change as a consequence of
   the intervention. The contrast attributes the outcome change to the declared
   cells, not to an isolated feature mechanism.
3. **Positivity / overlap.** Each cell is actually evaluated on each unit. The
   design satisfies this by construction, but the intervention may be
   off-distribution.
4. **Correct outcome orientation and scale.** \(Y\) is a declared probe. A
   positive contrast means "more of the probe", not "more vulnerable".
5. **No off-target changes.** A change in an undeclared latent in only one cell
   produces a nonzero contrast (demonstrated synthetically: \(+4\)). The joint
   cell is a bundle intervention, not a guarantee that only the named features
   changed.
6. **SAE fidelity.** The decoder direction is the SAE's reconstruction
   direction. If the SAE does not faithfully decompose the activation, the
   "feature" is not a well-identified mechanism.
7. **Feature identifiability across layers/checkpoints.** Independently trained
   SAEs do not guarantee that feature index \(f\) has the same meaning at another
   layer or checkpoint. Cross-layer and cross-checkpoint comparisons are
   therefore population-level unless features are explicitly matched.
8. **Unit exchangeability for the bootstrap.** The bootstrap treats prompts as
   exchangeable units. Lexical variants from the same template are correlated;
   the intervals may be too narrow for the broader population of code.
9. **No unmeasured prompt confounding.** The paired design removes unit-level
   baseline offsets, but it does not remove interactions between prompt content
   and the intervention.

The production documentation already states that SAE features are mathematical
latent directions and that activation, utilization, or reconstruction statistics
do not establish semantic meaning. This report is consistent with that boundary.

No p-values or significance claims are made. "Stable" in this report means
"same sign and overlapping descriptive intervals across the measured groups",
not "statistically significant" or "replicated in the population".

---

## 7. Limitations

- **Synthetic corpus.** The real-model corpus is generated from six pattern pairs
  with lexical variation. It is not a vulnerability benchmark and does not cover
  the diversity of real code.
- **Single model family and size.** Only Qwen2.5-Coder-0.5B base and instruct are
  used. Results may not transfer to other architectures or scales.
- **Small SAE training set.** 72 prompts and roughly 3,400 activation vectors per
  layer. The SAEs are validation instruments, not production-quality feature
  dictionaries.
- **Light sparsity.** \(L_0 \approx 173\) of 1792 latents; features may be
  polysemantic.
- **Probe validity.** The A/B next-token log-odds probe is a convenience readout.
  It is not validated against human vulnerability judgments or scanner labels.
- **Intervention magnitude.** The directional step \(\alpha = 0.25\) of the median
  residual norm is arbitrary. Ablation results are much smaller and are reported
  separately as a sensitivity check.
- **Bootstrap undercoverage.** Percentile intervals undercover at \(n=24\). They
  are descriptive.
- **Multiple comparisons.** Ten pairs and one triple are reported per config
  without multiplicity correction. No selection or ranking claim is made.
- **Feature identity.** Feature indices are SAE-specific. Cross-layer and
  cross-checkpoint stability is assessed at the population level, not by matched
  feature identity.
- **No external validation.** No held-out vulnerability benchmark, human feature
  labeling, or downstream repair experiment is included.

---

## 8. Reproduction

Environment used:

- Python 3.11.14
- PyTorch 2.15.0
- Transformers 5.22.2
- NumPy 2.4.6
- CPU, macOS (Apple silicon)

Commands:

```bash
# Synthetic mathematics and coverage checks
.venv/bin/python research/experiments/counterfactual_validation/run_synthetic_validation.py

# Automated tests
cd security-engine
../.venv/bin/python -m pytest \
  tests/unit/test_counterfactual_mathematical_validation.py \
  tests/unit/test_validation_corpus.py -q

# Independent numerical regression suite
cd ..
.venv/bin/python -m pytest mathematical-regression-tests -q

# Real-model experiment (requires the two Qwen checkpoints)
.venv/bin/python research/experiments/counterfactual_validation/run_real_model_validation.py \
  --layers 4,10,16,21 --top-k 5 --eval-variants 2 --train-variants 4 \
  --sae-epochs 8 --sparsity 0.3 --latent-multiplier 2 --n-boot 2000 \
  --direction-fraction 0.25 --checkpoints base,instruct \
  --output real_model_validation.json

# Smoke test
.venv/bin/python research/experiments/counterfactual_validation/run_real_model_validation.py \
  --smoke --checkpoints base --output smoke_validation.json
```

Artifacts:

- `research/experiments/counterfactual_validation/results/synthetic_validation.json`
- `research/experiments/counterfactual_validation/results/real_model_validation.json`
- `research/experiments/counterfactual_validation/artifacts/*.pt`

---

## Appendix A. Test inventory

The validation tests are intentionally model-independent. They run without a
model download, an SAE checkpoint, or a GPU.

| Test | What it establishes |
|---|---|
| `test_baseline_is_the_reference_cell_not_zero_and_constant_shifts_cancel` | Baseline is the empty cell; shifts cancel |
| `test_pairwise_engine_constructs_the_four_declared_intervention_cells` | Cell construction and engine contrast |
| `test_single_feature_ablation_sets_the_target_to_zero_and_leaves_others_alone` | Single-feature ablation semantics |
| `test_joint_intervention_is_simultaneous_and_not_sequential` | Joint cell is simultaneous |
| `test_pairwise_contrast_is_zero_for_a_purely_additive_outcome` | Additive null |
| `test_higher_order_contrast_matches_inclusion_exclusion_by_hand` | Third-order formula |
| `test_higher_order_contrast_rejects_incomplete_factorial_cells` | All \(2^k\) cells required |
| `test_interaction_direction_flips_when_the_outcome_is_negated` | Direction and orientation |
| `test_probability_and_logit_interactions_are_not_the_same_estimand` | Scale dependence |
| `test_paired_design_removes_a_sample_level_confounder_that_biases_unpaired_cells` | Pairing removes baseline confounding |
| `test_off_target_change_in_only_one_cell_creates_a_spurious_interaction` | Off-target sensitivity |
| `test_bootstrap_is_reproducible_and_matches_the_paired_standard_error` | Bootstrap determinism and SE |
| `test_bootstrap_interval_has_reasonable_coverage_for_a_known_interaction` | Coverage |
| `test_bootstrap_interval_for_a_null_effect_usually_contains_zero` | Null containment |
| `test_stability_summary_reports_sign_and_interval_agreement` | Stability semantics |
| `test_validation_helpers_reject_invalid_shapes_and_missing_values` | Input validation |
| `test_corpus_is_deterministic_balanced_and_unique` | Corpus reproducibility and balance |
| `test_generated_samples_are_valid_python_and_lexically_distinct` | Snippet validity |
| `test_corpus_rejects_invalid_variant_counts_and_empty_code` | Corpus input validation |
| `test_label_token_resolution_requires_single_token_labels` | Outcome-probe token resolution |

---

## Appendix B. Exact synthetic outputs

The synthetic runner records every observed value in
`research/experiments/counterfactual_validation/results/synthetic_validation.json`.
Selected values:

| Quantity | Value |
|---|---:|
| Pairwise contrast, \(Y = 1 + 2A + 3B + 5AB\) | 5.0 |
| Third-order contrast, \(Y = 2 + A + 2B + 3C + 7ABC\) | 7.0 |
| Probability-scale contrast (logit interaction 2.0) | 0.3492 |
| Logit-scale contrast | 2.0000 |
| Paired contrast under baseline shift | 0.0 |
| Unpaired spurious contrast under baseline imbalance | -10.0 |
| Bootstrap empirical coverage, \(n=50\) | 0.954 |
| Bootstrap null containment, \(n=60\) | 0.925 |
| Bootstrap null containment, \(n=24\) | 0.927 |
| Stability summary, stable groups | sign consistency 1.0, intervals overlap |
| Stability summary, mixed groups | sign consistency 0.75, not all same sign |

---

## Appendix C. Claim boundary

Supported by this work:

- The implementation computes the declared factorial contrasts correctly on
  controlled ground truth.
- The paired estimators use the same units in every cell and produce
  reproducible descriptive bootstrap intervals.
- The real-model pipeline can train SAEs on actual Qwen activations, apply
  declared decoder-direction interventions, and estimate pairwise and
  higher-order contrasts.
- Measured interactions can be compared across code samples, CWE-pattern
  categories, layers, and checkpoints as descriptive summaries.

Not supported by this work:

- That any SAE feature represents a vulnerability, a secure behaviour, or a
  human-interpretable security concept.
- That the A/B probe measures real vulnerability.
- That the observed interactions are causal effects of code properties on
  real-world security.
- That the results generalize beyond the synthetic corpus, the two checkpoints,
  the selected layers, the SAE training setup, the intervention step, and the
  probe.
- That any contrast is statistically significant, or that the absence of a
  nonzero contrast proves the absence of an interaction.
