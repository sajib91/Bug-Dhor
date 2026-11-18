# Bug Dhor — Mathematical Formulations

**Purpose.** A precise reference for every mathematical formulation in `Research.txt`, with variables, assumptions, correctness notes, and — where the paper is under-specified — a defensible operational form. This document is descriptive; it does not change any algorithm.

**Companion documents:**

- [`research/mathematical-framework-audit.md`](mathematical-framework-audit.md) — verdicts, issue register, evaluation readiness.
- [`research/mathematical-implementation-mapping.md`](mathematical-implementation-mapping.md) — equation-to-code map.

---

## 0. Notation and conventions

| Symbol | Meaning | Domain |
|---|---|---|
| `c` | A source-code sample (function, file, or code unit) | Source text |
| `i` | Sample index | `1..N` |
| `N` | Number of samples | Positive integer |
| `y`, `y_i` | Ground-truth vulnerability label (`1` vulnerable, `0` not) | `{0,1}` |
| `σ(·)` | Logistic sigmoid `1/(1+e^{−u})` | `R → (0,1)` |
| `I[·]` | Indicator function | `{0,1}` |
| `ReLU(u)` | `max(0,u)` | `R → R_{≥0}` |
| `‖·‖_1`, `‖·‖_2` | L1 and L2 norms | — |
| `E[·]` | Expectation under the data distribution | — |
| `Cov(·,·)` | Covariance | — |
| `∂` | Partial derivative | — |
| `⊨` | Satisfies / models (used informally for tests in the paper) | — |
| `\` | Set difference | — |
| `|S|` | Cardinality of set `S` | — |

### 0.1 Notation repairs adopted in this document

These repairs are used only to make the mathematics unambiguous. They do not alter the paper's intent.

| Paper notation | Problem | Repair used here |
|---|---|---|
| `f_θ` used for the detector (Eq. 2), the fused model (Eq. 44), and the latent model (Eq. 16) | Overloaded | `f_det` for the detector; `f_fuse` for the fused head; `f̃` for the latent-to-output map |
| `R` used for both risk score (Eq. 28) and risk function (Eq. 46) | Overloaded | `R_index` for the score; `R_fn` for the function |
| `G` used for prevention (Eq. 47) and repair (Eq. 30, 48) | Overloaded | `G_prevent` and `G_repair` |
| `w_j` in Eq. (8) written as a column | `W_e` is `d_s×d`, so feature `j` is a row | `w_j = W_e[j,:]^T` |
| `s_{j,pool}` | Never defined | Explicit pooled-SD formula in §4 |
| `FPR` used for functional pass rate (§7.6.3) | Collides with false positive rate | `FPass` for functional pass rate; `FPR` reserved for false positive rate |
| `Accuracy_L` (§7.4.4) | Collides with exact-match accuracy in code | `Acc_line` for line-level accuracy; exact-match is `EM` |

### 0.2 Estimand vs estimator

For every statistical equation, the paper states an estimand (a population quantity). An empirical claim requires an **estimator**, a **sampling assumption**, and an **uncertainty statement**. Where the paper gives only the estimand, this document states the conventional estimator and flags it as an audit addition, not as paper content.

---

## 1. Source-code representation — Eq. (1)

### 1.1 Paper form

```
x(c) = [ x_lex ; x_syn ; x_sem ; x_str ; x_sec ]                         (1)
```

### 1.2 Variables

| Symbol | Meaning |
|---|---|
| `x_lex` | Lexical features: tokens, identifiers, operators, API names |
| `x_syn` | Syntactic features from the grammar/program constructs |
| `x_sem` | Semantic representations from a code encoder or LLM hidden states |
| `x_str` | Structural features from control-flow and data-flow relationships |
| `x_sec` | Security features: validation, sensitive APIs, source-to-sink relations |
| `;` | Vector concatenation |

### 1.3 Assumptions

- **A1.1** Each view can be mapped to a fixed-length real vector.
- **A1.2** The views are computed from the same `c` and are aligned to the same code unit.
- **A1.3** The views are normalized or projected into compatible scales before concatenation.
- **A1.4** No view leaks the label or evaluation-only information.

### 1.4 Correctness

The equation is a **design schematic**, not a well-formed definition. It has three defects:

1. **Domain/dimension:** tokens are sequences, AST/CFG/DFG are graphs, taint evidence is a set of paths. Concatenation is undefined until each view is pooled or encoded to `R^{d_v}`.
2. **Redundancy:** `x_syn` and `x_str` overlap with the AST/CFG/DFG views; `x_sec` overlaps with taint evidence. Double-counting the same signal in a downstream linear model inflates its effective weight.
3. **No `Φ`:** Eq. (40) later writes `x = Φ(c)`, but `Φ` is never defined.

### 1.5 Operational form (audit addition)

For each view `v ∈ {lex, syn, sem, str, sec}`, define an encoder

```
φ_v : C → R^{d_v},   x_v = normalize_v(φ_v(c)),   d_v fixed.
```

Then

```
x(c) = [ x_lex ; x_syn ; x_sem ; x_str ; x_sec ] ∈ R^{d_x},   d_x = Σ_v d_v.
```

For graph views, `φ_v` must include a readout (e.g., mean/sum of node embeddings, or a graph-pooling operator). For taint, `φ_sec` must include a fixed-length summary (counts, max path length, sanitizer flags), not a variable-length path list.

**Alternative (preferred if modalities are missing):** do not concatenate; keep a per-view embedding `x_v` and a mask `m_v`, and fuse them with Eq. (25). Concatenation forces every view to exist, which contradicts the paper's own missing-modality requirement in §5.9.

### 1.6 Implementability

Implementable. The code has AST/CFG/DFG/taint views (`program_analysis/`), but no concatenated five-view vector and no `Φ`. See mapping `E-01`.

### 1.7 Evaluation

- Ablation: each view alone and all subsets.
- Leakage check: verify no view is derived from the label or test split.
- Missing-view stress test: drop one view and measure degradation.
- Dimensionality/cost report per view.

---

## 2. Vulnerability classification — Eq. (2)–(4)

### 2.1 Paper form

```
P(y=1 | c) = σ( f_θ(x(c)) )                                              (2)
ŷ          = I[ P(y=1 | c) ≥ η ]                                         (3)
L_det      = −(1/N) Σ_i [ y_i log p_i + (1−y_i) log(1−p_i) ]             (4)
```

### 2.2 Variables

| Symbol | Meaning |
|---|---|
| `f_θ` | Classifier scoring function with parameters `θ` |
| `θ` | All learned parameters |
| `p_i` | `P(y_i=1 | c_i)`, the predicted probability |
| `η` | Decision threshold, selected on validation data |
| `N` | Number of training samples |

### 2.3 Assumptions

- **A2.1** Samples `(c_i, y_i)` are independent and identically distributed from the target distribution.
- **A2.2** Labels are correct at the stated granularity (function/file/line).
- **A2.3** The sigmoid output is a calibrated probability, or calibration is applied post hoc.
- **A2.4** `η` is selected without using the test set.
- **A2.5** The loss is the negative log-likelihood; any class weighting changes the estimand.

### 2.4 Correctness

- Eq. (2) is the standard logistic model. Correct.
- Eq. (3) is the standard threshold rule. Correct. If misclassification costs `C_FP` and `C_FN` are known, the Bayes-optimal threshold is `η* = C_FP/(C_FP+C_FN)` under calibrated probabilities; otherwise `η` is a policy choice and must be reported.
- Eq. (4) is binary cross-entropy. Correct **only if** `p_i` is the model's probability for the same `y_i` and no class weighting is applied. With class weights `w_1, w_0`, the minimizer is a weighted posterior, not `P(y=1|c)`, so the output must be recalibrated before being interpreted as a probability.
- **Core problem:** none of this is implemented. There is no trained `f_θ`, no `θ_det`, no `η`, and no calibrated probability in the code. The live detector is a heuristic evidence combiner.

### 2.5 Operational form (audit addition)

```
p_i = σ(f_det(x_i; θ_det))
η   = argmax_η  F1(η; D_val)          # or: smallest η with FPR ≤ α
L_det = −(1/N) Σ_i [ w_{y_i} y_i log p_i + w_{1−y_i} (1−y_i) log(1−p_i) ]
p̂_i = Calibrate(p_i; D_cal)           # Platt or isotonic on a held-out split
```

Report `η`, the selection criterion, the calibration method, and the calibration metrics (Brier, ECE).

### 2.6 Implementability

Implementable, but not implemented. The evidence-fusion module can produce a ranking score; it cannot produce Eq. (2) without a trained model.

### 2.7 Evaluation

Accuracy, precision, recall, F1, MCC, ROC-AUC, PR-AUC, Brier, ECE; bootstrap CIs; threshold sensitivity; per-CWE and per-language breakdowns; calibration plots.

---

## 3. Sparse autoencoder — Eq. (5)–(7)

### 3.1 Paper form

```
z    = ReLU(W_e h + b_e)                                                (5)
ĥ    = W_d z + b_d                                                      (6)
L_SAE = (1/N_h) Σ_i ‖h_i − ĥ_i‖² + λ ‖z_i‖_1                            (7)
```

### 3.2 Variables

| Symbol | Meaning | Shape |
|---|---|---|
| `h` | Activation vector from a selected LLM layer and token position | `R^d` |
| `W_e` | Encoder weights | `R^{d_s×d}` |
| `b_e` | Encoder bias | `R^{d_s}` |
| `z` | Sparse latent code | `R^{d_s}` |
| `W_d` | Decoder weights | `R^{d×d_s}` |
| `b_d` | Decoder bias | `R^d` |
| `d` | Activation dimension | Positive integer |
| `d_s` | Latent dimension (`d_s > d` typical) | Positive integer |
| `λ` | Sparsity penalty | `λ ≥ 0` |
| `N_h` | Number of activation vectors | Positive integer |

### 3.3 Assumptions

- **A3.1** The activation distribution used for training matches the distribution at analysis time (same model, layer, hook, token pooling).
- **A3.2** L1 is an acceptable surrogate for sparsity.
- **A3.3** The decoder is a faithful reconstruction map.
- **A3.4** Features are stable enough to be compared across samples.

### 3.4 Correctness

- Eq. (5)–(6) are correct.
- Eq. (7) is correct as written. Note that the L1 term is inside the sample mean; equivalently `(1/N_h) Σ_i (‖h_i−ĥ_i‖² + λ‖z_i‖_1)`. The paper's placement of `λ‖z_i‖_1` inside the sum is unambiguous enough.
- **What the equation does not guarantee:** L1 does not guarantee a low L0 count, does not prevent dead features, and does not make features monosemantic. These are empirical properties.
- The paper never defines `h` preprocessing. If `h` is not normalized, `λ` is not comparable across layers/models.

### 3.5 Operational form (audit addition)

```
h_i ← Normalize(Activation(model, layer, hook, token_pool(c_i)))
z_i = ReLU(W_e h_i + b_e)
ĥ_i = W_d z_i + b_d
L_SAE = (1/N_h) Σ_i ‖h_i − ĥ_i‖² + λ (1/N_h) Σ_i ‖z_i‖_1
```

Report:

```
R²_recon = 1 − Σ_i ‖h_i − ĥ_i‖² / Σ_i ‖h_i − h̄‖²
L0_i     = ‖z_i‖_0
DeadFrac = |{j : max_i z_{ij} = 0}| / d_s
```

Also consider decoder-column normalization `‖W_d[:,j]‖_2 = 1` (a common SAE convention) and document whether weights are tied.

### 3.6 Implementability

Implemented at E1: `sae/model.py`, `sae/training.py`, `sae/metrics.py`. No real checkpoint, no normalization artifact, no dead-feature handling.

### 3.7 Evaluation

Reconstruction vs L0 Pareto frontier; dead-feature fraction; feature stability across seeds; downstream association stability; ablating `λ`; comparing tied vs untied weights; checking reconstruction on held-out code.

---

## 4. Latent feature activation and association — Eq. (8)–(10)

### 4.1 Paper form

```
z_ij  = ReLU(w_j^T h_i + b_j)                                           (8)
Δμ_j  = E[z_j | y=1] − E[z_j | y=0]                                      (9)
d_j   = (μ_{j,1} − μ_{j,0}) / s_{j,pool}                                (10)
```

### 4.2 Variables

| Symbol | Meaning |
|---|---|
| `z_ij` | Activation of feature `j` for sample `i` |
| `w_j` | Encoder weight vector for feature `j` (= `W_e[j,:]^T`) |
| `h_i` | Activation vector for sample `i` |
| `b_j` | Encoder bias for feature `j` |
| `μ_{j,1}` | `E[z_j | y=1]` |
| `μ_{j,0}` | `E[z_j | y=0]` |
| `s_{j,pool}` | Pooled standard deviation (undefined in the paper) |
| `Δμ_j` | Mean activation difference |
| `d_j` | Standardized mean difference |

### 4.3 Assumptions

- **A4.1** Samples are independent.
- **A4.2** The two groups are comparable except for the label (no dataset/confound shift).
- **A4.3** `s_{j,pool} > 0` and finite.
- **A4.4** The activation scale is meaningful (same SAE, same normalization).

### 4.4 Correctness

- Eq. (8) is correct after the row/column repair (`w_j = W_e[j,:]^T`). As printed, `w_j` is a column, which conflicts with `W_e ∈ R^{d_s×d}`.
- Eq. (9) is a raw mean difference. Correct as an estimand, but scale-dependent and not comparable across features.
- Eq. (10) is Cohen's *d*. The paper does not define `s_{j,pool}`. The conventional definition is

```
s_{j,pool} = sqrt( ((n_1−1)s_{j,1}² + (n_0−1)s_{j,0}²) / (n_1+n_0−2) )
```

with `n_1`, `n_0` the group sizes and `s_{j,1}`, `s_{j,0}` the group SDs.

- **Zero-inflation problem:** ReLU latents are often exactly zero for most samples. Then `s_{j,pool}` can be zero (undefined `d_j`) or the effect is dominated by activation frequency rather than magnitude. A feature that fires for 60% of vulnerable samples and 5% of secure samples is highly associated even if its conditional mean is modest.
- **Multiplicity:** with `d_s` in the thousands, testing every feature at `α=0.05` produces many false discoveries. The paper does not mention correction.

### 4.5 Operational form (audit addition)

```
Δμ_j = mean_{i:y_i=1} z_ij − mean_{i:y_i=0} z_ij
s_pool,j = sqrt( ((n_1−1)s_1² + (n_0−1)s_0²) / (n_1+n_0−2) )      if n_1+n_0 > 2
g_j = (1 − 3/(4(n_1+n_0)−9)) · Δμ_j / s_pool,j                    # Hedges' g
CI_j = bootstrap 95% CI of g_j (resample samples within groups)
freq_j(y) = mean_{i:y_i=y} I[z_ij > 0]
q_j = BH-adjusted p-value across features
```

Report `Δμ_j`, `g_j`, `freq_j(1)`, `freq_j(0)`, CI, and `q_j`. If `s_pool,j = 0`, report `g_j = undefined` and use a rank-based effect size (`Cliff's delta`) or the activation-frequency difference instead.

### 4.6 Implementability

Eq. (8)–(9) implemented at E1. Eq. (10) **not implemented**. `association.py` computes means, activation frequency, and a selectivity score. No pooled effect, no CI, no correction.

### 4.7 Evaluation

Feature ranking stability across seeds/datasets; CI coverage on synthetic data with a known effect; comparison of `g_j` vs frequency-based ranking; false-discovery behavior under the null (permute labels).

---

## 5. Feature interactions — Eq. (11)–(13)

### 5.1 Paper form

```
ρ_ij = Cov(z_i, z_j) / (σ_i σ_j)                                        (11)
I_ij = g(1,1) − g(1,0) − g(0,1) + g(0,0)                                (12)
I_ij(a,b) = g(z_i=a, z_j=b) − g(z_i=a, z_j=0)
          − g(z_i=0, z_j=b) + g(z_i=0, z_j=0)                          (13)
```

### 5.2 Variables

| Symbol | Meaning |
|---|---|
| `ρ_ij` | Pearson correlation between latent features `i` and `j` |
| `σ_i`, `σ_j` | Standard deviations of `z_i`, `z_j` |
| `g(·)` | Declared model outcome (e.g., vulnerability probability, logit, score) |
| `1`, `0` | Intervention states (on/off, or a reference state) |
| `a`, `b` | Continuous intervention magnitudes |

### 5.3 Assumptions

- **A5.1** The four cells are measured on the same input(s) with only the target features changed.
- **A5.2** The intervention operator is well-defined and applied identically in every cell.
- **A5.3** The outcome is measured on a scale where a difference-in-differences is meaningful.
- **A5.4** Correlation is computed on non-degenerate features.
- **A5.5** No other feature changes as a side effect of the intervention (or such changes are controlled).

### 5.4 Correctness

- Eq. (11) is Pearson correlation. Correct, but **it is not an interaction** and it is undefined when `σ_i=0` or `σ_j=0`. For zero-inflated latents, use Spearman or the phi coefficient on binarized activations, and report a CI.
- Eq. (12) is the standard 2×2 interaction contrast (difference-in-differences). Correct as a factorial contrast.
- Eq. (13) is the continuous-magnitude version. Correct.
- **What is missing:** the paper never defines the intervention operator, the outcome scale, or the reference state. `g(1,1)` is not a causal effect unless the same input is used and only the features are changed. On the probability scale, interaction is bounded and baseline-dependent; on the logit scale it is additive. The paper should report both or declare one.
- **Higher-order generalization** (used in code, not printed as an equation):

```
I_S = Σ_{T ⊆ S} (−1)^{|S|−|T|} g(T),   |S| = k
```

This is the Möbius interaction of order `k`. It requires all `2^k` cells. The paper mentions higher-order interactions in §1/§4 but only numbers the pairwise equations; the generalization should be stated explicitly.

### 5.5 Operational form (audit addition)

Define a feature-intervention operator `do(z_j = u)` (ablation to 0, clamp to `u`, or add a decoder direction). Then

```
g(T) = E_{x ~ D_eval}[ f_det(x; z_j = u_j for j ∈ T, z_j = 0 otherwise) ]
I_S  = Σ_{T ⊆ S} (−1)^{|S|−|T|} g(T)
```

Use the same inputs across cells (paired design). Report:

```
I_S^prob  = contrast on probability scale
I_S^logit = contrast on logit scale
CI        = bootstrap over inputs
p_perm    = permutation p-value under random feature/state assignment
```

Sign convention: `I > 0` = synergistic (joint effect exceeds additive); `I < 0` = antagonistic. State the convention explicitly.

### 5.6 Implementability

Eq. (12)–(13) implemented at E1 (`counterfactual/pairwise.py`, `higher_order.py`). Eq. (11) **not implemented** as a screening step; the code ranks by selectivity. No `τ_corr`/`τ_int`, no controls, no API wiring.

### 5.7 Evaluation

- Null calibration: permutation test should produce a uniform p-value distribution under no interaction.
- Power: synthetic outcome with a known interaction.
- Agreement between correlation screening and interaction ranking.
- Dose-response: `I` vs `a`, `b`.
- Cost: number of forward passes `2^k` per subset; sampling error vs `k`.

---

## 6. Feature attribution — Eq. (14)–(16)

### 6.1 Paper form

```
A_j       = | ∂f_θ(x) / ∂x_j |                                          (14)
IG_j(x)   = (x_j − x'_j) ∫_0^1 ∂f_θ(x' + α(x−x')) / ∂x_j dα              (15)
A_j^SAE   = | ∂f_θ(z) / ∂z_j |                                          (16)
```

### 6.2 Variables

| Symbol | Meaning |
|---|---|
| `A_j` | Gradient attribution for input feature `j` |
| `x'` | Baseline/reference input |
| `α ∈ [0,1]` | Interpolation coefficient |
| `IG_j` | Integrated gradient for feature `j` |
| `A_j^SAE` | Attribution for latent feature `j` |
| `z_j` | SAE latent activation |

### 6.3 Assumptions

- **A6.1** `f_θ` is differentiable almost everywhere (or a differentiable surrogate is used).
- **A6.2** The baseline `x'` is meaningful (e.g., all-zero embedding, mean activation, or a neutral code sample).
- **A6.3** The interpolation path stays on the model's valid input manifold.
- **A6.4** Attribution is a local sensitivity/contribution measure, not a causal effect.

### 6.4 Correctness

- Eq. (14) is the absolute input gradient. It measures **local sensitivity**, not contribution; it can be large for a feature that does not change the prediction under a finite intervention.
- Eq. (15) is Integrated Gradients. Correct. It satisfies the completeness axiom **only** if `f` is differentiable along the path and the integral is exact; a finite Riemann sum gives an approximation with error depending on the number of steps.
- Eq. (16) has a **notation defect**: `f_θ(z)` is not the same function as `f_θ(x)`. The latent-to-output map is

```
f̃(z) = f_det(W_d z + b_d)
∂f̃/∂z_j = (∂f_det/∂h) · W_d[:,j]
```

Without the chain rule, Eq. (16) is not the gradient of the model with respect to the latent.
- For discrete source code, `x` must be an embedding-space representation; gradients with respect to token IDs are undefined. The paper says this in §5.6/Algorithm 5 and should repeat it wherever Eq. (14)–(16) appear.

### 6.5 Operational form (audit addition)

```
A_j       = |∂f_det(x)/∂x_j|                         # local sensitivity
IG_j(x)   = (x_j − x'_j) · (1/m) Σ_{k=1}^m ∂f_det(x' + (k/m)(x−x'))/∂x_j
A_j^SAE   = |(∂f_det/∂h) · W_d[:,j]|                 # chain rule
```

For non-differentiable models, use a perturbation/ablation attribution:

```
A_j^pert = E[ f(x) − f(x with feature j ablated) ]
```

and document the ablation operator. Attribution is model-relative; it is not proof of a security concept.

### 6.6 Implementability

**Not implemented.** No gradient path, no IG, no SAE attribution, no ablation attribution. The explain module assembles evidence but does not attribute.

### 6.7 Evaluation

- Comprehensiveness: `Comp_k = f(x) − f(x \ A_k)` (larger is better).
- Sufficiency: `Suff_k = f(x) − f(x_{A_k})` (smaller is better).
- Attribution faithfulness: Spearman correlation between `|a_i|` and `|Δ_i|` under intervention.
- Stability: Spearman/Jaccard of top-k attributions under semantics-preserving perturbations.
- Sanity checks: random attribution baseline, model-parameter randomization.

---

## 7. AST and CFG — Eq. (17)–(20)

### 7.1 Paper form

```
G_AST = (V_AST, E_AST)                                                  (17)
G_CFG = (V_CFG, E_CFG)                                                  (18)
A_uv  = 1 if (u,v) ∈ E_CFG else 0                                       (19)
h_v^{(l+1)} = φ( W_0 h_v^{(l)} + Σ_{u∈N(v)} W_1 h_u^{(l)} )            (20)
```

### 7.2 Variables

| Symbol | Meaning |
|---|---|
| `V_AST`, `E_AST` | Syntax nodes and directed parent–child edges |
| `V_CFG`, `E_CFG` | Basic blocks and control-transfer edges |
| `A_uv` | CFG adjacency entry |
| `h_v^{(l)}` | Node representation at layer `l` |
| `N(v)` | Neighbors of `v` |
| `W_0`, `W_1` | Trainable weight matrices |
| `φ` | Nonlinear activation |

### 7.3 Assumptions

- **A7.1** The parser produces a faithful AST/CFG for the language.
- **A7.2** Basic-block boundaries are well-defined.
- **A7.3** Message passing is run on a graph with self-loops or a separate self term.
- **A7.4** A graph-level readout is defined.

### 7.4 Correctness

- Eq. (17)–(19) are standard definitions. Correct.
- Eq. (20) is the standard message-passing form **but it does not use `A_uv`** even though Eq. (19) defines it. As written, `Σ_{u∈N(v)}` already implies the adjacency; the paper should either write the sum over all `u` with `A_uv` or drop Eq. (19) from the message-passing description.
- Eq. (20) omits: the initial node features `h_v^{(0)}`, edge features, normalization (e.g., `1/sqrt(deg(u)deg(v))`), and the graph-level readout/pooling. Without these, the model is incomplete.

### 7.5 Operational form (audit addition)

```
h_v^{(l+1)} = φ( W_0 h_v^{(l)} + Σ_{u∈V} A_uv W_1 h_u^{(l)} )
h_G = Pool_{v∈V}( h_v^{(L)} )        # mean, sum, or attention pooling
```

State whether `A` includes self-loops, whether it is normalized, and what `Pool` is.

### 7.6 Implementability

AST/CFG construction is implemented (`program_analysis/ast` via parser, `cfg.py`). The GNN of Eq. (20) is **not implemented**; no message passing is used.

### 7.7 Evaluation

Graph construction validity on a parser test set; detection ablation with/without graph features; readout comparison; robustness to formatting-only changes.

---

## 8. DFG and taint — Eq. (21)–(23)

### 8.1 Paper form

```
G_DFG = (V_DFG, E_DFG)                                                  (21)
∃ s ∈ S, k ∈ K : Reachable_DFG(s,k) = 1                                 (22)
P_unsafe = { p ∈ P(S,K) : q(p) = 0 }                                    (23)
```

### 8.2 Variables

| Symbol | Meaning |
|---|---|
| `V_DFG` | Definitions and uses of program values |
| `E_DFG` | Data-dependency edges |
| `S` | Untrusted source nodes |
| `K` | Sensitive sink nodes |
| `P(S,K)` | Set of data-flow paths from a source to a sink |
| `q(p)` | Indicator that path `p` contains an adequate sanitizer |
| `P_unsafe` | Unsanitized source-to-sink paths |

### 8.3 Assumptions

- **A8.1** Sources, sinks, sanitizers, and propagators are correctly modeled for the language/framework.
- **A8.2** The analysis is sound enough for the claim being made (may-analysis vs must-analysis).
- **A8.3** `q(p)` correctly recognizes sanitization adequacy.
- **A8.4** Path enumeration is bounded or summarized.

### 8.4 Correctness

- Eq. (21) is a standard DFG definition. Correct.
- Eq. (22) is **may-reachability**: it says a path *can* exist, not that it is executable or exploitable. Correct as a static may-analysis; not a vulnerability proof.
- Eq. (23) is correct set notation, but `q(p)` is undefined. "Adequate sanitizer" is CWE- and framework-specific; a syntactic sanitizer call is not proof of adequacy. A binary `q` forces wrong sanitizers into "safe".
- Path explosion and context sensitivity are not addressed.

### 8.5 Operational form (audit addition)

Use a three-valued path status:

```
status(p) ∈ {sanitized, unsanitized, unknown}
P_unsafe = { p : status(p) = unsanitized }
P_unknown = { p : status(p) = unknown }
```

Report `P_unsafe` and `P_unknown` separately. `unknown` is not safe. Define sanitizer rules per CWE and version them.

### 8.6 Implementability

Implemented at E2 with intraprocedural limits (`program_analysis/taint.py`, `dfg.py`). Taint reachability is real; sanitizer adequacy is heuristic; interprocedural flows, reflection, dynamic dispatch, and framework models are incomplete.

### 8.7 Evaluation

Compare against a labeled taint benchmark or a mature tool (Semgrep/CodeQL) on the same files; report precision/recall and unknown rate; per-CWE breakdown; false-negative audit on known CVEs.

---

## 9. Multi-source evidence fusion — Eq. (24)–(27)

### 9.1 Paper form

```
e_i = [ e_neural ; e_SAE ; e_interaction ; e_AST ; e_CFG ; e_DFG ; e_taint ; e_dynamic ]   (24)
h_fusion = F_φ(e_i, m_i)                                                (25)
S_i = (Σ_j m_ij w_j q_ij) / (Σ_j m_ij w_j)                              (26)
P_fusion(y_i=1) = σ( w_f^T h_fusion + b_f )                             (27)
```

The paper's availability mask `m_i` is described in prose, but the displayed equation for it is missing.

### 9.2 Variables

| Symbol | Meaning |
|---|---|
| `e_i` | Concatenated modality evidence |
| `m_i` | Availability mask, `m_ij ∈ {0,1}` |
| `m_ij` | 1 if modality `j` is available for sample `i`, else 0 |
| `F_φ` | Learnable fusion function with parameters `φ` |
| `w_j` | Reliability weight for modality `j` |
| `q_ij` | Normalized evidence score for modality `j`, sample `i` |
| `J` | Number of modalities |
| `w_f`, `b_f` | Logistic head weights and bias |
| `h_fusion` | Fused representation |

### 9.3 Assumptions

- **A9.1** Modalities are normalized to a common scale.
- **A9.2** Missingness is ignorable (MAR) or explicitly modeled.
- **A9.3** Weights `w_j` are calibrated on held-out data.
- **A9.4** The logistic head is trained with a proper loss and calibrated.
- **A9.5** Modalities are not double-counted.

### 9.4 Correctness

- Eq. (24) is a schematic; the components have different dimensions, so concatenation requires per-modality encoders.
- Eq. (25) is under-specified: no architecture, no output dimension, no training objective, no missing-modality mechanism beyond the mask.
- Eq. (26) is correct and explicitly defined only when `Σ_j m_ij w_j > 0`. It is a weighted mean, **not** a probability. If `q_ij` is a probability, `S_i` is a weighted average of probabilities, which is a valid score but not a calibrated probability.
- Eq. (27) is a logistic head. Correct if `h_fusion` is a vector and `F_φ` does not already apply a sigmoid. If `F_φ` outputs a scalar probability, Eq. (27) double-applies the link.
- **The mask equation is missing** from the paper. It must be displayed.

### 9.5 Operational form (audit addition)

```
m_ij = 1[ modality j produced evidence for sample i ]
q_ij ∈ [0,1]  (normalized per modality)
w_j ≥ 0       (calibrated on D_val; Σ_j m_ij w_j > 0)

S_i = (Σ_j m_ij w_j q_ij) / (Σ_j m_ij w_j)          # transparent baseline

# Learned alternative:
u_ij = Encoder_j(e_ij)                              # per-modality encoder
h_i  = Σ_j m_ij α_ij u_ij / Σ_j m_ij α_ij           # masked attention or mean
p_i  = σ(w_f^T h_i + b_f)                           # train with BCE; calibrate
```

If a modality is missing, exclude it from both numerator and denominator; do not impute zero.

### 9.6 Alternative implemented in code (documented, not paper-derived)

The code uses a family-wise noisy-OR:

```
combined_family = 1 − Π_{k ∈ family} (1 − decayed_support_k)
combined        = 1 − Π_{family} (1 − combined_family)
penalty         = min(0.95, refutation_scale × noisy_or(refutations))
score           = clamp(combined × (1 − penalty), 0, 1)
```

This is a valid **heuristic prioritization score** under an independence assumption. It is **not** a probability, and it is not Eq. (25)–(27). The code says so explicitly (`LIM-DET-01`). It must be reported as a separate baseline.

### 9.7 Implementability

Eq. (26) is implementable; Eq. (25)/(27) require training. The code implements the noisy-OR alternative at E2; no learned fusion, no calibration, no mask vector.

### 9.8 Evaluation

Compare noisy-OR, Eq. (26), and Eq. (25)/(27) on identical splits; ablation over modality subsets; missing-modality stress tests; AUROC/AUPRC/MCC; calibration (Brier/ECE); decision-curve analysis.

---

## 10. Security risk scoring — Eq. (28)–(29)

### 10.1 Paper form

```
R(v) = α P(v) + β S(v) + γ E(v) + δ I(v)                                (28)
C(v) = Critical if R(v) ≥ τ_3
       High     if τ_2 ≤ R(v) < τ_3
       Medium   if τ_1 ≤ R(v) < τ_2
       Low      if R(v) < τ_1                                           (29)
```

### 10.2 Variables

| Symbol | Meaning |
|---|---|
| `P(v)` | Calibrated probability that finding `v` is a vulnerability |
| `S(v)` | Normalized severity |
| `E(v)` | Normalized exposure/exploitability |
| `I(v)` | Normalized impact |
| `α,β,γ,δ` | Non-negative weights |
| `τ_1 < τ_2 < τ_3` | Priority thresholds |

### 10.3 Assumptions

- **A10.1** `P`, `S`, `E`, `I` are normalized to a common range (e.g., `[0,1]`).
- **A10.2** The weights are calibrated or chosen by a documented policy.
- **A10.3** The linear additive form is an acceptable multi-criteria aggregation.
- **A10.4** `P(v)` is calibrated if it is called a probability.
- **A10.5** CVSS or another severity source is not double-counted inside `S`, `E`, `I`.

### 10.4 Correctness

- Eq. (28) is a valid **linear prioritization index**. It is not a probability and has no probabilistic interpretation. If inputs are in `[0,1]` and `α+β+γ+δ=1`, then `R ∈ [0,1]`; otherwise `R` can exceed 1 and the thresholds lose meaning.
- Eq. (29) is correct given ordered thresholds.
- The paper says `P(v)` is "calibrated" but specifies no calibration method. That is a gap, not an algebraic error.
- The paper warns against double-counting CVSS factors. Good; this should be enforced in the normalization definition.

### 10.5 Operational form (audit addition)

```
P, S, E, I ∈ [0,1]
α, β, γ, δ ≥ 0,  α+β+γ+δ = 1        # recommended normalization
R_index(v) = α P(v) + β S(v) + γ E(v) + δ I(v)

0 < τ_1 < τ_2 < τ_3 ≤ 1
C(v) as in (29)
```

If the score is meant to be a probability, replace Eq. (28) with a calibrated logistic model on the same inputs, and report Brier/ECE. Do not call `R_index` a probability.

### 10.6 Implementability

Partial at E2: `steering/risk_controller.py` computes a different additive priority with CWE policy weights, a context multiplier, and a clamp. There is no `P(v)` decomposition and no calibration except an optional caller-supplied calibrator.

### 10.7 Evaluation

If a probability is claimed: reliability diagram, Brier, ECE, AUC. If an index: precision@k, NDCG, cost-weighted utility, expert agreement. Sensitivity analysis over weights and thresholds; ablations of each term.

### 10.8 Unified-engine operational form (audit addition)

`bugdhor.risk` implements Eq. (28)–(29) without changing their meaning. Its
additional definitions are operational, not new mathematics. For declared
dependency groups `D_g` (AST/CFG/DFG/taint → `program_analysis`;
model/SAE/interaction → `model_internal`):

```
r_g   = max{ r_i : i ∈ D_g, r_i > 0 }                    # group reliability
s_g   = (Σ r_i·v_i) / (Σ r_i)  over supporting i          # weighted support
q_g   = (Σ r_i·v_i) / (Σ r_i)  over refuting i            # weighted refutation
Δ_g   = clip(Σ_{int ∈ D_g} r_int·signed(int), −1, 1)      # interactions, same group only
s_g   = clip(s_g + Δ_g)        if Δ_g > 0
q_g   = clip(q_g + |Δ_g|)      if Δ_g < 0

S_hat = 1 − Π_g (1 − r_g·s_g)                            # noisy-OR across groups
Q_hat = 1 − Π_g (1 − r_g·q_g)
p_hat = S_hat·(1 − Q_hat)                                # heuristic until calibrated

R_index = Σ_{k ∈ present} (w_k / Σ_{j ∈ present} w_j)·v_k     # renormalize
R_index = unavailable                                        # if policy refuses gaps
```

Zero-reliability evidence is excluded before these sums and reported with a
reason. No component is imputed. A rejected calibration artifact leaves
`p_hat` and `R_index` heuristic and emits no probability. `Uncertainty` is
`max(evidence_deficit, support/refutation_conflict)`, not a credible interval;
only a validated calibration evaluation supplies interval fields. Default
weights are equal under a maximum-entropy neutral prior, not experimental
findings. See [`docs/unified-risk-engine.md`](../docs/unified-risk-engine.md).

---

## 11. Repair generation and objective — Eq. (30)–(33)

### 11.1 Paper form

```
P' = G_ψ(P, L, Q, π_r)                                                  (30)
P* = argmin_{P' ∈ C(P)} J_repair(P, P')                                 (31)
J_repair = λ_s L_security + λ_f L_function + λ_r L_regression + λ_d L_diff   (32)
P' ⊨ Q_func    and    P' ⊨ Q_security                                   (33)
```

### 11.2 Variables

| Symbol | Meaning |
|---|---|
| `P` | Original vulnerable program |
| `P'` | Candidate repaired program |
| `L` | Localization result |
| `Q` | Functional/regression test suite |
| `π_r` | Generation settings (model, prompt, temperature, budget) |
| `G_ψ` | Repair-generation model with parameters `ψ` |
| `C(P)` | Finite set of generated candidates |
| `λ_s, λ_f, λ_r, λ_d` | Non-negative objective weights |
| `L_security` | Residual security weakness |
| `L_function` | Deviation from functional specification |
| `L_regression` | Regression-test violations |
| `L_diff` | Unnecessary code change |
| `Q_func`, `Q_security` | Functional and security constraints |

### 11.3 Assumptions

- **A11.1** `G_ψ` produces at least one syntactically valid candidate for a non-trivial fraction of inputs.
- **A11.2** Each loss term is measurable.
- **A11.3** The weights reflect a defensible trade-off.
- **A11.4** The constraints are decidable by the available tools.
- **A11.5** The candidate set is finite and generated before selection.

### 11.4 Correctness

- Eq. (30) is a **schematic**, not a function definition: no domain/codomain, no distribution over outputs, no guarantee of non-empty output.
- Eq. (31) is meaningful only over the finite generated set `C(P)`. It is **selection**, not optimization over program space. The paper concedes that a language model does not optimize Eq. (32) by gradient descent, which is correct; the notation should say `argmin` over candidates, not over all programs.
- Eq. (32) is under-specified: none of the four losses is defined. Without definitions, `J_repair` is not computable and the weights are not interpretable.
- Eq. (33) uses `⊨` for a test suite and a security constraint set. Tests are not formal specifications; `P' ⊨ Q_func` should be read as "P' passes Q_func", which is an operational predicate, not semantic entailment.

### 11.5 Operational form (audit addition)

```
C(P) = { P'_1, ..., P'_m }                       # generated candidates
L_security(P,P')   = residual_targeted_findings(P') / max(1, targeted_findings(P))
L_function(P,P')   = 1 − Pass_func(P', T)
L_regression(P,P') = regressed_tests(P,P') / max(1, |T|)
L_diff(P,P')       = changed_lines(P,P') / max(1, lines(P))

J_repair = λ_s L_security + λ_f L_function + λ_r L_regression + λ_d L_diff
P* = argmin_{P' ∈ C(P)} J_repair(P,P')
subject to  Pass_func(P',T) = 1  and  SecurityOK(P')
```

This makes Eq. (32) computable and keeps Eq. (33) as a hard constraint. If a candidate violates a constraint, it is infeasible and excluded before ranking (or heavily penalized, but the choice must be stated).

### 11.6 Implementability

Partial at E1: `repair/engine.py` generates proposals; `repair/ranking.py` applies hard constraints and a weighted score with eight terms (security improvement 4, functional tests 3, regression tests 3, syntax 2, CWE remediation 3, repository consistency 2, patch complexity 1, unnecessary changes 2). It does **not** implement Eq. (32) or an iterative repair loop.

### 11.7 Evaluation

PGR, CSR, TPR, PSR, SRR, SFR, ART, ANC; ablations of each loss term; weight sensitivity; candidate-count vs success; human review of accepted patches.

---

## 12. Patch correctness and security preservation — Eq. (34)–(39)

### 12.1 Paper form

```
Pass_func(P', T) = (Σ_{t∈T} I[P'(t) = o_t]) / |T|                       (34)
V_func(P')       = I[ Pass_func(P', T) = 1 ]                            (35)
{P} P' {Q}                                                              (36)
V_target(P') ∩ V_target(P) = ∅                                          (37)
V(P') \ V(P) = ∅                                                        (38)
Accept(P') = V_syntax(P') ∧ V_func(P') ∧ V_reg(P') ∧ V_security(P')     (39)
```

### 12.2 Variables

| Symbol | Meaning |
|---|---|
| `T` | Test set |
| `o_t` | Expected output for test `t` |
| `P` | Precondition (Hoare) / original program |
| `Q` | Postcondition (Hoare) |
| `V_target(P)` | Targeted vulnerability instances in `P` |
| `V(P)` | All validated vulnerabilities in `P` |
| `V_syntax` | Syntactic validity predicate |
| `V_func` | Functional correctness predicate |
| `V_reg` | Regression predicate |
| `V_security` | Security predicate |

### 12.3 Assumptions

- **A12.1** Tests are representative, deterministic, and isolated.
- **A12.2** Output comparison is well-defined (exact, tolerance, or harness).
- **A12.3** Vulnerability identity/correspondence is defined across versions.
- **A12.4** The security tools have acceptable sensitivity.
- **A12.5** `V_reg` and `V_security` are decidable with the available tools.

### 12.4 Correctness

- Eq. (34) is too strict: exact output equality fails on floating-point, timing, environment, and formatting. The operational definition should be the test harness's pass/fail (exit code and assertions), or a tolerance-based comparison.
- Eq. (35) is correct given Eq. (34), but inherits the test suite's coverage limits.
- Eq. (36) is a Hoare triple. Correct as a proof obligation, but **not computable** by Alg. 9; no specifications, invariants, or verifier are provided. The paper says "where a formal specification is available", which is the right caveat; the algorithm should say so too.
- Eq. (37) is set intersection. Correct, but the correspondence between findings across versions must be defined (category, location, data-flow evidence). Without correspondence, the equation is not evaluable.
- Eq. (38) is the ideal "no new vulnerabilities" condition. It is **detector-relative**: if the detector misses a new vulnerability, the set difference is empty and the condition is vacuously satisfied. The paper acknowledges this; the notation should not suggest a guarantee.
- Eq. (39) is a correct conjunction. But `V_reg` and `V_security` are not defined in the paper. Define them explicitly.

### 12.5 Operational form (audit addition)

Use three-valued predicates:

```
V_x(P') ∈ {pass, fail, inconclusive}
Accept(P') = 1  iff  V_syntax = V_func = V_reg = V_security = pass
```

Do not treat `inconclusive` as `pass`. Report the inconclusive rate. Define:

```
V_syntax   = parser/compiler accepts P'
V_func     = test harness passes all required tests (not exact-output equality)
V_reg      = no regression relative to the baseline test results
V_security = targeted finding removed AND no new finding under the same
             independently configured analysis; unknown → inconclusive
```

### 12.6 Implementability

Partial at E2: `verification/engine.py` performs before/after static scans, taint comparison, CWE checks, syntax checks, and regression checks; `verification/functional.py` runs test frameworks in a sandbox when available. It classifies outcomes with pass/fail/inconclusive. It does **not** implement Hoare logic (36); Docker execution is unavailable in this environment.

### 12.7 Evaluation

TPR, PSR, SRR, SFR; false-acceptance rate on adversarial patches; inconclusive rate; agreement between independent tools; regression rate; test coverage.

---

## 13. Unified model — Eq. (40)–(49)

### 13.1 Paper form (with the notation repairs from §0.1)

```
x        = Φ(c)                                                         (40)
z        = SAE(h_m(c))                                                  (41)
e        = Ψ(x, z, G_AST, G_CFG, G_DFG, h_dyn)                           (42)
h_u      = F_φ(e, m)                                                    (43)
p̂        = σ(f_fuse(h_u))                                               (44)
A        = Attribution(p̂, x, z)                                         (45)
R_index  = R_fn(p̂, S, E, I)                                              (46)
c_secure = G_prevent(m, p, Q_security)                                  (47)
P'       = G_repair(P, A, Q_security)                                   (48)
P*       = P' if Accept(P') = 1 else P                                  (49)
```

### 13.2 Correctness

This is a **pipeline schematic**, not an independent mathematical model. It adds no theorem, no identification result, and no error-propagation analysis. Specific defects:

- Eq. (41) conflates the SAE with its encoder; write `z = Encode_SAE(h_m(c))`.
- Eq. (42) omits `e_interaction` (present in Eq. 24) and `e_SAE` is implicit in `z`.
- Eq. (44) reuses `f_θ` from Eq. (2) for a different function; use `f_fuse`.
- Eq. (46) omits the weights `α,β,γ,δ` from Eq. (28).
- Eq. (47) omits `V_known`, `S_req`, `C_sec`, `B`, and `τ_sec` from Algorithm 7.
- Eq. (48) omits `L` and `π_r` from Eq. (30).
- Eq. (49) is correct as a fallback rule, but `Accept` is detector-relative (see §12).

### 13.3 Recommended presentation

Present Eq. (40)–(49) as a **data-flow diagram with typed stages**, not as a model with mathematical content. If a single model is desired, define it as a composition of functions with explicit domains/codomains and state the availability/missing-modality behavior at each stage.

### 13.4 Evaluation

End-to-end pipeline test on a fixed sample; stage-wise availability/coverage; ablation of each stage; latency and failure-mode analysis; no end-to-end metric until the detector and SAE artifacts exist.

### 13.5 Unified-engine realization of the schematic (audit addition)

`bugdhor.risk` and `bugdhor.decision` are programmatic realizations of parts of
this schematic. They do not add a theorem and do not change Eq. (40)–(49):

| Schematic stage | Realization | Boundary |
|---|---|---|
| (42) evidence `e` | `risk.normalization` + declared dependency groups | Correlated sources are collapsed before aggregation; missing evidence is excluded, not imputed. |
| (43)–(44) fused support `p̂` | reliability-weighted group means + noisy-OR + signed interaction adjustments | `p_hat` stays a heuristic unless a validated calibration artifact is supplied. |
| (45) attribution `A` | `RiskResult.contributions`, `explanation`, `excluded_evidence` | Component contributions are additive; no feature attribution or causal claim is made. |
| (46) `R_index` | Eq. (28)–(29) as specified in §10 and §10.8 | Never a probability. |
| (47)–(49) prevention, repair, acceptance | Separate repair/recommendation/verification workflow and human approval | Outside these packages; no automatic patch application. |

The advisory decision package consumes `RiskResult` via `context_from_risk` and
selects developer-facing actions under transparent rules or a deterministic
declared-preference utility ranking. It is not another equation in Eq.
(40)–(49), makes no optimal-decision claim, and is not reinforcement learning.
See [`docs/adaptive-decision-policy.md`](../docs/adaptive-decision-policy.md).

---

## 14. Explainable localization — unnumbered formula in §5.8 and Algorithm 5

### 14.1 Paper form

```
L(r_i) = α a_i + β s_i + γ t_i + δ n_i
```

with `a_i` model attribution, `s_i` static-analysis evidence, `t_i` taint/data-flow evidence, `n_i` neural-feature evidence, and non-negative `α,β,γ,δ`.

Algorithm 5 gives a more general normalized form in prose:

```
L(u,v) = (Σ_r m_r α_r e_r(u,v)) / (Σ_r m_r α_r)
```

with a zero-denominator "insufficient evidence" status.

### 14.2 Variables

| Symbol | Meaning |
|---|---|
| `r_i` / `u` | Source-code region or unit |
| `a_i` | Attribution score |
| `s_i` | Static-analysis evidence |
| `t_i` | Taint/data-flow evidence |
| `n_i` | Neural-feature evidence |
| `α,β,γ,δ` | Non-negative weights |
| `m_r` | Availability mask for evidence source `r` |
| `e_r` | Normalized evidence score `∈ [0,1]` |
| `τ_l` | Localization threshold |

### 14.3 Assumptions

- **A14.1** Each `e_r` is normalized to `[0,1]`.
- **A14.2** Weights are calibrated on validation data.
- **A14.3** Missing evidence is excluded, not set to zero.
- **A14.4** The score is a ranking criterion, not a probability.
- **A14.5** Regions have a consistent granularity (line/statement/function).

### 14.4 Correctness

- The §5.8 formula is a valid **linear ranking score** but lacks the mask that the prose requires and that Algorithm 5 supplies. This is an internal inconsistency.
- No `τ_l` appears in the formula, although Algorithm 5 uses one.
- `a_i`, `s_i`, `t_i`, `n_i` are not defined operationally; their scales differ.
- The score can exceed 1 unless the weights/inputs are normalized; that does not affect ranking but does affect threshold interpretation.

### 14.5 Operational form (audit addition)

```
e_r(u,v) ∈ [0,1],  m_r ∈ {0,1},  α_r ≥ 0
L(u,v) = (Σ_r m_r α_r e_r(u,v)) / (Σ_r m_r α_r)     if Σ_r m_r α_r > 0
L(u,v) = insufficient_evidence                      otherwise
L = { (u, L(u,v)) : L(u,v) ≥ τ_l }, sorted descending
```

Use Algorithm 5's normalized form, not the unnormalized §5.8 form.

### 14.6 Implementability

**Not implemented.** `explain/engine.py` assembles evidence-grounded explanations; it does not compute `L`, rank regions, or compute attribution. `evaluation/metrics.py` computes line precision, recall, and exact-set accuracy only.

### 14.7 Evaluation

Line/statement/function precision, recall, F1, IoU, Hit@k, MRR; comprehensiveness/sufficiency of the selected regions; stability under paraphrases; ablations of each evidence source; expert rating; insufficient-evidence rate.

---

## 15. Evaluation metrics — §7.2–7.6

These are standard metrics; the audit verifies the formulas and flags notation collisions and implementation gaps. All symbols are counts from the test set.

### 15.1 Detection (§7.2)

```
TP, TN, FP, FN
Accuracy  = (TP + TN) / (TP + TN + FP + FN)
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 · Precision · Recall / (Precision + Recall)
MCC       = (TP·TN − FP·FN) /
            sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
```

- **ROC-AUC:** `P(score(x⁺) > score(x⁻)) + 0.5·P(tie)`, estimated by the Mann–Whitney statistic.
- **PR-AUC / Average Precision:** `AP = Σ_n (R_n − R_{n−1}) P_n` over thresholded operating points. A trapezoidal PR-AUC is a different estimator; state which one is used. The code's `_pr_auc` is a custom trapezoid seeded with `prev_precision=1.0`; it must be documented and validated against a reference.
- **Brier:** `(1/N) Σ_i (p_i − y_i)²`.
- **ECE:** `Σ_b (n_b/N) |acc(b) − conf(b)|` with fixed bins.
- **Multi-class/CWE:** macro and micro precision/recall/F1; per-CWE support and undefined-metric handling.

**Undefined cases:** if `TP+FP=0`, precision is undefined (report `None`, not 0); if `TP+FN=0`, recall is undefined; if the denominator of MCC is 0, MCC is undefined. The paper mentions undefined metrics in §7.8.3; the code returns `None` for some but not all cases.

### 15.2 Explainability (§7.3)

```
Comp_k(x) = f(x) − f(x \ A_k)                  # larger is better
Suff_k(x) = f(x) − f(x_{A_k})                  # smaller is better
AF = SpearmanCorr({|a_i|}, {|Δ_i|})            # attribution faithfulness
AS_rank = SpearmanCorr(a(x), a(x̃))             # rank stability
AS_top-k = |A_k(x) ∩ A_k(x̃)| / |A_k(x) ∪ A_k(x̃)|   # Jaccard
Sim(i,j) = d_i^T d_j / (‖d_i‖₂ ‖d_j‖₂)         # decoder-direction similarity
```

- **Caveat:** `Comp`/`Suff` are model-relative and depend on the ablation/masking operator. A large `Comp` can reflect out-of-distribution inputs, not feature importance.
- **Caveat:** a high `AF` is correlation, not causality; correlated features can substitute.
- **Caveat:** `AS_rank` is undefined when attributions are constant; `AS_top-k` ignores magnitude and depends on `k`.

### 15.3 Localization (§7.4)

```
Precision_L = TP_L / (TP_L + FP_L)
Recall_L    = TP_L / (TP_L + FN_L)
F1_L        = 2 · Precision_L · Recall_L / (Precision_L + Recall_L)
Acc_line    = (TP_L + TN_L) / (TP_L + TN_L + FP_L + FN_L)
IoU         = |L_Pred ∩ L_GT| / |L_Pred ∪ L_GT|
Hit@k       = (1/N) Σ_i I[gold region of i ∈ top-k predicted]
MRR         = (1/N) Σ_i 1/rank_i                (0 if not found)
```

- The paper calls `Acc_line` "localization accuracy"; the code's `localization_accuracy` is **exact-set match**, not line accuracy. This is a naming collision that must be resolved.
- Report the granularity (line/statement/function) and the annotation source.

### 15.4 Repair (§7.5)

```
PGR = N_G / N_V                                  # ≥1 candidate generated
CSR = N_C / N_P                                  # compiled
TPR_patch = N_T / N_P                            # all tests pass
TPR_compiled = N_T / N_C                         # conditional on compiling
FC  = (1/N_P) Σ_j FC_j                           # functional correctness
PSR = (1/N_V) Σ_i Success_i                      # ≥1 accepted patch
SRR = N_R / N_E                                  # new security regressions
SFR = N_F / N_V                                  # targeted vulnerabilities fixed
ART = (1/N_V) Σ_i t_i                            # average repair time
ANC = (1/N_V) Σ_i r_i                            # average candidates
```

- The paper explicitly says not to mix units (per candidate vs per vulnerability). Keep `N_P`, `N_V`, `N_E` distinct and report them.
- `FC` and `TPR_patch` are not independent if they use the same tests; the paper says so. Report one as primary and the other as diagnostic.

### 15.5 Prevention (§7.6)

```
VR   = (V/N) × 100
VRR  = ((VR_B − VR_S) / VR_B) × 100             # undefined if VR_B = 0
ΔVR  = VR_B − VR_S
FPass = (F/N) × 100
FPR_preserve = ((F_S/N_S) / (F_B/N_B)) × 100    # undefined if F_B = 0
SCR  = (N_compliant / N) × 100
```

- **Notation collision:** the paper calls functional pass rate `FPR`, which is conventionally false positive rate. Use `FPass` (or `FuPR`) and reserve `FPR` for false positives.
- **Undefined cases:** `VRR` is undefined when `VR_B=0`; `FPR_preserve` is undefined when `F_B=0`. Report the absolute difference alongside the relative measure.
- **Design:** baseline and security-aware conditions must use the same model, tasks, language, and evaluation; otherwise `VRR` is confounded.

### 15.6 Statistical inference

The paper describes repeated trials and significance tests but does not pin the estimators. Defensible defaults:

```
Paired design:      paired t-test if normality holds; otherwise Wilcoxon signed-rank
Independent groups: Welch t-test; otherwise Mann–Whitney U
Effect size:        Cohen's d (paired) or Cliff's delta (non-parametric)
CI:                 bootstrap percentile CI (≥ 1,000 resamples)
Multiplicity:       Holm–Bonferroni (FWER) or Benjamini–Hochberg (FDR)
```

These are implemented in `evaluation/statistics.py` (bootstrap, paired permutation, Wilcoxon, Mann–Whitney, paired t-test, Cohen's d, Cliff's delta, Holm, BH), but the module has **no automated tests** and no executed experiment.

---

## 16. Equations and claims that should not be used as written

| Item | Problem | Use instead |
|---|---|---|
| Eq. (1) as a literal concatenation | Heterogeneous, undefined dimensions | Define per-view encoders + fixed-size pooling, or masked fusion |
| Eq. (2) as a result | No trained model | Report as a design equation; implement before claiming results |
| Eq. (7) as a sparsity guarantee | L1 does not guarantee low L0 | Report measured L0/dead features |
| Eq. (10) without `s_{j,pool}` | Undefined denominator | Define pooled SD; use Hedges' g + CI |
| Eq. (11) as "interaction" | Correlation ≠ interaction | Use as a screening statistic only |
| Eq. (12)–(13) as causal effects | Intervention not specified | Define the operator, scale, and controls |
| Eq. (16) as `∂f/∂z` | Missing decoder chain rule | Use `∂f/∂h · W_d[:,j]` |
| Eq. (20) without `A_uv`, `h^(0)`, readout | Incomplete GNN | State the full message-passing and pooling |
| Eq. (22) as exploitability | May-reachability only | Report as potential flow; add dynamic validation |
| Eq. (23) with binary `q(p)` | Wrong sanitizers treated as safe | Three-valued path status |
| Eq. (25)–(27) as the implemented fusion | Code uses noisy-OR | Label the code's score as a separate heuristic |
| Eq. (28) as a probability | It is a linear index | Call it a prioritization index; calibrate separately |
| Eq. (31) as program-space optimization | It selects over generated candidates | Say "selection over `C(P)`" |
| Eq. (32) without definitions | Not computable | Define each loss operationally |
| Eq. (34) with exact output equality | Too strict | Use the test harness pass/fail or tolerance |
| Eq. (36) as implemented | No Hoare verifier | Say "where a specification and verifier exist" |
| Eq. (38) as a guarantee | Detector-relative | Report as "no new finding under the configured tools" |
| §5.8 `L(r_i)` without a mask | Inconsistent with the prose | Use the masked, normalized form from Alg. 5 |
| `FPR` for functional pass rate | Collides with false positive rate | Use `FPass` |
| `Accuracy_L` in code as exact match | Name collision | Report as `EM` (exact match) |

---

## 17. What would make each formulation falsifiable

A formulation is experimentally testable when it specifies (a) the estimand, (b) the estimator, (c) the data, (d) the uncertainty, and (e) the decision rule. The table states what is missing for each.

| Formulation | Missing for falsifiability |
|---|---|
| Eq. (1) | `Φ`, view dimensions, normalization, leakage check |
| Eq. (2)–(4) | Trained model, `η` rule, calibration, split protocol |
| Eq. (5)–(7) | `h` extraction/normalization, `λ` selection, reconstruction/sparsity metrics |
| Eq. (8)–(10) | Pooled SD, effect-size estimator, CI, multiplicity correction |
| Eq. (11)–(13) | Intervention operator, outcome scale, controls, null model |
| Eq. (14)–(16) | Differentiable model, baseline, attribution operator, faithfulness metric |
| Eq. (17)–(20) | Full GNN specification, readout, training objective |
| Eq. (21)–(23) | Sanitizer adequacy rules, interprocedural model, unknown handling |
| Eq. (24)–(27) | Mask equation, `F_φ` architecture, training loss, calibration |
| Eq. (28)–(29) | Normalization, weight calibration, probability vs index decision |
| Eq. (30)–(33) | Loss definitions, candidate-set protocol, weight selection |
| Eq. (34)–(39) | Test harness semantics, correspondence rule, three-valued acceptance |
| Eq. (40)–(49) | Typed stage composition, notation table, end-to-end test |
| §5.8 localization | Masked normalized score, `e_r` definitions, threshold, ranking |
| §7 metrics | Complete implementations, undefined-case policy, statistical tests |

Until these are specified, the correct description of the project is: **a framework proposal with partial executable components and no empirical results**, which is exactly what `Research.txt` and `final-audit.md` say.
