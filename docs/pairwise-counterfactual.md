# Pairwise SAE feature interactions

Pairwise analysis evaluates four intervention cells on an explicitly declared
outcome scale:

```text
Interaction(A, B) =
  Outcome(A,B) - Outcome(A,0) - Outcome(0,B) + Outcome(0,0)
```

In the API, `baseline`, `feature_a`, `feature_b`, and `joint` are the four
cells. The contrast is computed on the supplied scale, such as a risk score,
security metric, or logit. It is not invariant to nonlinear transformations of
that outcome and depends on the intervention design, target values, controls,
and replicate sampling.

With at least two independent replicates per cell, the engine reports a
descriptive standard error and 95% normal-approximation interval using the
independent-cell sample-variance delta method. With one replicate, uncertainty
is unavailable. Neither result is a statistical significance test; no
p-values or significance labels are produced.

Feature selection can use explicit indices or measured selectivity from an SAE
feature dictionary, including CWE-filtered selection. Pairwise output records
the experiment ID, seed, outcome scale, replicate count, and optional model,
layer, and SAE checkpoint provenance.
