# Higher-order SAE feature interactions

For a feature subset `S` of order `k`, Bug Dhor uses the factorial contrast:

```text
sum(T subset S) (-1)^(k - |T|) Outcome(T)
```

All `2^k` intervention cells are required. The contrast is computed on the
declared outcome scale and depends on the intervention value, controls,
replicates, and experimental design. It is not invariant to nonlinear outcome
transformations. Therefore reports must name the outcome scale and should not
use unqualified terms such as “synergistic” or “antagonistic.”

The engine addresses combinatorial growth with feature preselection from
measured SAE selectivity, configurable minimum/maximum order, exhaustive or
seeded random subset sampling, and an evaluation budget. Identical
intervention cells are cached across subsets. Complexity reports include both
theoretical factorial cost and observed evaluations.

With repeated independent outcomes, the engine reports a descriptive
independent-cell sample-variance uncertainty interval. It does not produce
p-values or statistical significance claims.
