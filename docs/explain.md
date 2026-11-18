# Explainable vulnerability analysis

`bugdhor.explain.ExplainableVulnerabilityEngine` builds structured and
human-readable reports from a fused `VulnerabilityFinding`.

The report preserves evidence boundaries:

- AST, CFG, DFG, taint, and static-tool records are retained as direct evidence
  or explicitly labelled inferences.
- Taint source-to-sink paths retain source, sink, intermediate steps, flow
  confidence, and analysis limitations.
- LLM evidence is emitted separately as an uncalibrated hypothesis.
- SAE features are association records only; the engine does not assign
  semantic labels or causal meanings.
- Feature interactions are included only when the caller marks the experiment
  as validated and supplies its outcome scale.
- Counterfactuals are controlled intervention comparisons, not proof that true
  vulnerability status changed.

`VulnerabilityExplanation.to_dict()` and `to_json()` provide structured output.
`to_human()` renders a concise report and explicitly calls out hypotheses,
unavailable impact evidence, and limitations. Security impact remains
`null`/unavailable unless supplied as evidence; category or severity alone is
not treated as proof of exploitability.

The engine does not execute generated code or run external analyzers
implicitly. Callers provide already-measured SAE, counterfactual, static, and
LLM records with their provenance.

## VS Code dashboard data flow

The extension dashboard starts with explicit unavailable/empty state. A
successful backend scan updates vulnerability findings and summary counts;
explanation, SAE feature extraction, and counterfactual commands update their
corresponding panels with the validated `response.result` payload. The
dashboard does not create findings, feature values, interaction effects, or
explanations locally. A backend response with `analysisAvailable: false`
remains unavailable rather than being rendered as a clean result.
