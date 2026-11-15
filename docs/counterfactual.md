# SAE counterfactual analysis

`craftsec.counterfactual.CounterfactualEngine` runs reproducible single-feature
SAE interventions against a compatible local Transformers model. It measures
baseline layer activations, performs ablation or target-value modification,
generates baseline and intervened outputs with identical generation settings,
and records activation, output, and optional risk-score differences.

Each result preserves model/version, layer, SAE checkpoint, prompt hash,
generation parameters, seed, feature, intervention mode, and token positions.
Ground-truth vulnerability status is supplied independently and is never
recomputed from generated output. Model-output changes and true-status changes
are separate fields.

The engine records controlled output comparisons, not automatic causal claims.
Observational feature correlations do not establish causal effects; causal
interpretation requires a separately designed intervention study with controls
and independent security evaluation.
