# SAE feature association analysis

The SAE analysis API consumes explicitly labeled secure/vulnerable samples and
actual SAE feature activations. It reports activation frequency, vulnerable and
secure means, mean differences, active-feature precision/recall, CWE-specific
statistics, selectivity, per-dataset direction stability, and cross-dataset
validation metrics.

Feature dictionaries retain model ID/version, Transformer layer, SAE checkpoint,
dataset IDs, experiment ID, and activation threshold. They intentionally record
`association_only; no causal or semantic claim`. A feature that activates more
often on vulnerable samples is not thereby a vulnerability detector, a named CWE
feature, or a causal mechanism. Causal influence requires a separate controlled
intervention experiment.

Use [`craftsec.sae.extract_feature_samples`](../security-engine/src/craftsec/sae/association.py)
to encode token-aligned model activations from an activation batch, then pass
the labeled samples to `analyze_features`.
