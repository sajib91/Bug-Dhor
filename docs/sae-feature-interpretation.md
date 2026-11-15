# SAE feature interpretation

The interpretation engine turns feature-association evidence and
source-backed activating examples into research reports. Reports include model
and layer provenance, activation strength, representative positive and negative
examples, observed CWE associations, selectivity, evidence-coverage confidence,
limitations, and optional human annotations.

Automatic output is explicitly marked as an interpretation hypothesis. It is
not a proven semantic meaning, vulnerability detector, or causal explanation.
Researchers can maintain revisioned descriptions through
`FeatureAnnotationBook`. Controlled intervention observations are accepted only
as supplied evidence; the engine does not fabricate intervention results.

Reports can be exported as nested JSON or flattened CSV. Nested fields such as
examples, annotations, limitations, and intervention observations remain JSON
strings in CSV so the evidence is not silently discarded.
