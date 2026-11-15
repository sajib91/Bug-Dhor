# SAE activation steering

`craftsec.steering.ActivationSteeringEngine` performs local, white-box
activation interventions for compatible Hugging Face Transformer models. It is
disabled by default: callers must set `SteeringSpec.enabled=True`.

## Intervention

The engine uses the selected SAE decoder columns as the steering directions.
For each configured feature, it adds:

```
strength(feature) * SAE.decoder.weight[:, feature]
```

to the selected Transformer block output. `target_positions` restricts the
intervention to token positions; when omitted, all positions in each forward
pass are eligible. `max_delta_norm` bounds the combined direction and rejects
non-finite directions or modified activations.

The engine currently supports architectures for which
`LayerDiscovery` can identify a block named like `transformer.h.N`,
`model.layers.N`, or another supported layer layout, and whose hook output is
`[batch, tokens, hidden]`. Unsupported layers and incompatible SAE dimensions
raise `ModelCompatibilityError`; no prompt text is rewritten.

## Validation and provenance

Each enabled run generates the original output and a steered output using the
same prompt and generation settings. It records model/tokenizer versions,
layer, SAE checkpoint, features, strengths, token positions, norm bound,
prompt hash, seed, and generation parameters. Validation checks finiteness,
shape compatibility, maximum applied delta norm, and hook cleanup.

Hooks modify a cloned activation tensor and are removed in a `finally` block,
so original model parameters and activations are not permanently changed.
Steering disables the KV cache for the steered generation so token positions
remain addressable across generation steps.

Steering changes model behavior under an intervention; it does not prove a
change in true vulnerability status, establish feature semantics, or provide
causal evidence. No model weights are downloaded automatically.

## Adaptive interaction-aware policy

`AdaptiveSteeringPolicy` integrates a measured `FeatureDictionary`, pairwise
interaction results, and higher-order factorial results. Feature selection is
ranked by a configured measured importance metric (selectivity by default),
with optional CWE filtering and minimum evidence thresholds. The resulting
decision exposes separate individual, pairwise, and higher-order contribution
records; no opaque feature weights are introduced.

Context can provide a CWE, token positions, and measured per-position SAE
activations. The policy schedules only configured positions and scales each
selected feature from its observed activation relative to an explicit
reference. Feature count, interaction order, schedule length, strength
limits, context multiplier, and direction mode are all serialized
configuration values. `association_reducing` is an association-derived
hypothesis, not a causal claim.

`AdaptiveSteeringEngine` stores each policy decision and steering result in an
intervention history and can save that history as JSON for reproducibility.

## CWE-specific adaptive risk control

`CweRiskController` combines evidence under an explicit `CweRiskPolicy` for
each vulnerability category. Policies define the weights, activation and
interaction thresholds, context multipliers, priority bands, steering
threshold, and maximum steering strength. The controller records separate
feature, interaction, static-analysis, and optional heuristic components so
researchers can audit how a decision was formed.

The resulting `heuristic_priority` is bounded policy evidence, not a calibrated
probability. A probability is exposed only when a model- and version-specific
`RiskCalibrator` returns a `CalibrationResult` containing the calibrator,
method, and dataset identifiers. Missing calibration, missing static evidence,
missing interactions, and thresholded-out feature evidence are recorded as
explicit fallback reasons.

Steering is disabled when no feature activation meets the CWE policy threshold,
or when priority is below the steering threshold. Source context such as
`internet_facing=true` can apply a configured multiplier, but no implicit
context weights are introduced. Decisions, calibration metadata, evidence
availability, and fallback reasons can be persisted with `save_history`; the
history is intended for reproducible research auditing rather than a claim of
causal vulnerability reduction.

## Functional-preservation constraints

`FunctionalConstraintEvaluator` gates a steered candidate with measured
evidence instead of treating syntactic validity as functional equivalence. It
can require syntax validity, compilation success, unit-test pass rate,
behavioral consistency, bounded functional regression, minimum security
improvement, and bounded generation overhead. Application-specific compilers,
test suites, behavior comparators, and security analyzers are supplied through
the `FunctionalEvidenceEvaluator` callback; no generated code is executed
implicitly by the steering engine.

`ActivationSteeringEngine.run` accepts this evaluator. A candidate that violates
the configured limits is retained as `rejected_candidate` for auditability but
is not exposed as the accepted steered output. The result records the
constraints and measured security/functionality trade-off in steering metadata.
Unavailable required evidence is rejected by default and can be made explicit
in the evaluation result.
