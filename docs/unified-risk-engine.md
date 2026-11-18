# Unified security risk engine

**Status:** implemented as a programmatic backend library (`bugdhor.risk`). It is
**not** exposed as an HTTP endpoint, is **not** wired into the orchestrator, and
ships **no** labelled dataset or calibration artifact. It produces auditable
prioritization values; it does not claim to measure or guarantee security.

## Purpose and boundary

The engine combines the kinds of evidence the project can actually obtain —
static findings, program analysis, taint evidence, SAE activations,
counterfactual interactions, CWE metadata, model predictions, repository
context, exploitability signals, verification outcomes — into one explainable
result per finding. It is deliberately separate from:

- `bugdhor.detection`: the wired detection/evidence-fusion path and its
  `HeuristicRisk` priority score.
- `security-engine/mathematics/cwe_risk.py`: the dependency-light Eq. (28)
  reference implementation.
- `bugdhor.steering.risk_controller`: the CWE-specific *steering priority*
  controller. These similarly named objects are not interchangeable.

Eq. (28) and Eq. (29) remain the authoritative definitions in
[`research/mathematical-formulations.md`](../research/mathematical-formulations.md).
Eq. (40)–(49) is a pipeline schematic, not a new theorem; this engine is one
operational realization of that schematic.

## Three deliberately separate numbers

| Field | Meaning | Probability? |
|---|---|---|
| `p_hat` | Reliability-weighted, correlation-controlled likelihood support that a reported finding is real. | No, unless a validated calibration artifact is supplied. |
| `index` | Eq. (28) prioritization index `α·p_hat + β·S + γ·E + δ·I`. | **Never.** |
| `probability` | Calibrated probability for a finding. | Yes, but only with a validated artifact fitted and evaluated on disjoint groups. |

`RiskResult.score_kind` is always `heuristic_index`. `probability_kind` is
`calibrated_probability` only when `probability` is non-`None`. A heuristic
index is never relabelled as a probability, and a probability is never
presented as a security guarantee.

## Evidence contract

Each `EvidenceObservation` records:

- `source` — one of `static_analysis`, `ast`, `cfg`, `dfg`, `taint`,
  `sae_activation`, `counterfactual_interaction`, `cwe_metadata`,
  `model_prediction`, `repository_context`, `exploitability`, `verification`.
- `claim_kind` — `observation`, `inference`, or `hypothesis`. This matches the
  shared schema vocabulary; see the claim-taxonomy note in
  [`research-alignment.md`](research-alignment.md#2-claim-taxonomy).
- `polarity` — `supports`, `refutes`, or `neutral`.
- `value` in `[0, 1]`, with an explicit normalization description.
- `ReliabilityEvidence` — validation precision/specificity, or reported
  confidence and coverage, or an explicit failed/unavailable run status.
- `source_id`, `rationale`, and optional limitations.

Reliability precedence:

1. Validation precision for supporting evidence and validation specificity for
   refuting evidence.
2. `reported_confidence × coverage` when no validation metrics exist.
3. Zero, with a reason, when the run failed, was unavailable, was partial
   without coverage, or is an unvalidated hypothesis.

Zero-reliability observations are excluded from the denominator and listed in
`excluded_evidence` with the reason. No value is imputed, and no unlabeled
number is silently assigned a scale.

## Correlation control

Declared dependency groups prevent correlated views from being counted as
independent votes:

| Sources | Dependency group |
|---|---|
| `ast`, `cfg`, `dfg`, `taint` | `program_analysis` |
| `model_prediction`, `sae_activation`, `counterfactual_interaction` | `model_internal` |
| `static_analysis` | `static_tool` |
| `cwe_metadata` | `cwe_metadata` |
| `repository_context` | `repository_context` |
| `exploitability` | `exploitability` |
| `verification` | `verification` |

- Within a group, observations are averaged with reliability weights.
- Group reliability is the **maximum** source reliability in that group, not a
  sum or an inflated independent count.
- Across groups, support is combined with noisy-OR; refutation is applied as a
  separate multiplicative penalty.
- Counterfactual interactions are **signed adjustments inside** `model_internal`.
  They are never an independent group and never convert a model-internal
  observation into real-world causal evidence.

The grouping is configuration, listed in
`research/configs/risk/unified_risk.json`, and is included in the config hash.

## Index, missing values, and bands

The engine computes the four Eq. (28) components from grouped evidence or from
an explicitly based CWE profile. No CWE has an implicit severity: an empty
`cweProfiles` map is the default, and a profile must carry a declared `basis`.

- `missing_policy = "renormalize"` (default): unavailable components are
  excluded and the remaining declared weights are renormalized. Missing values
  are reported in `components.available` and in the explanation.
- `missing_policy = "unavailable"`: the engine refuses to score, returning
  `index = None` and `band = "unknown"`.

`contributions` reports each component's weighted contribution; the present
contributions sum to the index. Bands are lowercase `low`, `medium`, `high`,
`critical` at the configured `0.25 / 0.50 / 0.75` boundaries. `unknown` is used
when no index exists. These are prioritization bands, not severity verdicts.

`Uncertainty` is a documented heuristic function of coverage, mean reliability,
and support/refutation conflict. It is **not** a confidence interval around a
calibrated probability. Interval fields are populated only by a validated
calibration evaluation.

## Calibration

`bugdhor.risk.calibration` implements Platt scaling with:

- disjoint `fitGroups` and `validationGroups` (overlap is rejected at config
  load time),
- validation-only Brier score, log loss, equal-width ECE, and Mann–Whitney
  AUROC,
- seeded bootstrap intervals at the configured confidence level,
- explicit acceptance thresholds for every reported metric plus convergence.

A fitted artifact is `validated` only if **all** gates pass. A rejected artifact
is retained with its failures for audit, but
`CalibrationArtifact.probability()` returns `None`; the engine then emits only
the heuristic index. The shipped `research/configs/risk/calibration.json`
contains `REPLACE_WITH_*` placeholders. There is no real dataset and no
calibrated probability shipped with the project.

Dataset and invocation rules are in
[`research/datasets/risk/README.md`](../research/datasets/risk/README.md).

## Reproducible configuration

| File | Role |
|---|---|
| `research/configs/risk/unified_risk.json` | Weights, bands, dependency groups, missing policy. Equal weights encode a maximum-entropy neutral prior — not a validated preference. |
| `research/configs/risk/calibration.json` | Dataset/group identifiers, acceptance gates, fit settings. Placeholders until a registered dataset is supplied. |
| `research/configs/risk/policy.json` | Decision-policy configuration; see [`adaptive-decision-policy.md`](adaptive-decision-policy.md). |

The default config hash is `422b0ac3f07f…`; the shipped policy config hash is
`538038f65c16…`. Every `RiskResult` and batch `RiskAssessment` carries the
full hash, so a score cannot be separated from the configuration that produced
it. Ranking in `assess_batch` is deterministic: index descending, then the
configured tie-breaker (`finding_id`). Findings without an index receive no
rank and appear in batch warnings.

## Usage

```python
from bugdhor.risk import UnifiedRiskEngine, default_risk_config
from bugdhor.risk.engine import FindingRiskInput
from bugdhor.risk.models import EvidenceObservation, EvidenceSource, ReliabilityEvidence

finding = FindingRiskInput(
    finding_id="F-1",
    cwe="CWE-79",
    observations=(
        EvidenceObservation(
            source=EvidenceSource.STATIC_ANALYSIS,
            source_id="semgrep-1",
            value=0.8,
            reliability=ReliabilityEvidence(
                validation_precision=0.7,
                basis="tool_validation_run",
            ),
        ),
    ),
)
result = UnifiedRiskEngine(default_risk_config()).assess(finding)
print(result.index, result.band, result.score_kind, result.probability)
```

## What this engine does not claim

- No perfect security, no guarantee that a finding is true or false.
- No probability from an unvalidated heuristic index.
- No causal effect from SAE activations or counterfactual interactions.
- No validity for evidence from failed, unavailable, or unvalidated sources.
- No experimentally derived weights: the defaults are neutral and heuristic.
- No HTTP surface, no workspace mutation, and no automatic patch application.

Tests: `security-engine/tests/unit/test_unified_risk_engine.py` and the
independent arithmetic checks in
`mathematical-regression-tests/test_unified_risk_reference.py`.
