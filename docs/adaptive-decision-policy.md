# Adaptive security decision policy

**Status:** implemented as a programmatic backend library (`bugdhor.decision`).
It is advisory by default, is **not** exposed as an HTTP endpoint, is **not**
wired into the orchestrator, and never applies a patch or changes a workspace.
It selects *what to tell the developer or request next*; it does not decide
whether code may be written to disk.

This is distinct from [`docs/steering.md`](steering.md): that document describes
an **adaptive activation-steering policy** for scheduling decoder-direction
interventions. The policy here is an **adaptive decision policy** over
developer-facing actions.

## Contract

`DecisionEngine(config).decide(context)` returns a `PolicyDecision` with:

- `actions` — ordered, de-duplicated advisory actions;
- `primary_action` — the first selected action, or `None`;
- `rationale` — the rationale of every matched rule;
- `baseline_actions` — the rule-selected actions that also passed the gates;
- `trace` — a `DecisionTrace` containing the rule evaluations with their
  observed conditions, utility scores, blocked actions with reasons, the
  objective string, the resolved context, config hash, and context hash.

If `PolicyContext.preferences` is `None`, `DecisionEngine.decide` falls back to
`PolicyConfig.preferences`. Direct callers of `evaluate_rules`, `action_gate`,
or `adaptive_rank` must resolve preferences themselves:

```python
from dataclasses import replace
resolved = replace(context, preferences=context.preferences or config.preferences)
```

## Actions

| `PolicyAction` | Meaning |
|---|---|
| `inform_developer` | Report the finding. |
| `display_vulnerability_warning` | Show a risk warning. |
| `recommend_secure_coding_practices` | Recommend CWE-relevant secure practices. |
| `request_additional_analysis` | Ask for more evidence when uncertain. |
| `perform_counterfactual_analysis` | Propose a model-internal counterfactual study. |
| `apply_activation_steering` | Use a validated local steering pipeline. |
| `generate_secure_code_alternatives` | Offer proposal-only alternatives. |
| `request_independent_verification` | Require verification by a separate engine. |
| `reject_unsafe_repair_candidate` | Reject a candidate that failed or lacks grounds. |

Every action is gated. Blocked actions are recorded in the trace for **all**
`PolicyAction` values, including actions that no rule matched, so a missing
capability or withheld consent is visible rather than silently omitted.

## Transparent baseline (default)

The default `mode` is `rule_baseline`. Nine documented rules R01–R09 produce
the candidate set; each records exact observed conditions:

| Rule | Matches when |
|---|---|
| R01_INFORM_DEVELOPER | Notifications are enabled. |
| R02_DISPLAY_VULNERABILITY_WARNING | Risk index, band, or validated probability crosses the warning threshold and warnings are allowed. |
| R03_RECOMMEND_PRACTICES | Risk or evidence strength is material and practice recommendations are allowed. |
| R04_REQUEST_ADDITIONAL_ANALYSIS | Uncertainty is high, or evidence strength/risk is missing, and analysis is allowed. |
| R05_COUNTERFACTUAL_ANALYSIS | Model evidence exists, uncertainty is material, capability and consent are present. |
| R06_ACTIVATION_STEERING | Model evidence and high risk exist, the steering pipeline is validated, and consent is present. |
| R07_GENERATE_SECURE_ALTERNATIVES | A candidate exists, generation is supported and consented. |
| R08_REQUEST_INDEPENDENT_VERIFICATION | A candidate exists and verification is absent/inconclusive/failed while required or available. |
| R09_REJECT_UNSAFE_CANDIDATE | Explicit rejection reasons, failed verification, or blocking enforcement without a passing verification. |

The baseline does not learn, rank by utility, or claim optimality. Its
objective string is `transparent_rule_baseline: ordered documented rules, no
learned weights, no utility maximization, and no optimality claim`.

## Capability and consent gates

`ModelCapabilities` are declared, never inferred from a provider name:

- `supports_counterfactual`
- `supports_activation_steering` plus `activation_steering_pipeline`
  (`none` or `validated`)
- `supports_secure_code_generation`
- `verification_available`

`DeveloperPreferences` are configurable and versioned in
`research/configs/risk/policy.json`: notification level (`off`/`summary`/
`detailed`), warnings, practice recommendations, additional analysis,
counterfactual analysis, activation steering, secure code generation,
independent verification requirement, and enforcement (`advisory`/`blocking`).
Each preference set carries a `basis`.

Important consequences:

- Hosted assistants declare `activation_steering_pipeline = "none"`, so the
  steering action can never be selected for them even if a model exposes
  related features.
- `perform_counterfactual_analysis` requires both declared capability and
  explicit consent; SAE/interaction evidence alone is never sufficient.
- A candidate is only recommended after independent verification when that is
  required. The generator cannot verify its own proposal.

## Adaptive mode

Setting `mode = "adaptive"` ranks the same gated candidate set by a deterministic
multi-attribute utility. For each action:

```text
urgency          = max(risk_index or 0, calibrated_probability or 0)
efficacy_factor  = 0.5·urgency + 0.5·(evidence_strength or 0)
harm_factor      = 0.5 + (uncertainty or 1)
score            = efficacy_factor·efficacy_weight
                 - cost_weight
                 - harm_factor·harm_weight
```

Only permitted actions with a positive score are returned. Efficacy, cost, and
harm weights are **declared developer preferences** with a recorded basis in
`PolicyConfig.utility`, not measured intervention effects. The trace records
every score and its gate reason.

The objective string is explicit:

```text
preference_weighted_utility_ranking: ... deterministic, not learned, and not
claimed to be optimal
```

This is **not** reinforcement learning. There is no reward, no policy update,
no learned parameters, and no optimal-decision claim. "Adaptive" means only
that the fixed preference utility is modulated by the current risk, evidence
strength, and uncertainty of this finding.

## Projection from the risk engine

`context_from_risk(result, ...)` projects a `RiskResult` into a `PolicyContext`,
preserving index, band, calibrated-probability status, evidence strength,
uncertainty, `score_kind`, and `calibration_status`. SAE activations and
counterfactual interactions are forwarded as **descriptive** evidence only.
Their hypothesis/low-strength status is preserved by the risk engine, and the
gates above decide whether any action may use them.

## Reproducibility and traceability

- `research/configs/risk/policy.json` — shipped baseline configuration; its
  hash (`538038f65c16…`) is embedded in every decision trace.
- `context_hash` and `decision_id` are deterministic SHA-256 canonical hashes,
  so an identical configuration and context yield an identical decision.
- Changing mode, thresholds, utility weights, or preferences changes the
  config hash and decision id.
- `PolicyDecision.to_dict()` and `DecisionTrace.to_dict()` emit camelCase
  payloads suitable for logging or a future contract, without source text or
  secrets.

## What this policy does not claim

- No optimal decision, no learned policy, no reinforcement learning.
- No workspace mutation, patch application, or override of human approval.
- No capability inference; missing capability is recorded as blocked.
- No security guarantee from a heuristic index or an unvalidated probability.
- No HTTP endpoint; this is currently a backend library only.

Tests: `security-engine/tests/unit/test_adaptive_decision_policy.py` and the
independent arithmetic checks in
`mathematical-regression-tests/test_unified_risk_reference.py`.
