# ADR-009: Unified risk score and decision semantics

**Status:** accepted
**Date:** 2026-11-18
**Scope:** `bugdhor.risk`, `bugdhor.decision`, `research/configs/risk/*`

## Context

The repository has several values called "risk" or "score": the wired detection
heuristic, the Eq. (28) reference module, the steering CWE priority controller,
post-patch regression risk, and now a unified risk engine. Conflating them would
make a heuristic index look like a probability or a steering priority look like
a vulnerability likelihood. The research-level claim taxonomy in
`docs/research-alignment.md` also lists five labels, while the shared schema and
production code use three, and band vocabularies differ across modules.

## Decision

1. `bugdhor.risk` keeps three separate numbers: `p_hat` (evidence support),
   `index` (Eq. (28) prioritization index, never a probability), and
   `probability` (only from a validated calibration artifact).
   `RiskResult.score_kind` is always `heuristic_index`; `probability_kind` is
   `calibrated_probability` only when a probability exists.
2. The canonical serializable `ClaimKind` vocabulary is the shared schema's
   three values: `observation | inference | hypothesis`. The five research
   labels are mapped to those values plus provenance or a verification verdict;
   see `docs/research-alignment.md#21-runtime-claim_kind-mapping`.
3. Unified-engine bands are lowercase `low | medium | high | critical` with
   `unknown` when no index exists. Other modules keep their own labels; no
   cross-module band equivalence is implied.
4. Correlated evidence is collapsed into declared dependency groups before
   aggregation. AST/CFG/DFG/taint form `program_analysis`; model prediction,
   SAE activations, and counterfactual interactions form `model_internal`, where
   interactions are signed within-group adjustments.
5. A calibrated probability requires a `validated` artifact fitted and
   evaluated on disjoint groups. A rejected artifact is retained for audit but
   cannot emit a probability. No labelled dataset or calibrated artifact ships.
6. Default weights are equal under a maximum-entropy neutral prior and are
   recorded in `config_hash`. They are heuristic, not experimental findings.
7. `bugdhor.decision` is advisory: it uses transparent rules or a deterministic
   declared-preference utility ranking, records a trace with blocked actions,
   and never mutates a workspace. It is not reinforcement learning and makes no
   optimal-decision claim.
8. Both packages are programmatic backend libraries. They are not exposed via
   HTTP in this change. If an endpoint is added later, it must not accept a
   client-supplied calibration artifact, and the shared contract and schema
   version must be updated deliberately.

## Alternatives considered

- Reuse the detection `HeuristicRisk` and its `RiskScore` contract. Rejected:
  it cannot express correlation groups, explicit excluded evidence, or a
  separate validated probability.
- Adopt the five-value research claim taxonomy in the schema. Rejected for now:
  it would require a schema version bump and fixture/test rewrites without
  changing any user-visible capability.
- Expose risk/decision through `/api/v1` immediately. Rejected: there is no
  validated calibration artifact or labelled dataset, and a client-supplied
  artifact would let unverified scores be presented as probabilities.
- Present the adaptive policy as reinforcement learning or optimal control.
  Rejected: there is no learned policy, reward, objective evaluation, or
  intervention study to support that claim.

## Consequences

- Positive: heuristic scores, steering priorities, and calibrated probabilities
  cannot be silently substituted for one another; correlation and missing-data
  behaviour are explicit and auditable; advisory actions preserve consent and
  capability boundaries.
- Negative: callers must project `RiskResult` into `PolicyContext` explicitly
  (`context_from_risk`) and resolve `PolicyContext.preferences` when calling
  `evaluate_rules`, `action_gate`, or `adaptive_rank` directly.
- Follow-up: a shared-contract/schema decision is required before any HTTP
  exposure, together with a real registered dataset and a passing calibration
  artifact. This ADR does not bump `shared/schemas/VERSION` because no schema
  or API payload changes here.
