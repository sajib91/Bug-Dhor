# Mathematical regression tests

This suite independently re-derives the numbers produced by the production
`bugdhor` package.  It is intentionally separate from
`security-engine/tests/` and from `security-engine/mathematics/`:

* `security-engine/tests/` exercises product behaviour and contracts.
* `security-engine/mathematics/` is a dependency-light reference package.
* **this directory** checks that the production implementation matches an
  independent calculation, including boundary and degenerate cases, and that
  saved experiment artifacts can be recomputed from their stored cells.

Every expected value is computed in `reference.py` (NumPy / closed-form maths)
rather than by calling the function under test.  Where an algorithm is defined
to use a specific random stream (percentile bootstrap), the reference re-runs
that stream independently so that reproducibility is checked exactly.

## Running

From the repository root:

```bash
.venv/bin/python -m pytest mathematical-regression-tests -q
```

The suite requires NumPy.  Artifact tests require
`research/experiments/counterfactual_validation/results/real_model_validation.json`.
All checkpoint references in that JSON are POSIX-style paths relative to
`research/experiments/counterfactual_validation/`; absolute developer paths are
no longer stored.  The cross-checkpoint cosine recomputation loads the
committed, SHA-256-verified decoder-column bundle under
`decoder_fixtures/v1/`, extracted from the original real SAE checkpoints.  The
full-checkpoint integration test is marked `real_model_integration` and is
deselected from default CI; enable it only after provisioning the full
checkpoints under the documented artifact root.

## Contents

| File | Scope |
| --- | --- |
| `test_sae_reference.py` | Encoder/decoder, loss, activation threshold, L0/dead-feature statistics |
| `test_counterfactual_reference.py` | Pairwise contrast, independent-cell SE, Möbius contrast, ranking |
| `test_validation_reference.py` | Per-unit factorial contrasts, scale transforms, bootstrap, stability |
| `test_statistics_reference.py` | Paired tests, effect size, Holm/BH, NaN/pairing/cluster semantics |
| `test_steering_reference.py` | Decoder-direction steering and norm clamping |
| `test_steering_policy_reference.py` | Adaptive importance/direction/allocation/schedule and risk priority/band/strength |
| `test_association_reference.py` | Association statistics, stability, cross-dataset transfer, CWE ranking |
| `test_artifact_recomputation.py` | Recompute the saved real-model contrasts and cross-checkpoint cosines |
| `test_config_reproducibility.py` | Configuration hashing and checkpoint round-trip |
| `test_boundary_degenerate.py` | Invalid, empty, constant, and single-observation cases |

## Scope note

The tests establish numerical and mathematical consistency.  They do not
establish that an SAE feature is a vulnerability concept, that a contrast is
causal, or that the synthetic validation corpus is vulnerability ground truth.
