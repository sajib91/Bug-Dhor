# Model compatibility testing

Bug Dhor's compatibility framework records **declared** model/provider capabilities separately from **observed** probe
results. A registry entry, setting, or documentation string never grants a capability. A capability is reported as
`supported` only when a real probe against a local checkpoint or provider produced concrete evidence.

## Status

The committed report is at
[`research/experiments/model_compatibility/results/model_compatibility_report.md`](../research/experiments/model_compatibility/results/model_compatibility_report.md)
and its machine-readable evidence is in the sibling `model_compatibility_report.json`. It was generated from config hash
`10b8282eac8a9c104fd8bdfb0b936078f3f2021e0868fcdc92c31472e8d1d540`.

Observed outcomes in that report:

- Both locally cached research checkpoints — `Qwen/Qwen2.5-Coder-0.5B` and
  `Qwen/Qwen2.5-Coder-0.5B-Instruct` — support code generation, secure-code-generation prompting, activation extraction,
  SAE compatibility with the tested layer-4 artifacts, counterfactual intervention, token-level intervention, activation
  steering, seeded output reproducibility, and hardware measurement.
- `code_analysis` is **`partial`** for both checkpoints: they produced text, but not the requested valid JSON object.
- The three registered production checkpoints are all `unavailable` because none is present in the local Hugging Face
  cache. No capability is inferred for them.
- All five assistant integration targets are `unavailable` from this CLI runner: no VS Code host, endpoint, model path,
  or extension manifest was configured. Declared A-F capabilities are shown, but discovered capabilities are empty.
- The probes use programmatic libraries. The HTTP `/features/extract`, `/counterfactual/analyze`, and `/prevention/steer`
  routes remain honest stubs and are not treated as evidence.

## What is probed

Each local model target is probed independently for:

1. code generation;
2. code analysis;
3. secure-code-generation prompting;
4. model activation extraction;
5. SAE compatibility;
6. counterfactual intervention;
7. activation steering;
8. token-level intervention;
9. output reproducibility;
10. hardware and inference limits.

Code-generation probes record output hashes, token counts, previews, and elapsed time. They do **not** establish code
correctness or security. Code analysis requires a parseable JSON response for `supported`; malformed output is `partial`.

Activation extraction uses the real `ActivationCollector` and checks shape, dtype, device, and detached status. SAE
compatibility loads a local checkpoint through `bugdhor.sae.checkpoint.load_checkpoint`, verifies its config hash, input
dimension against model hidden size, finite decoder weights, and a declared hook point. The hook point is declared by
configuration because the checkpoint format does not embed it.

Counterfactual, token-level, and steering probes run the real `bugdhor.counterfactual` and `bugdhor.steering` engines with
a position-indexed intervention. They record measured activation deltas and validation flags. Their claim kind is
`hypothesis` for effect interpretation and `computed` for measured values; they are not real-world causal claims.

Reproducibility is measured by repeating greedy generation with a fixed seed on the observed device. It is reported with
a `seeded` determinism tier and does not claim determinism on other hardware or library versions.

## Recorded model fields

For every model the report records:

- model name;
- exact checkpoint or provider identifier;
- exact snapshot revision;
- architecture;
- tokenizer class;
- all discovered hookable layers;
- observed activation access;
- observed SAE compatibility;
- observed steering compatibility;
- measured hardware/dtype/memory/runtime data;
- inference limitations and claim boundaries.

In the committed run, both local checkpoints report `Qwen2ForCausalLM`, `Qwen2Tokenizer`, 24 discovered layers
(`model.layers.0` through `model.layers.23`), hidden size 896, CPU/float32, and layer-4 SAE artifacts with decoder shape
`[896, 1792]`.

## Running the framework

From the repository root:

```bash
.venv/bin/python research/experiments/model_compatibility/run_compatibility_matrix.py
```

Inputs:

- [`research/configs/models/compatibility-matrix.json`](../research/configs/models/compatibility-matrix.json) — pinned
  model targets, exact local revisions, artifact paths, probe prompts, budgets, and assistant provider targets.

Outputs:

- `research/experiments/model_compatibility/results/model_compatibility_report.json`
- `research/experiments/model_compatibility/results/model_compatibility_report.md`

The runner uses local files only. It never downloads checkpoints, never reads secret values into reports, and records
only environment variable **names** for missing provider prerequisites.

## Legacy research artifacts

The tested SAE checkpoints were generated before the repository rename. Their PyTorch metadata references
`craftsec.sae.*`. The compatibility runner installs temporary module aliases to the current `bugdhor.sae.*` classes before
loading those local files. This is an artifact compatibility shim, not a claim that the old training code is still the
production implementation.

## Limitations

- `LIM-COMPAT-01`: the local 0.5B checkpoints are research probes and are not registered production adapters.
- `LIM-SAE-01`: SAE features are tied to one model revision, layer, and hook point.
- `LIM-CF-01` / `LIM-CF-03`: interventions are off-distribution and model-internal, not real-world causal effects.
- `LIM-STEER-01` / `LIM-STEER-02`: steering may degrade capability and may not generalize.
- `LIM-REPRO-01`: exact reproduction is limited to the observed host and library versions.
- `LIM-ENV-01`: hosted providers expose no internals and remain unavailable without configured access.
- Generation previews in the report are evidence that text was produced, not validated secure code.

See [AI assistant integration](ai-assistant-integration.md) for the static A-F provider matrix and the separate
[benchmark](../../benchmarks/README.md), which remains `not_run` until a real model provider, sandbox, analyzer rule
pack, and executor are configured.
