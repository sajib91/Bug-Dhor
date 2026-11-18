# Model compatibility report — current workspace

- Date: 2026-11-18
- Command: `.venv/bin/python research/experiments/model_compatibility/run_compatibility_matrix.py`
- Result: rerun completed successfully with unchanged configuration
- Config hash: `10b8282eac8a9c104fd8bdfb0b936078f3f2021e0868fcdc92c31472e8d1d540`
- Generated at: `2026-11-18T11:06:59.933585Z`
- Git commit recorded by harness: `709c92b00d8c17fe4ba32c977f4bdb312d2c8ae5`
- Environment: Python 3.11.14, macOS 26.3.1 arm64, Torch 2.15.0, Transformers 5.22.2
- Source report: [`research/experiments/model_compatibility/results/model_compatibility_report.md`](research/experiments/model_compatibility/results/model_compatibility_report.md)
- Machine-readable evidence: [`research/experiments/model_compatibility/results/model_compatibility_report.json`](research/experiments/model_compatibility/results/model_compatibility_report.json)

Declared capabilities are configuration, not evidence. Only observed probe outcomes are reported here. The harness ran against the current worktree, but the recorded git commit is the underlying HEAD because the integration changes are uncommitted.

## 1. Registered production model targets

| Target | Checkpoint | Generation | Analysis | Secure gen | Activations | SAE | Counterfactual | Steering | Token-level | Reproducibility | Hardware |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `registered-llama-3.1-8b-instruct` | `meta-llama/Llama-3.1-8B-Instruct` | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |
| `registered-qwen2.5-coder-7b-instruct` | `Qwen/Qwen2.5-Coder-7B-Instruct` | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |
| `registered-deepseek-coder-6.7b-instruct` | `deepseek-ai/DeepSeek-Coder-6.7B-Instruct` | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |

Reason for every capability: `registered checkpoint_not_present in local Hugging Face cache`.

These targets remain **unavailable**. No result was inferred from model names, registry entries, or documentation.

## 2. Local research compatibility probes

| Target | Checkpoint and revision | Generation | Analysis | Secure gen | Activations | SAE | Counterfactual | Steering | Token-level | Reproducibility | Hardware |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `local-qwen2.5-coder-0.5b-base` | `Qwen/Qwen2.5-Coder-0.5B` @ `8123ea2e9354afb7ffcc6c8641d1b2f5ecf18301` | supported | partial | supported | supported | supported | supported | supported | supported | supported | supported |
| `local-qwen2.5-coder-0.5b-instruct` | `Qwen/Qwen2.5-Coder-0.5B-Instruct` @ `ea3f2471cf1b1f0db85067f1ef93848e38e88c25` | supported | partial | supported | supported | supported | supported | supported | supported | supported | supported |

The only `partial` probe for both local checkpoints is `code_analysis`: generated text was not valid JSON, so format compliance was not established. This is not a production analysis capability.

Observed probe details include:

- Activation extraction at layer `model.layers.4` on CPU with float32 tensors.
- Layer-4 SAE artifacts `qwen05b-base-layer4` and `qwen05b-instruct-layer4` with recorded SHA-256 hashes.
- Controlled activation comparison and position-indexed intervention with measured values.
- Steering changed output behavior; this does **not** establish a security gain.
- Seeded, non-sampling outputs were identical across repeated runs.

### Limitation `LIM-COMPAT-01`

Both local 0.5B checkpoints are **research compatibility probes**, not registered production adapters. Their `supported` probe results prove only that the specific revision, artifact, and layer hook could be exercised in the harness. They do not:

- register a production checkpoint;
- enable the extension’s D/E/F capabilities;
- wire SAE/counterfactual/steering into the HTTP workflow;
- establish calibrated risk, causal effects, or improved security;
- substitute for the 7B benchmark model binding in `benchmarks/configs/coding-benchmark-v1.json`.

## 3. Assistant integrations

The CLI compatibility runner has no VS Code host, so every assistant integration is observed as `unavailable`. The A–F values below are the declared matrix, not discovered live capabilities.

| Provider | Observed status | Discovered capabilities | Declared A–F | Reason |
|---|---|---|---|---|
| VS Code editor monitoring | unavailable | none | A supported; B/C/D/E/F not-supported | no VS Code host is available to the CLI runner |
| VS Code Language Model API | unavailable | none | A editor-fallback; B/C conditional; D/E/F not-supported | no VS Code host is available to the CLI runner |
| OpenAI-compatible endpoint | unavailable | none | A editor-fallback; B/C conditional; D/E/F not-supported | no VS Code host; missing `BUGDHOR_LLM_API_KEY`, `BUGDHOR_BENCHMARK_ENDPOINT` |
| Direct local Hugging Face model | unavailable | none | A editor-fallback; B/C/D/E/F conditional | no VS Code host; missing `BUGDHOR_BENCHMARK_MODEL_PATH` |
| Official extension-specific API | unavailable | none | A editor-fallback; B/C/D/E/F conditional | no VS Code host; missing `BUGDHOR_BENCHMARK_EXTENSION_MANIFEST` |

This CLI result does not contradict the Extension Host e2e result: capability A is separately observed as **fully** working in a real VS Code host. It does mean B/C/D/E/F remain unavailable in the operational local path without configured, documented providers and validated accessors.

## 4. Capability taxonomy interpretation

| Capability | Meaning | Current operational status |
|---|---|---|
| A | Documented editor change monitoring | **Fully** in Extension Host; CLI runner cannot observe it |
| B | Documented generation request access | **Unavailable** locally |
| C | Documented generation response access | **Unavailable** locally |
| D | Real model-internal activation access | **Unavailable** in extension path; probes use direct harness access |
| E | SAE integration requiring D and validated artifact | **Unavailable** in extension path |
| F | Activation steering requiring D, E, and explicit contract | **Unavailable** in extension path |

`conditional` never means enabled by default. `E` implies `D`; `F` implies `D` and `E`. Hosted providers cannot claim D/E/F.

## 5. What would change these statuses

| Needed for upgrade | Current gap |
|---|---|
| Production checkpoint registration | Registered checkpoints are not present locally |
| Exact benchmark model binding | `resolvedRevision` is null; required environment variables absent |
| Live hosted assistant integration | No endpoint, key, or official extension manifest |
| D capability in extension | No validated local `activationAccessor` |
| E capability in extension | No production SAE artifact and mapping wired through D |
| F capability in extension | No real steering contract with explicit effect metric wired through D/E |
| Empirical research claims | No benchmark executor, sandbox profile, pinned analyzer rule pack, or executed run |

## 6. Final determination

- Registered production targets: **unavailable**
- Local Qwen 0.5B probes: **supported** for most research hooks, **partial** for code analysis
- Assistant B/C/D/E/F in the operational extension path: **unavailable**
- No simulated model capability was used to fill a gap

This report is compatibility evidence only. It is not an empirical performance, security, or research-completeness result.
