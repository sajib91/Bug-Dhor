# Local model runtime

Bug Dhor uses a lazy Hugging Face Transformers adapter for local execution.
Importing `bugdhor.models` does not import PyTorch or Transformers and never
downloads weights. `ModelConfig.local_files_only` defaults to `true`; callers
must provision checkpoints separately and may opt into remote resolution
explicitly.

## Supported checkpoints

| Key | Exact checkpoint | License / limitation |
| --- | --- | --- |
| `llama-3.1-8b-instruct` | `meta-llama/Llama-3.1-8B-Instruct` | Llama 3.1 Community License; gated on Hugging Face and requires accepting Meta's terms. |
| `qwen2.5-coder-7b-instruct` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Apache-2.0. Long contexts require substantial host memory. |
| `deepseek-coder-6.7b-instruct` | `deepseek-ai/deepseek-coder-6.7b-instruct` | DeepSeek Model License; this exact 6.7B instruct checkpoint is selected, not an arbitrary DeepSeek-Coder variant. |

Users must review and comply with the applicable license, acceptable-use
terms, export restrictions, and any gated-model access requirements before
provisioning a checkpoint. Bug Dhor does not redistribute weights.

## Activations and limitations

`HuggingFaceAdapter.collect_activations()` performs a real no-grad forward pass
and uses temporary forward hooks on discovered Transformer blocks. It returns
detached CPU tensors indexed by layer and token, with tokenizer offsets
preserved for source correspondence. Selected function character spans can be
aggregated into per-layer vectors. Hooks are removed in a `finally` block even
when the forward pass fails.

Activation tensors are stored with model ID/version, tokenizer ID/version,
layer names, hidden size, dtype, device, token IDs, token strings, and offsets.
They may be large; use `batch_size` and selected layers to bound memory. The
activation layout is model/version dependent, and this layer does not promise
cross-model comparability or SAE feature alignment.

CPU execution is supported but can be slow and memory intensive for 7B/8B
models. Explicit CUDA selection fails if CUDA is unavailable; `auto` selects
CUDA when available and otherwise CPU. Loading failures, missing optional
dependencies, and inference failures are reported as typed runtime errors.
