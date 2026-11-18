# Model compatibility report

- Generated at: `2026-11-18T09:01:49.486957Z`
- Config hash: `10b8282eac8a9c104fd8bdfb0b936078f3f2021e0868fcdc92c31472e8d1d540`
- Git commit: `332814d7f8a14d285c17e30ff4dba8b98db24448`
- Python: `3.11.14`
- Platform: `macOS-26.3.1-arm64-arm-64bit`
- Torch: `2.15.0`
- Transformers: `5.22.2`

Declared capabilities are configuration, not evidence. Only observed probe outcomes are reported below.

| Target | Runtime | Generation | Analysis | Secure gen | Activations | SAE | Counterfactual | Steering | Token-level | Reproducibility | Hardware |
|---|---|---|---|---|---|---|---|---|---|---|---|
| registered-llama-3.1-8b-instruct | bugdhor_adapter | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |
| registered-qwen2.5-coder-7b-instruct | bugdhor_adapter | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |
| registered-deepseek-coder-6.7b-instruct | bugdhor_adapter | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |
| local-qwen2.5-coder-0.5b-base | transformers_direct | supported | partial | supported | supported | supported | supported | supported | supported | supported | supported |
| local-qwen2.5-coder-0.5b-instruct | transformers_direct | supported | partial | supported | supported | supported | supported | supported | supported | supported | supported |

## Per-target details

### registered-llama-3.1-8b-instruct

- Name: Llama 3.1 8B Instruct
- Checkpoint: `meta-llama/Llama-3.1-8B-Instruct`
- Revision: `unresolved`
- Architecture: `unobserved`
- Tokenizer: `unobserved`
- Layers: unobserved

| Capability | Status | Evidence / reason |
|---|---|---|
| code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| code_analysis | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| secure_code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_extraction | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| sae_compatibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| counterfactual_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_steering | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| token_level_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| output_reproducibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| hardware_inference_limits | unavailable | registered checkpoint_not_present in local Hugging Face cache |

### registered-qwen2.5-coder-7b-instruct

- Name: Qwen2.5-Coder 7B Instruct
- Checkpoint: `Qwen/Qwen2.5-Coder-7B-Instruct`
- Revision: `unresolved`
- Architecture: `unobserved`
- Tokenizer: `unobserved`
- Layers: unobserved

| Capability | Status | Evidence / reason |
|---|---|---|
| code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| code_analysis | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| secure_code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_extraction | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| sae_compatibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| counterfactual_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_steering | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| token_level_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| output_reproducibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| hardware_inference_limits | unavailable | registered checkpoint_not_present in local Hugging Face cache |

### registered-deepseek-coder-6.7b-instruct

- Name: DeepSeek-Coder 6.7B Instruct
- Checkpoint: `deepseek-ai/deepseek-coder-6.7b-instruct`
- Revision: `unresolved`
- Architecture: `unobserved`
- Tokenizer: `unobserved`
- Layers: unobserved

| Capability | Status | Evidence / reason |
|---|---|---|
| code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| code_analysis | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| secure_code_generation | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_extraction | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| sae_compatibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| counterfactual_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| activation_steering | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| token_level_intervention | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| output_reproducibility | unavailable | registered checkpoint_not_present in local Hugging Face cache |
| hardware_inference_limits | unavailable | registered checkpoint_not_present in local Hugging Face cache |

### local-qwen2.5-coder-0.5b-base

- Name: Qwen2.5-Coder 0.5B
- Checkpoint: `Qwen/Qwen2.5-Coder-0.5B`
- Revision: `8123ea2e9354afb7ffcc6c8641d1b2f5ecf18301`
- Architecture: `Qwen2ForCausalLM`
- Tokenizer: `Qwen2Tokenizer`
- Layers: ('model.layers.0', 'model.layers.1', 'model.layers.2', 'model.layers.3', 'model.layers.4', 'model.layers.5', 'model.layers.6', 'model.layers.7', 'model.layers.8', 'model.layers.9', 'model.layers.10', 'model.layers.11', 'model.layers.12', 'model.layers.13', 'model.layers.14', 'model.layers.15', 'model.layers.16', 'model.layers.17', 'model.layers.18', 'model.layers.19', 'model.layers.20', 'model.layers.21', 'model.layers.22', 'model.layers.23')

| Capability | Status | Evidence / reason |
|---|---|---|
| code_generation | supported | {"elapsedMs": 2341.11, "generatedTokens": 64, "parsedJson": null, "preview": " The function should also remove any leading or trailing whitespace from the input text. The function should handle any non-alphanumeric characters and non-ASCII characters, and should not modify the original text. The function should also ", "promptTokens": 31, "textSha256": "b611bab878a5875e480c508895ea9863f5c00ded8b30f7846d8c0fd6d6b49aa1"} |
| code_analysis | partial | generated text was not valid JSON; format compliance is not established |
| secure_code_generation | supported | {"elapsedMs": 2037.52, "generatedTokens": 64, "parsedJson": null, "preview": " The function should also handle the case where the file is not found and return an appropriate error message. The function should also handle the case where the file is not readable and return an appropriate error message. The function sho", "promptTokens": 37, "textSha256": "c6ce2e4df53ef34f5fbf7a10ac4839c8dc62f3fb475e4a815403c2bd65d3b72d"} |
| activation_extraction | supported | {"device": "cpu", "dtype": "float32", "layer": "model.layers.4", "provenance": {"batch_size": 1, "device": "cpu", "dtype": "torch.float32", "hidden_size": 896, "layer_names": ["model.layers.4"], "model_id": "Qwen/Qwen2.5-Coder-0.5B", "model_version": "8123ea2e9354afb7ffcc6c8641d1b2f5ecf18301", "tokenizer_id": "/Users/md.khayrulislamsajib/.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-0.5B/snapshots/8123ea2e9354afb7ffcc6c8641d1b2f5ecf18301", "tokenizer_version": "unknown"}, "requiresGrad": false, "shape": [1, 31, 896]} |
| sae_compatibility | supported | {"artifactId": "qwen05b-base-layer4", "configHash": "505c04af9a2a72f51dcb0f71a455111ed096ce4a13f67de5e7f1452c760e4f12", "declaredHookPoint": "residual_stream", "decoderShape": [896, 1792], "finiteDecoder": true, "hiddenSize": 896, "inputDim": 896, "latentDim": 1792, "path": "/Users/md.khayrulislamsajib/Downloads/Bug-Dhor/research/experiments/counterfactual_validation/artifacts/base_layer4.pt", "sha256": "3335632d561f63a16da2d3cccfc22cb34c863e2c6eb57c3318a2f85fa2a3b50f"} |
| counterfactual_intervention | supported | Controlled activation comparison only; no causal claim. |
| token_level_intervention | supported | Position-indexed intervention with measured post-intervention values. |
| activation_steering | supported | Steering changes output behavior; it does not establish a security gain. |
| output_reproducibility | supported | {"determinismTier": "seeded", "device": "cpu", "doSample": false, "identical": true, "outputHashes": ["b611bab878a5875e480c508895ea9863f5c00ded8b30f7846d8c0fd6d6b49aa1", "b611bab878a5875e480c508895ea9863f5c00ded8b30f7846d8c0fd6d6b49aa1"]} |
| hardware_inference_limits | supported | Measured from the loaded checkpoint and host runtime. |

### local-qwen2.5-coder-0.5b-instruct

- Name: Qwen2.5-Coder 0.5B Instruct
- Checkpoint: `Qwen/Qwen2.5-Coder-0.5B-Instruct`
- Revision: `ea3f2471cf1b1f0db85067f1ef93848e38e88c25`
- Architecture: `Qwen2ForCausalLM`
- Tokenizer: `Qwen2Tokenizer`
- Layers: ('model.layers.0', 'model.layers.1', 'model.layers.2', 'model.layers.3', 'model.layers.4', 'model.layers.5', 'model.layers.6', 'model.layers.7', 'model.layers.8', 'model.layers.9', 'model.layers.10', 'model.layers.11', 'model.layers.12', 'model.layers.13', 'model.layers.14', 'model.layers.15', 'model.layers.16', 'model.layers.17', 'model.layers.18', 'model.layers.19', 'model.layers.20', 'model.layers.21', 'model.layers.22', 'model.layers.23')

| Capability | Status | Evidence / reason |
|---|---|---|
| code_generation | supported | {"elapsedMs": 2203.95, "generatedTokens": 64, "parsedJson": null, "preview": " Here's an example:\n\n```python\ndef slugify(text):\n    \"\"\"\n    Convert text to lowercase and replace sequences of non-alphanumeric characters with a single hyphen.\n    \n    Args:\n    text (str): The input string to be slugified.\n    \n    Ret", "promptTokens": 31, "textSha256": "9d7a550e9a0a0c2f1e4dbabbeb426954a46f275790f4ed014a3ceace7053ea3b"} |
| code_analysis | partial | generated text was not valid JSON; format compliance is not established |
| secure_code_generation | supported | {"elapsedMs": 2048.95, "generatedTokens": 64, "parsedJson": null, "preview": " Here's an example of how you might implement this:\n\n```python\nimport os\n\ndef read_text(path):\n    if not os.path.exists(path):\n        raise ValueError(\"Path does not exist\")\n    with open(path, 'r', encoding='utf-8') as file:\n        retu", "promptTokens": 37, "textSha256": "f01009a50c6c861de206179a43fd0fc5439b02140ef671fd983247dc93dfcb4a"} |
| activation_extraction | supported | {"device": "cpu", "dtype": "float32", "layer": "model.layers.4", "provenance": {"batch_size": 1, "device": "cpu", "dtype": "torch.float32", "hidden_size": 896, "layer_names": ["model.layers.4"], "model_id": "Qwen/Qwen2.5-Coder-0.5B-Instruct", "model_version": "ea3f2471cf1b1f0db85067f1ef93848e38e88c25", "tokenizer_id": "/Users/md.khayrulislamsajib/.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-0.5B-Instruct/snapshots/ea3f2471cf1b1f0db85067f1ef93848e38e88c25", "tokenizer_version": "unknown"}, "requiresGrad": false, "shape": [1, 31, 896]} |
| sae_compatibility | supported | {"artifactId": "qwen05b-instruct-layer4", "configHash": "505c04af9a2a72f51dcb0f71a455111ed096ce4a13f67de5e7f1452c760e4f12", "declaredHookPoint": "residual_stream", "decoderShape": [896, 1792], "finiteDecoder": true, "hiddenSize": 896, "inputDim": 896, "latentDim": 1792, "path": "/Users/md.khayrulislamsajib/Downloads/Bug-Dhor/research/experiments/counterfactual_validation/artifacts/instruct_layer4.pt", "sha256": "647f93b9fcca16a82c13ad350a8b686fa121f3c98488a3b9533ea64b93a0aa41"} |
| counterfactual_intervention | supported | Controlled activation comparison only; no causal claim. |
| token_level_intervention | supported | Position-indexed intervention with measured post-intervention values. |
| activation_steering | supported | Steering changes output behavior; it does not establish a security gain. |
| output_reproducibility | supported | {"determinismTier": "seeded", "device": "cpu", "doSample": false, "identical": true, "outputHashes": ["9d7a550e9a0a0c2f1e4dbabbeb426954a46f275790f4ed014a3ceace7053ea3b", "9d7a550e9a0a0c2f1e4dbabbeb426954a46f275790f4ed014a3ceace7053ea3b"]} |
| hardware_inference_limits | supported | Measured from the loaded checkpoint and host runtime. |

## Assistant integrations

| Provider | Observed status | Discovered capabilities | Declared A-F | Reason |
|---|---|---|---|---|
| VS Code editor monitoring | unavailable | none | A:supported/B:not-supported/C:not-supported/D:not-supported/E:not-supported/F:not-supported | no VS Code host is available to the CLI runner |
| VS Code Language Model API | unavailable | none | A:editor-fallback/B:conditional/C:conditional/D:not-supported/E:not-supported/F:not-supported | no VS Code host is available to the CLI runner |
| OpenAI-compatible endpoint | unavailable | none | A:editor-fallback/B:conditional/C:conditional/D:not-supported/E:not-supported/F:not-supported | no VS Code host is available to the CLI runner; missing BUGDHOR_LLM_API_KEY, BUGDHOR_BENCHMARK_ENDPOINT |
| Direct local Hugging Face model | unavailable | none | A:editor-fallback/B:conditional/C:conditional/D:conditional/E:conditional/F:conditional | no VS Code host is available to the CLI runner; missing BUGDHOR_BENCHMARK_MODEL_PATH |
| Official extension-specific API | unavailable | none | A:editor-fallback/B:conditional/C:conditional/D:conditional/E:conditional/F:conditional | no VS Code host is available to the CLI runner; missing BUGDHOR_BENCHMARK_EXTENSION_MANIFEST |

## Claim boundary

Only capabilities with concrete probe evidence are reported as supported. Generation fluency is not security accuracy; model-internal effects are not real-world causal effects; hosted providers expose no internals.

## Limitations

- LIM-SAE-01: SAE features are tied to one model revision, layer, and hook point.
- LIM-CF-01: activation interventions are off-distribution and may be invalid.
- LIM-CF-03: model-internal effects are not real-world causal effects.
- LIM-STEER-01: steering may degrade capability or fluency.
- LIM-REPRO-01: hardware/library nondeterminism limits exact reproduction.
- LIM-ENV-01: hosted providers expose no model internals.
- LIM-COMPAT-01: local 0.5B checkpoints are research probes and are not registered production adapters.
