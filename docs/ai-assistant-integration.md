# AI assistant integration (model-independent)

Bug Dhor can observe ordinary editor changes and, when explicitly configured,
discover documented generation access from an AI coding assistant. The
integration is model-independent: it works through provider adapters instead of
assuming a particular assistant, model family, or internal representation.

The integration is deliberately honest. It never infers the author or model of
an edit, never reverse-engineers an assistant, never simulates model internals,
and never turns an unavailable capability into a finding or a clean result.
Vulnerability diagnostics still come only from validated backend scan results.

## Capability taxonomy

| Capability | Meaning | Default |
|---|---|---|
| **A** | Code monitoring through documented editor change events | Yes |
| **B** | Generation request access through a documented, configured API | No |
| **C** | Generation response access through a documented, configured API | No |
| **D** | Real model internal activation access through a validated local accessor | No |
| **E** | Sparse autoencoder (SAE) integration backed by D and a validated SAE artifact | No |
| **F** | Activation steering backed by D and E plus an explicit intervention contract | No |

Invariants enforced by `vscode-extension/src/integrations/capabilities.js`:

- `E` requires `D`.
- `F` requires both `D` and `E`.
- Hosted providers may only claim `A`, `B`, and `C`.
- `conditional` in the compatibility matrix never means enabled by default.

Capability validation is structural plus provider-specific. A setting that merely
names a model, endpoint, or extension cannot grant `D`, `E`, or `F`.

## Provider compatibility matrix

`PROVIDER_COMPATIBILITY` and `toCompatibilityMatrix()` in
`vscode-extension/src/integrations/compatibilityMatrix.js` report the following
static matrix. `editor-fallback` means code monitoring still comes from ordinary
VS Code document events even when another provider supplies generation.

| Provider | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| VS Code editor monitoring | supported | not-supported | not-supported | not-supported | not-supported | not-supported |
| VS Code Language Model API | editor-fallback | conditional | conditional | not-supported | not-supported | not-supported |
| OpenAI-compatible endpoint | editor-fallback | conditional | conditional | not-supported | not-supported | not-supported |
| Direct local Hugging Face model | editor-fallback | conditional | conditional | conditional | conditional | conditional |
| Official extension-specific API | editor-fallback | conditional | conditional | conditional | conditional | conditional |

The live `bugdhor.showAssistantCapabilities` command returns the same matrix
augmented with discovered provider records. Each record contains the provider
ID, kind, hosted flag, status, capabilities, model summary (when available),
reason/detail for failures, documented API description, and limitations.

## Workspace monitoring provider matrix

`vscode-extension/src/monitoring/providerMatrix.js` describes the universal
fallback separately from optional generation adapters. It covers GitHub
Copilot, Cursor, Claude-assisted workflows, ChatGPT-pasted code, OpenCode, other
VS Code assistants, and manual code. Every row uses
`workspace-document-events`, reports `workspaceMonitoring: 'supported'`, and
sets `attribution: 'none'`.

| Source or workflow | Observation | Attribution | Optional adapters |
|---|---|---|---|
| GitHub Copilot | `workspace-document-events` | `none` | VS Code Language Model API |
| Cursor | `workspace-document-events` | `none` | none |
| Claude-assisted workflows | `workspace-document-events` | `none` | OpenAI-compatible / extension API |
| ChatGPT-pasted code | `workspace-document-events` | `none` | OpenAI-compatible |
| OpenCode | `workspace-document-events` | `none` | OpenAI-compatible / extension API |
| Other assistants | `workspace-document-events` | `none` | extension API |
| Manually written code | `workspace-document-events` | `none` | none |

The matrix lists only official events: `onDidOpenTextDocument`,
`onDidChangeTextDocument`, `onDidSaveTextDocument`, `onDidCreateFiles`,
`onDidDeleteFiles`, and `onDidChangeWorkspaceFolders`. Private APIs and
reverse-engineered extension internals are never used, and an optional adapter
never changes scan eligibility, severity, or diagnostics. See
[the workspace scanning audit](workspace-scanning-audit.md) for the evidence
boundary.

## Provider rules

### Editor monitoring (default)

`createEditorProvider()` exposes only capability `A`. The workspace monitor owns
all official document and workspace events; the incremental executor records
bounded, zero-based half-open line ranges plus document URI/version metadata. It
does not attribute an edit to a person, assistant, or model. Source text leaves
the extension only when `bugdhor.monitoring.enabled` is true,
`bugdhor.monitoring.allowAutomaticSourceSharing` is true, and
`bugdhor.privacy.sendSourceText` is true. The nonexistent setting
`bugdhor.monitoring.sendSourceText` must not be used.

### VS Code Language Model API

`createVscodeLanguageModelProvider()` uses only documented surfaces:

- `vscode.lm.selectChatModels(selector)`
- `LanguageModelChat.sendRequest(messages, options, token)`

The optional selector comes from
`bugdhor.assistant.vscodeLanguageModel.selector`. The API does not support a
system role, so system messages are folded into user messages rather than
silently dropped. Requests and responses are normalized through the shared
generation adapter and keep provider/model/request provenance. Hosted language
models never expose `D`, `E`, or `F`.

### OpenAI-compatible endpoints

`createOpenAiCompatibleProvider()` sends only documented chat-completions
fields to `bugdhor.assistant.openAiCompatible.endpoint` with
`bugdhor.assistant.openAiCompatible.model`. The fetch implementation is injected
by the host. Credentials are read from the environment variable named by
`bugdhor.assistant.openAiCompatible.apiKeyEnvironmentVariable` (default
`BUGDHOR_LLM_API_KEY`); keys are never stored in settings or logs.

Transport, timeout, authentication, and rate-limit failures become typed
provider errors with stable codes. No undocumented response field is parsed, and
hosted endpoints never expose `D`, `E`, or `F`.

### Direct local Hugging Face model

`createLocalHuggingFaceProvider()` reads `config.json` from
`bugdhor.assistant.localHuggingFace.modelPath` for public metadata only (model
ID, family, version, and layer/hidden-size summary). Reading metadata does not
prove generation or internal access.

- Generation (`B`/`C`) requires an injected local generation adapter.
- `D` requires a real `activationAccessor` with `validated === true`,
  `readActivations`, `artifactId`, and `method`.
- `E` additionally requires a validated SAE artifact with `artifactId`, a
  documented `mapping`, and a real `extractFeatures` function.
- `F` additionally requires a configured steering contract with a real `run`
  function and an explicit `effectMetric`.

Missing, invalid, or failed accessors leave the corresponding capability
unavailable. No activation is inferred from weights or config files.

### Official extension-specific API

`createExtensionApiProvider()` requires an explicit JSON manifest referenced by
`bugdhor.assistant.extensionApi.manifestPath` (or injected directly by a host).
The manifest must declare:

- `extensionId` in `publisher.name` form
- `apiVersion`
- an absolute `http:`/`https:` `documentationUrl`
- optional `modelId`
- `capabilities`
- `generationMethod` when `B`/`C` is declared
- `hosted`
- `internalActivationContract` with `method`, `documentationUrl`,
  `validationMethod`, and optional `artifactId` when `D`/`E`/`F` is declared

Only method names explicitly listed in the manifest are called. An absent,
unreadable, undocumented, or reverse-engineered interface is rejected with an
unavailable provider record and a reason code such as `E_MANIFEST_REQUIRED`,
`E_MANIFEST_INVALID`, `E_EXTENSION_API_UNAVAILABLE`,
`E_GENERATION_METHOD_MISSING`, `E_ACTIVATION_CONTRACT_MISSING`, or
`E_HOSTED_INTERNALS_FORBIDDEN`.

## Generation interfaces

`vscode-extension/src/integrations/generation.js` defines shared request and
response shapes:

- `createGenerationRequest()` normalizes provider ID, model ID, messages,
  `maxTokens`, `temperature`, stop sequences, and metadata. It computes a
  SHA-256 request hash and stable request ID. Source text is not added here;
  callers decide explicitly what may be included under consent.
- `normalizeGenerationResponse()` accepts a string or an object with `text` or
  `content`, validates token usage when supplied, and requires the adapter to
  supply model identity rather than guessing it.
- `createGenerationAdapter()` enforces `B`/`C`, records provenance, and maps
  provider failures to typed errors.

`SecurityHooks.wrapGeneration()` records request and response hashes and
finish reasons. Prompts and generated code are never retained by the hooks.

## Security hooks and provenance

`SecurityHooks` is attached to the realtime monitor and the provider registry:

- `observeChange()` records URI, version, range count, and reason, with
  `authorAttribution: 'none'` and `modelAttribution: 'none'`.
- `observeGenerationRequest()` / `observeGenerationResponse()` require validated
  `B`/`C` and record metadata/hashes only.
- `attachSaeProvider()` requires enabled settings plus validated `D` and `E`.
- `attachCounterfactualProvider()` requires enabled settings plus validated
  `D`, `E`, and `F`.
- `getStatus()` reports active provider, capability list, observation counts,
  SAE/counterfactual availability, `findingsPublishedByHooks: 0`, and no author
  attribution.

Hooks never synthesize findings, never publish diagnostics, and never attribute
a changed function to a model or assistant. The extension returns
`assistantRegistry` and `assistantHooks` from `activate()` for host/test use.

## Assisted-analysis workflow

The Python implementation is
`security-engine/src/bugdhor/detection/assisted.py`
(`IncrementalAssistedAnalyzer`). It consumes source text, bounded change
regions, optional static-tool results, and optional real SAE/counterfactual
providers. It is a library: only the extension publishes diagnostics.

The twelve reported stages are:

1. `change_detection`
2. `region_identification`
3. `syntax_analysis`
4. `ast_analysis`
5. `cfg_dfg_analysis`
6. `taint_analysis`
7. `static_analysis`
8. `sae_features`
9. `counterfactual_analysis`
10. `evidence_fusion`
11. `classification`
12. `diagnostic_export`

Each stage has an explicit status: `completed`, `skipped`, `unavailable`,
`failed`, or `cached`, with a reason code where applicable. Cache hits append an
`incremental_cache` record. Parse failures, missing static tools, absent SAE
providers, unconfigured counterfactual providers, and fusion failures are never
marked `completed`.

The workflow narrows analysis to changed functions where possible, runs
syntax-aware parsing, AST analysis, CFG/DFG construction, taint analysis, and
static tools, then fuses evidence, classifies and localizes findings, and
exports API-shaped findings. The cache key includes source, path, document URI,
language, config hash, change regions, static result, optional provider
identities, and SAE/counterfactual flags, preserving incremental performance
without hiding disabled or unavailable stages.

### SAE and counterfactual evidence

When a validated SAE provider is attached, its features are added as
`EvidenceFamily.LLM` / `ClaimKind.HYPOTHESIS` evidence with strength capped at
`0.25` and explicit limitations. Counterfactual effects are added as LLM-family
hypotheses with strength capped at `0.20` and are described as model-internal
effects, not real-world causal effects. Neither can independently confirm a
vulnerability.

### Confirmation and potential findings

`classify_confirmation()` labels a finding `confirmed` only when:

- its category is mapped (not `UNKNOWN`),
- there is no recorded conflict or refutation, and
- at least two supporting evidence items from at least two independent
  observation/inference evidence families exist.

Hypothesis evidence is excluded from confirmation. Everything else is
`potential`. The VS Code diagnostics layer displays this as verification
provenance in the diagnostic, related information, and hover, and never infers
confirmation from a model response alone.

### Vulnerability categories

The engine can classify SQL injection, command injection, code injection, XSS,
path traversal, unsafe deserialization, hardcoded secrets, weak cryptography,
insecure TLS, XXE, SSRF, open redirect, CSRF, authentication bypass,
authorization weakness, IDOR, and input validation, with `UNKNOWN` retained when
evidence does not support a mapped category.

## Configuration summary

| Setting | Purpose |
|---|---|
| `bugdhor.assistant.provider` | `editor` (default), `vscode-language-model`, `openai-compatible`, `local-hugging-face`, or `extension-api` |
| `bugdhor.assistant.vscodeLanguageModel.selector` | Optional documented chat-model selector |
| `bugdhor.assistant.openAiCompatible.endpoint` | Endpoint base URL or full `/chat/completions` URL |
| `bugdhor.assistant.openAiCompatible.model` | Model identifier sent to the endpoint |
| `bugdhor.assistant.openAiCompatible.apiKeyEnvironmentVariable` | Environment variable name for the API key |
| `bugdhor.assistant.localHuggingFace.modelPath` | Local model directory containing `config.json` |
| `bugdhor.assistant.extensionApi.manifestPath` | Official extension API manifest path |
| `bugdhor.assistant.sae.enabled` | Attempt SAE provider attachment; does not grant capability |
| `bugdhor.assistant.counterfactual.enabled` | Attempt counterfactual provider attachment; does not grant capability |

Changing `bugdhor.assistant.*` settings updates the hooks and refreshes provider
discovery. Discovery failures remain visible as unavailable records.

## Verification

Relevant automated checks are:

```sh
cd vscode-extension && npm test && npm run lint
cd security-engine && ./.venv/bin/ruff check \
  src/bugdhor/detection/assisted.py \
  src/bugdhor/detection/models.py \
  src/bugdhor/detection/ast_analysis.py \
  tests/integration/test_assisted_analysis.py
cd security-engine && ./.venv/bin/python -m pytest \
  tests/integration/test_assisted_analysis.py \
  tests/unit/test_detection_engine.py \
  tests/unit/test_detection_fusion.py -q
```

The extension unit suite includes
`vscode-extension/test/unit/assistantIntegration.test.js`, which checks the
capability invariants, all provider adapters, registry failure behavior,
security-hook provenance, compatibility matrix, and diagnostic display of
backend verification status.

## Limitations

- No capability is inherited from another provider; each adapter declares and
  validates its own documented surface.
- SAE and counterfactual evidence remains a low-strength model-family
  hypothesis, never independent verification.
- Hosted assistants cannot provide `D`, `E`, or `F`.
- No reverse-engineered or undocumented VS Code, extension, endpoint, or model
  interface is used.
- The integration does not add source text to generation requests automatically;
  existing consent settings remain authoritative.
- Diagnostics are only published from validated backend scan results, even when
  generation or monitoring hooks are active.
