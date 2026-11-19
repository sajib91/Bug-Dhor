'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  CAPABILITIES,
  validateCapabilities,
  normalizeCapabilities,
  createGenerationRequest,
  createGenerationAdapter,
  createProviderRegistry,
  SecurityHooks,
  createEditorProvider,
  createVscodeLanguageModelProvider,
  createOpenAiCompatibleProvider,
  createLocalHuggingFaceProvider,
  createExtensionApiProvider,
  toCompatibilityMatrix,
  renderCompatibilityMatrixMarkdown,
  errors
} = require('../../src/integrations');
const { DiagnosticController } = require('../../src/diagnostics/diagnosticController');
const {
  createFakeVscode,
  createRawFinding
} = require('./diagnosticsFake');

/**
 * Build a read-only fake filesystem. Keys and lookups use the host path rules
 * so fixtures declared as POSIX paths still match the native path production
 * code builds (for example `D:\models\tiny\config.json` on Windows).
 *
 * @param {Record<string, string>} files
 */
function fakeFileSystem(files) {
  const entries = new Map(
    Object.entries(files).map(([filePath, contents]) => [path.resolve(filePath), contents])
  );
  return {
    readFileSync(filePath) {
      const key = path.resolve(String(filePath));
      if (!entries.has(key)) {
        const error = new Error(`ENOENT: ${key}`);
        error.code = 'ENOENT';
        throw error;
      }
      return entries.get(key);
    }
  };
}

test('fake filesystem resolves fixture keys with host path rules', () => {
  const fileSystem = fakeFileSystem({ '/models/tiny/config.json': '{"model_type":"gpt2"}' });

  assert.equal(
    fileSystem.readFileSync(path.join(path.resolve('/models/tiny'), 'config.json')),
    '{"model_type":"gpt2"}'
  );
  assert.throws(() => fileSystem.readFileSync('/models/missing/config.json'), /ENOENT/);
});

function createFakeFetch(response) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      json: async () => response.json
    };
  };
  return { fetchImpl, calls };
}

test('capability taxonomy enforces E implies D and F implies D and E', () => {
  assert.deepEqual(CAPABILITIES, ['A', 'B', 'C', 'D', 'E', 'F']);
  assert.ok(validateCapabilities(['E']).errors.some((message) => message.includes('capability D')));
  assert.ok(validateCapabilities(['F', 'D']).errors.some((message) => message.includes('capability E')));
  assert.deepEqual(validateCapabilities(['D', 'E', 'F']).errors, []);
  assert.throws(
    () => normalizeCapabilities(['E'], { hosted: true }),
    errors.ProviderCapabilityError
  );
});

test('editor provider exposes only capability A and never attributes an edit', () => {
  const provider = createEditorProvider();
  assert.deepEqual(provider.capabilities, ['A']);
  assert.equal(provider.observeChange({ uri: 'file:///workspace/app.py' }).authorAttribution, 'none');
  return assert.rejects(() => provider.generate({}), errors.ProviderUnsupportedCapabilityError);
});

test('generation adapter validates requests and records provenance without guessing', async () => {
  const request = createGenerationRequest({
    providerId: 'test',
    modelId: 'model-1',
    messages: [{ role: 'user', content: 'Return a parameterized query.' }]
  });
  assert.equal(request.temperature, 0);
  assert.match(request.requestId, /^gen-[0-9a-f]{16}$/);
  assert.throws(
    () =>
      createGenerationRequest({
        providerId: 'test',
        modelId: 'model-1',
        messages: [{ role: 'tool', content: 'bad' }]
      }),
    errors.ProviderGenerationError
  );

  const adapter = createGenerationAdapter({
    providerId: 'test',
    modelId: 'model-1',
    infer: () => ({ text: 'SELECT * FROM users WHERE id = ?', finishReason: 'stop' })
  });
  const response = await adapter.generate({
    messages: [{ role: 'user', content: 'Generate a safe query.' }]
  });
  assert.equal(response.text, 'SELECT * FROM users WHERE id = ?');
  assert.deepEqual(response.provenance.capabilities, ['B', 'C']);
  assert.equal(response.provenance.modelId, 'model-1');
});

test('local Hugging Face provider reads metadata and does not claim internal access', async () => {
  const fileSystem = fakeFileSystem({
    '/models/tiny/config.json': JSON.stringify({
      model_type: 'gpt2',
      num_hidden_layers: 6,
      hidden_size: 768,
      transformers_version: '4.40.0'
    })
  });
  const provider = createLocalHuggingFaceProvider({
    modelPath: '/models/tiny',
    fileSystem,
    generationAdapter: () => ({ text: 'safe output' })
  });
  assert.deepEqual(provider.capabilities, ['B', 'C']);
  assert.equal(provider.model.family, 'gpt2');
  assert.ok(provider.limitations.some((item) => item.includes('does not by itself grant')));
  await assert.rejects(() => provider.extractActivations({}), errors.ProviderInternalActivationError);
});

test('local Hugging Face provider reports D/E/F only for validated real accessors', () => {
  const fileSystem = fakeFileSystem({
    '/models/tiny/config.json': JSON.stringify({ model_type: 'gpt2' })
  });
  const provider = createLocalHuggingFaceProvider({
    modelPath: '/models/tiny',
    fileSystem,
    generationAdapter: () => ({ text: 'safe output' }),
    activationAccessor: {
      validated: true,
      artifactId: 'activation-reader-v1',
      method: 'documented.local.tensor.read',
      readActivations: () => ({ activations: [[0.1, -0.2]] }),
      saeArtifact: {
        validated: true,
        artifactId: 'sae-v1',
        mapping: 'validated mapping',
        extractFeatures: () => []
      },
      steeringContract: {
        configured: true,
        effectMetric: 'measured logit delta',
        run: () => ({ effect: 0.2 })
      }
    }
  });
  assert.deepEqual(provider.capabilities, ['B', 'C', 'D', 'E', 'F']);
});

test('extension API provider requires an official documented manifest', async () => {
  const missing = await createExtensionApiProvider({});
  assert.equal(missing.status, 'unavailable');
  assert.equal(missing.reasonCode, 'E_MANIFEST_REQUIRED');

  const hosted = await createExtensionApiProvider({
    manifest: {
      extensionId: 'publisher.assistant',
      apiVersion: '1.0.0',
      documentationUrl: 'https://example.com/api',
      capabilities: ['B', 'C', 'D'],
      generationMethod: 'generate',
      hosted: true
    },
    getExtensionApi: () => ({ generate: () => ({ text: 'safe output' }) })
  });
  assert.equal(hosted.status, 'unavailable');
  assert.equal(hosted.reasonCode, 'E_HOSTED_INTERNALS_FORBIDDEN');

  const official = await createExtensionApiProvider({
    manifest: {
      extensionId: 'publisher.assistant',
      apiVersion: '1.0.0',
      documentationUrl: 'https://example.com/api',
      capabilities: ['B', 'C'],
      generationMethod: 'generate',
      hosted: true
    },
    getExtensionApi: () => ({ generate: () => ({ text: 'safe output' }) })
  });
  assert.equal(official.status, 'available');
  assert.deepEqual(official.capabilities, ['B', 'C']);
  assert.match(official.documentedApi, /example\.com\/api/);
});

test('VS Code Language Model provider uses only documented API surfaces', async () => {
  const sent = [];
  const vscode = {
    LanguageModelChatMessage: {
      User: (content) => ({ role: 'user', content }),
      Assistant: (content) => ({ role: 'assistant', content })
    },
    lm: {
      async selectChatModels(selector) {
        assert.deepEqual(selector, { vendor: 'copilot' });
        return [
          {
            id: 'model-1',
            name: 'Test Model',
            family: 'gpt-4o',
            version: '1',
            async sendRequest(messages, options, token) {
              sent.push({ messages, options, token });
              return {
                text: (async function* () {
                  yield 'SELECT ';
                  yield '* FROM users WHERE id = ?';
                })()
              };
            }
          }
        ];
      }
    }
  };
  const provider = await createVscodeLanguageModelProvider({
    vscode,
    selector: { vendor: 'copilot' }
  });
  assert.equal(provider.status, 'available');
  assert.deepEqual(provider.capabilities, ['B', 'C']);
  const response = await provider.generate({
    messages: [
      { role: 'system', content: 'Prefer parameterized queries.' },
      { role: 'user', content: 'Write a query.' }
    ]
  });
  assert.equal(
    response.text,
    'SELECT * FROM users WHERE id = ?'
  );
  assert.equal(sent[0].messages[0].content, 'Prefer parameterized queries.\nWrite a query.');
  await assert.rejects(() => provider.extractActivations({}), errors.ProviderUnsupportedCapabilityError);
});

test('OpenAI-compatible provider sends only documented fields and maps provider errors', async () => {
  const { fetchImpl, calls } = createFakeFetch({
    status: 200,
    json: {
      choices: [{ message: { content: 'safe output' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 }
    }
  });
  const provider = createOpenAiCompatibleProvider({
    endpoint: 'https://llm.example.com/v1',
    model: 'example-model',
    apiKey: 'test-key',
    fetch: fetchImpl
  });
  assert.deepEqual(provider.capabilities, ['B', 'C']);
  const response = await provider.generate({
    messages: [{ role: 'user', content: 'Write safe code.' }]
  });
  assert.equal(response.text, 'safe output');
  assert.equal(response.usage.totalTokens, 7);
  assert.equal(calls[0].url, 'https://llm.example.com/v1/chat/completions');
  assert.equal(calls[0].init.headers.authorization, 'Bearer test-key');
  assert.equal(calls[0].init.body.includes('"stream":false'), true);

  assert.throws(
    () =>
      createOpenAiCompatibleProvider({
        endpoint: 'https://user:pass@llm.example.com/v1',
        model: 'example-model',
        fetch: fetchImpl
      }),
    errors.ProviderConfigurationError
  );

  const denied = createOpenAiCompatibleProvider({
    endpoint: 'https://llm.example.com/v1',
    model: 'example-model',
    fetch: createFakeFetch({ status: 401, json: {} }).fetchImpl
  });
  await assert.rejects(
    () => denied.generate({ messages: [{ role: 'user', content: 'test' }] }),
    errors.ProviderAuthenticationError
  );
});

test('registry defaults to editor monitoring and reports discovery failures honestly', async () => {
  const registry = createProviderRegistry({ settings: { provider: 'editor' } });
  let snapshot = await registry.refresh();
  assert.equal(snapshot.activeProviderId(), 'editor-monitor');
  assert.deepEqual(snapshot.capabilities(), ['A']);

  const failing = createProviderRegistry({
    settings: {
      provider: 'openai-compatible',
      openAiCompatible: { endpoint: '', model: '' }
    }
  });
  snapshot = await failing.refresh();
  assert.equal(snapshot.activeProviderId(), 'editor-monitor');
  const failedRecord = snapshot.records().find((record) => record.kind === 'openai-compatible');
  assert.equal(failedRecord.status, 'unavailable');
  assert.deepEqual(failedRecord.capabilities, []);
});

test('compatibility matrix marks internals conditional, never default-supported', () => {
  const rows = toCompatibilityMatrix();
  const local = rows.find((row) => row.kind === 'local-hugging-face');
  assert.equal(local.A, 'editor-fallback');
  assert.equal(local.D, 'conditional');
  assert.equal(local.E, 'conditional');
  assert.equal(local.F, 'conditional');
  const markdown = renderCompatibilityMatrixMarkdown();
  assert.match(markdown, /SAE integration/);
  assert.match(markdown, /Activation steering/);
});

test('security hooks record provenance only and block unavailable capabilities', async () => {
  const registry = createProviderRegistry({ settings: { provider: 'editor' } });
  await registry.refresh();
  const hooks = new SecurityHooks({ registry });
  const change = hooks.observeChange({
    uri: 'file:///workspace/app.py',
    version: 3,
    ranges: [{ startLine: 1, endLine: 4 }],
    reason: 'change'
  });
  assert.equal(change.authorAttribution, 'none');
  assert.equal(change.modelAttribution, 'none');
  assert.equal(hooks.getStatus().observationCounts.editor_change, 1);
  assert.equal(hooks.getStatus().sae.status, 'unavailable');
  assert.equal(hooks.getStatus().counterfactual.status, 'unavailable');
  assert.throws(
    () => hooks.observeGenerationRequest('editor-monitor', {}),
    errors.ProviderUnsupportedCapabilityError
  );

  const { fetchImpl } = createFakeFetch({
    status: 200,
    json: { choices: [{ message: { content: 'safe output' } }] }
  });
  const generationRegistry = createProviderRegistry({
    settings: {
      provider: 'openai-compatible',
      openAiCompatible: { endpoint: 'https://llm.example.com/v1', model: 'example-model' }
    },
    fetch: fetchImpl
  });
  await generationRegistry.refresh();
  const generationHooks = new SecurityHooks({ registry: generationRegistry });
  const provider = generationRegistry.getActiveProvider();
  const wrapped = generationHooks.wrapGeneration(provider.providerId, provider.generate);
  const response = await wrapped({ messages: [{ role: 'user', content: 'Write code.' }] });
  assert.equal(response.text, 'safe output');
  assert.equal(generationHooks.getStatus().observationCounts.generation_request, 1);
  assert.equal(generationHooks.getStatus().observationCounts.generation_response, 1);
  assert.ok(!JSON.stringify(generationHooks.getStatus()).includes('Write code.'));
});

test('diagnostics publish backend verification provenance without synthesizing findings', () => {
  const { vscode, collections, logger } = createFakeVscode();
  const controller = new DiagnosticController({ vscode, logger });
  const vulnerable = createRawFinding({
    id: 'finding-confirmed',
    verificationStatus: 'confirmed',
    evidence: 'SQL sink reached by request data; static rule agrees.'
  });
  const potential = createRawFinding({
    id: 'finding-potential',
    verificationStatus: 'potential',
    location: {
      uri: 'file:///workspace/src/app.py',
      range: { start: { line: 8, character: 0 }, end: { line: 8, character: 20 } }
    }
  });
  const result = controller.publishScanResult({
    findings: [vulnerable, potential],
    scope: { uris: ['file:///workspace/src/app.js', 'file:///workspace/src/app.py'] }
  });
  assert.equal(result.published, 2);
  const related = collections[0].entries.get('file:///workspace/src/app.js').flatMap(
    (diagnostic) => diagnostic.relatedInformation.map((item) => item.message)
  );
  assert.ok(related.some((message) => message.includes('Verification: confirmed')));

  const secure = controller.publishScanResult({
    findings: [],
    scope: { uris: ['file:///workspace/src/app.js', 'file:///workspace/src/app.py'] }
  });
  assert.equal(secure.published, 0);
  assert.equal(collections[0].entries.size, 0);
});
