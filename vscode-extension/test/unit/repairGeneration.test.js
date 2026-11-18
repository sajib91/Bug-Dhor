'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createRepairGenerator } = require('../../src/repair/repairGeneration');

const SOURCE = "query = 'SELECT * FROM users WHERE name = %s' % name\n";
const PATCH =
  '--- a/app.py\n' +
  '+++ b/app.py\n' +
  '@@ -1,1 +1,1 @@\n' +
  "-query = 'SELECT * FROM users WHERE name = %s' % name\n" +
  '+cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n';

const FINDING = {
  findingId: 'finding-1',
  documentUri: 'file:///workspace/app.py',
  range: { start: { line: 0, character: 0 }, end: { line: 0, character: 60 } },
  cwe: 'CWE-89',
  severity: 'high',
  message: 'String formatting reaches a SQL query.',
  evidence: 'Untrusted parameter reaches execute().',
  repairEligible: true
};

function createHarness(options = {}) {
  const calls = [];
  const editor = {
    document: {
      uri: { toString: () => 'file:///workspace/app.py', fsPath: '/workspace/app.py' },
      getText: () => SOURCE
    },
    selection: { start: { line: 0, character: 0 } }
  };
  const service = {
    generateRecommendation: async (request, context, label) => {
      calls.push({ method: 'generateRecommendation', request, context, label });
      if (options.prompt === undefined) {
        return { result: { prompt: { text: 'Repair prompt.', promptHash: 'prompt-hash' } } };
      }
      return { result: { prompt: options.prompt } };
    },
    repairVulnerability: async (request, context) => {
      calls.push({ method: 'repairVulnerability', request, context });
      return { result: { analysisAvailable: true, requiresApproval: true, patch: PATCH } };
    }
  };
  const provider = {
    providerId: options.providerId ?? 'configured-provider',
    model: { id: 'model-1' },
    capabilities: options.capabilities ?? ['B', 'C'],
    status: options.status ?? 'available',
    hosted: false,
    async generate(request, context) {
      calls.push({ method: 'provider.generate', request, context });
      return { text: options.providerText ?? `\`\`\`diff\n${PATCH}\n\`\`\`` };
    }
  };
  const request = {
    workspaceFolder: '/workspace',
    workspaceFolderName: 'workspace',
    filePath: '/workspace/app.py',
    documentUri: 'file:///workspace/app.py',
    languageId: 'python',
    sourceText: SOURCE,
    editor,
    finding: options.omitFinding ? undefined : FINDING
  };
  const generator = createRepairGenerator({
    vscode: { window: { activeTextEditor: editor } },
    service,
    diagnostics: {
      findAt: () => [FINDING],
      getFindingsForUri: () => []
    },
    assistantRegistry: {
      getActiveProvider: () => (options.noProvider ? undefined : provider)
    },
    assistantHooks: {
      wrapGeneration: (_providerId, generate) => generate
    },
    getSettings: () => ({
      runFunctionalTests: true,
      allowSandboxedExecution: false,
      testCommand: ['pytest', '-q'],
      testTimeoutSeconds: 90
    }),
    logger: { debug() {}, warn() {}, error() {}, info() {} }
  });
  return { generator, request, calls, provider };
}

async function rejectsWithCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code);
    return true;
  });
}

test('repair generation obtains a prompt, calls a configured B/C provider, then verifies one patch', async () => {
  const { generator, request, calls } = createHarness();
  const token = { isCancellationRequested: () => false };

  const result = await generator(request, { token, progress: { report() {} } });

  assert.deepEqual(
    calls.map((call) => call.method),
    ['generateRecommendation', 'provider.generate', 'repairVulnerability']
  );
  assert.equal(calls[0].label, 'Repair prompt');
  assert.deepEqual(calls[0].request.candidates, []);
  assert.equal(calls[0].request.provider.steeringRequested, false);
  assert.equal(calls[0].request.runFunctionalTests, true);
  assert.equal(calls[0].request.executionConsent.granted, false);
  assert.equal(calls[0].request.executionConsent.allowNetwork, false);
  assert.deepEqual(calls[0].request.projectTestCommand, ['pytest', '-q']);
  assert.equal(calls[0].request.securityEvidence[0].type, 'backend_finding');
  assert.equal(calls[2].request.patch, PATCH.trim());
  assert.equal(calls[2].request.generate, false);
  assert.match(calls[2].request.snapshotHash, /^[a-f0-9]{64}$/);
  assert.equal(result.result.requiresApproval, true);
});

test('repair generation rejects a missing or capability-limited provider', async () => {
  const noProvider = createHarness({ noProvider: true });
  await rejectsWithCode(
    noProvider.generator(noProvider.request, { token: { isCancellationRequested: () => false } }),
    'E_PROVIDER_UNAVAILABLE'
  );
  assert.equal(noProvider.calls.length, 0);

  const capabilityA = createHarness({ capabilities: ['A'] });
  await rejectsWithCode(
    capabilityA.generator(capabilityA.request, { token: { isCancellationRequested: () => false } }),
    'E_PROVIDER_CAPABILITY_REQUIRED'
  );
  assert.equal(capabilityA.calls.length, 0);
});

test('repair generation rejects an unusable prompt or a provider response without a patch', async () => {
  const noPrompt = createHarness({ prompt: null });
  await rejectsWithCode(
    noPrompt.generator(noPrompt.request, { token: { isCancellationRequested: () => false } }),
    'E_REPAIR_PROMPT_UNAVAILABLE'
  );
  assert.equal(noPrompt.calls.length, 1);

  const noPatch = createHarness({ providerText: 'No unified diff was produced.' });
  await rejectsWithCode(
    noPatch.generator(noPatch.request, { token: { isCancellationRequested: () => false } }),
    'E_NO_CANDIDATE'
  );
  assert.deepEqual(
    noPatch.calls.map((call) => call.method),
    ['generateRecommendation', 'provider.generate']
  );
});

test('repair generation selects a published finding for palette invocations', async () => {
  const { generator, request, calls } = createHarness({ omitFinding: true });

  await generator(request, { token: { isCancellationRequested: () => false } });

  assert.equal(calls[0].request.finding.findingId, FINDING.findingId);
  assert.equal(calls[2].request.finding.findingId, FINDING.findingId);
});
