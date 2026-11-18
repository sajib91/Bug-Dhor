'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createSecureCodeGenerator,
  extractCandidates,
  toProviderMetadata
} = require('../../src/recommendations/secureCodeGeneration');

const SOURCE = 'query = "SELECT * FROM users WHERE name = \'%s\'" % name\n';
const PATCH =
  '--- a/app.py\n' +
  '+++ b/app.py\n' +
  '@@ -1,1 +1,1 @@\n' +
  '-query = "SELECT * FROM users WHERE name = \'%s\'" % name\n' +
  '+cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n';

function createLogger() {
  return {
    entries: [],
    debug(message) {
      this.entries.push(['debug', message]);
    },
    warn(message) {
      this.entries.push(['warn', message]);
    },
    error(message) {
      this.entries.push(['error', message]);
    },
    info(message) {
      this.entries.push(['info', message]);
    }
  };
}

function createHarness(options = {}) {
  const calls = [];
  const finding = {
    id: 'finding-1',
    documentUri: 'file:///workspace/app.py',
    cwe: 'CWE-89',
    ruleId: 'BD-SQL-001',
    severity: 'high',
    message: 'String formatting reaches a SQL query.',
    evidence: 'Tainted request parameter reaches execute().',
    range: { start: { line: 0, character: 0 }, end: { line: 0, character: 60 } },
    repairEligible: true
  };
  const editor = {
    document: {
      uri: {
        toString: () => 'file:///workspace/app.py',
        fsPath: '/workspace/app.py'
      },
      version: 1,
      getText: () => SOURCE
    },
    selection: { start: { line: 0, character: 0 } }
  };
  const service = {
    generateRecommendation: async (request, context, label) => {
      calls.push({ request, context, label });
      if (calls.length === 1) {
        return {
          result: {
            prompt: {
              text: 'Secure prompt with <untrusted_source_file> data only.',
              promptHash: 'prompt-hash'
            }
          }
        };
      }
      return { result: { state: 'recommended', verified: true, requiresApproval: true } };
    },
    repairVulnerability: async () => {
      throw new Error('repairVulnerability must not be called');
    }
  };
  const provider = {
    providerId: options.providerId ?? 'hosted-assistant',
    model: { id: 'model-1' },
    capabilities: options.capabilities ?? ['B', 'C'],
    hosted: options.hosted ?? true,
    status: 'available',
    generate: async () => ({ text: '```diff\n' + PATCH + '\n```' })
  };
  const request = {
    workspaceFolder: '/workspace',
    workspaceFolderName: 'workspace',
    filePath: '/workspace/app.py',
    documentUri: 'file:///workspace/app.py',
    languageId: 'python',
    documentVersion: 1,
    sourceText: SOURCE,
    editor,
    finding
  };
  const generator = createSecureCodeGenerator({
    vscode: { window: { activeTextEditor: editor } },
    service,
    diagnostics: {
      findAt: () => options.findings === undefined ? [finding] : options.findings,
      getFindingsForUri: () => []
    },
    assistantRegistry: { getActiveProvider: () => options.noProvider ? undefined : provider },
    assistantHooks: options.noHooks
      ? undefined
      : {
          wrapGeneration: (_providerId, generate) => generate
        },
    getSettings: () => ({
      runFunctionalTests: true,
      allowSandboxedExecution: false,
      testCommand: ['pytest', '-q'],
      testTimeoutSeconds: 90
    }),
    logger: createLogger()
  });
  return { generator, request, service, calls, provider, finding };
}

test('extractCandidates accepts fenced diffs for the target file only', () => {
  const candidates = extractCandidates(`Explanation\n\`\`\`diff\n${PATCH}\n\`\`\`\n`, {
    source: SOURCE,
    targetPath: 'app.py',
    allowedPaths: ['app.py', 'src/app.py', '/workspace/app.py']
  });
  assert.deepEqual(candidates, [PATCH.trim()]);

  assert.deepEqual(
    extractCandidates(PATCH.replace('b/app.py', 'b/other.py'), {
      source: SOURCE,
      targetPath: 'app.py'
    }),
    []
  );
});

test('provider metadata never claims steering from the HTTP workflow', () => {
  assert.deepEqual(
    toProviderMetadata({
      providerId: 'local',
      modelId: 'model-2',
      capabilities: ['B', 'C', 'D', 'E', 'F'],
      hosted: false
    }),
    {
      providerId: 'local',
      modelId: 'model-2',
      capabilities: ['B', 'C', 'D', 'E', 'F'],
      hosted: false,
      steeringRequested: false,
      steeringValidated: false
    }
  );
});

test('secure generation obtains a prompt, calls a B/C provider, then verifies candidates', async () => {
  const { generator, request, calls } = createHarness();

  const result = await generator(request, { token: { isCancellationRequested: () => false } });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].label, 'Secure prompt');
  assert.deepEqual(calls[0].request.candidates, []);
  assert.equal(calls[0].request.provider.steeringRequested, false);
  assert.equal(calls[0].request.provider.steeringValidated, false);
  assert.equal(calls[0].request.runFunctionalTests, true);
  assert.equal(calls[0].request.executionConsent.granted, false);
  assert.equal(calls[0].request.executionConsent.allowNetwork, false);
  assert.deepEqual(calls[0].request.projectTestCommand, ['pytest', '-q']);
  assert.equal(calls[0].request.testTimeoutSeconds, 90);
  assert.deepEqual(calls[0].request.securityEvidence[0].type, 'backend_finding');

  assert.equal(calls[1].label, 'Secure recommendation verification');
  assert.deepEqual(calls[1].request.candidates, [PATCH.trim()]);
  assert.equal(calls[1].request.finding.findingId, 'finding-1');
  assert.match(calls[1].request.snapshotHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(result, { result: { state: 'recommended', verified: true, requiresApproval: true } });
});

test('monitor-only provider without generation access is rejected before any request', async () => {
  const { generator, request, calls } = createHarness({
    providerId: 'editor-monitor',
    capabilities: ['A'],
    hosted: false
  });

  await assert.rejects(
    generator(request, { token: { isCancellationRequested: () => false } }),
    /capabilities B and C/
  );
  assert.equal(calls.length, 0);
});

test('a command-palette invocation without a validated finding generates nothing', async () => {
  const { generator, request, calls } = createHarness({ findings: [] });

  await assert.rejects(
    generator(request, { token: { isCancellationRequested: () => false } }),
    /requires a Bug Dhor finding/
  );
  assert.equal(calls.length, 0);
});

test('cancellation after the secure prompt prevents a provider generation request', async () => {
  let generated = false;
  let cancelled = false;
  const harness = createHarness();
  harness.provider.generate = async () => {
    generated = true;
    return { text: PATCH };
  };
  const generator = createSecureCodeGenerator({
    vscode: { window: { activeTextEditor: harness.request.editor } },
    service: {
      generateRecommendation: async (request, context, label) => {
        harness.calls.push({ request, context, label });
        return {
          result: { prompt: { text: 'secure prompt', promptHash: 'hash' } }
        };
      }
    },
    diagnostics: { findAt: () => [harness.finding], getFindingsForUri: () => [] },
    assistantRegistry: { getActiveProvider: () => harness.provider },
    logger: createLogger()
  });
  const context = {
    token: { isCancellationRequested: () => cancelled },
    progress: {
      report(info) {
        if (String(info?.message ?? '').includes('Building')) {
          cancelled = true;
        }
      }
    }
  };

  const result = await generator(harness.request, context);
  assert.equal(result, undefined);
  assert.equal(generated, false);
  assert.equal(harness.calls.length, 1);
});
