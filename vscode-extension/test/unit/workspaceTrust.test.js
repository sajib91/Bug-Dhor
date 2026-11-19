'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createConfigurationService } = require('../../src/api/configurationService');
const {
  applyWorkspaceTrustToSettings,
  endpointPolicyViolation,
  isOperationAllowed
} = require('../../src/security/trustPolicy');
const {
  WorkspaceTrustError,
  createTrustGate,
  createTrustedService
} = require('../../src/security/trustGate');

function fakeVscode(trusted, trustEmitter) {
  return {
    workspace: {
      isTrusted: trusted,
      onDidChangeWorkspaceTrust(listener) {
        trustEmitter.listener = listener;
        return { dispose() {} };
      },
      getConfiguration() {
        return {
          get(key, fallback) {
            return fallback;
          }
        };
      }
    }
  };
}

test('untrusted workspaces allow health only', () => {
  assert.equal(isOperationAllowed({ trusted: false, operation: 'health' }), true);
  for (const operation of ['scanFile', 'scanWorkspace', 'repairVulnerability', 'localEngine']) {
    assert.equal(isOperationAllowed({ trusted: false, operation }), false);
  }
  assert.equal(isOperationAllowed({ trusted: true, operation: 'scanFile' }), true);
});

test('untrusted settings override every source-egress and execution opt-in', () => {
  const settings = applyWorkspaceTrustToSettings(
    {
      sendSourceText: true,
      monitoringEnabled: true,
      monitoringAllowAutomaticSourceSharing: true,
      repositoryAutoScanOnWorkspaceOpen: true,
      recommendationAllowSandboxedExecution: true,
      localEngineEnabled: true,
      localEngineAllowSourceWrite: true,
      assistantProvider: 'openai-compatible',
      assistantOpenAiEndpoint: 'https://assistant.example.test/v1'
    },
    false
  );

  assert.equal(settings.sendSourceText, false);
  assert.equal(settings.monitoringEnabled, false);
  assert.equal(settings.monitoringAllowAutomaticSourceSharing, false);
  assert.equal(settings.repositoryAutoScanOnWorkspaceOpen, false);
  assert.equal(settings.recommendationAllowSandboxedExecution, false);
  assert.equal(settings.localEngineEnabled, false);
  assert.equal(settings.localEngineAllowSourceWrite, false);
  assert.equal(settings.assistantProvider, 'editor');
  assert.equal(settings.assistantOpenAiEndpoint, '');
});

test('endpoint policy requires HTTPS and trust for non-loopback backends', () => {
  assert.equal(
    endpointPolicyViolation({ baseUrl: 'http://127.0.0.1:8765', trusted: false }),
    undefined
  );
  assert.equal(
    endpointPolicyViolation({ baseUrl: 'https://engine.example.test', trusted: false }),
    'E_UNTRUSTED_REMOTE_ENDPOINT'
  );
  assert.equal(
    endpointPolicyViolation({ baseUrl: 'http://engine.example.test', trusted: true }),
    'E_INSECURE_REMOTE_ENDPOINT'
  );
  assert.equal(
    endpointPolicyViolation({ baseUrl: 'https://engine.example.test', trusted: true }),
    undefined
  );
});

test('trust gate fails closed and wraps every service method', async () => {
  const emitter = {};
  const vscode = fakeVscode(false, emitter);
  const gate = createTrustGate({ vscode });
  assert.equal(gate.isTrusted(), false);
  assert.throws(
    () => gate.assertCapability('scanFile'),
    (error) => error.code === 'E_WORKSPACE_TRUST_REQUIRED'
  );
  assert.doesNotThrow(() => gate.assertCapability('health'));

  let sourceCalls = 0;
  const service = {
    async health() {
      return { status: 'ok' };
    },
    async scanFile() {
      sourceCalls += 1;
      return { findings: [] };
    }
  };
  const trustedService = gate.createTrustedService(service);
  await assert.rejects(
    Promise.resolve().then(() => trustedService.scanFile({})),
    (error) => error.code === 'E_WORKSPACE_TRUST_REQUIRED'
  );
  {
    assert.equal(sourceCalls, 0);
    assert.deepEqual(await trustedService.health({}), { status: 'ok' });

    emitter.listener({ isTrusted: true });
    assert.equal(gate.isTrusted(), true);
    await trustedService.scanFile({});
    assert.equal(sourceCalls, 1);
    gate.dispose();
  }
});

test('configuration service denies remote endpoints in untrusted workspaces', () => {
  const settings = { 'backend.url': 'https://engine.example.test' };
  const vscode = {
    workspace: {
      isTrusted: false,
      getConfiguration() {
        return { get: (key, fallback) => settings[key] ?? fallback };
      }
    }
  };
  const service = createConfigurationService({ vscode });
  assert.throws(
    () => service.get(),
    (error) => error.code === 'E_UNTRUSTED_REMOTE_ENDPOINT'
  );
});

test('configuration service rejects insecure non-loopback endpoints in trusted workspaces', () => {
  const settings = { 'backend.url': 'http://engine.example.test' };
  const vscode = {
    workspace: {
      isTrusted: true,
      getConfiguration() {
        return { get: (key, fallback) => settings[key] ?? fallback };
      }
    }
  };
  const service = createConfigurationService({ vscode });
  assert.throws(
    () => service.get(),
    (error) => error.code === 'E_INSECURE_REMOTE_ENDPOINT'
  );
});

test('trusted service proxy and trust errors expose stable types', () => {
  assert.equal(new WorkspaceTrustError('scanFile').name, 'WorkspaceTrustError');
  assert.throws(() => createTrustedService(null, () => true), /requires a service object/);
});
