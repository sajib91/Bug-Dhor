'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const { COMMANDS } = require('../../src/constants');
const { DIAGNOSTIC_SOURCE } = require('../../src/diagnostics/findingModel');

/** @param {number} ms */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** @param {string} text */
function sha256(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function bugdhorDiagnostics() {
  return vscode.languages
    .getDiagnostics()
    .flatMap(([uri, diagnostics]) =>
      diagnostics
        .filter((diagnostic) => diagnostic.source === DIAGNOSTIC_SOURCE)
        .map((diagnostic) => ({ uri, diagnostic }))
    );
}

/** @param {string} name @returns {string} */
function requiredEnvironment(name) {
  const value = process.env[name];
  assert.ok(value, `${name} must be provided by runUntrustedTest.js`);
  return value;
}

async function run() {
  const manifest = require('../../package.json');
  const extensionId = `${manifest.publisher}.${manifest.name}`;
  const extension = vscode.extensions.getExtension(extensionId);
  assert.ok(extension, `extension ${extensionId} must be discoverable`);
  const api = await extension.activate();
  assert.equal(extension.isActive, true, 'the extension must activate in an untrusted workspace');
  assert.ok(api, 'activation must expose the trust-gated extension API');

  for (const name of [
    'service',
    'configurationService',
    'checkBackendHealth',
    'monitor',
    'feedback',
    'assistantRegistry',
    'assistantHooks',
    'trustGate'
  ]) {
    assert.ok(api[name], `the activation API must expose ${name}`);
  }

  const backendUrl = requiredEnvironment('BUGDHOR_UNTRUSTED_BACKEND_URL');
  const workspacePath = requiredEnvironment('BUGDHOR_UNTRUSTED_WORKSPACE');
  const sourcePath = requiredEnvironment('BUGDHOR_UNTRUSTED_FILE');
  const diskSha256 = requiredEnvironment('BUGDHOR_UNTRUSTED_DISK_SHA256');
  const maliciousBackendUrl = requiredEnvironment('BUGDHOR_UNTRUSTED_MALICIOUS_BACKEND_URL');
  const maliciousSettingsPath = requiredEnvironment('BUGDHOR_UNTRUSTED_MALICIOUS_SETTINGS');
  const executionMarkerPath = requiredEnvironment('BUGDHOR_UNTRUSTED_EXECUTION_MARKER');
  const sourceMarker = requiredEnvironment('BUGDHOR_UNTRUSTED_SOURCE_MARKER');
  const requestLogPath = requiredEnvironment('BUGDHOR_UNTRUSTED_REQUEST_LOG');

  // -----------------------------------------------------------------------
  // Workspace trust must be genuinely off, not simulated by a fake.
  // -----------------------------------------------------------------------
  assert.equal(vscode.workspace.isTrusted, false, 'the test workspace must actually be untrusted');
  assert.equal(api.trustGate.isTrusted(), false);
  assert.throws(
    () => api.trustGate.assertCapability('sourceAnalysis'),
    (error) => error?.code === 'E_WORKSPACE_TRUST_REQUIRED'
  );
  assert.doesNotThrow(() => api.trustGate.assertCapability('health'));

  // -----------------------------------------------------------------------
  // The hostile workspace file must not affect machine-scoped configuration.
  // -----------------------------------------------------------------------
  const maliciousSettings = JSON.parse(fs.readFileSync(maliciousSettingsPath, 'utf8'));
  assert.equal(maliciousSettings['bugdhor.backend.url'], maliciousBackendUrl);
  assert.equal(maliciousSettings['bugdhor.privacy.sendSourceText'], true);
  assert.equal(maliciousSettings['bugdhor.monitoring.enabled'], true);

  const configuration = vscode.workspace.getConfiguration('bugdhor');
  assert.equal(
    configuration.get('backend.url'),
    backendUrl,
    'a workspace setting must not override the machine-scoped backend URL'
  );
  assert.equal(configuration.get('privacy.sendSourceText'), true);
  assert.equal(configuration.get('monitoring.enabled'), false);
  assert.equal(configuration.get('monitoring.allowAutomaticSourceSharing'), false);
  assert.equal(configuration.get('repository.autoScanOnWorkspaceOpen'), false);
  assert.equal(configuration.get('recommendations.allowSandboxedExecution'), false);
  assert.deepEqual(configuration.get('recommendations.testCommand'), []);
  assert.equal(configuration.get('localEngine.enabled'), false);
  assert.equal(configuration.get('localEngine.allowSourceWrite'), false);
  assert.equal(configuration.get('assistant.provider'), 'editor');
  assert.equal(configuration.get('assistant.openAiCompatible.endpoint'), '');
  assert.equal(configuration.get('assistant.sae.enabled'), false);
  assert.equal(configuration.get('assistant.counterfactual.enabled'), false);
  assert.equal(fs.existsSync(executionMarkerPath), false, 'no workspace-supplied command ran');

  const effectiveConfiguration = api.configurationService.get();
  assert.equal(effectiveConfiguration.baseUrl, backendUrl);
  assert.equal(
    effectiveConfiguration.sendSourceText,
    false,
    'workspace trust must force source sharing off even when user settings allow it'
  );
  assert.equal(
    api.configurationService.getRaw().sendSourceText,
    true,
    'the raw user setting should allow sharing; only the trust gate may override it'
  );

  // Exercise the remote-endpoint rejection through the live configuration
  // service. The temporary user-level update is restored in `finally`.
  await configuration.update('backend.url', maliciousBackendUrl, vscode.ConfigurationTarget.Global);
  try {
    assert.throws(
      () => api.configurationService.get(),
      (error) =>
        error?.name === 'ConfigurationError' && error?.code === 'E_UNTRUSTED_REMOTE_ENDPOINT',
      'an untrusted workspace must reject a non-loopback backend endpoint'
    );
  } finally {
    await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Global);
  }
  assert.equal(api.configurationService.get().baseUrl, backendUrl);

  // -----------------------------------------------------------------------
  // Every source-bearing operation is denied before a request is formed.
  // -----------------------------------------------------------------------
  const sourceText = fs.readFileSync(sourcePath, 'utf8');
  assert.ok(sourceText.includes(sourceMarker), 'the source fixture must contain its marker');
  const cancellation = new vscode.CancellationTokenSource();
  const context = { token: cancellation.token, progress: { report() {} } };
  /** @type {Record<string, unknown>} */
  const request = {
    workspaceFolder: workspacePath,
    workspaceFolderName: path.basename(workspacePath),
    filePath: sourcePath,
    documentUri: vscode.Uri.file(sourcePath).toString(),
    languageId: 'python',
    documentVersion: 1,
    sourceText,
    selectedText: sourceText,
    selection: { start: { line: 0, character: 0 }, end: { line: 1, character: 0 } },
    findingId: 'finding-not-used',
    finding: { id: 'finding-not-used' },
    patch: '--- a/unused\n+++ b/unused\n'
  };
  const sourceOperations = [
    'scanFile',
    'scanSelection',
    'scanWorkspace',
    'explainVulnerability',
    'analyzeSecurityFeatures',
    'counterfactualAnalysis',
    'generateSecureCode',
    'generateRecommendation',
    'repairVulnerability',
    'generateRepair',
    'verifyRepair'
  ];
  try {
    for (const operation of sourceOperations) {
      assert.equal(typeof api.service[operation], 'function', `${operation} must be exposed`);
      assert.throws(
        () => api.service[operation](request, context),
        (error) =>
          error?.name === 'WorkspaceTrustError' && error?.code === 'E_WORKSPACE_TRUST_REQUIRED',
        `${operation} must be blocked in an untrusted workspace`
      );
    }
  } finally {
    cancellation.dispose();
  }

  // Health is the one capability an untrusted workspace may use.
  const directHealth = await api.service.health({});
  assert.equal(directHealth.status, 'ok');
  assert.equal(directHealth.apiVersion, 'v1');
  assert.equal(typeof directHealth.capabilities, 'object');
  const checkedHealth = await api.checkBackendHealth();
  assert.ok(checkedHealth, 'the loopback health check must remain available');
  assert.equal(checkedHealth.status, 'ok');

  const commands = await vscode.commands.getCommands(true);
  for (const command of Object.values(COMMANDS)) {
    assert.ok(commands.includes(command), `${command} must be registered`);
  }

  // -----------------------------------------------------------------------
  // Exercise ordinary editor activity. No monitor, scan, diagnostic, or disk
  // change may follow from it in an untrusted workspace.
  // -----------------------------------------------------------------------
  const document = await vscode.workspace.openTextDocument(sourcePath);
  const editor = await vscode.window.showTextDocument(document, { preview: false });
  assert.equal(editor.document.getText(), sourceText);
  const edit = new vscode.WorkspaceEdit();
  edit.insert(document.uri, new vscode.Position(0, 0), '# untrusted in-memory edit\n');
  assert.equal(await vscode.workspace.applyEdit(edit), true);
  assert.equal(editor.document.isDirty, true, 'the edit must stay in memory only');
  await delay(1_000);

  const monitorStats = api.monitor.getStats();
  assert.equal(monitorStats.registeredEvents, false, 'background monitoring must not be started');
  assert.equal(monitorStats.enabled, false);
  assert.equal(monitorStats.analyses.length, 0, 'no background analysis may be recorded');
  assert.equal(monitorStats.workspace.fullScans, 0, 'no automatic workspace scan may run');
  assert.equal(monitorStats.workspace.openEvents, 0);
  assert.equal(api.assistantRegistry.refreshedAt, null, 'assistant discovery must be skipped');
  assert.deepEqual(api.assistantRegistry.records(), []);
  assert.deepEqual(api.feedback.getSnapshot().stats, {
    scans: 0,
    suppressed: 0,
    followUpRescans: 0,
    patches: 0,
    verifications: 0,
    resolutions: 0
  });
  assert.deepEqual(bugdhorDiagnostics(), [], 'no Bug Dhor diagnostics may be published');
  assert.equal(
    sha256(fs.readFileSync(sourcePath, 'utf8')),
    diskSha256,
    'the source file is unchanged'
  );
  assert.equal(fs.existsSync(executionMarkerPath), false, 'no workspace-controlled command ran');

  // -----------------------------------------------------------------------
  // The recorder saw only health requests, with no body or source text.
  // -----------------------------------------------------------------------
  const requests = JSON.parse(fs.readFileSync(requestLogPath, 'utf8'));
  assert.ok(Array.isArray(requests), 'the request log must be a JSON array');
  assert.ok(requests.length > 0, 'the loopback health check must have reached the recorder');
  for (const request of requests) {
    assert.equal(
      request.url,
      '/api/v1/health',
      `unexpected request ${request.method} ${request.url}`
    );
    assert.equal(request.method, 'GET');
    assert.equal(request.body, '', 'no request may carry a body');
    assert.equal(
      JSON.stringify(request).includes(sourceMarker),
      false,
      'no request may contain source text'
    );
  }

  console.log('Untrusted workspace Extension Host assertions passed.');
}

module.exports = {
  async run() {
    let watchdog;
    try {
      await Promise.race([
        run(),
        new Promise((_, reject) => {
          watchdog = setTimeout(
            () => reject(new Error('Untrusted workspace checks exceeded 3 minutes.')),
            3 * 60_000
          );
        })
      ]);
    } catch (error) {
      const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
      console.error(`Bug Dhor untrusted workspace failure: ${detail}`);
      throw error;
    } finally {
      clearTimeout(watchdog);
    }
  }
};
