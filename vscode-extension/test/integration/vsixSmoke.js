'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vscode = require('vscode');

const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { DASHBOARD_TITLE } = require('../../src/webviews/dashboardPanel');
const manifest = require('../../package.json');
const { canonicalPath } = require('./pathUtils');

/** @param {string} label @param {number} [timeoutMs] */
async function waitForTab(label, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tab = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .find((entry) => entry.label === label);
    if (tab) {
      return tab;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return undefined;
}

async function run() {
  const extensionId = process.env.BUGDHOR_VSIX_ID ?? `${manifest.publisher}.${manifest.name}`;
  const expectedVersion = process.env.BUGDHOR_VSIX_VERSION ?? manifest.version;
  const backendUrl = process.env.BUGDHOR_VSIX_BACKEND_URL;
  const workspacePath = process.env.BUGDHOR_VSIX_WORKSPACE;
  const sourcePath = process.env.BUGDHOR_VSIX_FILE;
  const diskSha256 = process.env.BUGDHOR_VSIX_DISK_SHA256;

  for (const [name, value] of Object.entries({
    backendUrl,
    workspacePath,
    sourcePath,
    diskSha256
  })) {
    assert.ok(value, `${name} must be provided by runVsixTest.js`);
  }

  const extension = vscode.extensions.getExtension(extensionId);
  assert.ok(
    extension,
    `the extension installed from the VSIX (${extensionId}) must be discoverable`
  );
  assert.equal(
    extension.packageJSON.version,
    expectedVersion,
    'the installed VSIX must contain the expected extension version'
  );
  const api = await extension.activate();
  assert.equal(extension.isActive, true, 'the installed extension must activate');
  assert.equal(typeof api.checkBackendHealth, 'function');
  assert.equal(typeof api.service.health, 'function');

  const configuration = vscode.workspace.getConfiguration('bugdhor');
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Global);
  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Global);

  const health = await api.checkBackendHealth();
  assert.ok(health, `the installed extension must reach the backend at ${backendUrl}`);
  assert.equal(health.status, 'ok');
  assert.equal(health.apiVersion, 'v1');
  const direct = await api.service.health({});
  assert.equal(direct.service, health.service);
  assert.equal(direct.version, health.version);

  const commands = await vscode.commands.getCommands(true);
  for (const command of [
    COMMANDS.scanCurrentFile,
    COMMANDS.scanWorkspace,
    COMMANDS.openSecurityDashboard
  ]) {
    assert.ok(commands.includes(command), `${command} must be registered by the installed VSIX`);
  }

  const document = await vscode.workspace.openTextDocument(sourcePath);
  await vscode.window.showTextDocument(document, { preview: false });
  const scan = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(scan, 'the installed extension must return a validated backend scan');
  assert.equal(scan.operation, 'scan_file');
  assert.equal(scan.apiVersion, 'v1');
  assert.equal(scan.analysisAvailable, true);
  assert.deepEqual(scan.findings, [], 'benign code must not produce fabricated findings');
  assert.equal(scan.filesScanned, 1);
  assert.equal(scan.file.path, canonicalPath(sourcePath));
  assert.equal(
    scan.file.sha256,
    crypto
      .createHash('sha256')
      .update(Buffer.from(await fs.promises.readFile(sourcePath)))
      .digest('hex'),
    'the scan must hash the UTF-8 source from the Unicode workspace path'
  );
  assert.equal(scan.file.sha256, diskSha256);

  const contributes = extension.packageJSON.contributes;
  const container = contributes.viewsContainers.activitybar.find(
    (entry) => entry.id === CONTAINER_ID
  );
  assert.ok(container, 'the Activity Bar container must be contributed by the installed VSIX');
  const sidebar = contributes.views[CONTAINER_ID].find((entry) => entry.id === VIEW_ID);
  assert.ok(sidebar, 'the sidebar view must be contributed by the installed VSIX');
  assert.equal(sidebar.type, 'webview');

  await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
  assert.ok(
    await waitForTab(DASHBOARD_TITLE),
    'the dashboard webview must render in the installed VSIX'
  );

  console.log('Bug Dhor VSIX smoke checks passed.');
}

module.exports = {
  async run() {
    try {
      await run();
    } catch (error) {
      const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
      console.error(`Bug Dhor VSIX smoke failure: ${detail}`);
      throw error;
    }
  }
};
