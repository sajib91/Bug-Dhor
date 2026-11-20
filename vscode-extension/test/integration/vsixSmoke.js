'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { DASHBOARD_TITLE } = require('../../src/webviews/dashboardPanel');
const manifest = require('../../package.json');
const { canonicalPath, fileUriMatchesPath } = require('./pathUtils');

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

/**
 * Wait for the extension's own lifecycle manager to bring the bundled engine
 * online. No external process is started by this test.
 *
 * @param {{ engineManager: { getStatus: () => object } }} api
 * @param {number} [timeoutMs]
 */
async function waitForManagedEngine(api, timeoutMs = 240_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = api.engineManager.getStatus();
    if (last.state === 'online') {
      return last;
    }
    if (last.state === 'startup_failed' || last.state === 'not_installed') {
      throw new Error(`Managed engine failed to start: ${JSON.stringify(last)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Managed engine did not come online: ${JSON.stringify(last)}`);
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
  assert.ok(api.engineManager, 'the installed extension must expose its engine lifecycle manager');

  const installedRoot = process.env.BUGDHOR_VSIX_INSTALLED_ROOT;
  assert.ok(installedRoot, 'BUGDHOR_VSIX_INSTALLED_ROOT must be provided by runVsixTest.js');
  assert.equal(
    canonicalPath(extension.extensionPath),
    canonicalPath(installedRoot),
    'the activated extension must be the one installed from the VSIX'
  );
  for (const asset of [
    path.join('engine', 'src', 'bugdhor', '__main__.py'),
    path.join('engine', 'pyproject.toml'),
    path.join('engine', 'requirements-runtime.txt')
  ]) {
    assert.ok(
      fs.existsSync(path.join(extension.extensionPath, asset)),
      `${asset} must resolve inside the installed VSIX`
    );
  }

  const configuration = vscode.workspace.getConfiguration('bugdhor');
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Global);
  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Global);

  const engineStatus = await waitForManagedEngine(api);
  assert.equal(engineStatus.owned, true, 'the extension must own the engine process it started');
  assert.equal(
    engineStatus.errorKind,
    undefined,
    'a clean managed startup must not report a runtime-install or startup error'
  );
  console.log(
    `Clean-install managed engine reached ${engineStatus.state} (pid ${engineStatus.pid}).`
  );

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

  // Full Repository Scan is the exact path that used to fail with
  // `body.filePaths: Extra inputs are not permitted`. It must now send only the
  // stable workspaceFolders field and return a real backend response.
  const repositoryScan = await vscode.commands.executeCommand(COMMANDS.scanRepository);
  assert.ok(repositoryScan, 'Full Repository Scan must return a validated backend result');
  assert.equal(repositoryScan.operation, 'scan_workspace');
  assert.equal(repositoryScan.apiVersion, 'v1');
  assert.equal(repositoryScan.analysisAvailable, true);
  assert.ok(['ok', 'partial'].includes(repositoryScan.status));
  assert.ok(repositoryScan.filesScanned >= 1, 'the managed engine must enumerate a workspace file');
  assert.deepEqual(
    repositoryScan.findings,
    [],
    'benign files must not produce fabricated findings'
  );
  assert.ok(
    Array.isArray(repositoryScan.scope?.uris) &&
      repositoryScan.scope.uris.some((uri) =>
        fileUriMatchesPath(uri, sourcePath, { parseUri: (value) => vscode.Uri.parse(value) })
      ),
    'diagnostics scope must come from the backend response'
  );
  const statusAfterScan = api.engineManager.getStatus();
  assert.notEqual(statusAfterScan.state, 'startup_failed');
  assert.equal(statusAfterScan.errorKind, undefined);

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
