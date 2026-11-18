'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const vscode = require('vscode');
const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { DASHBOARD_TITLE } = require('../../src/webviews/dashboardPanel');
const { DIAGNOSTIC_SOURCE } = require('../../src/diagnostics/findingModel');

const VULNERABLE_FILE = 'vulnerable.py';
const VULNERABLE_SOURCE = [
  'import sqlite3',
  '',
  '',
  'def login(username):',
  '    conn = sqlite3.connect("app.db")',
  '    cur = conn.cursor()',
  '    query = "SELECT * FROM users WHERE name=\'" + username + "\'"',
  '    cur.execute(query)',
  '    return cur.fetchone()',
  ''
].join('\n');
const REPAIR_PATCH = [
  '--- a/vulnerable.py',
  '+++ b/vulnerable.py',
  '@@ -4,6 +4,5 @@',
  ' def login(username):',
  '     conn = sqlite3.connect("app.db")',
  '     cur = conn.cursor()',
  '-    query = "SELECT * FROM users WHERE name=\'" + username + "\'"',
  '-    cur.execute(query)',
  '+    cur.execute("SELECT * FROM users WHERE name=?", (username,))',
  '     return cur.fetchone()',
  ''
].join('\n');

async function waitForTab(label, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
    const tab = tabs.find((entry) => entry.label === label);
    if (tab) {
      return tab;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return undefined;
}

/**
 * @param {string} text
 * @returns {string}
 */
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

async function waitForBugdhorDiagnostics(uri, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const entries = bugdhorDiagnostics().filter((entry) => entry.uri.toString() === uri.toString());
    if (entries.length > 0) {
      return entries;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return [];
}

async function assertBackendHealth(api, backendUrl) {
  const health = await api.checkBackendHealth();
  assert.ok(health, `the extension must reach the backend at ${backendUrl}`);
  assert.equal(health.status, 'ok');
  assert.equal(health.apiVersion, 'v1');
  assert.equal(typeof health.capabilities, 'object');

  const direct = await api.service.health({});
  assert.equal(direct.service, health.service);
  assert.equal(direct.version, health.version);
}

async function run() {
  const manifest = require('../../package.json');
  const extensionId = `${manifest.publisher}.${manifest.name}`;
  const extension = vscode.extensions.getExtension(extensionId);

  assert.ok(extension, `extension ${extensionId} must be discoverable`);
  const api = await extension.activate();
  assert.equal(extension.isActive, true, 'extension must activate');
  assert.ok(api, 'activation must expose the backend service and health check');
  assert.equal(typeof api.checkBackendHealth, 'function');
  assert.equal(typeof api.service.health, 'function');
  assert.equal(typeof api.configurationService.get, 'function');

  const backendUrl = process.env.BUGDHOR_E2E_BACKEND_URL;
  const workspacePath = process.env.BUGDHOR_E2E_WORKSPACE;
  const sourcePath = process.env.BUGDHOR_E2E_FILE;
  const diskSha256 = process.env.BUGDHOR_E2E_DISK_SHA256;
  assert.ok(backendUrl, 'BUGDHOR_E2E_BACKEND_URL must be provided by runTest.js');
  assert.ok(workspacePath, 'BUGDHOR_E2E_WORKSPACE must be provided by runTest.js');
  assert.ok(sourcePath, 'BUGDHOR_E2E_FILE must be provided by runTest.js');
  assert.ok(diskSha256, 'BUGDHOR_E2E_DISK_SHA256 must be provided by runTest.js');

  const configuration = vscode.workspace.getConfiguration('bugdhor');
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Workspace);
  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Workspace);

  await assertBackendHealth(api, backendUrl);

  const commands = await vscode.commands.getCommands(true);
  for (const command of Object.values(COMMANDS)) {
    assert.ok(commands.includes(command), `${command} must be registered`);
  }

  assert.equal(
    bugdhorDiagnostics().length,
    0,
    'activation must not publish hardcoded Bug Dhor diagnostics'
  );

  // End-to-end file scan: the unsaved editor buffer must be what the backend
  // hashes, not the stale saved copy on disk.
  const document = await vscode.workspace.openTextDocument(sourcePath);
  const editor = await vscode.window.showTextDocument(document, { preview: false });
  assert.equal(editor.document.isDirty, false);

  const inserted = '# E2E unsaved marker\n';
  assert.equal(
    await editor.edit((builder) => builder.insert(new vscode.Position(0, 0), inserted)),
    true
  );
  assert.equal(editor.document.isDirty, true);
  const unsavedText = editor.document.getText();
  assert.notEqual(unsavedText, undefined);
  assert.notEqual(sha256(unsavedText), diskSha256);

  const scan = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(scan, 'the file scan must return a validated backend response');
  assert.equal(scan.operation, 'scan_file');
  assert.equal(scan.apiVersion, 'v1');
  assert.equal(scan.analysisAvailable, true, 'the backend must report its analysis state honestly');
  assert.deepEqual(scan.findings, [], 'benign code must not produce fabricated findings');
  assert.equal(scan.filesScanned, 1);
  assert.equal(
    scan.file.path,
    fs.realpathSync(sourcePath),
    'the backend must report the resolved path of the scanned file'
  );
  assert.ok(scan.file.uri.startsWith('file:'), 'the scanned file must be a file URI');
  assert.equal(
    scan.file.sha256,
    sha256(unsavedText),
    'the backend must hash the unsaved editor buffer, not the disk copy'
  );
  assert.notEqual(scan.file.sha256, diskSha256);
  assert.equal(
    bugdhorDiagnostics().length,
    0,
    'a scan with no findings must not publish diagnostics'
  );

  // With source sharing disabled the backend must fall back to the saved file.
  await configuration.update('privacy.sendSourceText', false, vscode.ConfigurationTarget.Workspace);
  assert.equal(
    await editor.edit((builder) =>
      builder.insert(new vscode.Position(0, 0), '# E2E consent disabled\n')
    ),
    true
  );
  assert.notEqual(sha256(editor.document.getText()), diskSha256);

  const withoutConsent = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(withoutConsent);
  assert.equal(
    withoutConsent.file.sha256,
    diskSha256,
    'without consent the backend must inspect the saved file only'
  );

  await configuration.update('privacy.sendSourceText', true, vscode.ConfigurationTarget.Workspace);

  // Workspace scans send metadata only; benign sources yield no findings.
  const workspaceScan = await vscode.commands.executeCommand(COMMANDS.scanWorkspace);
  assert.ok(workspaceScan);
  assert.equal(workspaceScan.operation, 'scan_workspace');
  assert.ok(workspaceScan.filesScanned >= 1);
  assert.equal(workspaceScan.analysisAvailable, true);
  assert.deepEqual(workspaceScan.findings, []);
  assert.ok(
    workspaceScan.scope.uris.every((uri) => uri.startsWith('file:')),
    'workspace scope must contain only file URIs'
  );

  // A selection scan exercises the detection transport and reports the
  // backend's analysis state honestly; benign code yields no findings.
  editor.selection = new vscode.Selection(0, 0, 0, 10);
  const selectionScan = await vscode.commands.executeCommand(COMMANDS.scanSelection);
  assert.ok(selectionScan);
  assert.equal(selectionScan.operation, 'detection_analyze');
  assert.equal(selectionScan.analysisAvailable, true);
  assert.deepEqual(selectionScan.findings, []);
  assert.deepEqual(selectionScan.scope.uris, [document.uri.toString()]);

  // An unreachable backend must be reported as unavailable, never as a clean
  // analysis. Port 1 on loopback refuses connections immediately.
  await configuration.update(
    'backend.url',
    'http://127.0.0.1:1',
    vscode.ConfigurationTarget.Workspace
  );
  assert.equal(await api.checkBackendHealth(), undefined);
  await configuration.update('backend.url', backendUrl, vscode.ConfigurationTarget.Workspace);
  await assertBackendHealth(api, backendUrl);

  const contributes = extension.packageJSON.contributes;
  const container = contributes.viewsContainers.activitybar.find(
    (entry) => entry.id === CONTAINER_ID
  );
  assert.ok(container, 'activity bar container must be contributed');

  const sidebar = contributes.views[CONTAINER_ID].find((view) => view.id === VIEW_ID);
  assert.ok(sidebar, 'sidebar webview must be contributed');
  assert.equal(sidebar.type, 'webview');

  assert.equal(configuration.get('logging.level'), 'info');
  assert.equal(configuration.get('ui.showStatusBarItem'), true);

  await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
  const dashboardTab = await waitForTab(DASHBOARD_TITLE);
  assert.ok(dashboardTab, 'the dashboard panel must open in an editor tab');

  await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
  const dashboardTabs = vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .filter((entry) => entry.label === DASHBOARD_TITLE);
  assert.equal(dashboardTabs.length, 1, 'the dashboard panel must be a singleton');

  // ---------------------------------------------------------------------
  // Real-time monitoring. The monitored files are benign, so these checks
  // verify scheduling, debouncing, function-level scoping, cancellation,
  // privacy gating, and that no finding is fabricated for clean code.
  // ---------------------------------------------------------------------
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function waitForMonitor(predicate, timeoutMs = 10_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) {
        return;
      }
      await delay(50);
    }
    throw new Error('Timed out waiting for Bug Dhor monitor state.');
  }

  function completedAnalyses(uri) {
    return api.monitor
      .getStats()
      .analyses.filter((entry) => entry.uri === uri && entry.status === 'completed');
  }

  async function openMonitoringFile(name, initialText) {
    const filePath = path.join(workspacePath, name);
    fs.writeFileSync(filePath, initialText, 'utf8');
    const document = await vscode.workspace.openTextDocument(filePath);
    return { document, uri: document.uri.toString() };
  }

  // WorkspaceEdit fires onDidChangeTextDocument without requiring a visible,
  // still-open TextEditor, which keeps these scenarios independent of tab churn.
  function applyInsert(document, newText) {
    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, new vscode.Position(0, 0), newText);
    return vscode.workspace.applyEdit(edit);
  }

  function applyReplace(document, range, newText) {
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, range, newText);
    return vscode.workspace.applyEdit(edit);
  }

  await configuration.update('monitoring.enabled', true, vscode.ConfigurationTarget.Workspace);
  await configuration.update('monitoring.debounceMs', 400, vscode.ConfigurationTarget.Workspace);
  await configuration.update(
    'monitoring.analysisScope',
    'function',
    vscode.ConfigurationTarget.Workspace
  );
  await configuration.update(
    'monitoring.allowAutomaticSourceSharing',
    true,
    vscode.ConfigurationTarget.Workspace
  );
  assert.equal(api.monitor.getStats().enabled, true);

  // Rapid changes from ordinary editor edits collapse into one scan of the
  // newest version. No attribution to any model is made or inferred.
  const rapid = await openMonitoringFile('rapid.py', 'value = 0\n');
  for (let index = 1; index <= 5; index += 1) {
    assert.equal(await applyInsert(rapid.document, `# rapid ${index}\n`), true);
  }
  await waitForMonitor(() => completedAnalyses(rapid.uri).length === 1);
  await delay(500);
  assert.equal(
    completedAnalyses(rapid.uri).length,
    1,
    'rapid edits must produce exactly one debounced analysis'
  );
  assert.equal(completedAnalyses(rapid.uri)[0].version, rapid.document.version);
  assert.equal('sourceText' in completedAnalyses(rapid.uri)[0], false);

  // A paste is a single bulk edit; its inserted lines are identified and the
  // enclosing JavaScript functions become the analysis target.
  const pasted = await openMonitoringFile('paste.js', 'const start = 0;\n');
  const pastedText = [
    'function first() {',
    '  return 1;',
    '}',
    '',
    'function second() {',
    '  return 2;',
    '}',
    ''
  ].join('\n');
  assert.equal(await applyInsert(pasted.document, pastedText), true);
  await waitForMonitor(() => completedAnalyses(pasted.uri).length === 1);
  await delay(500);
  assert.equal(completedAnalyses(pasted.uri).length, 1, 'a paste must produce one scan');
  assert.equal(completedAnalyses(pasted.uri)[0].kind, 'function');
  assert.ok(completedAnalyses(pasted.uri)[0].changedLines >= 7);

  // Saving flushes immediately with a file-level scan and supersedes any
  // pending debounced edit for the same document.
  const saved = await openMonitoringFile('saved.py', 'value = 1\n');
  assert.equal(await applyReplace(saved.document, new vscode.Range(0, 0, 0, 9), 'value = 2'), true);
  assert.equal(await saved.document.save(), true);
  await waitForMonitor(() => completedAnalyses(saved.uri).length === 1);
  await delay(500);
  assert.equal(completedAnalyses(saved.uri).length, 1);
  assert.equal(completedAnalyses(saved.uri)[0].reason, 'save');
  assert.equal(completedAnalyses(saved.uri)[0].kind, 'file');

  // Edits to different documents are tracked independently.
  const concurrentA = await openMonitoringFile('concurrent-a.py', 'a = 0\n');
  const concurrentB = await openMonitoringFile('concurrent-b.js', 'const b = 0;\n');
  await Promise.all([
    applyInsert(concurrentA.document, '# concurrent a\n'),
    applyInsert(concurrentB.document, '// concurrent b\n')
  ]);
  await waitForMonitor(
    () =>
      completedAnalyses(concurrentA.uri).length === 1 &&
      completedAnalyses(concurrentB.uri).length === 1
  );
  assert.equal(completedAnalyses(concurrentA.uri).length, 1);
  assert.equal(completedAnalyses(concurrentB.uri).length, 1);

  // With explicit automatic consent disabled, no background request is sent
  // even when monitoring is enabled and the general sharing setting is true.
  await configuration.update(
    'monitoring.allowAutomaticSourceSharing',
    false,
    vscode.ConfigurationTarget.Workspace
  );
  const skippedBefore = api.monitor.getStats().skipped;
  assert.equal(await applyInsert(concurrentA.document, '# no consent\n'), true);
  await delay(600);
  assert.equal(completedAnalyses(concurrentA.uri).length, 1);
  assert.ok(api.monitor.getStats().skipped > skippedBefore);

  await configuration.update('monitoring.enabled', false, vscode.ConfigurationTarget.Workspace);
  await configuration.update('monitoring.debounceMs', 750, vscode.ConfigurationTarget.Workspace);
  assert.equal(
    bugdhorDiagnostics().length,
    0,
    'benign monitored edits must never fabricate diagnostics'
  );

  // ---------------------------------------------------------------------
  // Vulnerable end-to-end workflow. This exercises a real detector finding,
  // unified heuristic risk, an evidence-grounded explanation, honest SAE and
  // counterfactual stubs, a proposal-only repair, and independent verification
  // with an explicit caller-supplied patch. No patch is applied to the editor
  // or disk, and no finding is marked resolved by this workflow.
  // ---------------------------------------------------------------------
  const vulnerablePath = path.join(workspacePath, VULNERABLE_FILE);
  fs.writeFileSync(vulnerablePath, VULNERABLE_SOURCE, 'utf8');
  const vulnerableDocument = await vscode.workspace.openTextDocument(vulnerablePath);
  const vulnerableEditor = await vscode.window.showTextDocument(vulnerableDocument, {
    preview: false
  });
  assert.equal(vulnerableEditor.document.getText(), VULNERABLE_SOURCE);

  const vulnerableScan = await vscode.commands.executeCommand(COMMANDS.scanCurrentFile);
  assert.ok(vulnerableScan, 'the vulnerable fixture must reach the real backend');
  assert.equal(vulnerableScan.operation, 'scan_file');
  assert.equal(vulnerableScan.analysisAvailable, true);
  assert.ok(vulnerableScan.findings.length > 0, 'the detector must produce a real finding');
  const finding = vulnerableScan.findings.find((entry) => entry.cwe === 'CWE-89');
  assert.ok(finding, 'the SQL-injection fixture must produce a CWE-89 finding');

  const risk = finding.riskAssessment;
  assert.ok(risk, 'the backend must enrich a real finding with unified risk evidence');
  assert.equal(risk.scoreKind, 'heuristic_index');
  assert.equal(risk.probability, null);
  assert.equal(risk.probabilityKind, null);
  assert.ok(typeof risk.index === 'number' && risk.index >= 0 && risk.index <= 1);
  assert.ok(typeof risk.band === 'string' && risk.band.length > 0);
  assert.ok(risk.evidenceCount >= 1);
  assert.ok(risk.configHash);
  assert.ok(risk.explanation.some((line) => /not a probability/i.test(line)));

  const published = await waitForBugdhorDiagnostics(vulnerableDocument.uri);
  assert.ok(
    published.length > 0,
    `a real finding must become a native diagnostic; saw ${bugdhorDiagnostics().length} ` +
      `Bug Dhor diagnostic(s), finding URI ${finding.location.uri}, document URI ` +
      `${vulnerableDocument.uri.toString()}`
  );
  assert.equal(
    published[0].diagnostic.source,
    DIAGNOSTIC_SOURCE,
    'the diagnostic must come from the validated backend finding'
  );

  const hoverPosition = new vscode.Position(
    finding.location.range.start.line,
    finding.location.range.start.character + 1
  );
  const hovers = await vscode.commands.executeCommand(
    'vscode.executeHoverProvider',
    vulnerableDocument.uri,
    hoverPosition
  );
  const hoverText = (hovers ?? [])
    .flatMap((hover) => (Array.isArray(hover.contents) ? hover.contents : [hover.contents]))
    .map((part) => (typeof part === 'string' ? part : (part?.value ?? '')))
    .join('\n');
  assert.match(hoverText, /heuristic index/);
  assert.match(hoverText, /not a calibrated probability/);
  assert.match(hoverText, /Backend evidence items/);

  const explanation = await vscode.commands.executeCommand(COMMANDS.explainVulnerability, {
    findingId: finding.id
  });
  assert.ok(explanation);
  assert.equal(explanation.operation, 'explanation_analyze');
  assert.equal(explanation.result.analysisAvailable, true);
  assert.equal(explanation.result.findingId, finding.id);
  assert.ok(explanation.result.graph, 'a matching backend finding must produce a real graph');
  assert.equal(explanation.result.graph.cwe, 'CWE-89');
  assert.ok(explanation.result.claimKinds.length > 0);
  assert.ok(
    explanation.result.limitations.some((line) => /No model-internal feature/i.test(line)),
    'the explanation must state that no model-internal evidence was used'
  );

  const cancellationSource = new vscode.CancellationTokenSource();
  const engineContext = {
    token: cancellationSource.token,
    progress: { report() {} }
  };
  const backendRequest = {
    workspaceFolder: workspacePath,
    workspaceFolderName: 'workspace',
    filePath: vulnerablePath,
    documentUri: vulnerableDocument.uri.toString(),
    languageId: 'python',
    documentVersion: vulnerableDocument.version,
    sourceText: VULNERABLE_SOURCE
  };

  const features = await api.service.analyzeSecurityFeatures(backendRequest, engineContext);
  assert.equal(features.operation, 'features_extract');
  assert.equal(features.result.analysisAvailable, false);
  assert.deepEqual(features.result.features, []);

  const counterfactual = await api.service.counterfactualAnalysis(
    {
      ...backendRequest,
      findingId: finding.id,
      interventions: [{ kind: 'ablate', featureIndices: [0], strength: 1 }]
    },
    engineContext
  );
  assert.equal(counterfactual.operation, 'counterfactual_analyze');
  assert.equal(counterfactual.result.scope, 'model_intervention');
  assert.deepEqual(counterfactual.result.effects, []);
  cancellationSource.dispose();

  const feedbackBeforeRepair = api.feedback.getSnapshot();
  const trackedBefore = feedbackBeforeRepair.findings.find(
    (entry) => entry.findingId === finding.id
  );
  assert.ok(trackedBefore, 'the scan must be recorded separately from research tracking');
  assert.notEqual(trackedBefore.state, 'resolved');

  // The default editor provider exposes capability A only. Repair generation
  // must therefore fail honestly instead of inventing a proposal, and it must
  // leave the scanned source untouched.
  const repair = await vscode.commands.executeCommand(COMMANDS.repairVulnerability, {
    findingId: finding.id,
    documentUri: vulnerableDocument.uri.toString(),
    range: finding.location.range,
    cwe: finding.cwe,
    ruleId: finding.ruleId
  });
  assert.equal(
    repair,
    undefined,
    'repair generation must not return a proposal without a configured B/C provider'
  );
  assert.equal(
    vulnerableEditor.document.getText(),
    VULNERABLE_SOURCE,
    'repair must not edit source'
  );
  assert.equal(fs.readFileSync(vulnerablePath, 'utf8'), VULNERABLE_SOURCE);
  const trackedAfterRepair = api.feedback
    .getSnapshot()
    .findings.find((entry) => entry.findingId === finding.id);
  assert.notEqual(trackedAfterRepair?.state, 'resolved', 'no patch was applied');

  const verificationsBefore = api.feedback.getSnapshot().stats.verifications;
  const verification = await vscode.commands.executeCommand(COMMANDS.verifyRepair, {
    findingId: finding.id,
    patch: REPAIR_PATCH,
    profile: 'static_only',
    runExecution: false
  });
  assert.ok(verification);
  assert.equal(verification.operation, 'verification_run');
  assert.ok(verification.result);
  assert.ok(
    ['passed', 'failed', 'inconclusive', 'not_run'].includes(verification.result.verdict),
    'the verifier must report one of its declared verdicts'
  );
  assert.ok(Array.isArray(verification.result.checks));
  assert.ok(Array.isArray(verification.result.limitations));
  assert.equal(typeof verification.result.sandboxBackend, 'string');
  assert.equal(
    api.feedback.getSnapshot().stats.verifications,
    verificationsBefore + 1,
    'verification must be recorded in ordinary finding feedback, not as research evidence'
  );
  assert.equal(vulnerableEditor.document.getText(), VULNERABLE_SOURCE);
  assert.equal(fs.readFileSync(vulnerablePath, 'utf8'), VULNERABLE_SOURCE);
  assert.notEqual(
    api.feedback.getSnapshot().findings.find((entry) => entry.findingId === finding.id)?.state,
    'resolved',
    'verification alone must not resolve a finding without an approved applied patch'
  );

  console.log('Bug Dhor Extension Host checks passed.');
}

module.exports = { run };
