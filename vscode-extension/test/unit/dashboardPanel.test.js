'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const {
  DashboardPanelController,
  DASHBOARD_TITLE,
  DASHBOARD_VIEW_TYPE,
  EXECUTABLE_COMMANDS
} = require('../../src/webviews/dashboardPanel');

function createUri(path) {
  return {
    path,
    fsPath: path,
    scheme: 'file',
    toString() {
      return `file://${path}`;
    }
  };
}

function createFakeVscode(options = {}) {
  const createdPanels = [];
  const executedCommands = [];
  const openedDocuments = [];
  const shownDocuments = [];
  const appliedEdits = [];
  let documentText = options.documentText ?? 'const value = 1;\n';
  let documentVersion = options.documentVersion ?? 1;
  const document = {
    uri: createUri('/workspace/src/app.js'),
    version: documentVersion,
    getText() {
      return documentText;
    },
    positionAt(offset) {
      const prefix = documentText.slice(0, offset);
      const lines = prefix.split('\n');
      return new Position(lines.length - 1, lines.at(-1).length);
    }
  };
  class WorkspaceEdit {
    constructor() {
      this.edits = [];
    }
    replace(uri, range, text) {
      this.edits.push({ uri, range, text });
    }
  }

  const vscode = {
    ViewColumn: { One: 1 },
    Uri: {
      parse(value) {
        return createUri(value.replace(/^file:\/\//, ''));
      },
      joinPath(base, ...parts) {
        const separator = base.path.endsWith('/') ? '' : '/';
        return createUri(`${base.path}${separator}${parts.join('/')}`);
      },
      file(filePath) {
        return createUri(filePath);
      }
    },
    WorkspaceEdit,
    window: {
      createWebviewPanel(viewType, title, column, panelOptions) {
        const panel = createFakePanel({ options: panelOptions, viewType, title, column });
        createdPanels.push(panel);
        return panel;
      },
      async showTextDocument(document, options) {
        shownDocuments.push({ document, options });
      },
      async showWarningMessage(message, modalOptions, action) {
        if (typeof options.approval === 'function') {
          return options.approval(message, action);
        }
        return options.approval ?? undefined;
      }
    },
    workspace: {
      workspaceFolders: [{ uri: createUri('/workspace') }],
      async openTextDocument(uri) {
        if (uri?.path === document.uri.path) {
          openedDocuments.push(document);
          return document;
        }
        const opened = { uri };
        openedDocuments.push(opened);
        return opened;
      },
      async applyEdit(edit) {
        appliedEdits.push(edit);
        const replacement = edit.edits[0];
        if (replacement) {
          documentText = replacement.text;
          documentVersion += 1;
          document.version = documentVersion;
        }
        return options.applyEditResult ?? true;
      }
    },
    Position,
    Range,
    commands: {
      async executeCommand(command, ...args) {
        executedCommands.push({ command, args });
        const error = options.commandErrors?.get(command);
        if (error) {
          throw error;
        }
        return undefined;
      }
    }
  };

  return {
    vscode,
    createdPanels,
    executedCommands,
    openedDocuments,
    shownDocuments,
    appliedEdits,
    document,
    setDocumentText(text) {
      documentText = text;
      documentVersion += 1;
      document.version = documentVersion;
    }
  };
}

class Position {
  constructor(line, character) {
    this.line = line;
    this.character = character;
  }
}

class Range {
  constructor(start, end) {
    this.start = start;
    this.end = end;
  }
}

function createFakePanel({ options, viewType, title, column }) {
  const messageHandlers = new Set();
  const disposeHandlers = new Set();
  const postedMessages = [];
  const revealCalls = [];

  const panel = {
    viewType,
    title,
    viewColumn: column,
    options,
    iconPath: undefined,
    disposed: false,
    postedMessages,
    revealCalls,
    webview: {
      cspSource: 'vscode-webview://test',
      html: '',
      options,
      asWebviewUri(uri) {
        return {
          toString() {
            return `vscode-webview://test${uri.path}`;
          }
        };
      },
      onDidReceiveMessage(handler) {
        messageHandlers.add(handler);
        return {
          dispose() {
            messageHandlers.delete(handler);
          }
        };
      },
      async postMessage(message) {
        postedMessages.push(message);
        return true;
      }
    },
    reveal(viewColumn) {
      revealCalls.push(viewColumn);
      return this;
    },
    onDidDispose(handler) {
      disposeHandlers.add(handler);
      return {
        dispose() {
          disposeHandlers.delete(handler);
        }
      };
    },
    dispose() {
      if (this.disposed) {
        return;
      }
      this.disposed = true;
      for (const handler of [...disposeHandlers]) {
        handler();
      }
      disposeHandlers.clear();
    },
    async send(message) {
      for (const handler of [...messageHandlers]) {
        await handler(message);
      }
    },
    messageHandlerCount() {
      return messageHandlers.size;
    }
  };

  return panel;
}

function createFakeLogger() {
  const entries = [];
  const logger = {
    entries,
    shown: false,
    trace(message) {
      entries.push({ level: 'trace', message });
    },
    debug(message) {
      entries.push({ level: 'debug', message });
    },
    info(message) {
      entries.push({ level: 'info', message });
    },
    warn(message) {
      entries.push({ level: 'warn', message });
    },
    error(message, error) {
      entries.push({ level: 'error', message, error });
    },
    show() {
      logger.shown = true;
    },
    applySettings() {},
    dispose() {}
  };
  return logger;
}

function createHarness(options = {}) {
  const fake = createFakeVscode(options);
  const logger = createFakeLogger();
  const stateCalls = [];
  const controller = new DashboardPanelController({
    vscode: fake.vscode,
    extensionUri: createUri('/extension'),
    logger,
    feedback: options.feedback,
    memento: options.memento,
    getState() {
      stateCalls.push('state');
      return {
        dataMode: 'empty',
        generatedAt: '2026-11-11T12:00:00.000Z',
        request: stateCalls.length
      };
    }
  });

  return { ...fake, logger, stateCalls, controller };
}

const REPAIR_PATCH =
  '--- a/src/app.js\n' +
  '+++ b/src/app.js\n' +
  '@@ -1,1 +1,1 @@\n' +
  '-const value = 1;\n' +
  '+const value = 2;\n';

function repairResponse(patch = REPAIR_PATCH) {
  return {
    result: {
      analysisAvailable: true,
      patch,
      metadata: {
        repairId: 'repair-1',
        modelId: 'test-model',
        verificationStatus: 'not-run'
      }
    }
  };
}

function repairRequest() {
  return {
    documentUri: 'file:///workspace/src/app.js',
    filePath: '/workspace/src/app.js',
    workspaceFolder: '/workspace',
    languageId: 'javascript',
    finding: { findingId: 'finding-1' }
  };
}

function verificationResponse(overrides = {}) {
  return {
    result: {
      analysisAvailable: true,
      repairId: 'repair-1',
      verdict: 'passed',
      classification: 'verified_security_improvement',
      profile: 'static_only',
      checks: [
        {
          checkId: 'check-01',
          kind: 'security',
          name: 'Static security comparison',
          status: 'passed'
        }
      ],
      sandboxBackend: 'none',
      limitations: ['No isolated execution backend was available.'],
      report: {
        priorWorkflowEvidence: {
          repairId: 'repair-1',
          state: 'FULLY_VERIFIED',
          beforeAfterComparison: { security: { before: 1, after: 0 } }
        }
      },
      ...overrides
    }
  };
}

function recommendationResponse() {
  return {
    result: {
      analysisAvailable: true,
      findingId: 'finding-1',
      cwe: 'CWE-89',
      state: 'recommended',
      verified: true,
      requiresApproval: true,
      originalCode: 'const value = 1;\n',
      repairedCode: 'const value = 2;\n',
      selected: {
        candidateId: 'selected',
        patch: REPAIR_PATCH,
        verification: { verdict: 'passed' },
        functional: { passRate: 1 }
      },
      candidates: [],
      prompt: { promptHash: 'prompt-hash', steeringApplied: false },
      stages: [],
      explanation: {
        summary: 'Uses a parameterized query.',
        changes: ['Replaced string interpolation with a bound parameter.'],
        why: ['Untrusted input no longer changes the SQL syntax.'],
        remainingRisks: ['Database permissions still need review.'],
        functionalAssurance: 'Unit tests passed.'
      },
      metadata: { recommendationId: 'recommendation-1', modelId: 'test-model' }
    }
  };
}

test('dashboard panel opens once with local-resource and script options', () => {
  const harness = createHarness();

  const panel = harness.controller.open();

  assert.equal(harness.createdPanels.length, 1);
  assert.equal(panel, harness.createdPanels[0]);
  assert.equal(panel.viewType, DASHBOARD_VIEW_TYPE);
  assert.equal(panel.title, DASHBOARD_TITLE);
  assert.equal(panel.webview.options.enableScripts, true);
  assert.equal(panel.webview.options.retainContextWhenHidden, true);
  assert.equal(panel.webview.options.localResourceRoots.length, 1);
  assert.equal(panel.webview.options.localResourceRoots[0].path, '/extension/media');
  assert.equal(panel.iconPath.path, '/extension/media/icon.png');
  assert.match(panel.webview.html, /default-src &#39;none&#39;/);
  assert.match(panel.webview.html, /Loading dashboard/);
  assert.ok(!panel.webview.html.includes('unsafe-inline'));
  assert.deepEqual(harness.stateCalls, ['state']);
  assert.equal(panel.messageHandlerCount(), 1);

  harness.controller.dispose();
});

test('repair approval applies a single-file patch and keeps verification separate', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  await harness.controller.recordRepairResult(repairResponse(), repairRequest());

  await harness.controller.acceptRepair({ repairId: 'repair-1', candidateId: 'selected' });

  assert.equal(harness.appliedEdits.length, 1);
  assert.equal(harness.document.getText(), 'const value = 2;\n');
  assert.equal(harness.controller.repairRecords.get('repair-1').status, 'accepted');
  assert.equal(harness.controller.repairRecords.get('repair-1').verificationStatus, 'not-run');
});

test('a rejected repair candidate cannot be applied', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  const response = repairResponse();
  response.result.metadata.candidates = [
    {
      candidateId: 'rejected',
      patch: REPAIR_PATCH,
      accepted: false,
      rejectionReason: 'mandatory verification gate failed'
    }
  ];
  await harness.controller.recordRepairResult(response, repairRequest());

  await harness.controller.acceptRepair({ repairId: 'repair-1', candidateId: 'rejected' });

  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(harness.document.getText(), 'const value = 1;\n');
});

test('a verified full-text proposal applies when no candidate patch exists', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  const response = recommendationResponse();
  response.result.selected.patch = '';
  response.result.candidates = [];
  await harness.controller.recordRecommendationResult(response, repairRequest());

  await harness.controller.acceptRepair({ repairId: 'recommendation-1' });

  assert.equal(harness.appliedEdits.length, 1);
  assert.equal(harness.document.getText(), 'const value = 2;\n');
});

test('a full-text proposal larger than 2 MiB is rejected', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  const response = recommendationResponse();
  response.result.selected.patch = '';
  response.result.candidates = [];
  response.result.repairedCode = 'x'.repeat(2 * 1024 * 1024 + 1);
  await harness.controller.recordRecommendationResult(response, repairRequest());

  await harness.controller.acceptRepair({ repairId: 'recommendation-1' });

  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(harness.document.getText(), 'const value = 1;\n');
});

test('repair approval starts verification with the stored repair identity', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  const panel = harness.controller.open();
  await harness.controller.recordRepairResult(repairResponse(), repairRequest());

  await harness.controller.acceptRepair({ repairId: 'repair-1', candidateId: 'selected' });

  const verificationCall = harness.executedCommands.find(
    (call) => call.command === COMMANDS.verifyRepair
  );
  assert.ok(verificationCall);
  assert.equal(verificationCall.args[0].repairId, 'repair-1');
  assert.equal(verificationCall.args[0].patch, REPAIR_PATCH);
  assert.equal(verificationCall.args[0].findingId, 'finding-1');
  assert.ok(!('cwe' in verificationCall.args[0]));

  await harness.controller.recordVerificationResult(verificationResponse(), {
    repairId: 'repair-1'
  });
  const state = panel.postedMessages.at(-1).state;
  const [repair] = state.repairs;
  assert.equal(repair.verificationStatus, 'passed');
  assert.equal(repair.verification.verdict, 'passed');
  assert.equal(repair.verification.report.priorWorkflowEvidence.state, 'FULLY_VERIFIED');
  assert.ok(repair.verifiedAt);
});

test('repair proposals surface workflow, functional, and before/after evidence', async () => {
  const harness = createHarness({ documentText: 'const value = 1;\n' });
  const panel = harness.controller.open();
  const response = repairResponse();
  response.result.workflow = {
    state: 'FULLY_VERIFIED',
    steps: [{ name: 'Run independent security checks', status: 'completed', detail: 'passed' }],
    security: { classification: 'verified_security_improvement', verdict: 'passed' },
    functional: { status: 'passed', executed: true },
    comparison: { security: { before: 1, after: 0 }, regressions: [] }
  };

  await harness.controller.recordRepairResult(response, repairRequest());

  const state = panel.postedMessages.at(-1).state;
  const [repair] = state.repairs;
  assert.equal(repair.state, 'FULLY_VERIFIED');
  assert.equal(repair.securityVerification.verdict, 'passed');
  assert.equal(repair.functionalVerification.status, 'passed');
  assert.deepEqual(repair.beforeAfterComparison.regressions, []);
  assert.equal(repair.workflowSteps[0].name, 'Run independent security checks');
});

test('repair acceptance rejects stale document content', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  await harness.controller.recordRepairResult(repairResponse(), repairRequest());
  harness.setDocumentText('const value = 9;\n');
  await harness.controller.acceptRepair({ repairId: 'repair-1' });

  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(harness.controller.repairRecords.get('repair-1').status, 'stale');
});

test('recommendation result records original and repaired code without applying a patch', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await harness.controller.recordRecommendationResult(recommendationResponse(), repairRequest());

  const state = panel.postedMessages.at(-1).state;
  assert.equal(state.recommendations.length, 1);
  assert.equal((state.repairs ?? []).length, 0);
  const [recommendation] = state.recommendations;
  assert.equal(recommendation.originalCode, 'const value = 1;\n');
  assert.equal(recommendation.repairedCode, 'const value = 2;\n');
  assert.equal(recommendation.state, 'recommended');
  assert.equal(recommendation.verificationStatus, 'passed');
  assert.equal(recommendation.requiresApproval, true);
  assert.deepEqual(recommendation.explanation.changes, [
    'Replaced string interpolation with a bound parameter.'
  ]);
  assert.deepEqual(recommendation.explanation.why, [
    'Untrusted input no longer changes the SQL syntax.'
  ]);
  assert.deepEqual(recommendation.explanation.remainingRisks, [
    'Database permissions still need review.'
  ]);
  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(harness.document.getText(), 'const value = 1;\n');
});

test('an approved recommendation application records applied-patch feedback only after the edit', async () => {
  const recorded = [];
  const feedback = {
    recordAppliedPatch(entry) {
      recorded.push(entry);
    }
  };
  const harness = createHarness({ approval: 'Apply Fix', feedback });
  await harness.controller.recordRecommendationResult(recommendationResponse(), repairRequest());

  await harness.controller.acceptRepair({
    repairId: 'recommendation-1',
    candidateId: 'selected'
  });

  assert.equal(harness.appliedEdits.length, 1);
  assert.equal(harness.document.getText(), 'const value = 2;\n');
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].findingId, 'finding-1');
  assert.equal(recorded[0].source, 'dashboard.explicit-approval');
  assert.match(recorded[0].patchHash, /^[a-f0-9]{64}$/);
  assert.match(recorded[0].appliedHash, /^[a-f0-9]{64}$/);
});

test('a stale recommendation snapshot cannot record applied-patch feedback', async () => {
  const recorded = [];
  const harness = createHarness({
    approval: 'Apply Fix',
    feedback: {
      recordAppliedPatch(entry) {
        recorded.push(entry);
      }
    }
  });
  await harness.controller.recordRecommendationResult(recommendationResponse(), repairRequest());
  harness.setDocumentText('const value = 9;\n');

  await harness.controller.acceptRepair({ repairId: 'recommendation-1' });

  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(recorded.length, 0);
});

test('repair rejection does not modify the source', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: undefined
  });
  await harness.controller.recordRepairResult(repairResponse(), repairRequest());
  await harness.controller.acceptRepair({ repairId: 'repair-1' });

  assert.equal(harness.appliedEdits.length, 0);
  assert.equal(harness.document.getText(), 'const value = 1;\n');
});

test('restore requires approval and restores the captured original', async () => {
  const harness = createHarness({
    documentText: 'const value = 1;\n',
    approval: 'Apply Fix'
  });
  await harness.controller.recordRepairResult(repairResponse(), repairRequest());
  await harness.controller.acceptRepair({ repairId: 'repair-1' });
  harness.vscode.window.showWarningMessage = async () => 'Restore Original';

  await harness.controller.restoreRepair({ repairId: 'repair-1' });

  assert.equal(harness.document.getText(), 'const value = 1;\n');
  assert.equal(harness.controller.repairRecords.get('repair-1').status, 'restored');
});

test('opening an existing dashboard reveals the same panel', () => {
  const harness = createHarness();
  const first = harness.controller.open();

  const second = harness.controller.open();

  assert.equal(second, first);
  assert.equal(harness.createdPanels.length, 1);
  assert.deepEqual(first.revealCalls, [1]);
  assert.deepEqual(harness.stateCalls, ['state']);

  harness.controller.dispose();
});

test('ready and refresh messages post the current state', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'ready' });
  await panel.send({ type: 'refresh' });

  assert.deepEqual(harness.stateCalls, ['state', 'state']);
  assert.deepEqual(panel.postedMessages, [
    {
      type: 'state',
      state: {
        dataMode: 'empty',
        generatedAt: '2026-11-11T12:00:00.000Z',
        request: 1,
        findingReviews: {},
        repairHistory: []
      }
    },
    {
      type: 'state',
      state: {
        dataMode: 'empty',
        generatedAt: '2026-11-11T12:00:00.000Z',
        request: 2,
        findingReviews: {},
        repairHistory: []
      }
    }
  ]);

  harness.controller.dispose();
});

test('live backend results replace unavailable dashboard data without inventing fields', () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  harness.controller.updateLiveState({
    vulnerabilities: [{ findingId: 'finding-1' }],
    explanations: [{ findingId: 'finding-1', analysisAvailable: true }]
  });

  assert.deepEqual(panel.postedMessages.at(-1), {
    type: 'state',
    state: {
      dataMode: 'live',
      generatedAt: '2026-11-11T12:00:00.000Z',
      request: 2,
      vulnerabilities: [{ findingId: 'finding-1' }],
      explanations: [{ findingId: 'finding-1', analysisAvailable: true }],
      findingReviews: {},
      repairHistory: []
    }
  });

  harness.controller.dispose();
});

test('live runtime state is merged into the dashboard without inventing fields', () => {
  const harness = createHarness();
  const panel = harness.controller.open();
  const patch = {
    engine: {
      state: 'ready',
      detail: 'Local engine is reachable at http://127.0.0.1:8765.',
      managed: true
    },
    monitoring: {
      enabled: true,
      registeredEvents: true,
      scheduled: 4,
      completed: 3,
      skipped: 1,
      failed: 0,
      notifications: 2
    },
    counters: { findings: 7, scans: 3, repairs: 1 }
  };

  harness.controller.updateLiveState(patch);

  const message = panel.postedMessages.at(-1);
  assert.equal(message.type, 'state');
  assert.equal(message.state.dataMode, 'live');
  assert.deepEqual(message.state.engine, patch.engine);
  assert.deepEqual(message.state.monitoring, patch.monitoring);
  assert.deepEqual(message.state.counters, patch.counters);
  assert.equal(message.state.request, 2);

  harness.controller.dispose();
});

test('focusSection posts only valid section names to the webview', () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  harness.controller.focusSection('findings');
  harness.controller.focusSection('');
  harness.controller.focusSection(42);

  assert.deepEqual(panel.postedMessages, [{ type: 'focusSection', section: 'findings' }]);

  harness.controller.dispose();
});

test('demo messages are ignored and never rebuild the dashboard with sample data', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'setDemoMode', enabled: true });
  await panel.send({ type: 'setDemoMode', enabled: false });
  await panel.send({ type: 'setDemoMode', enabled: 'yes' });

  assert.deepEqual(harness.stateCalls, ['state']);
  assert.deepEqual(panel.postedMessages, []);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.message === 'Ignored an unknown dashboard message.'
    )
  );
  assert.equal(harness.controller.buildCurrentState().dataMode, 'empty');

  harness.controller.dispose();
});

test('finding review decisions are validated, persisted, and published', async () => {
  const stored = new Map();
  const memento = {
    get(key, fallback) {
      return stored.has(key) ? stored.get(key) : fallback;
    },
    async update(key, value) {
      stored.set(key, value);
    }
  };
  const harness = createHarness({ memento });
  const panel = harness.controller.open();

  await panel.send({ type: 'setFindingReviewed', findingId: 'finding-1', reviewed: true });
  assert.deepEqual(stored.get('bugdhor.dashboard.findingReviews'), { 'finding-1': true });
  assert.equal(panel.postedMessages.at(-1).state.findingReviews['finding-1'], true);

  const restored = createHarness({ memento });
  const restoredPanel = restored.controller.open();
  await restoredPanel.send({ type: 'ready' });
  assert.equal(restoredPanel.postedMessages.at(-1).state.findingReviews['finding-1'], true);

  await restoredPanel.send({ type: 'setFindingReviewed', findingId: 'finding-1', reviewed: false });
  assert.deepEqual(stored.get('bugdhor.dashboard.findingReviews'), { 'finding-1': false });

  await restoredPanel.send({ type: 'setFindingReviewed', findingId: 42, reviewed: true });
  assert.ok(restored.logger.entries.some((entry) => entry.level === 'warn'));

  harness.controller.dispose();
  restored.controller.dispose();
});

test('repair history records only observed proposal, application, and verification results', async () => {
  const stored = new Map();
  const memento = {
    get(key, fallback) {
      return stored.has(key) ? stored.get(key) : fallback;
    },
    update(key, value) {
      stored.set(key, value);
      return undefined;
    }
  };
  const harness = createHarness({ memento, approval: 'Apply Fix' });
  const panel = harness.controller.open();
  const historyKey = 'bugdhor.dashboard.repairHistory';

  await harness.controller.recordRepairResult(repairResponse(), repairRequest());
  let history = stored.get(historyKey);
  assert.equal(history.length, 1);
  assert.equal(history[0].status, 'proposed');
  assert.equal(history[0].approvalStatus, 'pending');
  assert.equal(history[0].applicationStatus, 'not-applied');
  assert.equal(history[0].verificationStatus, 'not-run');
  assert.equal(history[0].verifiedAt, undefined);

  await harness.controller.acceptRepair({ repairId: 'repair-1' });
  history = stored.get(historyKey);
  assert.equal(history[0].status, 'accepted');
  assert.equal(history[0].approvalStatus, 'approved');
  assert.equal(history[0].applicationStatus, 'applied');
  assert.equal(history[0].verificationStatus, 'not-run');
  assert.equal(history[0].verifiedAt, undefined);

  await harness.controller.recordVerificationResult(verificationResponse({ verdict: 'passed' }), {
    repairId: 'repair-1'
  });
  history = stored.get(historyKey);
  assert.equal(history[0].verificationStatus, 'passed');
  assert.equal(typeof history[0].verifiedAt, 'string');
  assert.equal(panel.postedMessages.at(-1).state.repairHistory[0].verificationStatus, 'passed');

  const restored = createHarness({ memento });
  assert.equal(restored.controller.repairHistory[0].verificationStatus, 'passed');
  assert.equal(restored.controller.repairHistory[0].applicationStatus, 'applied');

  harness.controller.dispose();
  restored.controller.dispose();
});

test('finding rescan opens the validated source location before scanning', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({
    type: 'rescanFinding',
    path: '/workspace/src/app.js',
    line: 4,
    column: 2
  });

  assert.deepEqual(harness.executedCommands, [{ command: COMMANDS.scanCurrentFile, args: [] }]);
  assert.equal(harness.shownDocuments.length, 1);
  assert.equal(harness.shownDocuments[0].options.selection.start.line, 4);
  assert.equal(harness.shownDocuments[0].options.selection.start.character, 2);

  await panel.send({ type: 'rescanFinding', path: '/outside/secret.js', line: 0 });
  assert.deepEqual(harness.executedCommands, [{ command: COMMANDS.scanCurrentFile, args: [] }]);
  assert.ok(
    panel.postedMessages.some((message) => message.type === 'notice' && message.level === 'warning')
  );

  harness.controller.dispose();
});

test('dashboard commands are restricted to the engine command allowlist', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace });
  assert.deepEqual(harness.executedCommands, [{ command: COMMANDS.scanWorkspace, args: [] }]);
  assert.ok(EXECUTABLE_COMMANDS.has(COMMANDS.scanWorkspace));
  assert.ok(!EXECUTABLE_COMMANDS.has(COMMANDS.openSecurityDashboard));
  assert.ok(EXECUTABLE_COMMANDS.has(COMMANDS.verifyRepair));
  for (const command of [
    COMMANDS.startEngine,
    COMMANDS.stopEngine,
    COMMANDS.debugProject,
    COMMANDS.viewFindings,
    COMMANDS.reviewFixes
  ]) {
    assert.ok(EXECUTABLE_COMMANDS.has(command), `${command} must be executable from the dashboard`);
  }

  await panel.send({ type: 'executeCommand', command: COMMANDS.openSecurityDashboard });
  await panel.send({ type: 'executeCommand', command: 'workbench.action.terminal.new' });
  await panel.send({ type: 'executeCommand', command: 42 });
  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace, args: ['extra'] });

  assert.deepEqual(harness.executedCommands, [
    { command: COMMANDS.scanWorkspace, args: [] },
    { command: COMMANDS.scanWorkspace, args: [] }
  ]);

  harness.controller.dispose();
});

test('dashboard opens Bug Dhor settings and the output channel', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'openSettings' });
  await panel.send({ type: 'showLogs' });

  assert.deepEqual(harness.executedCommands, [
    { command: 'workbench.action.openSettings', args: ['bugdhor'] }
  ]);
  assert.equal(harness.logger.shown, true);

  harness.controller.dispose();
});

test('dashboard opens workspace-contained explanation source locations', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({
    type: 'openLocation',
    path: '/workspace/src/app.py',
    line: 7,
    column: 3
  });

  assert.equal(harness.openedDocuments.length, 1);
  assert.equal(harness.openedDocuments[0].uri.path, '/workspace/src/app.py');
  assert.equal(harness.shownDocuments.length, 1);
  assert.equal(harness.shownDocuments[0].options.selection.start.line, 7);
  assert.equal(harness.shownDocuments[0].options.selection.start.character, 3);

  harness.controller.dispose();
});

test('dashboard rejects explanation locations outside the workspace', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send({ type: 'openLocation', path: '/outside/app.py', line: 1 });

  assert.equal(harness.openedDocuments.length, 0);
  assert.equal(panel.postedMessages.at(-1).level, 'warning');
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'warn'));

  harness.controller.dispose();
});

test('command failures produce an error notice without inventing success', async () => {
  const harness = createHarness({
    commandErrors: new Map([[COMMANDS.scanWorkspace, new Error('engine unavailable')]])
  });
  const panel = harness.controller.open();

  await panel.send({ type: 'executeCommand', command: COMMANDS.scanWorkspace });

  assert.equal(panel.postedMessages.length, 1);
  assert.equal(panel.postedMessages[0].type, 'notice');
  assert.equal(panel.postedMessages[0].level, 'error');
  assert.match(panel.postedMessages[0].message, /Unable to run/);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));
  assert.ok(!panel.postedMessages.some((message) => /success/i.test(String(message.message))));

  harness.controller.dispose();
});

test('settings failures produce an error notice', async () => {
  const harness = createHarness({
    commandErrors: new Map([['workbench.action.openSettings', new Error('settings unavailable')]])
  });
  const panel = harness.controller.open();

  await panel.send({ type: 'openSettings' });

  assert.equal(panel.postedMessages.length, 1);
  assert.equal(panel.postedMessages[0].level, 'error');
  assert.match(panel.postedMessages[0].message, /Unable to open VS Code settings/);

  harness.controller.dispose();
});

test('unknown and malformed messages are ignored', async () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  await panel.send(null);
  await panel.send('ready');
  await panel.send({ type: 'notARealMessage' });
  await panel.send({ type: 'state', state: {} });

  assert.deepEqual(panel.postedMessages, []);
  assert.equal(harness.executedCommands.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'debug' && /unknown dashboard message/.test(entry.message)
    )
  );

  harness.controller.dispose();
});

test('disposing the dashboard releases listeners and allows a fresh panel', () => {
  const harness = createHarness();
  const first = harness.controller.open();

  assert.equal(first.messageHandlerCount(), 1);
  harness.controller.dispose();
  assert.equal(first.disposed, true);
  assert.equal(first.messageHandlerCount(), 0);
  assert.equal(harness.controller.panel, undefined);

  const second = harness.controller.open();
  assert.notEqual(second, first);
  assert.equal(harness.createdPanels.length, 2);

  harness.controller.dispose();
});

test('a panel closed by VS Code clears controller state', () => {
  const harness = createHarness();
  const panel = harness.controller.open();

  panel.dispose();

  assert.equal(harness.controller.panel, undefined);
  assert.equal(harness.controller.state, undefined);
  assert.equal(panel.messageHandlerCount(), 0);

  harness.controller.dispose();
});
