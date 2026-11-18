'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { COMMANDS } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const { registerCommands, expectedCommandIds } = require('../../src/commands');
const { CommandRegistry } = require('../../src/commands/registry');

const ENGINE_METHODS = Object.freeze([
  'health',
  'scanFile',
  'scanSelection',
  'scanWorkspace',
  'explainVulnerability',
  'analyzeSecurityFeatures',
  'counterfactualAnalysis',
  'generateSecureCode',
  'generateRecommendation',
  'repairVulnerability',
  'verifyRepair'
]);

/**
 * @param {string} fsPath
 * @param {string} [scheme]
 */
function createUri(fsPath, scheme = 'file') {
  return {
    scheme,
    fsPath,
    toString() {
      return `${scheme}://${fsPath}`;
    }
  };
}

class FakeRange {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    this.start = { line: startLine, character: startCharacter };
    this.end = { line: endLine, character: endCharacter };
  }
}

/**
 * @param {string} [fsPath]
 * @param {string} [name]
 */
function createWorkspaceFolder(fsPath = '/workspace', name = 'workspace') {
  return { name, index: 0, uri: createUri(fsPath) };
}

/**
 * @param {{
 *   empty?: boolean,
 *   start?: { line: number, character: number },
 *   end?: { line: number, character: number }
 * }} [options]
 */
function createSelection(options = {}) {
  return {
    isEmpty: options.empty ?? false,
    start: options.start ?? { line: 1, character: 0 },
    end: options.end ?? { line: 3, character: 2 }
  };
}

/**
 * @param {{
 *   fsPath?: string,
 *   scheme?: string,
 *   languageId?: string,
 *   version?: number,
 *   text?: string,
 *   selection?: object
 * }} [options]
 */
function createEditor(options = {}) {
  const {
    fsPath = '/workspace/src/app.js',
    scheme = 'file',
    languageId = 'javascript',
    version = 4,
    text = 'const value = 1;',
    selection = createSelection()
  } = options;
  const uri = createUri(fsPath, scheme);

  return {
    document: {
      uri,
      languageId,
      version,
      getText() {
        return text;
      }
    },
    selection
  };
}

/**
 * @param {{
 *   activeTextEditor?: object,
 *   workspaceFolders?: object[],
 *   cancellationRequested?: boolean,
 *   informationMessageResult?: string,
 *   errorMessageResult?: string,
 *   executeCommandError?: Error,
 *   executeCommandResult?: unknown,
 *   getWorkspaceFolder?: (uri: object) => object | undefined
 * }} [options]
 */
function createFakeVscode(options = {}) {
  const handlers = new Map();
  const registrations = [];
  const progressReports = [];
  const progressOptions = [];
  const informationMessages = [];
  const warningMessages = [];
  const errorMessages = [];
  const executedCommands = [];
  const shownDocuments = [];
  const workspaceFolders = options.workspaceFolders ?? [];
  let activeTextEditor = options.activeTextEditor;

  const vscode = {
    ProgressLocation: { Notification: 15 },
    FileType: Object.freeze({ File: 1, Directory: 2, SymbolicLink: 64 }),
    Uri: {
      file: createUri,
      joinPath: (base, ...parts) => createUri(path.join(base.fsPath, ...parts))
    },
    Range: FakeRange,
    commands: {
      registerCommand(commandId, handler) {
        if (handlers.has(commandId)) {
          throw new Error(`Command already registered: ${commandId}`);
        }
        handlers.set(commandId, handler);

        const registration = {
          commandId,
          disposed: false,
          dispose() {
            registration.disposed = true;
            handlers.delete(commandId);
          }
        };
        registrations.push(registration);
        return registration;
      },
      async executeCommand(command, ...args) {
        executedCommands.push({ command, args });
        if (options.executeCommandError) {
          throw options.executeCommandError;
        }
        return options.executeCommandResult;
      }
    },
    window: {
      get activeTextEditor() {
        return activeTextEditor;
      },
      async showInformationMessage(message, ...actions) {
        informationMessages.push({ message, actions });
        return options.informationMessageResult;
      },
      async showWarningMessage(message, ...actions) {
        warningMessages.push({ message, actions });
        return options.warningMessageResult;
      },
      async showErrorMessage(message, ...actions) {
        errorMessages.push({ message, actions });
        return options.errorMessageResult;
      },
      async showTextDocument(document, documentOptions) {
        shownDocuments.push({ document, options: documentOptions });
        return { document, selection: documentOptions?.selection };
      },
      async withProgress(configuration, task) {
        progressOptions.push(configuration);
        const progress = {
          report(value) {
            progressReports.push(value);
          }
        };
        const token = {
          isCancellationRequested: Boolean(options.cancellationRequested),
          onCancellationRequested() {
            return { dispose() {} };
          }
        };
        return task(progress, token);
      }
    },
    workspace: {
      workspaceFolders,
      fs: {
        async readDirectory(uri) {
          if (uri.fsPath === '/workspace') {
            return [['src', 2]];
          }
          if (uri.fsPath === path.join('/workspace', 'src')) {
            return [['app.js', 1]];
          }
          return [];
        },
        async stat(uri) {
          if (uri.fsPath === '/workspace' || uri.fsPath === path.join('/workspace', 'src')) {
            return { type: 2, size: 0 };
          }
          if (uri.fsPath === path.join('/workspace', 'src', 'app.js')) {
            return { type: 1, size: 16 };
          }
          return { type: 0, size: 0 };
        },
        async readFile(uri) {
          if (uri.fsPath === path.join('/workspace', 'src', 'app.js')) {
            return new TextEncoder().encode('const value = 1;');
          }
          throw new Error(`ENOENT: ${uri.fsPath}`);
        }
      },
      getConfiguration() {
        return {
          get(key, defaultValue) {
            return options.configuration?.[key] ?? defaultValue;
          }
        };
      },
      getWorkspaceFolder(uri) {
        if (options.getWorkspaceFolder) {
          return options.getWorkspaceFolder(uri);
        }
        return workspaceFolders.find(
          (folder) =>
            uri.fsPath === folder.uri.fsPath || uri.fsPath.startsWith(`${folder.uri.fsPath}/`)
        );
      }
    }
  };

  return {
    vscode,
    handlers,
    registrations,
    progressReports,
    progressOptions,
    informationMessages,
    warningMessages,
    errorMessages,
    executedCommands,
    shownDocuments,
    setActiveTextEditor(editor) {
      activeTextEditor = editor;
    }
  };
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

/**
 * @param {Record<string, (request: object, context: object) => Promise<unknown>>} [overrides]
 */
function createFakeService(overrides = {}) {
  const calls = [];
  const service = {};

  for (const method of ENGINE_METHODS) {
    service[method] = async (request, context) => {
      calls.push({ method, request, context });
      if (overrides[method]) {
        return overrides[method](request, context);
      }
      if (method === 'health') {
        return {
          service: 'bugdhor-engine',
          status: 'ok',
          version: '0.1.0',
          apiVersion: 'v1',
          timestamp: new Date().toISOString(),
          uptimeSeconds: 1,
          capabilities: {},
          sandboxBackend: 'docker'
        };
      }
      return { method, request };
    };
  }

  return { service, calls };
}

function createFakeDashboard(options = {}) {
  const openCalls = [];
  return {
    openCalls,
    dashboard: {
      open() {
        openCalls.push({});
        if (options.openError) {
          throw options.openError;
        }
        return { revealed: false };
      }
    }
  };
}

function createFakeDiagnostics(options = {}) {
  const publications = [];
  const findingsByUri = options.findingsByUri ?? {};
  return {
    publications,
    getFindingsForUri(uri) {
      const key = typeof uri === 'string' ? uri : uri.toString();
      return findingsByUri[key] ?? [];
    },
    getPublishedUris() {
      return ['file:///workspace/src/app.js'];
    },
    publishScanResult(result, publishOptions) {
      publications.push({ result, options: publishOptions });
      return { published: 0, files: [], rejected: [] };
    }
  };
}

const REPAIR_DIFF =
  '--- a/src/app.js\n' +
  '+++ b/src/app.js\n' +
  '@@ -1,1 +1,1 @@\n' +
  '-const value = 1;\n' +
  '+const value = 2;\n';

function createRepairProvider(options = {}) {
  return {
    providerId: options.providerId ?? 'test-provider',
    model: { id: 'test-model' },
    capabilities: options.capabilities ?? ['B', 'C'],
    status: options.status ?? 'available',
    hosted: false,
    async generate() {
      return { text: `Explanation\n\`\`\`diff\n${REPAIR_DIFF}\n\`\`\`` };
    }
  };
}

function createHarness(options = {}) {
  const fake = createFakeVscode(options);
  const logger = createFakeLogger();
  const { service, calls } = createFakeService(options.serviceOverrides);
  const { dashboard, openCalls } = createFakeDashboard(options);
  const { publications, ...diagnostics } = createFakeDiagnostics({
    findingsByUri: options.findingsByUri
  });
  const registry = registerCommands({
    vscode: fake.vscode,
    service,
    logger,
    dashboard,
    diagnostics,
    assistantRegistry: options.assistantRegistry,
    getRecommendationSettings:
      options.getRecommendationSettings ??
      (() => ({
        runFunctionalTests: false,
        allowSandboxedExecution: false,
        testCommand: [],
        testTimeoutSeconds: 120
      })),
    getRepositorySettings: () => ({
      backendUrl: 'http://127.0.0.1:8765',
      sendSourceText: true,
      monitoringAllowAutomaticSourceSharing: false,
      repositoryMaxFiles: 2000,
      repositoryMaxFileBytes: 1_048_576,
      repositoryExcludeGlobs: [],
      repositoryIncludeUntrackedFiles: true,
      repositoryGitTimeoutMs: 1000
    }),
    gitRunner: options.gitRunner ?? (async () => 'src/app.js\0')
  });
  return {
    ...fake,
    logger,
    service,
    calls,
    dashboard,
    openCalls,
    diagnostics,
    publications,
    registry
  };
}

test('registerCommands registers every declared command exactly once', () => {
  const harness = createHarness();
  const expected = [...expectedCommandIds()].sort();

  assert.equal(harness.registry.size, expected.length);
  assert.deepEqual(harness.registry.ids().sort(), expected);
  assert.deepEqual([...harness.handlers.keys()].sort(), expected);
  assert.equal(harness.registrations.length, expected.length);

  harness.registry.dispose();
});

test('disposing the registry releases every registration and is idempotent', () => {
  const harness = createHarness();
  const registrations = [...harness.registrations];

  harness.registry.dispose();

  assert.equal(harness.handlers.size, 0);
  assert.equal(harness.registry.size, 0);
  assert.ok(registrations.every((registration) => registration.disposed));

  harness.registry.dispose();
  assert.throws(
    () => harness.registry.register('bugdhor.lateCommand', () => {}),
    /Cannot register command after disposal/
  );
});

test('the registry refuses duplicate command IDs', () => {
  const fake = createFakeVscode();
  const registry = new CommandRegistry(fake.vscode, createFakeLogger());

  registry.register('bugdhor.testCommand', () => {});
  assert.throws(
    () => registry.register('bugdhor.testCommand', () => {}),
    /Command is already registered/
  );

  registry.dispose();
});

test('editor commands reject a missing editor without calling the engine', async () => {
  const harness = createHarness({ activeTextEditor: undefined });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(result, undefined);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open a text editor/);
  assert.deepEqual(harness.errorMessages[0].actions, ['Show Logs']);
  assert.equal(harness.informationMessages.length, 0, 'no success message may be shown');
  assert.equal(harness.logger.entries.at(-1).level, 'warn');

  harness.registry.dispose();
});

test('unsaved or virtual documents are rejected before analysis', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ scheme: 'untitled', fsPath: '/workspace/Untitled-1' }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Save the active file/);

  harness.registry.dispose();
});

test('files outside the workspace are rejected before analysis', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ fsPath: '/outside/app.js' }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /not inside an open workspace folder/);

  harness.registry.dispose();
});

test('workspace commands require an open workspace', async () => {
  const harness = createHarness({ workspaceFolders: [] });

  await harness.handlers.get(COMMANDS.scanWorkspace)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open a folder or workspace/);

  harness.registry.dispose();
});

test('selection commands require a non-empty selection', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor({ selection: createSelection({ empty: true }) }),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.scanSelection)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Select code/);

  harness.registry.dispose();
});

test('scan current file passes saved editor context and cancellable progress', async () => {
  const workspaceFolder = createWorkspaceFolder('/workspace');
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [workspaceFolder]
  });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 1);
  const [{ method, request, context }] = harness.calls;
  assert.equal(method, 'scanFile');
  assert.equal(request.workspaceFolder, '/workspace');
  assert.equal(request.workspaceFolderName, 'workspace');
  assert.equal(request.filePath, '/workspace/src/app.js');
  assert.equal(request.languageId, 'javascript');
  assert.equal(request.documentVersion, 4);
  assert.deepEqual(request.selection, {
    start: { line: 1, character: 0 },
    end: { line: 3, character: 2 }
  });
  assert.equal(request.selectedText, 'const value = 1;');
  assert.equal(request.sourceText, 'const value = 1;');
  assert.equal(typeof context.token.isCancellationRequested, 'boolean');

  assert.equal(harness.progressOptions[0].location, 15);
  assert.equal(harness.progressOptions[0].cancellable, true);
  assert.equal(harness.progressOptions[0].title, 'Bug Dhor: Scanning current file');
  assert.deepEqual(harness.progressReports, [{ message: 'Contacting the Bug Dhor backend.' }]);

  assert.deepEqual(result, { method: 'scanFile', request });
  assert.equal(harness.informationMessages.length, 0, 'no success message may be shown');
  assert.equal(harness.errorMessages.length, 0);

  harness.registry.dispose();
});

test('every engine-backed command invokes its declared service method', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });
  // Generate Secure Code and Repair Vulnerability are custom, provider-backed
  // workflows. They obtain a backend prompt before submitting generated
  // candidates to the engine and are covered by their dedicated tests.
  const engineDefinitions = COMMAND_DEFINITIONS.filter(
    (definition) =>
      definition.serviceMethod &&
      definition.id !== COMMANDS.generateSecureCode &&
      definition.id !== COMMANDS.repairVulnerability &&
      definition.id !== COMMANDS.scanSelectedFolder
  );

  for (const definition of engineDefinitions) {
    await harness.handlers.get(definition.id)();
  }

  assert.deepEqual(
    harness.calls.map((call) => call.method),
    engineDefinitions.map((definition) => definition.serviceMethod)
  );
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);

  harness.registry.dispose();
});

test('explain vulnerability forwards only an existing finding identifier', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.explainVulnerability)({
    findingId: 'finding-9',
    unexpected: 'ignored'
  });
  const first = harness.calls.find((call) => call.method === 'explainVulnerability');
  assert.ok(first);
  assert.equal(first.request.findingId, 'finding-9');
  assert.equal('unexpected' in first.request, false);

  await harness.handlers.get(COMMANDS.explainVulnerability)();
  const second = harness.calls.filter((call) => call.method === 'explainVulnerability').at(-1);
  assert.equal('findingId' in second.request, false);

  harness.registry.dispose();
});

test('verify repair forwards only an explicit caller-supplied target', async () => {
  const patch = '--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n';
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.verifyRepair)({
    repairId: 'repair-1',
    patch,
    profile: 'static_only',
    runExecution: false,
    unexpected: 'ignored'
  });
  const first = harness.calls.find((call) => call.method === 'verifyRepair');
  assert.ok(first);
  assert.equal(first.request.repairId, 'repair-1');
  assert.equal(first.request.patch, patch);
  assert.equal(first.request.profile, 'static_only');
  assert.equal(first.request.runExecution, false);
  assert.equal('unexpected' in first.request, false);

  await harness.handlers.get(COMMANDS.verifyRepair)();
  const second = harness.calls.filter((call) => call.method === 'verifyRepair').at(-1);
  assert.equal('repairId' in second.request, false);
  assert.equal('patch' in second.request, false);

  harness.registry.dispose();
});

test('service failures show an error with a log action and never a success notice', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    errorMessageResult: 'Show Logs',
    serviceOverrides: {
      scanFile: async () => {
        throw new Error('engine connection failed');
      }
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /engine connection failed/);
  assert.deepEqual(harness.errorMessages[0].actions, ['Show Logs']);
  assert.equal(harness.informationMessages.length, 0);
  assert.equal(harness.logger.shown, true);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));

  harness.registry.dispose();
});

test('pre-cancelled commands report cancellation without an error notification', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    cancellationRequested: true
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'info' && /cancelled/.test(entry.message)
    )
  );

  harness.registry.dispose();
});

test('a scan cancelled during the engine call publishes no diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile(request, context) {
        context.token.isCancellationRequested = true;
        return { findings: [] };
      }
    }
  });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(result, undefined);
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.publications.length, 0);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);
  assert.ok(
    harness.logger.entries.some(
      (entry) => entry.level === 'info' && /cancelled/.test(entry.message)
    )
  );

  harness.registry.dispose();
});

test('open security dashboard opens the dashboard panel', async () => {
  const harness = createHarness();

  const result = await harness.handlers.get(COMMANDS.openSecurityDashboard)();

  assert.equal(result, undefined);
  assert.equal(harness.openCalls.length, 1);
  assert.deepEqual(harness.executedCommands, []);
  assert.equal(harness.errorMessages.length, 0);
  assert.equal(harness.informationMessages.length, 0);

  harness.registry.dispose();
});

test('dashboard failures are logged and reported', async () => {
  const harness = createHarness({
    openError: new Error('view unavailable'),
    errorMessageResult: 'Show Logs'
  });

  await harness.handlers.get(COMMANDS.openSecurityDashboard)();

  assert.equal(harness.openCalls.length, 1);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Unable to open the Security Dashboard/);
  assert.equal(harness.logger.shown, true);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'error'));

  harness.registry.dispose();
});

test('show status reports reachable backend capability flags without claiming success', async () => {
  const harness = createHarness({ informationMessageResult: 'Open Security Dashboard' });

  await harness.handlers.get(COMMANDS.showStatus)();

  assert.equal(harness.informationMessages.length, 1);
  assert.match(harness.informationMessages[0].message, /reachable/);
  assert.match(harness.informationMessages[0].message, /Declared available capabilities/);
  assert.match(harness.informationMessages[0].message, /Declared unavailable capabilities/);
  assert.doesNotMatch(harness.informationMessages[0].message, /success/i);
  assert.deepEqual(harness.informationMessages[0].actions, [
    'Open Security Dashboard',
    'Show Logs'
  ]);
  assert.deepEqual(harness.executedCommands, [
    { command: COMMANDS.openSecurityDashboard, args: [] }
  ]);

  harness.registry.dispose();
});

test('show status reports an unreachable backend without claiming success', async () => {
  const harness = createHarness({
    errorMessageResult: 'Open Settings',
    serviceOverrides: {
      health: async () => {
        throw new Error('Cannot reach the Bug Dhor backend at http://127.0.0.1:8765.');
      }
    }
  });

  await harness.handlers.get(COMMANDS.showStatus)();

  assert.equal(harness.informationMessages.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Cannot reach/);
  assert.deepEqual(harness.errorMessages[0].actions, ['Show Logs', 'Open Settings']);
  assert.deepEqual(harness.executedCommands, [
    { command: 'workbench.action.openSettings', args: ['bugdhor.backend.url'] }
  ]);
  assert.ok(harness.logger.entries.some((entry) => entry.level === 'warn'));

  harness.registry.dispose();
});

test('show logs opens the Bug Dhor output channel', async () => {
  const harness = createHarness();

  await harness.handlers.get(COMMANDS.showLogs)();

  assert.equal(harness.logger.shown, true);

  harness.registry.dispose();
});

test('next finding navigates to an accepted finding and wraps at the end', async () => {
  const uri = createUri('/workspace/src/app.js');
  const findings = [
    {
      id: 'first',
      range: {
        start: { line: 1, character: 2 },
        end: { line: 1, character: 12 }
      }
    },
    {
      id: 'second',
      range: {
        start: { line: 8, character: 4 },
        end: { line: 8, character: 14 }
      }
    }
  ];
  const harness = createHarness({
    activeTextEditor: createEditor({
      selection: createSelection({
        start: { line: 9, character: 0 },
        end: { line: 9, character: 0 }
      })
    }),
    findingsByUri: { [uri.toString()]: findings }
  });

  const target = await harness.handlers.get(COMMANDS.nextFinding)();

  assert.equal(target.id, 'first');
  assert.equal(harness.shownDocuments.length, 1);
  assert.equal(harness.shownDocuments[0].document.uri.toString(), uri.toString());
  assert.deepEqual(harness.shownDocuments[0].options.selection.start, { line: 1, character: 2 });
  assert.deepEqual(harness.shownDocuments[0].options.selection.end, { line: 1, character: 12 });
  assert.equal(harness.shownDocuments[0].options.preserveFocus, false);
  assert.equal(harness.shownDocuments[0].options.preview, false);

  harness.registry.dispose();
});

test('previous finding walks backward through accepted findings', async () => {
  const uri = createUri('/workspace/src/app.js');
  const findings = [
    {
      id: 'first',
      range: {
        start: { line: 1, character: 2 },
        end: { line: 1, character: 12 }
      }
    },
    {
      id: 'second',
      range: {
        start: { line: 8, character: 4 },
        end: { line: 8, character: 14 }
      }
    }
  ];
  const harness = createHarness({
    activeTextEditor: createEditor({
      selection: createSelection({
        start: { line: 9, character: 0 },
        end: { line: 9, character: 0 }
      })
    }),
    findingsByUri: { [uri.toString()]: findings }
  });

  const target = await harness.handlers.get(COMMANDS.previousFinding)();

  assert.equal(target.id, 'second');
  assert.deepEqual(harness.shownDocuments[0].options.selection.start, { line: 8, character: 4 });

  harness.registry.dispose();
});

test('finding navigation reports missing context instead of inventing a target', async () => {
  const harness = createHarness();

  assert.equal(await harness.handlers.get(COMMANDS.nextFinding)(), undefined);
  assert.equal(await harness.handlers.get(COMMANDS.previousFinding)(), undefined);
  assert.equal(harness.informationMessages.length, 2);
  assert.match(harness.informationMessages[0].message, /Open a source file/);
  assert.equal(harness.shownDocuments.length, 0);

  harness.setActiveTextEditor(createEditor());
  assert.equal(await harness.handlers.get(COMMANDS.nextFinding)(), undefined);
  assert.equal(harness.informationMessages.length, 3);
  assert.match(harness.informationMessages.at(-1).message, /no findings in the active file/);
  assert.equal(harness.shownDocuments.length, 0);

  harness.registry.dispose();
});

test('scan results are published to diagnostics with the scanned file scope', async () => {
  const backendResult = { findings: [] };
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile: async () => backendResult
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.publications.length, 1);
  assert.equal(harness.publications[0].result, backendResult);
  assert.deepEqual(harness.publications[0].options, {
    scopeUris: ['file:///workspace/src/app.js']
  });

  harness.registry.dispose();
});

test('unavailable analysis is reported and never treated as a clean scan', async () => {
  const backendResult = { findings: [], analysisAvailable: false };
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile: async () => backendResult
    }
  });

  const result = await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(result, backendResult);
  assert.equal(harness.publications.length, 1);
  assert.equal(harness.warningMessages.length, 1);
  assert.match(harness.warningMessages[0].message, /analysis is unavailable/i);
  assert.match(harness.warningMessages[0].message, /No findings or security conclusion/);
  assert.equal(harness.informationMessages.length, 0, 'no success message may be shown');
  assert.equal(harness.errorMessages.length, 0);

  harness.registry.dispose();
});

test('workspace scans publish diagnostics without inventing a file scope', async () => {
  const backendResult = { findings: [], scope: { uris: ['file:///workspace/src/app.js'] } };
  const harness = createHarness({
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanWorkspace: async () => backendResult
    }
  });

  await harness.handlers.get(COMMANDS.scanWorkspace)();

  assert.equal(harness.publications.length, 1);
  assert.equal(harness.publications[0].result, backendResult);
  assert.equal(harness.publications[0].options, undefined);

  harness.registry.dispose();
});

test('analysis commands do not publish diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.explainVulnerability)();
  await harness.handlers.get(COMMANDS.analyzeSecurityFeatures)();

  assert.equal(harness.publications.length, 0);

  harness.registry.dispose();
});

test('failed scans never publish diagnostics', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    serviceOverrides: {
      scanFile: async () => {
        throw new Error('engine connection failed');
      }
    }
  });

  await harness.handlers.get(COMMANDS.scanCurrentFile)();

  assert.equal(harness.publications.length, 0);
  assert.equal(harness.errorMessages.length, 1);

  harness.registry.dispose();
});

test('a repair Quick Fix sends finding context with the editor request', async () => {
  const provider = createRepairProvider();
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')],
    assistantRegistry: { getActiveProvider: () => provider },
    serviceOverrides: {
      generateRecommendation: async () => ({
        result: { prompt: { text: 'Repository-aware repair prompt.', promptHash: 'hash' } }
      })
    }
  });
  const finding = {
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 4, character: 2 },
      end: { line: 4, character: 42 }
    },
    cwe: 'CWE-89',
    ruleId: 'js/sql-injection'
  };

  await harness.handlers.get(COMMANDS.repairVulnerability)(finding);

  const serviceCalls = harness.calls.map((call) => call.method);
  assert.deepEqual(serviceCalls, ['generateRecommendation', 'repairVulnerability']);
  const repairCall = harness.calls.find((call) => call.method === 'repairVulnerability');
  assert.deepEqual(repairCall.request.finding, finding);
  assert.equal(repairCall.request.filePath, '/workspace/src/app.js');
  assert.equal(repairCall.request.generate, false);
  assert.equal(repairCall.request.patch, REPAIR_DIFF.trim());
  assert.equal(harness.errorMessages.length, 0);

  harness.registry.dispose();
});

test('repair generation fails honestly when no B/C provider is configured', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });
  const finding = {
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 5 }
    }
  };

  await harness.handlers.get(COMMANDS.repairVulnerability)(finding);

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /No configured generation provider/);

  harness.registry.dispose();
});

test('a repair Quick Fix for another file is rejected before the engine call', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.repairVulnerability)({
    findingId: 'finding-1',
    documentUri: 'file:///workspace/src/other.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 5 }
    }
  });

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Open the file that contains this finding/);

  harness.registry.dispose();
});

test('malformed repair finding context is rejected before the engine call', async () => {
  const harness = createHarness({
    activeTextEditor: createEditor(),
    workspaceFolders: [createWorkspaceFolder('/workspace')]
  });

  await harness.handlers.get(COMMANDS.repairVulnerability)({
    findingId: '',
    documentUri: 'file:///workspace/src/app.js',
    range: {
      start: { line: 0, character: 0 },
      end: { line: 0, character: 5 }
    }
  });

  assert.equal(harness.calls.length, 0);
  assert.equal(harness.errorMessages.length, 1);
  assert.match(harness.errorMessages[0].message, /Invalid repair finding context/);

  harness.registry.dispose();
});

test('registration fails atomically when the diagnostics controller is missing', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();
  const { dashboard } = createFakeDashboard();

  assert.throws(
    () =>
      registerCommands({
        vscode: fake.vscode,
        service,
        logger: createFakeLogger(),
        dashboard
      }),
    /diagnostics controller/
  );
  assert.equal(fake.handlers.size, 0);
  assert.equal(fake.registrations.length, 0);
});

test('registration fails atomically when the service contract is incomplete', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();
  const { dashboard } = createFakeDashboard();
  delete service.verifyRepair;

  assert.throws(
    () =>
      registerCommands({
        vscode: fake.vscode,
        service,
        logger: createFakeLogger(),
        dashboard,
        diagnostics: createFakeDiagnostics()
      }),
    /SecurityEngineService\.verifyRepair/
  );
  assert.equal(fake.handlers.size, 0);
  assert.ok(fake.registrations.every((registration) => registration.disposed));
});

test('registration fails atomically when the dashboard controller is missing', () => {
  const fake = createFakeVscode();
  const { service } = createFakeService();

  assert.throws(
    () => registerCommands({ vscode: fake.vscode, service, logger: createFakeLogger() }),
    /dashboard controller/
  );
  assert.equal(fake.handlers.size, 0);
  assert.equal(fake.registrations.length, 0);
});
