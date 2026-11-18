'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { WorkspaceMonitor } = require('../../src/monitoring/workspaceMonitor');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await delay(10);
  }
  throw new Error('Timed out waiting for workspace monitor state.');
}

function createUri(fsPath) {
  return {
    scheme: 'file',
    fsPath,
    path: fsPath,
    toString() {
      return `file://${fsPath}`;
    }
  };
}

function createDocument(options = {}) {
  const fsPath = options.fsPath ?? '/workspace/src/app.py';
  const text = options.text ?? 'value = 1\n';
  return {
    uri: createUri(fsPath),
    languageId: options.languageId ?? 'python',
    version: options.version ?? 1,
    lineCount: text.split('\n').length,
    isDirty: options.isDirty ?? true,
    getText() {
      return text;
    }
  };
}

function createHarness(settings = {}, options = {}) {
  const listeners = {
    open: [],
    change: [],
    save: [],
    create: [],
    delete: [],
    folders: [],
    close: []
  };
  const disposables = [];
  const calls = [];
  const published = [];
  const cleared = [];
  const notifications = [];
  const loggerEntries = [];
  const documents = new Map();

  function subscribe(name) {
    return (listener) => {
      listeners[name].push(listener);
      const disposable = { disposed: false, dispose() { this.disposed = true; } };
      disposables.push(disposable);
      return disposable;
    };
  }

  const workspaceFolders = [
    { name: 'workspace', index: 0, uri: createUri('/workspace') }
  ];
  const vscode = {
    workspace: {
      workspaceFolders,
      textDocuments: [],
      getWorkspaceFolder(uri) {
        return typeof uri?.fsPath === 'string' && uri.fsPath.startsWith('/workspace')
          ? workspaceFolders[0]
          : undefined;
      },
      openTextDocument(uri) {
        const key = uri.toString();
        if (!documents.has(key)) {
          documents.set(
            key,
            createDocument({
              fsPath: uri.fsPath,
              languageId: options.languageId ?? 'python',
              version: 1,
              text: options.newFileText ?? 'value = 1\n'
            })
          );
        }
        return Promise.resolve(documents.get(key));
      },
      onDidOpenTextDocument: subscribe('open'),
      onDidChangeTextDocument: subscribe('change'),
      onDidSaveTextDocument: subscribe('save'),
      onDidCreateFiles: subscribe('create'),
      onDidDeleteFiles: subscribe('delete'),
      onDidChangeWorkspaceFolders: subscribe('folders'),
      onDidCloseTextDocument: subscribe('close')
    },
    window: {
      showWarningMessage(message) {
        notifications.push(message);
        return Promise.resolve(undefined);
      }
    },
    commands: {
      executeCommand() {
        return Promise.resolve();
      }
    }
  };

  const service = {
    async scanFile(request, context) {
      calls.push({ method: 'scanFile', request, token: context?.token });
      return { findings: [], operation: 'scan_file' };
    },
    async scanSelection(request, context) {
      calls.push({ method: 'scanSelection', request, token: context?.token });
      return { findings: [], operation: 'detection_analyze' };
    },
    async scanWorkspace(request, context) {
      calls.push({ method: 'scanWorkspace', request, token: context?.token });
      return { findings: [], operation: 'scan_workspace' };
    }
  };
  const diagnostics = {
    publishScanResult(result, options = {}) {
      published.push({ result, options });
      return { published: 0, findings: [], rejected: [] };
    },
    clearUri(uri) {
      cleared.push(uri);
    }
  };
  const logger = {
    trace(message) { loggerEntries.push(message); },
    debug(message) { loggerEntries.push(message); },
    info(message) { loggerEntries.push(message); },
    warn(message) { loggerEntries.push(message); },
    error(message) { loggerEntries.push(message); }
  };

  const monitor = new WorkspaceMonitor({
    vscode,
    service,
    diagnostics,
    logger,
    getSettings: () => ({
      enabled: true,
      allowAutomaticSourceSharing: true,
      sendSourceText: true,
      debounceMs: 100,
      fullScanDebounceMs: 100,
      analysisScope: 'function',
      maxFileBytes: 1024 * 1024,
      maxChangedLines: 500,
      maxConcurrentScans: 2,
      maxWorkspaceFiles: 20,
      languages: ['python', 'javascript'],
      excludeGlobs: [],
      notifyOnFindings: true,
      scanOnOpen: false,
      fullScanOnWorkspaceChange: false,
      ...settings
    })
  });

  function fire(name, value) {
    for (const listener of listeners[name]) {
      listener(value);
    }
  }

  return {
    monitor,
    vscode,
    listeners,
    disposables,
    calls,
    published,
    cleared,
    notifications,
    loggerEntries,
    fire,
    open: (document) => fire('open', document),
    change: (document, contentChanges) => fire('change', { document, contentChanges }),
    save: (document) => fire('save', document),
    delete: (files) => fire('delete', { files }),
    folders: (event) => fire('folders', event)
  };
}

function edit(line, text = 'x') {
  return {
    text,
    rangeLength: text.length,
    range: {
      start: { line, character: 0 },
      end: { line, character: text.length }
    }
  };
}

test('registers every required official workspace event', () => {
  const harness = createHarness();
  harness.monitor.start();
  for (const name of ['open', 'change', 'save', 'create', 'delete', 'folders']) {
    assert.equal(harness.listeners[name].length, 1, `${name} listener must be registered`);
  }
  assert.equal(harness.monitor.getStats().registeredEvents, true);
  harness.monitor.dispose();
  assert.ok(harness.disposables.every((entry) => entry.disposed));
});

test('observing an open document does not scan by default', async () => {
  const harness = createHarness();
  harness.monitor.start();
  harness.open(createDocument());
  await delay(180);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.monitor.getStats().workspace.openEvents, 1);
  harness.monitor.dispose();
});

test('scan-on-open runs once per version when explicitly enabled', async () => {
  const harness = createHarness({ scanOnOpen: true });
  harness.monitor.start();
  const document = createDocument();
  try {
    harness.open(document);
    harness.open(document);
    await waitUntil(() => harness.calls.length === 1);
    await delay(160);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].method, 'scanFile');
    assert.equal(harness.calls[0].request.documentVersion, 1);

    harness.open(createDocument({ version: 2, text: 'value = 2\n' }));
    await waitUntil(() => harness.calls.length === 2);
    assert.equal(harness.calls[1].request.documentVersion, 2);
  } finally {
    harness.monitor.dispose();
  }
});

test('document changes and pasted text are routed through incremental analysis', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    harness.change(
      createDocument({
        version: 2,
        text: 'function pasted() {\n  return 1;\n}\nconst b = 1;\n',
        languageId: 'javascript'
      }),
      [
        {
          text: 'function pasted() {\n  return 1;\n}\n',
          rangeLength: 0,
          range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } }
        }
      ]
    );
    await waitUntil(() => harness.calls.length === 1);
    assert.equal(harness.calls[0].method, 'scanSelection');
    assert.match(harness.calls[0].request.selectedText, /function pasted/);
  } finally {
    harness.monitor.dispose();
  }
});

test('save supersedes a pending edit scan with an immediate file scan', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const document = createDocument({ version: 2 });
  try {
    harness.change(document, [edit(0)]);
    harness.save(document);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].method, 'scanFile');
    await delay(180);
    assert.equal(harness.calls.length, 1);
    assert.ok(harness.monitor.getStats().cancelled >= 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('new source files are opened and scanned once', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const uri = createUri('/workspace/src/new.py');
  try {
    await harness.monitor.handleCreate({ files: [uri] });
    await waitUntil(() => harness.calls.length === 1);
    assert.equal(harness.calls[0].method, 'scanFile');
    assert.equal(harness.calls[0].request.filePath, '/workspace/src/new.py');

    await harness.monitor.handleCreate({ files: [uri] });
    await delay(180);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.monitor.getStats().workspace.createdFiles, 1);
    assert.ok(harness.monitor.getStats().workspace.ignoredCreations >= 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('binary and generated files are skipped before opening', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    await harness.monitor.handleCreate({
      files: [createUri('/workspace/image.png'), createUri('/workspace/app.min.js')]
    });
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.equal(harness.monitor.getStats().workspace.ignoredCreations, 2);
  } finally {
    harness.monitor.dispose();
  }
});

test('deleting a file cancels pending work and clears diagnostics', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const document = createDocument();
  try {
    harness.change(document, [edit(0)]);
    harness.delete([document.uri]);
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.ok(harness.cleared.includes(document.uri.toString()));
    assert.equal(harness.monitor.getStats().workspace.deletedFiles, 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('workspace folder changes can schedule a metadata-only full scan', async () => {
  const harness = createHarness({ fullScanOnWorkspaceChange: true });
  harness.monitor.start();
  try {
    harness.folders({ added: [createUri('/workspace/extra')], removed: [] });
    await waitUntil(() => harness.calls.some((call) => call.method === 'scanWorkspace'));
    const call = harness.calls.find((entry) => entry.method === 'scanWorkspace');
    assert.equal(call.request.workspaceFolders.length, 1);
    assert.equal('sourceText' in call.request, false);
    assert.equal('sourceText' in call.request.workspaceFolders[0], false);
    assert.equal(harness.published.length, 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('disabling monitoring stops all scan triggers', async () => {
  const harness = createHarness({ enabled: false });
  harness.monitor.start();
  const document = createDocument();
  try {
    harness.open(document);
    harness.change(document, [edit(0)]);
    harness.save(document);
    await harness.monitor.handleCreate({ files: [createUri('/workspace/new.py')] });
    harness.folders({ added: [createUri('/workspace/extra')], removed: [] });
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.equal(harness.monitor.getStats().enabled, false);
  } finally {
    harness.monitor.dispose();
  }
});

test('updateSettings cancels outstanding work when monitoring is disabled', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    harness.change(createDocument(), [edit(0)]);
    harness.monitor.updateSettings({ enabled: false });
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.equal(harness.monitor.getStats().pending, 0);
  } finally {
    harness.monitor.dispose();
  }
});
