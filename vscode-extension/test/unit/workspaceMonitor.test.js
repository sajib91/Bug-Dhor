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
    close: [],
    rename: [],
    externalCreate: [],
    externalChange: [],
    externalDelete: []
  };
  const disposables = [];
  const watcherGlobs = [];
  const calls = [];
  const published = [];
  const cleared = [];
  const notifications = [];
  const loggerEntries = [];
  const documents = new Map();

  function subscribe(name) {
    return (listener) => {
      listeners[name].push(listener);
      const disposable = {
        disposed: false,
        dispose() {
          this.disposed = true;
        }
      };
      disposables.push(disposable);
      return disposable;
    };
  }

  const workspaceFolders = [{ name: 'workspace', index: 0, uri: createUri('/workspace') }];
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
        const resolve = () => {
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
          return documents.get(key);
        };
        if (typeof options.beforeResolve === 'function') {
          return Promise.resolve().then(options.beforeResolve).then(resolve);
        }
        return Promise.resolve(resolve());
      },
      onDidOpenTextDocument: subscribe('open'),
      onDidChangeTextDocument: subscribe('change'),
      onDidSaveTextDocument: subscribe('save'),
      onDidCreateFiles: subscribe('create'),
      onDidDeleteFiles: subscribe('delete'),
      onDidChangeWorkspaceFolders: subscribe('folders'),
      onDidCloseTextDocument: subscribe('close'),
      onDidRenameFiles: subscribe('rename'),
      createFileSystemWatcher(glob) {
        watcherGlobs.push(glob);
        const watcher = {
          dispose() {
            this.disposed = true;
          },
          onDidCreate: subscribe('externalCreate'),
          onDidChange: subscribe('externalChange'),
          onDidDelete: subscribe('externalDelete')
        };
        disposables.push(watcher);
        return watcher;
      }
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
    trace(message) {
      loggerEntries.push(message);
    },
    debug(message) {
      loggerEntries.push(message);
    },
    info(message) {
      loggerEntries.push(message);
    },
    warn(message) {
      loggerEntries.push(message);
    },
    error(message) {
      loggerEntries.push(message);
    }
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
    service,
    listeners,
    disposables,
    watcherGlobs,
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
    folders: (event) => fire('folders', event),
    rename: (event) => fire('rename', event),
    externalCreate: (uri) => fire('externalCreate', uri),
    externalChange: (uri) => Promise.all(listeners.externalChange.map((listener) => listener(uri)))
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

test('official rename events clear the old path and scan the new path', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const oldUri = createUri('/workspace/src/old.py');
  const newUri = createUri('/workspace/src/renamed.py');
  try {
    harness.rename({ files: [{ oldUri, newUri }] });
    await waitUntil(() => harness.calls.some((call) => call.request.filePath === newUri.fsPath));

    assert.equal(harness.monitor.getStats().workspace.renames, 1);
    assert.ok(harness.cleared.includes(oldUri.toString()));
    assert.equal(harness.calls.at(-1).method, 'scanFile');
    assert.equal(harness.calls.at(-1).request.filePath, newUri.fsPath);
  } finally {
    harness.monitor.dispose();
  }
});

test('the external watcher scans created and externally changed files', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const createdUri = createUri('/workspace/src/external-created.py');
  const changedUri = createUri('/workspace/src/external-changed.py');
  try {
    assert.deepEqual(harness.watcherGlobs, ['**/*']);
    harness.externalCreate(createdUri);
    await waitUntil(() =>
      harness.calls.some((call) => call.request.filePath === createdUri.fsPath)
    );

    harness.externalChange(changedUri);
    await waitUntil(() =>
      harness.calls.some((call) => call.request.filePath === changedUri.fsPath)
    );

    assert.equal(harness.monitor.getStats().workspace.createdFiles, 1);
    assert.equal(harness.monitor.getStats().workspace.externalChanges, 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('a create scan is superseded by a rapid editor edit burst', async () => {
  const harness = createHarness({ debounceMs: 100 });
  harness.monitor.start();
  const finalText = ['# rapid 1', '# rapid 2', 'value = 2'].join('\n');
  const document = createDocument({ version: 1, text: 'value = 0\n' });
  harness.vscode.workspace.textDocuments = [document];
  try {
    await harness.monitor.handleCreate({ files: [document.uri] });
    for (let version = 2; version <= 3; version += 1) {
      document.version = version;
      document.getText = () => finalText;
      harness.change(document, [edit(0)]);
    }
    await waitUntil(() => harness.calls.length === 1);
    await delay(180);

    assert.equal(harness.calls.length, 1, 'the pending create scan must be cancelled');
    assert.equal(harness.calls[0].request.documentVersion, 3);
    const completed = harness.monitor
      .getStats()
      .analyses.filter((entry) => entry.status === 'completed');
    assert.deepEqual(
      completed.map((entry) => entry.reason),
      ['change']
    );
    assert.equal(harness.monitor.getStats().workspace.createdFiles, 1);
    assert.ok(harness.monitor.getStats().cancelled >= 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('late watcher events do not duplicate a rapid editor edit burst', async () => {
  const harness = createHarness({ debounceMs: 50 });
  harness.monitor.start();
  const finalText = [
    '# rapid 1',
    '# rapid 2',
    '# rapid 3',
    '# rapid 4',
    '# rapid 5',
    'value = 5'
  ].join('\n');
  const document = createDocument({ version: 1, text: 'value = 0\n' });
  harness.vscode.workspace.textDocuments = [document];
  try {
    for (let version = 2; version <= 6; version += 1) {
      document.version = version;
      document.getText = () => finalText;
      harness.change(document, [edit(0)]);
    }
    await waitUntil(() => harness.calls.length === 1);
    await delay(80);

    const watcherUri = createUri(document.uri.fsPath);
    await harness.externalChange(watcherUri);
    harness.externalCreate(watcherUri);
    await delay(80);

    assert.equal(harness.calls.length, 1, 'watcher events must not supersede the editor scan');
    const completed = harness.monitor
      .getStats()
      .analyses.filter((entry) => entry.status === 'completed');
    assert.equal(completed.length, 1);
    assert.equal(completed[0].version, 6);
    assert.equal(harness.monitor.getStats().workspace.externalChanges, 0);
  } finally {
    harness.monitor.dispose();
  }
});

test('external changes share the resolved document URI identity', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const document = createDocument({ version: 2, isDirty: false });
  harness.vscode.workspace.textDocuments = [document];
  const watcherUri = {
    ...createUri(document.uri.fsPath),
    toString() {
      return 'file://watcher-uri-variant';
    }
  };
  try {
    await harness.externalChange(watcherUri);
    await waitUntil(() => harness.calls.length === 1);

    assert.equal(harness.calls[0].request.documentUri, document.uri.toString());
    const completed = harness.monitor
      .getStats()
      .analyses.find((entry) => entry.status === 'completed');
    assert.equal(completed?.uri, document.uri.toString());
  } finally {
    harness.monitor.dispose();
  }
});

test('an external watcher event for a recent editor save does not scan twice', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const document = createDocument({ version: 4, isDirty: false });
  try {
    harness.save(document);
    await waitUntil(() => harness.calls.length === 1);

    harness.externalChange(document.uri);
    await delay(80);

    assert.equal(harness.calls.length, 1);
    assert.equal(harness.monitor.getStats().workspace.externalChanges, 0);
  } finally {
    harness.monitor.dispose();
  }
});

test('a watcher event cannot cancel an in-flight save scan', async () => {
  const harness = createHarness();
  harness.monitor.start();
  const document = createDocument({ version: 2, isDirty: false });
  let finishScan;
  harness.service.scanFile = (request, context) => {
    harness.calls.push({ method: 'scanFile', request, token: context?.token });
    return new Promise((resolve) => {
      finishScan = () => resolve({ findings: [], operation: 'scan_file' });
    });
  };
  try {
    harness.save(document);
    assert.equal(harness.calls.length, 1);

    // One watcher event consumes the time-based save marker. A duplicate event
    // arriving before the backend responds must still leave the save scan alone.
    await harness.externalChange(document.uri);
    await harness.externalChange(document.uri);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.monitor.getStats().workspace.externalChanges, 0);

    finishScan();
    await delay(20);
    assert.equal(harness.calls.length, 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('a save observed while the watcher resolves a document still suppresses the watcher scan', async () => {
  let releaseResolve;
  const resolveGate = new Promise((resolve) => {
    releaseResolve = resolve;
  });
  const harness = createHarness({}, { beforeResolve: () => resolveGate });
  harness.monitor.start();
  const document = createDocument({ version: 2, isDirty: false });
  try {
    // The watcher callback checks for a recent save before resolving the
    // document. On slow Windows runners the editor save can arrive while the
    // resolution is pending; the post-await recheck must still suppress it.
    const watcher = harness.externalChange(document.uri);
    harness.save(document);
    releaseResolve();
    await watcher;
    await delay(80);

    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].method, 'scanFile');
    assert.equal(harness.monitor.getStats().workspace.externalChanges, 0);
  } finally {
    harness.monitor.dispose();
  }
});
