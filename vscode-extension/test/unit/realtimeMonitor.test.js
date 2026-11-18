'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { RealtimeMonitor } = require('../../src/monitoring/realtimeMonitor');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await delay(10);
  }
  throw new Error('Timed out waiting for monitor state.');
}

function createDocument(options = {}) {
  const fsPath = options.fsPath ?? '/workspace/src/app.py';
  const text = options.text ?? 'value = 1\n';
  return {
    uri: {
      scheme: 'file',
      fsPath,
      toString() {
        return `file://${fsPath}`;
      }
    },
    languageId: options.languageId ?? 'python',
    version: options.version ?? 1,
    lineCount: text.split('\n').length,
    isDirty: options.isDirty ?? true,
    getText() {
      return text;
    }
  };
}

function createHarness(settings = {}) {
  const listeners = { change: [], save: [], close: [] };
  const calls = [];
  const published = [];
  const notifications = [];
  const executed = [];
  const loggerEntries = [];

  const vscode = {
    workspace: {
      workspaceFolders: [
        { name: 'workspace', index: 0, uri: { scheme: 'file', fsPath: '/workspace' } }
      ],
      getWorkspaceFolder(uri) {
        return uri?.fsPath?.startsWith('/workspace')
          ? { name: 'workspace', index: 0, uri: { scheme: 'file', fsPath: '/workspace' } }
          : undefined;
      },
      onDidChangeTextDocument(listener) {
        listeners.change.push(listener);
        return { dispose() {} };
      },
      onDidSaveTextDocument(listener) {
        listeners.save.push(listener);
        return { dispose() {} };
      },
      onDidCloseTextDocument(listener) {
        listeners.close.push(listener);
        return { dispose() {} };
      }
    },
    window: {
      showWarningMessage(message, action) {
        notifications.push({ message, action });
        return Promise.resolve(undefined);
      }
    },
    commands: {
      executeCommand(...args) {
        executed.push(args);
        return Promise.resolve();
      }
    }
  };

  const findings = settings.__findings ?? [];
  const service = {
    async scanFile(request, context) {
      calls.push({ method: 'scanFile', request, token: context?.token });
      return { findings, operation: 'scan_file' };
    },
    async scanSelection(request, context) {
      calls.push({ method: 'scanSelection', request, token: context?.token });
      return { findings, operation: 'detection_analyze' };
    }
  };
  const diagnostics = {
    publishScanResult(result, options) {
      published.push({ result, options });
    },
    clearUri() {}
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

  const monitor = new RealtimeMonitor({
    vscode,
    service,
    diagnostics,
    logger,
    getSettings: () => ({
      enabled: true,
      allowAutomaticSourceSharing: true,
      sendSourceText: true,
      debounceMs: 100,
      analysisScope: 'function',
      maxFileBytes: 1024 * 1024,
      maxChangedLines: 500,
      notifyOnFindings: true,
      ...settings
    })
  });

  return {
    monitor,
    calls,
    published,
    notifications,
    executed,
    loggerEntries,
    change(document, contentChanges) {
      for (const listener of listeners.change) {
        listener({ document, contentChanges });
      }
    },
    save(document) {
      for (const listener of listeners.save) {
        listener(document);
      }
    },
    close(document) {
      for (const listener of listeners.close) {
        listener(document);
      }
    }
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

test('debounces rapid edits into a single scan of the final document version', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    for (let version = 1; version <= 5; version += 1) {
      harness.change(createDocument({ version, text: `value = ${version}\n` }), [edit(0)]);
    }
    assert.equal(harness.calls.length, 0, 'no request may be sent before the debounce elapses');
    await waitUntil(() => harness.calls.length === 1);
    await delay(50);
    assert.equal(harness.calls.length, 1, 'rapid edits must collapse into one scan');
    assert.equal(harness.calls[0].request.documentVersion, 5);
    assert.equal(harness.calls[0].method, 'scanSelection');
    assert.ok(harness.calls[0].request.selectedText?.includes('value = 5'));
  } finally {
    harness.monitor.dispose();
  }
});

test('ignores duplicate and out-of-order document versions', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 3 }), [edit(0)]);
    harness.change(createDocument({ version: 3 }), [edit(0)]);
    harness.change(createDocument({ version: 2 }), [edit(0)]);
    await delay(160);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].request.documentVersion, 3);
    assert.equal(harness.monitor.getStats().duplicates, 2);
  } finally {
    harness.monitor.dispose();
  }
});

test('handles a multi-line paste as one bounded function-level scan', async () => {
  const text = ['def first():', '    return 1', '', 'def second():', '    return 2'].join('\n');
  const harness = createHarness();
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 1, text }), [
      {
        text: '# pasted line 1\n# pasted line 2\n# pasted line 3\n',
        rangeLength: 0,
        range: { start: { line: 1, character: 4 }, end: { line: 1, character: 4 } }
      }
    ]);
    await waitUntil(() => harness.calls.length === 1);
    await delay(50);
    assert.equal(harness.calls.length, 1);
    const analyses = harness.monitor
      .getStats()
      .analyses.filter((entry) => entry.status === 'completed');
    assert.equal(analyses.length, 1);
    assert.equal(analyses[0].kind, 'function');
    assert.ok(analyses[0].changedLines >= 4);
    assert.equal('sourceText' in analyses[0], false, 'stats must never expose source text');
  } finally {
    harness.monitor.dispose();
  }
});

test('save triggers an immediate file-level scan and supersedes a pending edit scan', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    const document = createDocument({ version: 2, text: 'value = 2\n' });
    harness.change(document, [edit(0)]);
    harness.save(document);
    assert.equal(harness.calls.length, 1, 'save must run without waiting for the debounce');
    assert.equal(harness.calls[0].method, 'scanFile');
    assert.ok(harness.monitor.getStats().cancelled >= 1);
    await delay(160);
    assert.equal(harness.calls.length, 1, 'the superseded debounce must not run');
  } finally {
    harness.monitor.dispose();
  }
});

test('sends no source text without explicit automatic consent', async () => {
  const harness = createHarness({ allowAutomaticSourceSharing: false });
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 1 }), [edit(0)]);
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.ok(harness.monitor.getStats().skipped >= 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('also requires the general source-sharing setting for automatic scans', async () => {
  const harness = createHarness({ sendSourceText: false });
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 1 }), [edit(0)]);
    await delay(180);
    assert.equal(harness.calls.length, 0);
  } finally {
    harness.monitor.dispose();
  }
});

test('cancels an outdated in-flight request and publishes only the latest result', async () => {
  const harness = createHarness();
  const resolvers = [];
  harness.monitor.service.scanSelection = (request, context) => {
    harness.calls.push({ method: 'scanSelection', request, token: context?.token });
    return new Promise((resolve, reject) => {
      resolvers.push({ resolve: () => resolve({ findings: [], request }), request });
      context?.token.onCancellationRequested(() => {
        reject(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
      });
    });
  };
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 1, text: 'value = 1\n' }), [edit(0)]);
    await waitUntil(() => harness.calls.length === 1);
    assert.equal(harness.calls[0].token.isCancellationRequested, false);
    harness.change(createDocument({ version: 2, text: 'value = 2\n' }), [edit(0)]);
    assert.equal(
      harness.calls[0].token.isCancellationRequested,
      true,
      'the superseded request must be aborted immediately'
    );
    await waitUntil(() => harness.calls.length === 2);
    for (const resolver of resolvers) {
      resolver.resolve();
    }
    await waitUntil(() => harness.published.length === 1);
    await delay(50);
    assert.equal(harness.published.length, 1);
    assert.equal(harness.calls[1].request.documentVersion, 2);
  } finally {
    harness.monitor.dispose();
  }
});

test('publishes native diagnostics and notifies when findings are reported', async () => {
  const finding = {
    id: 'finding-1',
    message: 'Potential SQL injection.',
    severity: 'high',
    location: {
      uri: 'file:///workspace/src/app.py',
      range: { start: { line: 0, character: 0 }, end: { line: 0, character: 9 } }
    }
  };
  const harness = createHarness({ __findings: [finding] });
  harness.monitor.start();
  try {
    harness.change(createDocument({ version: 1 }), [edit(0)]);
    await waitUntil(() => harness.published.length === 1);
    assert.equal(harness.published[0].options.scopeUris[0], 'file:///workspace/src/app.py');
    assert.equal(harness.published[0].result.findings.length, 1);
    assert.equal(harness.notifications.length, 1);
    assert.match(harness.notifications[0].message, /potential security finding in app\.py/);
    assert.equal(harness.monitor.getStats().notifications, 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('keeps concurrent document analyses independent', async () => {
  const harness = createHarness();
  harness.monitor.start();
  try {
    harness.change(createDocument({ fsPath: '/workspace/a.py', version: 1, text: 'a = 1\n' }), [
      edit(0)
    ]);
    harness.change(
      createDocument({
        fsPath: '/workspace/b.js',
        languageId: 'javascript',
        version: 1,
        text: 'const b = 1;\n'
      }),
      [edit(0)]
    );
    await waitUntil(() => harness.calls.length === 2);
    const uris = harness.calls.map((call) => call.request.documentUri).sort();
    assert.deepEqual(uris, ['file:///workspace/a.py', 'file:///workspace/b.js']);
  } finally {
    harness.monitor.dispose();
  }
});

test('skips unsupported languages, excluded paths, and oversized documents', async () => {
  const harness = createHarness({ maxFileBytes: 128 });
  harness.monitor.start();
  try {
    harness.change(createDocument({ languageId: 'ruby' }), [edit(0)]);
    harness.change(createDocument({ fsPath: '/workspace/node_modules/pkg/index.js' }), [edit(0)]);
    harness.change(createDocument({ text: 'x'.repeat(2000) }), [edit(0)]);
    await delay(180);
    assert.equal(harness.calls.length, 0);
    assert.ok(harness.monitor.getStats().skipped >= 1);
  } finally {
    harness.monitor.dispose();
  }
});

test('dispose cancels timers and removes listeners', async () => {
  const harness = createHarness();
  harness.monitor.start();
  harness.change(createDocument({ version: 1 }), [edit(0)]);
  harness.monitor.dispose();
  assert.equal(harness.monitor.getStats().pending, 0);
  await delay(160);
  assert.equal(harness.calls.length, 0);
  harness.change(createDocument({ version: 2 }), [edit(0)]);
  await delay(160);
  assert.equal(harness.calls.length, 0);
});
