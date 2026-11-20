'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { runEngineCommand } = require('../../src/commands/runEngineCommand');
const { registerEngineCommand } = require('../../src/commands/registerEngineCommand');

function createLogger() {
  const entries = [];
  return {
    entries,
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
    error(message) {
      entries.push({ level: 'error', message });
    },
    show() {}
  };
}

/**
 * @param {{ cancellationRequested?: boolean }} [options]
 */
function createVscode(options = {}) {
  return {
    ProgressLocation: { Notification: 15 },
    window: {
      async withProgress(_options, task) {
        const progress = { report() {} };
        const token = { isCancellationRequested: options.cancellationRequested === true };
        return task(progress, token);
      },
      async showErrorMessage() {
        return undefined;
      }
    }
  };
}

function createRegistry() {
  const handlers = new Map();
  return {
    register(id, handler) {
      handlers.set(id, handler);
      return {
        dispose() {
          handlers.delete(id);
        }
      };
    },
    async execute(id, ...args) {
      const handler = handlers.get(id);
      if (!handler) {
        throw new Error(`Not registered: ${id}`);
      }
      return handler(...args);
    }
  };
}

test('engine hooks observe the real request and completed backend response', async () => {
  const vscode = createVscode();
  const logger = createLogger();
  const events = [];
  const request = { filePaths: ['/workspace/src/app.py'] };
  const result = { analysisAvailable: true, findings: [], status: 'ok' };

  const actual = await runEngineCommand(
    { vscode, logger },
    {
      definition: { title: 'Scan', progressTitle: 'Scanning' },
      prepare: () => request,
      invoke: async () => result,
      onRequest(event) {
        events.push({ type: 'request', event });
        return { keys: request.filePaths, startedAt: event.startedAt };
      },
      onResult(value, observedRequest, meta) {
        events.push({ type: 'result', value, observedRequest, meta });
      }
    }
  );

  assert.equal(actual, result);
  assert.deepEqual(
    events.map((event) => event.type),
    ['request', 'result']
  );
  assert.equal(events[0].event.request, request);
  assert.equal(typeof events[0].event.startedAt, 'string');
  assert.equal(events[1].observedRequest, request);
  assert.deepEqual(events[1].meta.keys, request.filePaths);
});

test('hook failures are logged but never alter a backend result', async () => {
  const vscode = createVscode();
  const logger = createLogger();
  const result = { analysisAvailable: true, findings: [] };

  const actual = await runEngineCommand(
    { vscode, logger },
    {
      definition: { title: 'Scan', progressTitle: 'Scanning' },
      prepare: () => ({}),
      invoke: async () => result,
      onRequest() {
        throw new Error('observer failed');
      },
      onResult() {
        throw new Error('observer failed again');
      }
    }
  );

  assert.equal(actual, result);
  assert.equal(logger.entries.filter((entry) => entry.level === 'warn').length, 2);
});

test('a backend failure calls onError and never calls onResult', async () => {
  const vscode = createVscode();
  const logger = createLogger();
  const events = [];
  const failure = new Error('backend timeout');
  const request = { filePaths: ['/workspace/src/app.py'] };

  const result = await runEngineCommand(
    { vscode, logger },
    {
      definition: { title: 'Scan', progressTitle: 'Scanning' },
      prepare: () => request,
      invoke: async () => {
        throw failure;
      },
      onRequest() {
        return { keys: request.filePaths };
      },
      onResult() {
        events.push('result');
      },
      onError(event) {
        events.push({ type: 'error', event });
      }
    }
  );

  assert.equal(result, undefined);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, 'error');
  assert.equal(events[0].event.error, failure);
  assert.equal(events[0].event.request, request);
  assert.deepEqual(events[0].event.meta, { keys: request.filePaths });
});

test('cancellation skips observers and returns no result', async () => {
  const vscode = createVscode({ cancellationRequested: true });
  const logger = createLogger();
  const events = [];

  const result = await runEngineCommand(
    { vscode, logger },
    {
      definition: { title: 'Scan', progressTitle: 'Scanning' },
      prepare: () => ({}),
      invoke: async () => ({ analysisAvailable: true }),
      onRequest() {
        events.push('request');
      },
      onResult() {
        events.push('result');
      }
    }
  );

  assert.equal(result, undefined);
  assert.deepEqual(events, []);
});

test('registered engine commands compose global and local hooks', async () => {
  const vscode = createVscode();
  const logger = createLogger();
  const registry = createRegistry();
  const globalEvents = [];
  const localEvents = [];
  const request = { filePaths: ['/workspace/src/app.py'] };
  const backendResult = { analysisAvailable: true, findings: [], status: 'ok' };
  const service = {
    async scanFile(observedRequest, context) {
      assert.equal(observedRequest, request);
      assert.ok(context.token);
      return backendResult;
    }
  };
  const definition = {
    id: 'test.scanFile',
    title: 'Scan',
    progressTitle: 'Scanning',
    serviceMethod: 'scanFile'
  };

  registerEngineCommand(
    {
      vscode,
      service,
      logger,
      registry,
      engineHooks: {
        onRequest(event) {
          globalEvents.push({ type: 'request', event });
          return { keys: event.request.filePaths };
        },
        onResult(value, observedRequest, meta) {
          globalEvents.push({ type: 'result', meta });
        },
        onError(event) {
          globalEvents.push({ type: 'error', event });
        }
      }
    },
    definition,
    () => request,
    {
      onResult(value, observedRequest, meta) {
        localEvents.push({ value, observedRequest, meta });
      }
    }
  );

  const result = await registry.execute(definition.id);

  assert.equal(result, backendResult);
  assert.deepEqual(
    globalEvents.map((event) => event.type),
    ['request', 'result']
  );
  assert.deepEqual(globalEvents[1].meta, { keys: request.filePaths });
  assert.equal(localEvents.length, 1);
  assert.equal(localEvents[0].value, backendResult);
  assert.deepEqual(localEvents[0].meta, { keys: request.filePaths });
});
