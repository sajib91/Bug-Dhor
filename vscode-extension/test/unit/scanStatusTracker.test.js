'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ScanStatusTracker, pathKey, scopeKeys } = require('../../src/webviews/scanStatusTracker');

function uri(fsPath) {
  return { scheme: 'file', fsPath, toString: () => `file://${fsPath}` };
}

test('scan status starts unknown until real events are observed', () => {
  const tracker = new ScanStatusTracker();

  assert.deepEqual(tracker.getState(), {
    discoveredFiles: null,
    scannedFiles: null,
    pendingFiles: null,
    failedFiles: null,
    failedScans: null,
    lastScanAt: null
  });
});

test('editor events mark only real paths pending and clear removed paths', () => {
  const tracker = new ScanStatusTracker();
  const first = '/workspace/src/first.py';
  const second = '/workspace/src/second.py';

  tracker.observeEvent({ type: 'create', uris: [uri(first)] });
  assert.equal(tracker.getState().pendingFiles, 1);

  tracker.observeEvent({ type: 'change', uris: [uri(second)] });
  assert.equal(tracker.getState().pendingFiles, 2);

  tracker.observeEvent({ type: 'delete', uris: [uri(first)] });
  assert.equal(tracker.getState().pendingFiles, 1);

  tracker.observeEvent({
    type: 'rename',
    oldUri: uri(second),
    newUri: uri('/workspace/src/third.py')
  });
  let state = tracker.getState();
  assert.equal(state.pendingFiles, 1);
  assert.deepEqual(tracker.getDetailedStats().pendingKeys, ['/workspace/src/third.py']);

  tracker.complete({
    request: { filePaths: ['/workspace/src/third.py'] },
    result: { analysisAvailable: true, status: 'ok' },
    meta: { keys: ['/workspace/src/third.py'] }
  });
  state = tracker.getState();
  assert.equal(state.pendingFiles, 0);
  assert.equal(state.scannedFiles, 1);
});

test('a scan completes only after an analysis-capable backend response', () => {
  const tracker = new ScanStatusTracker();
  const filePath = '/workspace/src/app.py';
  const request = { filePaths: [filePath] };
  const meta = tracker.begin({ request, definition: { serviceMethod: 'scanWorkspace' } });

  assert.equal(tracker.getState().pendingFiles, 1);
  assert.equal(tracker.getState().lastScanAt, null);

  const unavailable = tracker.complete({
    request,
    meta,
    result: { analysisAvailable: false, status: 'unavailable', findings: [] }
  });
  assert.equal(unavailable.scannedFiles, 0);
  assert.equal(unavailable.failedFiles, 1);
  assert.equal(unavailable.failedScans, 1);
  assert.equal(unavailable.lastScanAt, null);

  const completed = tracker.complete({
    request,
    meta,
    result: { analysisAvailable: true, status: 'ok', findings: [] }
  });
  assert.equal(completed.pendingFiles, 0);
  assert.equal(completed.scannedFiles, 1);
  assert.equal(completed.failedFiles, 0);
  assert.equal(completed.failedScans, 1);
  assert.equal(typeof completed.lastScanAt, 'string');
});

test('transport failures are recorded as failures and cancellations as non-events', () => {
  const tracker = new ScanStatusTracker();
  const failedPath = '/workspace/src/fail.py';
  const cancelledPath = '/workspace/src/cancel.py';
  const failedMeta = tracker.begin({ request: { filePaths: [failedPath] } });

  const failed = tracker.fail({ meta: failedMeta, error: new Error('backend timeout') });
  assert.equal(failed.pendingFiles, 0);
  assert.equal(failed.scannedFiles, 0);
  assert.equal(failed.failedFiles, 1);
  assert.equal(failed.failedScans, 1);
  assert.equal(failed.lastScanAt, null);

  const cancelledMeta = tracker.begin({ request: { filePaths: [cancelledPath] } });
  const cancelled = tracker.fail({
    meta: cancelledMeta,
    error: Object.assign(new Error('stopped'), { name: 'CanceledError' })
  });
  assert.equal(cancelled.pendingFiles, 0);
  assert.equal(cancelled.scannedFiles, 0);
  assert.equal(cancelled.failedFiles, 1);
  assert.equal(cancelled.failedScans, 1);
});

test('inventory discovery bounds scanned and pending counts to real discovered files', () => {
  const tracker = new ScanStatusTracker();
  const known = '/workspace/src/known.py';
  const unknown = '/workspace/src/unknown.py';

  tracker.updateInventory({
    available: true,
    files: [{ fsPath: known }]
  });
  tracker.observeEvent({ type: 'change', uris: [uri(known), uri(unknown)] });

  const state = tracker.getState();
  assert.equal(state.discoveredFiles, 1);
  assert.equal(state.pendingFiles, 1);
  assert.equal(state.scannedFiles, 0);
  assert.deepEqual(tracker.getDetailedStats().pendingKeys.sort(), [known, unknown].sort());
});

test('path and scope keys normalize URIs without inventing paths', () => {
  assert.equal(pathKey(uri('/workspace/a.py')), '/workspace/a.py');
  assert.equal(pathKey('file:///workspace/b.py'), '/workspace/b.py');
  assert.equal(pathKey(undefined), null);

  assert.deepEqual(
    scopeKeys(
      {
        documentUri: 'file:///workspace/a.py',
        filePaths: ['/workspace/b.py'],
        scope: { uris: [uri('/workspace/c.py')] }
      },
      [uri('/workspace/d.py')]
    ).sort(),
    ['/workspace/a.py', '/workspace/b.py', '/workspace/c.py', '/workspace/d.py'].sort()
  );
});
