'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { DocumentVersionTracker } = require('../../src/monitoring/documentVersionTracker');

const URI = 'file:///workspace/src/app.py';

function change(line, text = 'x', length = 1) {
  return {
    text,
    range: {
      start: { line, character: 0 },
      end: { line, character: length }
    }
  };
}

test('tracks versions and merged changed-line ranges', () => {
  const tracker = new DocumentVersionTracker();
  const first = tracker.observeChange({
    uri: URI,
    version: 1,
    lineCount: 10,
    contentChanges: [change(2)]
  });
  assert.equal(first.ignored, false);
  assert.deepEqual(first.state.ranges, [{ startLine: 2, endLine: 3 }]);

  const second = tracker.observeChange({
    uri: URI,
    version: 2,
    lineCount: 12,
    contentChanges: [change(3, 'a\nb\n', 0), change(8)]
  });
  assert.deepEqual(second.state.ranges, [
    { startLine: 3, endLine: 6 },
    { startLine: 8, endLine: 9 }
  ]);
  assert.equal(second.state.fullDocument, false);
  assert.equal(second.state.bulkInsert, true);
});

test('ignores duplicate and out-of-order versions', () => {
  const tracker = new DocumentVersionTracker();
  tracker.observeChange({ uri: URI, version: 5, lineCount: 3, contentChanges: [change(0)] });
  const duplicate = tracker.observeChange({
    uri: URI,
    version: 5,
    lineCount: 3,
    contentChanges: [change(0)]
  });
  const stale = tracker.observeChange({
    uri: URI,
    version: 4,
    lineCount: 3,
    contentChanges: [change(0)]
  });
  assert.equal(duplicate.ignored, true);
  assert.equal(duplicate.reason, 'stale');
  assert.equal(stale.ignored, true);
  assert.equal(tracker.get(URI).version, 5);
});

test('treats a full-document event as the whole file', () => {
  const tracker = new DocumentVersionTracker();
  const observed = tracker.observeChange({
    uri: URI,
    version: 1,
    lineCount: 4,
    contentChanges: [{ text: 'a\nb\nc\n' }]
  });
  assert.equal(observed.state.fullDocument, true);
  assert.deepEqual(observed.state.ranges, [{ startLine: 0, endLine: 4 }]);
});

test('records saves without advancing the document version', () => {
  const tracker = new DocumentVersionTracker();
  tracker.observeChange({ uri: URI, version: 3, lineCount: 2, contentChanges: [change(1)] });
  const saved = tracker.observeSave({ uri: URI, version: 3 });
  assert.equal(saved.ignored, false);
  assert.equal(saved.state.version, 3);
  assert.equal(saved.state.savedVersion, 3);
});

test('records an open once per document version without attributing an author', () => {
  const tracker = new DocumentVersionTracker();
  const first = tracker.observeOpen({
    uri: URI,
    version: 1,
    lineCount: 4,
    fsPath: '/workspace/src/app.py'
  });
  assert.equal(first.ignored, false);
  assert.equal(first.state.openedVersion, 1);
  assert.deepEqual(first.state.ranges, []);

  const duplicate = tracker.observeOpen({ uri: URI, version: 1, lineCount: 4 });
  assert.equal(duplicate.ignored, true);
  assert.equal(duplicate.reason, 'stale');

  const observedChange = tracker.observeChange({
    uri: URI,
    version: 2,
    lineCount: 5,
    fsPath: '/workspace/src/app.py',
    contentChanges: [change(2)]
  });
  assert.equal(observedChange.ignored, false);
  assert.equal(tracker.get(URI).version, 2);
});

test('bounds tracked documents and supports forgetting a document', () => {
  const tracker = new DocumentVersionTracker({ maxDocuments: 2 });
  tracker.observeChange({ uri: 'file:///a.py', version: 1, lineCount: 1, timestamp: 1 });
  tracker.observeChange({ uri: 'file:///b.py', version: 1, lineCount: 1, timestamp: 2 });
  tracker.observeChange({ uri: 'file:///c.py', version: 1, lineCount: 1, timestamp: 3 });
  assert.equal(tracker.get('file:///a.py'), undefined);
  assert.equal(tracker.get('file:///c.py').version, 1);
  tracker.forget('file:///c.py');
  assert.equal(tracker.get('file:///c.py'), undefined);
});
