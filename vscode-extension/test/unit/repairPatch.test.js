'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { applyUnifiedPatch, patchFiles } = require('../../src/repair/patchApplication');

const PATCH =
  '--- a/src/app.py\n' +
  '+++ b/src/app.py\n' +
  '@@ -1,2 +1,2 @@\n' +
  ' def run(value):\n' +
  '-    return value\n' +
  '+    return value.strip()\n';

test('applies a matching patch without touching the original string', () => {
  const source = 'def run(value):\n    return value\n';

  assert.equal(applyUnifiedPatch(source, PATCH), 'def run(value):\n    return value.strip()\n');
  assert.equal(source, 'def run(value):\n    return value\n');
});

test('rejects stale patch context', () => {
  assert.throws(
    () => applyUnifiedPatch('def run(value):\n    return other\n', PATCH),
    /context|deletion/
  );
});

test('extracts patch files for safe WorkspaceEdit targeting', () => {
  assert.deepEqual(patchFiles(PATCH), ['src/app.py']);
});
