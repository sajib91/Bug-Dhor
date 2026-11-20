'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { removeTemporaryDirectory } = require('../integration/tempCleanup');

function createTemporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-cleanup-test-'));
}

test('removeTemporaryDirectory removes an unlocked directory', async () => {
  const root = createTemporaryDirectory();
  fs.writeFileSync(path.join(root, 'exthost.log'), 'log line\n');

  assert.equal(await removeTemporaryDirectory(root, { attempts: 2, delayMs: 1 }), true);
  assert.equal(fs.existsSync(root), false);
});

test('removeTemporaryDirectory treats an already missing directory as success', async () => {
  const root = createTemporaryDirectory();
  await removeTemporaryDirectory(root, { attempts: 1, delayMs: 1 });

  assert.equal(await removeTemporaryDirectory(root, { attempts: 1, delayMs: 1 }), true);
});

test('removeTemporaryDirectory retries Windows lock errors', async () => {
  const root = createTemporaryDirectory();
  fs.writeFileSync(path.join(root, 'exthost.log'), 'log line\n');
  const original = fs.rmSync;
  let calls = 0;
  fs.rmSync = (target, options) => {
    calls += 1;
    if (calls === 1) {
      const error = new Error('EBUSY: resource busy or locked');
      error.code = 'EBUSY';
      throw error;
    }
    return original(target, options);
  };

  try {
    assert.equal(await removeTemporaryDirectory(root, { attempts: 3, delayMs: 1 }), true);
    assert.equal(calls, 2);
    assert.equal(fs.existsSync(root), false);
  } finally {
    fs.rmSync = original;
  }
});

test('removeTemporaryDirectory does not fail a test when a file stays locked', async () => {
  const root = createTemporaryDirectory();
  fs.writeFileSync(path.join(root, 'exthost.log'), 'log line\n');
  const original = fs.rmSync;
  let calls = 0;
  fs.rmSync = () => {
    calls += 1;
    const error = new Error('EBUSY: resource busy or locked');
    error.code = 'EBUSY';
    throw error;
  };

  try {
    assert.equal(await removeTemporaryDirectory(root, { attempts: 2, delayMs: 1 }), false);
    assert.equal(calls, 2);
  } finally {
    fs.rmSync = original;
    original(root, { recursive: true, force: true });
  }
});

test('cleanup failure does not mask a failed Extension Host test', async () => {
  const originalExitCode = process.exitCode;
  const root = createTemporaryDirectory();
  const original = fs.rmSync;
  fs.rmSync = () => {
    const error = new Error('EBUSY: resource busy or locked');
    error.code = 'EBUSY';
    throw error;
  };
  const extensionHostError = new Error('Extension Host exited with 1');

  let observed;
  try {
    try {
      throw extensionHostError;
    } finally {
      await removeTemporaryDirectory(root, { attempts: 2, delayMs: 1 });
    }
  } catch (error) {
    observed = error;
  } finally {
    fs.rmSync = original;
    original(root, { recursive: true, force: true });
  }

  assert.equal(observed, extensionHostError);
  assert.equal(process.exitCode, originalExitCode);
});
