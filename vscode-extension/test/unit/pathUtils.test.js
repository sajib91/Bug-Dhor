'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { canonicalPath } = require('../integration/pathUtils');

test('canonicalPath uses the native resolver so Windows short names expand', () => {
  const calls = [];
  const realpathSync = (target) => {
    calls.push(['fallback', target]);
    return 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp';
  };
  realpathSync.native = (target) => {
    calls.push(['native', target]);
    return 'C:\\Users\\runneradmin\\AppData\\Local\\Temp';
  };

  assert.equal(
    canonicalPath('C:\\Users\\RUNNER~1\\AppData\\Local\\Temp', {
      fileSystem: { realpathSync },
      platform: 'win32'
    }),
    'C:\\Users\\runneradmin\\AppData\\Local\\Temp'
  );
  assert.deepEqual(calls, [['native', 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp']]);
});

test('canonicalPath falls back when the native resolver is unavailable', () => {
  const realpathSync = (target) => `fallback:${target}`;
  realpathSync.native = () => {
    throw new Error('ENOSYS');
  };

  assert.equal(
    canonicalPath('relative', { fileSystem: { realpathSync }, platform: 'linux' }),
    'fallback:relative'
  );
});

test('canonicalPath strips the Windows extended-length prefix', () => {
  const realpathSync = (target) => target;
  realpathSync.native = (target) => `\\\\?\\${target}`;

  assert.equal(
    canonicalPath('C:\\Users\\runneradmin\\temp', {
      fileSystem: { realpathSync },
      platform: 'win32'
    }),
    'C:\\Users\\runneradmin\\temp'
  );
});

test('canonicalPath restores UNC paths from the extended-length prefix', () => {
  const realpathSync = (target) => target;
  realpathSync.native = () => '\\\\?\\UNC\\server\\share\\file.py';

  assert.equal(
    canonicalPath('ignored', { fileSystem: { realpathSync }, platform: 'win32' }),
    '\\\\server\\share\\file.py'
  );
});
