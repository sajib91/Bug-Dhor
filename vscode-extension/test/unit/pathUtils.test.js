'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { canonicalPath, fileUriMatchesPath } = require('../integration/pathUtils');

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

test('fileUriMatchesPath compares parsed backend URIs by canonical path', () => {
  const realpathSync = (target) =>
    target === 'C:\\Users\\RUNNER~1\\work\\file.py'
      ? 'C:\\Users\\runneradmin\\work\\file.py'
      : target;
  realpathSync.native = realpathSync;
  const options = {
    fileSystem: { realpathSync },
    platform: 'win32',
    parseUri: (value) => {
      assert.equal(value, 'file:///C:/Users/RUNNER~1/work/file.py');
      return {
        scheme: 'file',
        fsPath: 'C:\\Users\\RUNNER~1\\work\\file.py'
      };
    }
  };

  assert.equal(
    fileUriMatchesPath(
      'file:///C:/Users/RUNNER~1/work/file.py',
      'C:\\Users\\runneradmin\\work\\file.py',
      options
    ),
    true,
    'Python as_uri() output must match a Windows path after parsing and canonicalization'
  );
  assert.equal(
    fileUriMatchesPath(
      'file:///C:/Users/RUNNER~1/work/file.py',
      'c:\\users\\runneradmin\\WORK\\file.py',
      options
    ),
    true,
    'Windows path comparison must ignore drive-letter and directory casing'
  );
  assert.equal(
    fileUriMatchesPath('file:///C:/other/file.py', 'C:\\Users\\runneradmin\\work\\file.py', options),
    false,
    'a path outside the reported file must not match'
  );
  assert.equal(
    fileUriMatchesPath('https://example.test/file.py', 'C:\\Users\\runneradmin\\work\\file.py', {
      ...options,
      parseUri: () => ({ scheme: 'https', fsPath: 'C:\\Users\\runneradmin\\work\\file.py' })
    }),
    false,
    'non-file URIs must be rejected'
  );
  assert.equal(
    fileUriMatchesPath('not a uri', 'C:\\Users\\runneradmin\\work\\file.py', {
      ...options,
      parseUri: () => {
        throw new Error('invalid URI');
      }
    }),
    false,
    'malformed URIs must be rejected without throwing'
  );
});
