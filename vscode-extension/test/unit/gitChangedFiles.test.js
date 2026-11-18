'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  GitChangedFilesError,
  collectGitChangedFiles,
  gitChangedFilesForRoot,
  parseNulPaths
} = require('../../src/repository/gitChangedFiles');

test('NUL-delimited Git output is parsed without inventing paths', () => {
  assert.deepEqual(parseNulPaths('src/app.js\0./notes.md\0\0../outside.py\0.\0'), [
    'src/app.js',
    'notes.md'
  ]);
  assert.deepEqual(parseNulPaths(undefined), []);
});

test('changed-file discovery uses fixed read-only Git queries and resolves paths', async () => {
  const root = path.resolve('/workspace/repo');
  const calls = [];
  const runner = async (cwd, args) => {
    calls.push({ cwd, args });
    if (args.includes('ls-files')) {
      return 'src/new.js\0';
    }
    if (args.includes('--cached')) {
      return 'src/staged.py\0';
    }
    return 'src/edited.py\0../outside.py\0';
  };

  const result = await gitChangedFilesForRoot(root, { runner, includeUntracked: true });

  assert.equal(result.available, true);
  assert.equal(result.cancelled, false);
  assert.deepEqual(result.paths, [
    path.join(root, 'src/edited.py'),
    path.join(root, 'src/staged.py'),
    path.join(root, 'src/new.js')
  ]);
  assert.equal(calls.length, 3);
  assert.ok(calls.every((call) => call.cwd === root));
  assert.deepEqual(
    calls.map((call) => call.args[0]),
    ['diff', 'diff', 'ls-files']
  );
  assert.ok(calls[0].args.includes('--diff-filter=ACMR'));
  assert.ok(calls[2].args.includes('--exclude-standard'));
});

test('a root without Git metadata is reported rather than treated as clean', async () => {
  const result = await gitChangedFilesForRoot(path.resolve('/workspace/plain'), {
    runner: async () => {
      throw new Error('fatal: not a git repository');
    }
  });

  assert.deepEqual(result, { available: false, cancelled: false, paths: [] });
});

test('cancellation stops changed-file discovery before any Git query', async () => {
  let calls = 0;
  const result = await gitChangedFilesForRoot(path.resolve('/workspace/repo'), {
    runner: async () => {
      calls += 1;
      return '';
    },
    cancellationToken: { isCancellationRequested: true }
  });

  assert.deepEqual(result, { available: true, cancelled: true, paths: [] });
  assert.equal(calls, 0);
});

test('collecting across roots deduplicates paths and reports when no repository exists', async () => {
  const first = await collectGitChangedFiles(
    [path.resolve('/workspace/a'), path.resolve('/workspace/b')],
    {
      includeUntracked: false,
      runner: async (cwd) => {
        if (cwd.endsWith('a')) {
          return 'src/shared.js\0src/only-a.py\0';
        }
        return 'src/shared.js\0';
      }
    }
  );
  assert.deepEqual(first.paths, [
    path.resolve('/workspace/a/src/shared.js'),
    path.resolve('/workspace/a/src/only-a.py'),
    path.resolve('/workspace/b/src/shared.js')
  ]);

  await assert.rejects(
    () =>
      collectGitChangedFiles([path.resolve('/workspace/plain')], {
        runner: async () => {
          throw new Error('fatal: not a git repository');
        }
      }),
    (error) => error instanceof GitChangedFilesError && error.code === 'E_NOT_A_REPOSITORY'
  );
});
