'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const nodeFs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  discoverRepositoryInventory,
  buildWorkspaceFolderMetadata,
  RepositoryInventoryError
} = require('../../src/repository/repositoryInventory');
const { GitIgnoreRules, parseGitIgnore } = require('../../src/repository/gitignore');

const FileType = Object.freeze({ File: 1, Directory: 2, SymbolicLink: 64 });

/** @param {string} fsPath */
function makeUri(fsPath) {
  return {
    scheme: 'file',
    fsPath,
    toString() {
      return `file://${fsPath}`;
    }
  };
}

/** @param {string[]} rootPaths @param {{ names?: string[] }} [options] */
function createVscode(rootPaths, options = {}) {
  const workspaceFolders = rootPaths.map((fsPath, index) => ({
    name: options.names?.[index] ?? path.basename(fsPath),
    index,
    uri: makeUri(fsPath)
  }));
  return {
    FileType,
    Uri: {
      file: makeUri,
      joinPath: (base, ...parts) => makeUri(path.join(base.fsPath, ...parts))
    },
    workspace: {
      workspaceFolders,
      fs: {
        /** @param {{ fsPath: string }} uri */
        async readDirectory(uri) {
          const entries = await nodeFs.readdir(uri.fsPath, { withFileTypes: true });
          return entries.map((entry) => {
            let type = 0;
            if (entry.isDirectory()) {
              type |= FileType.Directory;
            }
            if (entry.isFile()) {
              type |= FileType.File;
            }
            if (entry.isSymbolicLink()) {
              type |= FileType.SymbolicLink;
            }
            return [entry.name, type];
          });
        },
        /** @param {{ fsPath: string }} uri */
        async stat(uri) {
          const stats = await nodeFs.lstat(uri.fsPath);
          let type = 0;
          if (stats.isDirectory()) {
            type |= FileType.Directory;
          }
          if (stats.isFile()) {
            type |= FileType.File;
          }
          if (stats.isSymbolicLink()) {
            type |= FileType.SymbolicLink;
          }
          return { type, size: stats.size };
        },
        /** @param {{ fsPath: string }} uri */
        async readFile(uri) {
          const bytes = await nodeFs.readFile(uri.fsPath);
          return new Uint8Array(bytes);
        }
      }
    }
  };
}

/** @param {import('node:test').TestContext} t */
function createTempRoot(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-repo-'));
  const root = fs.realpathSync(temp);
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  return root;
}

/** @param {string} root @param {string} relative @param {string} [content] */
function write(root, relative, content = '') {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

/** @param {{ ignored: Array<{ reason: string }> }} inventory @param {string} reason */
function countReasons(inventory, reason) {
  return inventory.ignored.filter((entry) => entry.reason === reason).length;
}

test('parses nested gitignore rules with negation, anchors, escapes, and wildcards', () => {
  const rules = parseGitIgnore(
    ['# comment', '\\#literal.js', '\\!literal.js', '/root-only.js', '**/deep.js', '?.js'].join(
      '\n'
    ),
    { baseDir: 'src' }
  );

  assert.ok(rules instanceof GitIgnoreRules);
  assert.equal(rules.isIgnored('src/root-only.js'), true);
  assert.equal(rules.isIgnored('root-only.js'), false);
  assert.equal(rules.isIgnored('src/x.js'), true);
  assert.equal(rules.isIgnored('src/ab.js'), false);
  assert.equal(rules.isIgnored('src/a/b/deep.js'), true);
  assert.equal(rules.isIgnored('src/#literal.js'), true);
  assert.equal(rules.isIgnored('src/!literal.js'), true);

  const negated = parseGitIgnore('*.log\n!keep.log\nbuild/\n!build/keep.py');
  assert.equal(negated.isIgnored('keep.log'), false);
  assert.equal(negated.isIgnored('skip.log'), true);
  assert.equal(negated.isIgnored('build', true), true);
  assert.equal(negated.decide('build/keep.py')?.ignored, false);
});

test('discovers a single root with deterministic metadata and language counts', async (t) => {
  const root = createTempRoot(t);
  write(root, 'app.py', 'value = 1\n');
  write(root, 'src/util.js', 'const value = 1;\n');
  write(root, 'notes.txt', 'plain notes');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(inventory.folders, [
    { name: path.basename(root), path: root, uriText: `file://${root}` }
  ]);
  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['app.py', 'src/util.js']
  );
  assert.equal(inventory.files[0].language, 'python');
  assert.equal(inventory.files[0].rootIndex, 0);
  assert.equal(inventory.files[0].sizeBytes, Buffer.byteLength('value = 1\n'));
  assert.equal(inventory.files[0].uriText, `file://${path.join(root, 'app.py')}`);
  assert.deepEqual(inventory.languages, { javascript: 1, python: 1 });
  assert.deepEqual(inventory.stats, {
    directoriesVisited: 2,
    filesVisited: 3,
    filesIncluded: 2,
    filesExcluded: 1,
    symlinksSkipped: 0,
    truncated: false,
    cancelled: false
  });
  assert.deepEqual(countReasons(inventory, 'unknown-language'), 1);
});

test('supports multiple roots and tags files with their root index', async (t) => {
  const first = createTempRoot(t);
  const second = createTempRoot(t);
  write(first, 'a.py', 'x = 1\n');
  write(second, 'b.js', 'const x = 1;\n');

  const inventory = await discoverRepositoryInventory(
    createVscode([first, second], { names: ['first', 'second'] })
  );

  assert.deepEqual(
    inventory.folders.map((folder) => folder.name),
    ['first', 'second']
  );
  assert.deepEqual(
    inventory.files.map((file) => [file.relativePath, file.rootIndex]),
    [
      ['a.py', 0],
      ['b.js', 1]
    ]
  );
  assert.deepEqual(inventory.languages, { javascript: 1, python: 1 });
});

test('walks nested monorepo directories without leaving any workspace root', async (t) => {
  const root = createTempRoot(t);
  write(root, 'packages/a/src/index.js', 'export const a = 1;\n');
  write(root, 'packages/b/lib/core.py', 'value = 2\n');
  write(root, 'shared/helper.js', 'module.exports = {};\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['packages/a/src/index.js', 'packages/b/lib/core.py', 'shared/helper.js']
  );
  assert.equal(inventory.stats.directoriesVisited, 7);
  assert.equal(inventory.ignored.length, 0);
});

test('handles mixed source languages deterministically', async (t) => {
  const root = createTempRoot(t);
  for (const [name, content] of [
    ['a.py', 'x = 1\n'],
    ['b.js', 'const x = 1;\n'],
    ['c.ts', 'const x: number = 1;\n'],
    ['d.go', 'package main\n'],
    ['e.java', 'class E {}\n'],
    ['f.rb', 'x = 1\n'],
    ['g.css', 'body {}\n']
  ]) {
    write(root, name, content);
  }

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(inventory.languages, {
    css: 1,
    go: 1,
    java: 1,
    javascript: 1,
    python: 1,
    ruby: 1,
    typescript: 1
  });
  assert.equal(inventory.files.length, 7);
});

test('applies default excluded directory names without traversing them', async (t) => {
  const root = createTempRoot(t);
  const excludedNames = [
    '.git',
    'node_modules',
    'vendor',
    '.venv',
    'venv',
    'dist',
    'build',
    'coverage',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    '.cache',
    '.tox',
    '.vscode-test',
    '.bugdhor-data'
  ];
  for (const name of excludedNames) {
    write(root, `${name}/inside.js`, 'const x = 1;\n');
  }
  write(root, 'normal.js', 'const ok = true;\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['normal.js']
  );
  assert.equal(countReasons(inventory, 'default-excluded-directory'), excludedNames.length);
  assert.equal(inventory.stats.directoriesVisited, 1);
  assert.equal(inventory.stats.filesVisited, 1);
});

test('respects nested .gitignore negation without re-including excluded directories', async (t) => {
  const root = createTempRoot(t);
  write(
    root,
    '.gitignore',
    ['*.ignored.js', 'secret.js', '!keep.ignored.js', 'output/', '!output/keep.py'].join('\n')
  );
  write(root, 'src/.gitignore', ['*.tmp.js', '!important.tmp.js'].join('\n'));
  write(root, 'keep.ignored.js', 'const keep = 1;\n');
  write(root, 'skip.ignored.js', 'const skip = 1;\n');
  write(root, 'secret.js', 'const secret = 1;\n');
  write(root, 'output/keep.py', 'x = 1\n');
  write(root, 'output/other.py', 'x = 2\n');
  write(root, 'src/important.tmp.js', 'const a = 1;\n');
  write(root, 'src/other.tmp.js', 'const b = 2;\n');
  write(root, 'src/main.js', 'const c = 3;\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['keep.ignored.js', 'src/important.tmp.js', 'src/main.js']
  );
  assert.equal(countReasons(inventory, 'gitignore'), 4);
  assert.deepEqual(
    inventory.ignored
      .filter((entry) => entry.fsPath === path.join(root, 'output'))
      .map((entry) => entry.reason),
    ['gitignore']
  );
});

test('uses .git/info/exclude as a lower-precedence ignore source', async (t) => {
  const root = createTempRoot(t);
  write(root, '.git/info/exclude', 'excluded.js\n!included.js\n');
  write(root, '.gitignore', 'excluded.js\n');
  write(root, 'excluded.js', 'const x = 1;\n');
  write(root, 'included.js', 'const y = 2;\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['included.js']
  );
  assert.equal(countReasons(inventory, 'gitignore'), 1);
});

test('applies configurable user globs to files and directories', async (t) => {
  const root = createTempRoot(t);
  write(root, 'private/a.js', 'const a = 1;\n');
  write(root, 'src/skip1.js', 'const b = 2;\n');
  write(root, 'src/keep.js', 'const c = 3;\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]), {
    excludeGlobs: ['**/private/**', 'src/skip*.js']
  });

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['src/keep.js']
  );
  assert.equal(countReasons(inventory, 'user-glob'), 2);
});

test('skips binary, generated, oversized, and unknown-language files', async (t) => {
  const root = createTempRoot(t);
  write(root, 'image.png', 'binary');
  write(root, 'app.min.js', 'const x=1;');
  write(root, 'package-lock.json', '{}');
  write(root, 'big.js', 'x'.repeat(64));
  write(root, 'README.md', 'notes');
  write(root, 'good.py', 'x = 1\n');

  const inventory = await discoverRepositoryInventory(createVscode([root]), {
    maxFileBytes: 32
  });

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['good.py']
  );
  assert.deepEqual(inventory.languages, { python: 1 });
  assert.equal(countReasons(inventory, 'binary-file'), 1);
  assert.equal(countReasons(inventory, 'generated-file'), 2);
  assert.equal(countReasons(inventory, 'file-too-large'), 1);
  assert.equal(countReasons(inventory, 'unknown-language'), 1);
  assert.equal(inventory.stats.filesExcluded, 5);
});

test('skips symlinks, including symlinks to directories outside the root', async (t) => {
  const root = createTempRoot(t);
  const outside = createTempRoot(t);
  write(root, 'app.js', 'const x = 1;\n');
  write(outside, 'secret.js', 'const secret = 1;\n');
  fs.symlinkSync(outside, path.join(root, 'link-out'), 'dir');
  fs.symlinkSync(path.join(outside, 'secret.js'), path.join(root, 'link.js'), 'file');

  const inventory = await discoverRepositoryInventory(createVscode([root]));

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['app.js']
  );
  assert.equal(inventory.stats.symlinksSkipped, 2);
  assert.equal(countReasons(inventory, 'symbolic-link'), 2);
  assert.equal(inventory.stats.directoriesVisited, 1);
  assert.equal(
    inventory.files.some((file) => file.fsPath.includes('secret.js')),
    false
  );
});

test('clamps maxFiles, marks truncation, and stops safely', async (t) => {
  const root = createTempRoot(t);
  for (const name of ['a.js', 'b.js', 'c.js', 'd.js', 'e.js']) {
    write(root, name, `const ${name[0]} = 1;\n`);
  }

  const inventory = await discoverRepositoryInventory(createVscode([root]), {
    maxFiles: 2
  });

  assert.deepEqual(
    inventory.files.map((file) => file.relativePath),
    ['a.js', 'b.js']
  );
  assert.equal(inventory.stats.filesIncluded, 2);
  assert.equal(inventory.stats.truncated, true);
  assert.equal(inventory.stats.cancelled, false);
});

test('returns a cancelled partial inventory for a cancelled token', async (t) => {
  const root = createTempRoot(t);
  for (const name of ['a.js', 'b.js', 'c.js', 'd.js', 'e.js']) {
    write(root, name, `const ${name[0]} = 1;\n`);
  }
  const vscode = createVscode([root]);

  const immediate = await discoverRepositoryInventory(vscode, {
    cancellationToken: { isCancellationRequested: true }
  });
  assert.equal(immediate.stats.cancelled, true);
  assert.equal(immediate.files.length, 0);
  assert.equal(immediate.folders.length, 1);

  const functional = await discoverRepositoryInventory(vscode, {
    cancellationToken: { isCancellationRequested: () => true }
  });
  assert.equal(functional.stats.cancelled, true);

  let checks = 0;
  const midScan = await discoverRepositoryInventory(vscode, {
    cancellationToken: {
      get isCancellationRequested() {
        checks += 1;
        return checks >= 3;
      }
    }
  });
  assert.equal(midScan.stats.cancelled, true);
  assert.ok(midScan.files.length <= 5);
  assert.equal(midScan.stats.truncated, false);
});

test('rejects non-file workspace folder URIs with a typed error', async () => {
  const vscode = createVscode([]);
  vscode.workspace.workspaceFolders = [
    { name: 'remote', index: 0, uri: { scheme: 'vscode-remote', fsPath: '/remote' } }
  ];

  assert.throws(
    () => buildWorkspaceFolderMetadata(vscode),
    (error) => {
      assert.ok(error instanceof RepositoryInventoryError);
      assert.equal(error.code, 'E_UNSUPPORTED_WORKSPACE');
      return true;
    }
  );
  await assert.rejects(
    () => discoverRepositoryInventory(vscode),
    (error) => {
      assert.ok(error instanceof RepositoryInventoryError);
      assert.equal(error.code, 'E_UNSUPPORTED_WORKSPACE');
      return true;
    }
  );
});

test('produces identical output for repeated scans regardless of creation order', async (t) => {
  const root = createTempRoot(t);
  for (const name of ['z.js', 'm.py', 'a.js', 'b/nested.js', 'b/inner/deep.py']) {
    write(root, name, 'const x = 1;\n');
  }
  const vscode = createVscode([root]);

  const first = await discoverRepositoryInventory(vscode);
  const second = await discoverRepositoryInventory(vscode);

  assert.deepEqual(first, second);
  const relativePaths = first.files.map((file) => file.relativePath);
  assert.deepEqual(relativePaths, [...relativePaths].sort());
  const ignoredPaths = first.ignored.map((entry) => entry.fsPath);
  assert.deepEqual(ignoredPaths, [...ignoredPaths].sort());
});
