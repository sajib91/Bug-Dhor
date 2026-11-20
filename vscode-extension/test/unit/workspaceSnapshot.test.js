'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const nodeFs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { createWorkspaceSnapshotProvider } = require('../../src/webviews/workspaceSnapshot');

const FileType = Object.freeze({ File: 1, Directory: 2, SymbolicLink: 64 });

/** @param {string} fsPath */
function makeUri(fsPath) {
  return {
    scheme: 'file',
    fsPath,
    path: fsPath,
    toString() {
      return `file://${fsPath}`;
    }
  };
}

/**
 * @param {string[]} roots
 * @param {{
 *   name?: string,
 *   folderNames?: string[],
 *   readDirectoryError?: Error
 * }} [options]
 */
function createVscode(roots, options = {}) {
  const workspaceFolders = roots.map((fsPath, index) => ({
    name: options.folderNames?.[index] ?? path.basename(fsPath),
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
      name: options.name,
      workspaceFolders,
      fs: {
        /** @param {{ fsPath: string }} uri */
        async readDirectory(uri) {
          if (options.readDirectoryError) {
            throw options.readDirectoryError;
          }
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
          if (options.readDirectoryError) {
            throw options.readDirectoryError;
          }
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
          return new Uint8Array(await nodeFs.readFile(uri.fsPath));
        }
      }
    }
  };
}

/** @param {import('node:test').TestContext} t */
function createTempRoot(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-snapshot-'));
  const root = fs.realpathSync(temp);
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  return root;
}

/**
 * @param {string} root
 * @param {string} relative
 * @param {string} [content]
 */
function write(root, relative, content = 'value = 1\n') {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

const DEFAULT_SETTINGS = {
  repositoryMaxFiles: 2000,
  repositoryMaxFileBytes: 1_048_576,
  repositoryExcludeGlobs: []
};

test('snapshot starts with unknown values when no VS Code workspace is open', async () => {
  const provider = createWorkspaceSnapshotProvider({
    vscode: createVscode([]),
    getSettings: () => DEFAULT_SETTINGS
  });

  const patch = await provider.refresh();

  assert.deepEqual(patch.workspace, {
    available: false,
    name: null,
    path: null,
    folders: []
  });
  assert.deepEqual(patch.inventory, {
    available: false,
    totalFiles: null,
    languages: {},
    truncated: null
  });
  assert.deepEqual(provider.getDiscoveredPaths(), []);
  assert.equal(provider.getLastError(), null);
});

test('snapshot uses real folder metadata and discovers only eligible source files', async (t) => {
  const root = createTempRoot(t);
  write(root, 'src/app.py');
  write(root, 'src/util.js', 'const value = 1;\n');
  write(root, 'src/ignored.py');
  write(root, 'notes.md', '# notes');
  write(root, 'image.png', 'not source');
  write(root, 'excluded/skip.py');
  for (const excluded of [
    'node_modules/dep/index.js',
    '.venv/lib.py',
    'vendor/v.py',
    'dist/bundle.js',
    'build/generated.py',
    '.cache/temp.py',
    '__pycache__/module.py'
  ]) {
    write(root, excluded);
  }
  fs.writeFileSync(path.join(root, '.gitignore'), 'src/ignored.py\n');

  const provider = createWorkspaceSnapshotProvider({
    vscode: createVscode([root], { name: 'Single Root', folderNames: ['project'] }),
    getSettings: () => ({
      ...DEFAULT_SETTINGS,
      repositoryExcludeGlobs: ['**/excluded/**']
    })
  });

  const patch = await provider.refresh();

  assert.deepEqual(patch.workspace, {
    available: true,
    name: 'Single Root',
    path: root,
    folders: [{ name: 'project', path: root }]
  });
  assert.deepEqual(patch.inventory, {
    available: true,
    totalFiles: 2,
    languages: { javascript: 1, python: 1 },
    truncated: false
  });
  assert.deepEqual(provider.getDiscoveredPaths().sort(), [
    path.join(root, 'src/app.py'),
    path.join(root, 'src/util.js')
  ]);
  assert.equal(provider.hasDiscoveredPath(path.join(root, 'node_modules/dep/index.js')), false);
  assert.equal(provider.hasDiscoveredPath(path.join(root, 'src/ignored.py')), false);
  assert.equal(provider.getLastError(), null);
});

test('snapshot supports multiple roots without inventing a single workspace path', async (t) => {
  const first = createTempRoot(t);
  const second = createTempRoot(t);
  write(first, 'a.py');
  write(second, 'b.js', 'const value = 2;\n');

  const provider = createWorkspaceSnapshotProvider({
    vscode: createVscode([first, second], { folderNames: ['alpha', 'beta'] }),
    getSettings: () => DEFAULT_SETTINGS
  });
  const patch = await provider.refresh();

  assert.deepEqual(patch.workspace, {
    available: true,
    name: null,
    path: null,
    folders: [
      { name: 'alpha', path: first },
      { name: 'beta', path: second }
    ]
  });
  assert.equal(patch.inventory.totalFiles, 2);
  assert.deepEqual(
    provider.getDiscoveredPaths().sort(),
    [path.join(first, 'a.py'), path.join(second, 'b.js')].sort()
  );
});

test('snapshot reports discovery failure as unavailable instead of estimating counts', async () => {
  const root = '/workspace/project';
  const warnings = [];
  const provider = createWorkspaceSnapshotProvider({
    vscode: createVscode([root], { readDirectoryError: new Error('fs unavailable') }),
    logger: {
      warn(message) {
        warnings.push(message);
      }
    },
    getSettings: () => DEFAULT_SETTINGS
  });

  const patch = await provider.refresh();

  assert.equal(patch.workspace.available, true);
  assert.equal(patch.workspace.path, root);
  assert.deepEqual(patch.inventory, {
    available: false,
    totalFiles: null,
    languages: {},
    truncated: null
  });
  assert.deepEqual(provider.getDiscoveredPaths(), []);
  assert.match(provider.getLastError(), /Unable to stat/);
  assert.equal(warnings.length, 1);
});
