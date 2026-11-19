'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolvePython } = require('../integration/pythonDiscovery');
const {
  discoverRepositoryInventory,
  RepositoryInventoryError,
  IGNORE_REASONS
} = require('../../src/repository/repositoryInventory');
const { parseGitIgnore } = require('../../src/repository/gitignore');
const { languageForPath } = require('../../src/monitoring/fileFilter');
const { isPathExcluded } = require('../../src/monitoring/changeAnalyzer');
const { patchFiles, applyUnifiedPatch } = require('../../src/repair/patchApplication');

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

/** @param {string[]} rootPaths */
function makeVscode(rootPaths, fsApi) {
  return {
    FileType,
    Uri: {
      file: makeUri,
      joinPath: (base, ...parts) => makeUri(path.join(base.fsPath, ...parts))
    },
    workspace: {
      workspaceFolders: rootPaths.map((fsPath, index) => ({
        name: path.basename(fsPath),
        index,
        uri: makeUri(fsPath)
      })),
      fs: fsApi
    }
  };
}

/** @param {string} root @param {Array<[string, number]>} entries */
function makeMemoryFs(root, entries) {
  const known = new Map([[root, { type: FileType.Directory, size: 0 }]]);
  for (const [name, type] of entries) {
    known.set(path.join(root, name), { type, size: 10 });
  }
  return {
    async readDirectory(uri) {
      if (uri.fsPath !== root) {
        throw Object.assign(new Error('ENOTDIR'), { code: 'ENOTDIR' });
      }
      return entries.map(([name, type]) => [name, type]);
    },
    async stat(uri) {
      const result = known.get(uri.fsPath);
      if (!result) {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      }
      return result;
    },
    async readFile() {
      return new Uint8Array();
    }
  };
}

/** @param {import('node:test').TestContext} t */
function createTempRoot(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-platform-'));
  const root = fs.realpathSync(temp);
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  return root;
}

test('Python discovery is deterministic for every supported platform', () => {
  const repositoryRoot = path.resolve('/repo with spaces ünïcøde');
  const env = {};

  assert.equal(
    resolvePython({ platform: 'win32', repositoryRoot, env, exists: () => false }),
    'python',
    'Windows integration tests must not assume a POSIX python3 executable'
  );
  assert.equal(
    resolvePython({ platform: 'darwin', repositoryRoot, env, exists: () => false }),
    'python3'
  );
  assert.equal(
    resolvePython({ platform: 'linux', repositoryRoot, env, exists: () => false }),
    'python3'
  );

  const windowsVenv = path.win32.join(repositoryRoot, '.venv', 'Scripts', 'python.exe');
  const posixVenv = path.posix.join(repositoryRoot, '.venv', 'bin', 'python');
  assert.equal(
    resolvePython({ platform: 'win32', repositoryRoot, env, exists: () => true }),
    windowsVenv
  );
  assert.equal(
    resolvePython({ platform: 'linux', repositoryRoot, env, exists: () => true }),
    posixVenv
  );

  assert.equal(
    resolvePython({
      platform: 'win32',
      repositoryRoot,
      env: { BUGDHOR_PYTHON: '  C:\\Python312\\python.exe  ' },
      exists: () => true
    }),
    'C:\\Python312\\python.exe',
    'an explicit override must win over the virtual environment'
  );
});

test('repository inventory handles Unicode names and spaces on a real filesystem', async (t) => {
  const root = createTempRoot(t);
  const nested = path.join(root, 'src with spaces — 日本語');
  const source = path.join(nested, 'café — 日本語.py');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(source, 'value = 1\n', 'utf8');

  const vscode = makeVscode([root], {
    async readDirectory(uri) {
      const entries = await fs.promises.readdir(uri.fsPath, { withFileTypes: true });
      return entries.map((entry) => [
        entry.name,
        entry.isDirectory() ? FileType.Directory : FileType.File
      ]);
    },
    async stat(uri) {
      const stats = await fs.promises.lstat(uri.fsPath);
      return {
        type: stats.isDirectory() ? FileType.Directory : FileType.File,
        size: stats.size
      };
    },
    async readFile(uri) {
      return new Uint8Array(await fs.promises.readFile(uri.fsPath));
    }
  });

  const inventory = await discoverRepositoryInventory(vscode);

  assert.equal(inventory.files.length, 1);
  assert.equal(inventory.files[0].relativePath, 'src with spaces — 日本語/café — 日本語.py');
  assert.equal(inventory.files[0].fsPath, source);
  assert.equal(inventory.files[0].language, 'python');
  assert.equal(languageForPath(source), 'python');
  assert.equal(languageForPath(path.join(root, 'javascript — 日本語.js')), 'javascript');
});

test('Windows separators are normalized in globs, gitignore patterns, and repair paths', () => {
  assert.equal(
    isPathExcluded('C:\\repo\\node_modules\\package\\index.js', ['**/node_modules/**']),
    true,
    'backslash paths must match POSIX-style exclude globs'
  );
  const rules = parseGitIgnore('src\\generated\\*.js');
  assert.equal(rules.isIgnored('src/generated/a.js'), true);

  const patch = [
    '--- a/src\\old.py',
    '+++ b/src\\new.py',
    '@@ -1,2 +1,2 @@',
    ' value = 1',
    '-value = 2',
    '+value = 3'
  ].join('\r\n');
  assert.deepEqual(patchFiles(patch), ['src/new.py']);
  assert.equal(applyUnifiedPatch('value = 1\nvalue = 2', patch), 'value = 1\nvalue = 3');
  assert.throws(
    () => patchFiles('--- a/safe.py\n+++ b\\..\\..\\etc\\passwd\n@@ -1 +1 @@\n-x\n+y'),
    /escapes the target file scope/
  );
});

test('invalid entry names with Windows separators are rejected before traversal', async () => {
  const root = path.resolve('/repo with windows separators');
  const inventory = await discoverRepositoryInventory(
    makeVscode(
      [root],
      makeMemoryFs(root, [
        ['..\\escape.py', FileType.File],
        ['safe.py', FileType.File]
      ])
    )
  );

  assert.deepEqual(
    inventory.files.map((entry) => entry.relativePath),
    ['safe.py']
  );
  assert.equal(
    inventory.ignored.some(
      (entry) =>
        entry.reason === IGNORE_REASONS.invalidEntryName && entry.fsPath.includes('escape.py')
    ),
    true
  );
});

test('permission failures are reported as typed filesystem errors', async () => {
  const root = path.resolve('/repo with denied access');
  const denied = Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
  const fsApi = makeMemoryFs(root, [['safe.py', FileType.File]]);
  fsApi.readDirectory = async () => {
    throw denied;
  };

  await assert.rejects(
    discoverRepositoryInventory(makeVscode([root], fsApi)),
    (error) =>
      error instanceof RepositoryInventoryError &&
      error.code === 'E_FILESYSTEM' &&
      error.cause === denied
  );
});

test('large repository inventories stop at the configured bound and report truncation', async () => {
  const root = path.resolve('/very large repository 🚀');
  const entries = Array.from({ length: 2_500 }, (_, index) => [
    `module-${String(index).padStart(4, '0')}.py`,
    FileType.File
  ]);
  const inventory = await discoverRepositoryInventory(
    makeVscode([root], makeMemoryFs(root, entries)),
    {
      maxFiles: 50
    }
  );

  assert.equal(inventory.files.length, 50);
  assert.equal(inventory.stats.filesIncluded, 50);
  assert.equal(inventory.stats.filesVisited, 51, 'the first over-limit entry must stop traversal');
  assert.equal(inventory.stats.truncated, true);
  assert.equal(inventory.stats.cancelled, false);
  assert.equal(inventory.files[0].relativePath, 'module-0000.py');
  assert.equal(inventory.files.at(-1).relativePath, 'module-0049.py');
});
