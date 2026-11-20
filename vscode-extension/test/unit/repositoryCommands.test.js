'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { COMMANDS } = require('../../src/constants');
const {
  offerWorkspaceScan,
  registerRepositoryCommands
} = require('../../src/commands/repositoryCommands');

const FileType = Object.freeze({ File: 1, Directory: 2, SymbolicLink: 64 });

/** @param {string} fsPath */
function createUri(fsPath) {
  return {
    scheme: 'file',
    fsPath,
    path: fsPath,
    toString() {
      return `file://${fsPath}`;
    }
  };
}

/** @param {string} fsPath */
function fileTypeFromStats(stats) {
  if (stats.isSymbolicLink()) {
    return FileType.SymbolicLink;
  }
  if (stats.isDirectory()) {
    return FileType.Directory;
  }
  return FileType.File;
}

/**
 * @param {string[]} rootPaths
 * @param {{
 *   cancellationRequested?: boolean,
 *   informationResult?: string,
 *   textDocuments?: object[]
 * }} [options]
 */
function createVscode(rootPaths, options = {}) {
  const workspaceFolders = rootPaths.map((fsPath, index) => ({
    name: path.basename(fsPath) || `root-${index}`,
    index,
    uri: createUri(fsPath)
  }));
  const informationMessages = [];
  const errorMessages = [];
  const warningMessages = [];
  const executedCommands = [];
  const progressReports = [];

  return {
    vscode: {
      FileType,
      ProgressLocation: { Notification: 15 },
      Uri: {
        file: createUri,
        joinPath: (base, ...parts) => createUri(path.join(base.fsPath, ...parts))
      },
      commands: {
        async executeCommand(command, ...args) {
          executedCommands.push({ command, args });
          return undefined;
        }
      },
      window: {
        async showInformationMessage(message, ...actions) {
          informationMessages.push({ message, actions });
          return options.informationResult;
        },
        async showWarningMessage(message) {
          warningMessages.push(message);
          return undefined;
        },
        async showErrorMessage(message) {
          errorMessages.push(message);
          return undefined;
        },
        async withProgress(_options, task) {
          const token = {
            isCancellationRequested: options.cancellationRequested === true
          };
          return task(
            {
              report(value) {
                progressReports.push(value);
              }
            },
            token
          );
        }
      },
      workspace: {
        workspaceFolders,
        textDocuments: options.textDocuments ?? [],
        fs: {
          async readDirectory(uri) {
            const dirents = await fs.readdir(uri.fsPath, { withFileTypes: true });
            return dirents.map((entry) => {
              if (entry.isSymbolicLink()) {
                return [entry.name, FileType.SymbolicLink];
              }
              if (entry.isDirectory()) {
                return [entry.name, FileType.Directory];
              }
              return [entry.name, FileType.File];
            });
          },
          async stat(uri) {
            const stats = await fs.lstat(uri.fsPath);
            return { type: fileTypeFromStats(stats), size: stats.size };
          },
          async readFile(uri) {
            return new Uint8Array(await fs.readFile(uri.fsPath));
          }
        }
      }
    },
    informationMessages,
    errorMessages,
    warningMessages,
    executedCommands,
    progressReports
  };
}

function createRegistry() {
  const handlers = new Map();
  return {
    register(commandId, handler) {
      handlers.set(commandId, handler);
      return {
        dispose() {
          handlers.delete(commandId);
        }
      };
    },
    async execute(commandId, ...args) {
      const handler = handlers.get(commandId);
      if (!handler) {
        throw new Error(`Command was not registered: ${commandId}`);
      }
      return handler(...args);
    },
    ids() {
      return [...handlers.keys()];
    }
  };
}

function createLogger() {
  const entries = [];
  return {
    entries,
    debug(message) {
      entries.push({ level: 'debug', message });
    },
    info(message) {
      entries.push({ level: 'info', message });
    },
    warn(message) {
      entries.push({ level: 'warn', message });
    },
    error(message) {
      entries.push({ level: 'error', message });
    }
  };
}

function createHarness(options = {}) {
  const fake = createVscode(options.rootPaths ?? [], options);
  const registry = createRegistry();
  const serviceCalls = [];
  const service = {
    scanWorkspace: async (request, context) => {
      serviceCalls.push({ request, context });
      return {
        analysisAvailable: true,
        status: 'ok',
        findings: [],
        filesScanned: request.filePaths?.length ?? 0,
        scope: { uris: [] },
        stages: []
      };
    }
  };
  const defaultSettings = {
    backendUrl: 'http://127.0.0.1:8765',
    sendSourceText: true,
    monitoringAllowAutomaticSourceSharing: false,
    repositoryMaxFiles: 2000,
    repositoryMaxFileBytes: 1_048_576,
    repositoryExcludeGlobs: [],
    repositoryIncludeUntrackedFiles: true,
    repositoryGitTimeoutMs: 1000,
    repositoryNotifyOnWorkspaceOpen: true,
    repositoryAutoScanOnWorkspaceOpen: false,
    ...(options.settings ?? {})
  };
  const logger = createLogger();

  registerRepositoryCommands({
    vscode: fake.vscode,
    service,
    logger,
    registry,
    diagnostics: options.diagnostics ?? {},
    getRepositorySettings: () => defaultSettings,
    gitRunner: options.gitRunner
  });

  return { ...fake, registry, serviceCalls, logger, settings: defaultSettings };
}

async function createWorkspace(files, { gitignore } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bugdhor-repo-'));
  for (const [relative, content] of Object.entries(files)) {
    const filePath = path.join(root, relative);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf8');
  }
  if (gitignore) {
    await fs.writeFile(path.join(root, '.gitignore'), gitignore, 'utf8');
  }
  return root;
}

async function removeWorkspace(root) {
  await fs.rm(root, { recursive: true, force: true });
}

test('full repository scan sends only eligible explicit paths across multi-root and nested projects', async () => {
  const first = await createWorkspace(
    {
      'src/app.py': 'value = 1\n',
      'packages/api/handler.py': 'value = 2\n',
      'packages/web/app.js': 'const value = 3;\n',
      'packages/api/ignored.py': 'ignored = true\n',
      'node_modules/dependency/index.js': 'module.exports = {};\n',
      'dist/bundle.py': 'value = 4\n',
      'excluded/skip.py': 'value = 5\n',
      'notes.md': '# notes\n',
      'image.png': 'not source'
    },
    { gitignore: 'packages/api/ignored.py\n' }
  );
  const second = await createWorkspace({ 'lib/util.py': 'value = 6\n' });
  const harness = createHarness({
    rootPaths: [first, second],
    settings: { repositoryExcludeGlobs: ['**/excluded/**'] }
  });

  try {
    const result = await harness.registry.execute(COMMANDS.scanRepository);

    assert.equal(harness.serviceCalls.length, 1);
    assert.equal(result.filesScanned, 4);
    assert.deepEqual(
      harness.serviceCalls[0].request.filePaths.sort(),
      [
        path.join(first, 'packages/api/handler.py'),
        path.join(first, 'packages/web/app.js'),
        path.join(first, 'src/app.py'),
        path.join(second, 'lib/util.py')
      ].sort()
    );
    assert.equal(harness.serviceCalls[0].request.workspaceFolders.length, 2);
    assert.equal(harness.serviceCalls[0].request.sourceText, undefined);
    assert.ok(
      harness.progressReports.some((report) => String(report.message).includes('Discovered'))
    );
  } finally {
    await removeWorkspace(first);
    await removeWorkspace(second);
  }
});

test('rescan all uses the same bounded repository inventory', async () => {
  const root = await createWorkspace({ 'src/app.py': 'value = 1\n' });
  const harness = createHarness({ rootPaths: [root] });

  try {
    await harness.registry.execute(COMMANDS.rescanAll);
    assert.equal(harness.serviceCalls.length, 1);
    assert.deepEqual(harness.serviceCalls[0].request.filePaths, [path.join(root, 'src/app.py')]);
  } finally {
    await removeWorkspace(root);
  }
});

test('changed-file scan filters Git results through exclusions, gitignore, and the inventory', async () => {
  const root = await createWorkspace(
    {
      'src/app.py': 'value = 1\n',
      'src/edited.js': 'const value = 2;\n',
      'src/ignored.py': 'ignored = true\n',
      'node_modules/dependency/index.js': 'module.exports = {};\n'
    },
    { gitignore: 'src/ignored.py\n' }
  );
  const gitCalls = [];
  const harness = createHarness({
    rootPaths: [root],
    gitRunner: async (cwd, args) => {
      gitCalls.push({ cwd, args });
      if (args.includes('--cached')) {
        return 'src/app.py\0';
      }
      if (args.includes('ls-files')) {
        return 'src/edited.js\0src/ignored.py\0';
      }
      return 'src/edited.js\0node_modules/dependency/index.js\0src/deleted.py\0';
    }
  });

  try {
    await harness.registry.execute(COMMANDS.scanChangedFiles);
    assert.equal(harness.serviceCalls.length, 1);
    assert.deepEqual(
      harness.serviceCalls[0].request.filePaths.sort(),
      [path.join(root, 'src/app.py'), path.join(root, 'src/edited.js')].sort()
    );
    assert.equal(gitCalls.length, 3);
    assert.ok(gitCalls.every((call) => call.cwd === root));
    assert.ok(gitCalls[0].args.includes('--diff-filter=ACMR'));
    assert.ok(gitCalls[2].args.includes('--exclude-standard'));
  } finally {
    await removeWorkspace(root);
  }
});

test('selected folder scan is scoped to the chosen workspace folder', async () => {
  const root = await createWorkspace({
    'packages/api/handler.py': 'value = 1\n',
    'packages/web/app.js': 'const value = 2;\n'
  });
  const harness = createHarness({ rootPaths: [root] });

  try {
    await harness.registry.execute(
      COMMANDS.scanSelectedFolder,
      createUri(path.join(root, 'packages/api'))
    );
    assert.equal(harness.serviceCalls.length, 1);
    assert.deepEqual(harness.serviceCalls[0].request.filePaths, [
      path.join(root, 'packages/api/handler.py')
    ]);
    assert.equal(harness.serviceCalls[0].request.workspaceFolders.length, 1);
    assert.equal(
      harness.serviceCalls[0].request.workspaceFolders[0].path,
      path.join(root, 'packages/api')
    );
  } finally {
    await removeWorkspace(root);
  }
});

test('incremental scan targets published findings and dirty documents', async () => {
  const root = await createWorkspace({
    'src/found.py': 'value = 1\n',
    'src/dirty.js': 'const value = 2;\n',
    'src/clean.py': 'value = 3\n'
  });
  const harness = createHarness({
    rootPaths: [root],
    diagnostics: {
      getPublishedUris: () => [createUri(path.join(root, 'src/found.py')).toString()]
    },
    textDocuments: [
      {
        uri: createUri(path.join(root, 'src/dirty.js')),
        isDirty: true
      },
      {
        uri: createUri(path.join(root, 'src/clean.py')),
        isDirty: false
      }
    ]
  });

  try {
    await harness.registry.execute(COMMANDS.scanIncremental);
    assert.equal(harness.serviceCalls.length, 1);
    assert.deepEqual(
      harness.serviceCalls[0].request.filePaths.sort(),
      [path.join(root, 'src/dirty.js'), path.join(root, 'src/found.py')].sort()
    );
  } finally {
    await removeWorkspace(root);
  }
});

test('repository scans refuse non-loopback backends before inventory work', async () => {
  const root = await createWorkspace({ 'src/app.py': 'value = 1\n' });
  const harness = createHarness({
    rootPaths: [root],
    settings: { backendUrl: 'https://api.example.com' }
  });

  try {
    await harness.registry.execute(COMMANDS.scanRepository);
    assert.equal(harness.serviceCalls.length, 0);
    assert.equal(harness.errorMessages.length, 1);
    assert.match(harness.errorMessages[0], /loopback backend/);
  } finally {
    await removeWorkspace(root);
  }
});

test('cancellation stops a repository scan before contacting the backend', async () => {
  const root = await createWorkspace({ 'src/app.py': 'value = 1\n' });
  const harness = createHarness({
    rootPaths: [root],
    cancellationRequested: true
  });

  try {
    const result = await harness.registry.execute(COMMANDS.scanRepository);
    assert.equal(result, undefined);
    assert.equal(harness.serviceCalls.length, 0);
  } finally {
    await removeWorkspace(root);
  }
});

test('workspace detection offers a manual scan and records the one-time notice', async () => {
  const root = await createWorkspace({ 'src/app.py': 'value = 1\n' });
  const fake = createVscode([root], { informationResult: 'Scan Repository' });
  const values = new Map();
  const memento = {
    get(key, fallback) {
      return values.get(key) ?? fallback;
    },
    async update(key, value) {
      values.set(key, value);
    }
  };

  try {
    await offerWorkspaceScan({
      vscode: fake.vscode,
      logger: createLogger(),
      memento,
      settings: createHarness({ rootPaths: [root] }).settings,
      backendReachable: true
    });

    assert.equal(fake.informationMessages.length, 1);
    assert.deepEqual(fake.executedCommands, [{ command: COMMANDS.scanRepository, args: [] }]);
    assert.equal(values.size, 1);

    await offerWorkspaceScan({
      vscode: fake.vscode,
      logger: createLogger(),
      memento,
      settings: createHarness({ rootPaths: [root] }).settings,
      backendReachable: true
    });
    assert.equal(fake.informationMessages.length, 1);
    assert.equal(fake.executedCommands.length, 1);
  } finally {
    await removeWorkspace(root);
  }
});

test('workspace detection auto-scans only with all consent checks and a reachable backend', async () => {
  const root = await createWorkspace({ 'src/app.py': 'value = 1\n' });
  const fake = createVscode([root]);
  const values = new Map();
  const memento = {
    get(key, fallback) {
      return values.get(key) ?? fallback;
    },
    async update(key, value) {
      values.set(key, value);
    }
  };
  const base = createHarness({ rootPaths: [root] }).settings;

  try {
    await offerWorkspaceScan({
      vscode: fake.vscode,
      logger: createLogger(),
      memento,
      settings: {
        ...base,
        repositoryAutoScanOnWorkspaceOpen: true,
        monitoringAllowAutomaticSourceSharing: true,
        sendSourceText: true
      },
      backendReachable: true
    });

    assert.equal(fake.informationMessages.length, 0);
    assert.deepEqual(fake.executedCommands, [{ command: COMMANDS.scanRepository, args: [] }]);
  } finally {
    await removeWorkspace(root);
  }
});
