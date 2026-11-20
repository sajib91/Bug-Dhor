'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const path = require('node:path');

const {
  ENGINE_STATES,
  EngineManager,
  normalizeEngineSettings,
  registerManager,
  unregisterManager
} = require('../../src/engine/engineManager');
const {
  ENGINE_ERROR_KINDS,
  EngineError,
  assertRuntimeRequirements,
  buildEngineArguments,
  buildEngineEnvironment,
  clearRuntimeInstallCache,
  discoverEngineSource,
  discoverPythonCandidates,
  ensureManagedRuntime,
  loopbackEndpoint,
  runFixedCommand,
  validatePythonExecutable
} = require('../../src/engine/engineRuntime');

const EXTENSION_PATH = '/extension';
const ENGINE_ROOT = path.join(EXTENSION_PATH, 'engine');
const MODULE_ROOT = path.join(ENGINE_ROOT, 'src');
const PYTHON = '/opt/python3/bin/python3';
const MANIFEST = path.join(ENGINE_ROOT, 'pyproject.toml');
const REQUIREMENTS = path.join(ENGINE_ROOT, 'requirements-runtime.txt');
const RUNTIME_REQUIREMENTS_CONTENT = 'fastapi>=0.115,<1\npydantic>=2.8,<3\n';
const HEALTH_OK = Object.freeze({ service: 'bugdhor-engine', status: 'ok' });

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createFileSystem() {
  const files = new Set([
    path.join(MODULE_ROOT, 'bugdhor', '__main__.py'),
    path.join(MODULE_ROOT, 'bugdhor', 'api', 'app.py'),
    PYTHON,
    MANIFEST,
    REQUIREMENTS
  ]);
  const directories = new Set([ENGINE_ROOT, path.join(EXTENSION_PATH)]);
  return {
    files,
    directories,
    statSync(target) {
      if (files.has(target)) {
        return { isFile: () => true, isDirectory: () => false };
      }
      throw Object.assign(new Error(`ENOENT: ${target}`), { code: 'ENOENT' });
    },
    existsSync(target) {
      return files.has(target) || directories.has(target);
    },
    mkdirSync(target) {
      directories.add(target);
    },
    readFileSync(target) {
      if (target === REQUIREMENTS) {
        return RUNTIME_REQUIREMENTS_CONTENT;
      }
      if (target === MANIFEST) {
        return '[project]\nname = "bugdhor-engine"\n';
      }
      throw Object.assign(new Error(`ENOENT: ${target}`), { code: 'ENOENT' });
    }
  };
}

function createFakeProcess(options = {}) {
  const { autoClose = true, code = 0, pid = 4242, stdout = '', stderr = '' } = options;
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.pid = pid;
  child.exitCode = null;
  child.killSignals = [];
  child.kill = (signal) => {
    child.killSignals.push(signal);
    process.nextTick(() => {
      child.exitCode = code;
      child.emit('exit', code, null);
      child.emit('close', code, null);
    });
    return true;
  };
  if (autoClose) {
    process.nextTick(() => {
      if (stdout) {
        child.stdout.emit('data', stdout);
      }
      if (stderr) {
        child.stderr.emit('data', stderr);
      }
      child.exitCode = code;
      child.emit('exit', code, null);
      child.emit('close', code, null);
    });
  }
  return child;
}

function createSpawn({ engineProcess, probeCode = 0, onCall } = {}) {
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    onCall?.({ command, args, options });
    if (args[0] === '-m' && args[1] === 'bugdhor') {
      return engineProcess ?? createFakeProcess({ autoClose: false });
    }
    // Only dependency probes fail when probeCode is set; venv/pip commands use
    // their own success/failure fixtures.
    return createFakeProcess({ code: args[0] === '-c' ? probeCode : 0, stdout: 'ready' });
  };
  return { spawn, calls };
}

function createHealthService(responses) {
  const calls = [];
  const service = {
    calls,
    async health() {
      const index = Math.min(calls.length, responses.length - 1);
      const response = responses[index];
      calls.push(response);
      if (response instanceof Error) {
        throw response;
      }
      return response;
    }
  };
  return service;
}

function createLogger() {
  const entries = [];
  return {
    entries,
    info(message) {
      entries.push({ level: 'info', message });
    },
    warn(message) {
      entries.push({ level: 'warn', message });
    },
    error(message) {
      entries.push({ level: 'error', message });
    },
    debug(message) {
      entries.push({ level: 'debug', message });
    }
  };
}

function createManager(options = {}) {
  clearRuntimeInstallCache();
  const settings = {
    backendUrl: 'http://127.0.0.1:8765',
    pythonPath: PYTHON,
    manageRuntime: true,
    autoStart: true,
    ...options.settings
  };
  const service = createHealthService(options.healthResponses ?? [HEALTH_OK]);
  const logger = createLogger();
  const engineProcess = options.engineProcess ?? createFakeProcess({ autoClose: false });
  const { spawn, calls } = createSpawn({
    engineProcess,
    probeCode: options.probeCode ?? 0,
    onCall: options.onSpawn
  });
  const fileSystem = options.fileSystem ?? createFileSystem();
  const manager = new EngineManager({
    service,
    logger,
    context: {
      extensionPath: EXTENSION_PATH,
      repositoryRoot: options.repositoryRoot,
      globalStoragePath: '/storage'
    },
    getSettings: () => settings,
    spawn,
    fileSystem,
    platform: 'darwin',
    environment: options.environment ?? { HOME: '/home/test' },
    delay: options.delay ?? (async () => {})
  });
  return { manager, service, logger, engineProcess, spawnCalls: calls, fileSystem };
}

function engineSpawnCalls(calls) {
  return calls.filter((call) => call.args[0] === '-m' && call.args[1] === 'bugdhor');
}

test('loopbackEndpoint accepts only explicit loopback origins', () => {
  assert.deepEqual(loopbackEndpoint('http://127.0.0.1:9000'), {
    host: '127.0.0.1',
    port: 9000
  });
  assert.deepEqual(loopbackEndpoint('http://localhost'), { host: '127.0.0.1', port: 8765 });
  assert.deepEqual(loopbackEndpoint('http://[::1]:8765'), { host: '::1', port: 8765 });
  assert.throws(() => loopbackEndpoint('https://engine.example.test'), /loopback/);
  assert.throws(() => loopbackEndpoint('not a URL'), /valid URL/);
});

test('Python discovery rejects shell syntax and workspace-derived executables', () => {
  const fileSystem = createFileSystem();
  assert.equal(validatePythonExecutable(PYTHON, { platform: 'darwin', fileSystem }), PYTHON);
  assert.equal(validatePythonExecutable('python3', { platform: 'darwin', fileSystem }), 'python3');
  assert.equal(
    validatePythonExecutable('python3; curl https://example.test', {
      platform: 'darwin',
      fileSystem
    }),
    undefined
  );
  assert.equal(
    validatePythonExecutable('python3\nmalicious', { platform: 'darwin', fileSystem }),
    undefined
  );
  assert.equal(
    validatePythonExecutable('python3', {
      platform: 'darwin',
      fileSystem,
      allowCommandName: false
    }),
    undefined
  );

  const candidates = discoverPythonCandidates({
    configured: PYTHON,
    platform: 'darwin',
    environment: { BUGDHOR_PYTHON: 'python3', HOME: '/home/test' },
    fileSystem
  });
  assert.deepEqual(candidates.slice(0, 3), [PYTHON, 'python3', 'python']);
});

test('engine source discovery prefers bundled files and falls back to development files', () => {
  const fileSystem = createFileSystem();
  const developmentMain = path.join(
    '/repository',
    'security-engine',
    'src',
    'bugdhor',
    '__main__.py'
  );
  const developmentApp = path.join(
    '/repository',
    'security-engine',
    'src',
    'bugdhor',
    'api',
    'app.py'
  );
  fileSystem.files.add(developmentMain);
  fileSystem.files.add(developmentApp);

  const options = {
    extensionPath: EXTENSION_PATH,
    repositoryRoot: '/repository',
    fileSystem
  };
  assert.deepEqual(discoverEngineSource(options), {
    engineRoot: ENGINE_ROOT,
    moduleRoot: MODULE_ROOT,
    manifestPath: MANIFEST,
    requirementsPath: REQUIREMENTS,
    source: 'bundled'
  });

  const developmentEngineRoot = path.join('/repository', 'security-engine');
  fileSystem.files.add(path.join(developmentEngineRoot, 'pyproject.toml'));
  fileSystem.files.add(path.join(developmentEngineRoot, 'requirements-runtime.txt'));
  fileSystem.files.delete(path.join(MODULE_ROOT, 'bugdhor', '__main__.py'));
  assert.deepEqual(discoverEngineSource(options), {
    engineRoot: path.join('/repository', 'security-engine'),
    moduleRoot: path.join('/repository', 'security-engine', 'src'),
    manifestPath: path.join('/repository', 'security-engine', 'pyproject.toml'),
    requirementsPath: path.join('/repository', 'security-engine', 'requirements-runtime.txt'),
    source: 'development'
  });
});

test('engine discovery rejects file URLs, relative paths and missing manifests', () => {
  const fileSystem = createFileSystem();
  assert.equal(
    discoverEngineSource({ extensionPath: 'file:///extension', fileSystem }),
    undefined
  );
  assert.equal(discoverEngineSource({ extensionPath: 'extension', fileSystem }), undefined);
  assert.equal(
    discoverEngineSource({
      extensionUri: { fsPath: 'file:///extension' },
      fileSystem
    }),
    undefined,
    'a file URL must never be accepted, even from extensionUri'
  );

  fileSystem.files.delete(MANIFEST);
  assert.equal(discoverEngineSource({ extensionPath: EXTENSION_PATH, fileSystem }), undefined);
});

test('runtime requirements reject editable installs, local paths and extras', () => {
  assert.doesNotThrow(() => assertRuntimeRequirements(RUNTIME_REQUIREMENTS_CONTENT));
  assert.throws(() => assertRuntimeRequirements('-e .[dev,ml]\n'), /editable/);
  assert.throws(() => assertRuntimeRequirements('--editable .\n'), /editable/);
  assert.throws(() => assertRuntimeRequirements('file:///app\n'), /local path/);
  assert.throws(() => assertRuntimeRequirements('./security-engine\n'), /local path/);
  assert.throws(() => assertRuntimeRequirements('torch[ml]>=2\n'), /extras/);
});

test('runFixedCommand uses fixed argv without a shell and captures bounded output', async () => {
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    return createFakeProcess({ code: 0, stdout: 'hello', stderr: 'notice' });
  };

  const result = await runFixedCommand({
    command: 'python3',
    args: ['--version'],
    cwd: MODULE_ROOT,
    spawn
  });

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'hello');
  assert.equal(result.stderr, 'notice');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, ['--version']);
  assert.equal(calls[0].options.shell, false);
  assert.equal(calls[0].options.cwd, MODULE_ROOT);
  assert.deepEqual(calls[0].options.stdio, ['ignore', 'pipe', 'pipe']);
});

test('managed runtime installs from the absolute engine root without editable requirements', async () => {
  clearRuntimeInstallCache();
  const calls = [];
  const phases = [];
  const runtimePython = path.join('/storage', 'engine-runtime', 'bin', 'python');
  let runtimeExists = false;
  const fileSystem = {
    existsSync(target) {
      return target === REQUIREMENTS || (target === runtimePython && runtimeExists);
    },
    mkdirSync() {},
    statSync() {
      throw new Error('unused');
    },
    readFileSync(target) {
      if (target !== REQUIREMENTS) {
        throw new Error(`unexpected read: ${target}`);
      }
      return RUNTIME_REQUIREMENTS_CONTENT;
    }
  };
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === '-c') {
      return createFakeProcess({ code: 1 });
    }
    if (args[1] === 'venv') {
      runtimeExists = true;
    }
    return createFakeProcess({ code: 0 });
  };

  const options = {
    python: 'python3',
    runtimeDirectory: path.join('/storage', 'engine-runtime'),
    engineRoot: ENGINE_ROOT,
    requirementsPath: REQUIREMENTS,
    platform: 'darwin',
    fileSystem,
    spawn,
    onPhase: (phase) => phases.push(phase)
  };
  const result = await ensureManagedRuntime(options);

  assert.equal(result.python, runtimePython);
  assert.equal(result.installed, true);
  assert.deepEqual(phases, ['preparing-runtime', 'installing-dependencies']);
  assert.deepEqual(
    calls.map((call) => call.args),
    [
      ['-m', 'venv', path.join('/storage', 'engine-runtime')],
      [
        '-m',
        'pip',
        'install',
        '--disable-pip-version-check',
        '--no-input',
        '-r',
        REQUIREMENTS
      ]
    ]
  );
  assert.ok(
    calls.every((call) => call.options.shell === false && call.options.cwd === ENGINE_ROOT),
    'every managed-runtime command must run from the absolute engine root'
  );

  // A concurrent caller must share the same install instead of racing pip.
  const before = calls.length;
  const [first, second] = await Promise.all([
    ensureManagedRuntime(options),
    ensureManagedRuntime(options)
  ]);
  assert.equal(first.installed, second.installed);
  assert.equal(calls.length, before, 'cached installs must not spawn more commands');
});

test('managed runtime rejects a file URL requirements path and a developer requirements file', async () => {
  clearRuntimeInstallCache();
  await assert.rejects(
    () =>
      ensureManagedRuntime({
        python: 'python3',
        runtimeDirectory: '/storage/engine-runtime',
        requirementsPath: 'file:///extension/engine/requirements-runtime.txt',
        engineRoot: ENGINE_ROOT,
        platform: 'darwin',
        fileSystem: createFileSystem(),
        spawn: () => createFakeProcess({ code: 0 })
      }),
    (error) => {
      assert.equal(error.kind, ENGINE_ERROR_KINDS.RUNTIME_INSTALL);
      return true;
    }
  );

  const fileSystem = createFileSystem();
  fileSystem.files.add(path.join('/storage/other-runtime', 'bin', 'python'));
  fileSystem.readFileSync = () => '-e .[dev,ml]\n';
  await assert.rejects(
    () =>
      ensureManagedRuntime({
        python: 'python3',
        runtimeDirectory: '/storage/other-runtime',
        requirementsPath: REQUIREMENTS,
        engineRoot: ENGINE_ROOT,
        platform: 'darwin',
        fileSystem,
        spawn: (command, args) => createFakeProcess({ code: args[0] === '-c' ? 1 : 0 })
      }),
    /editable install/
  );
});

test('managed runtime install failures include captured stdout and stderr', async () => {
  clearRuntimeInstallCache();
  const fileSystem = createFileSystem();
  const runtimePython = path.join('/storage/failing-runtime', 'bin', 'python');
  fileSystem.files.add(runtimePython);
  const spawn = (command, args) => {
    if (args[0] === '-c') {
      return createFakeProcess({ code: 1 });
    }
    return createFakeProcess({
      code: 1,
      stdout: 'collecting packages',
      stderr: 'ERROR: file:/// does not appear to be a Python project'
    });
  };
  await assert.rejects(
    () =>
      ensureManagedRuntime({
        python: 'python3',
        runtimeDirectory: '/storage/failing-runtime',
        engineRoot: ENGINE_ROOT,
        requirementsPath: REQUIREMENTS,
        platform: 'darwin',
        fileSystem,
        spawn
      }),
    (error) => {
      assert.ok(error instanceof EngineError);
      assert.equal(error.kind, ENGINE_ERROR_KINDS.RUNTIME_INSTALL);
      assert.match(error.message, /does not appear to be a Python project/);
      assert.match(error.stderr, /file:\/\/\//);
      return true;
    }
  );
});

test('engine argv and environment are fixed and loopback-scoped', () => {
  assert.deepEqual(buildEngineArguments({ python: PYTHON, host: '127.0.0.1', port: 8765 }), [
    PYTHON,
    '-m',
    'bugdhor',
    '--host',
    '127.0.0.1',
    '--port',
    '8765'
  ]);
  const environment = buildEngineEnvironment({
    environment: { PATH: '/usr/bin', BUGDHOR_HOST: 'remote.test' },
    host: '127.0.0.1',
    port: 9000
  });
  assert.equal(environment.PATH, '/usr/bin');
  assert.equal(environment.PYTHONUNBUFFERED, '1');
  assert.equal(environment.PYTHONNOUSERSITE, '1');
  assert.equal(environment.BUGDHOR_HOST, '127.0.0.1');
  assert.equal(environment.BUGDHOR_PORT, '9000');
});

test('engine settings clamp numeric bounds for safe restarts', () => {
  const settings = normalizeEngineSettings({
    startupTimeoutMs: 1,
    healthPollMs: 999_999,
    maxRestarts: -4,
    restartBaseDelayMs: 0,
    restartMaxDelayMs: 999_999,
    autoStart: 'yes'
  });

  assert.equal(settings.startupTimeoutMs, 1000);
  assert.equal(settings.healthPollMs, 5000);
  assert.equal(settings.maxRestarts, 0);
  assert.equal(settings.restartBaseDelayMs, 100);
  assert.equal(settings.restartMaxDelayMs, 60000);
  assert.equal(settings.autoStart, true);
  assert.ok(Object.isFrozen(settings));
});

test('an already-running loopback engine is adopted without spawning', async () => {
  const harness = createManager({
    settings: { backendUrl: 'http://localhost:8765' },
    healthResponses: [HEALTH_OK]
  });

  assert.equal(await harness.manager.start({ reason: 'activation' }), true);
  assert.equal(harness.spawnCalls.length, 0);
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.ONLINE);
  assert.equal(harness.manager.getStatus().owned, false);
  assert.match(harness.manager.getStatus().detail, /no duplicate process/);
});

test('a managed engine starts once with a fixed argv and only its owned child is stopped', async () => {
  const engineProcess = createFakeProcess({ autoClose: false, pid: 4242 });
  const harness = createManager({
    engineProcess,
    healthResponses: [new Error('offline'), HEALTH_OK]
  });

  const [first, second] = await Promise.all([
    harness.manager.start({ reason: 'activation' }),
    harness.manager.start({ reason: 'command' })
  ]);
  assert.equal(first, true);
  assert.equal(second, true);

  const engineCalls = engineSpawnCalls(harness.spawnCalls);
  assert.equal(engineCalls.length, 1, 'concurrent callers must share one startup');
  const [engineCall] = engineCalls;
  assert.deepEqual(engineCall.args, ['-m', 'bugdhor', '--host', '127.0.0.1', '--port', '8765']);
  assert.equal(engineCall.command, PYTHON);
  assert.equal(engineCall.options.cwd, MODULE_ROOT);
  assert.equal(engineCall.options.shell, false);
  assert.equal(engineCall.options.windowsHide, true);
  assert.deepEqual(engineCall.options.stdio, ['ignore', 'pipe', 'pipe']);
  assert.equal(engineCall.options.env.BUGDHOR_HOST, '127.0.0.1');
  assert.equal(engineCall.options.env.BUGDHOR_PORT, '8765');
  assert.match(engineCall.options.env.PYTHONPATH, new RegExp(`^${MODULE_ROOT}`));

  const status = harness.manager.getStatus();
  assert.equal(status.state, ENGINE_STATES.ONLINE);
  assert.equal(status.owned, true);
  assert.equal(status.pid, 4242);

  assert.equal(await harness.manager.start(), true);
  assert.equal(engineSpawnCalls(harness.spawnCalls).length, 1);

  await harness.manager.stop();
  assert.deepEqual(engineProcess.killSignals, ['SIGTERM']);
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.OFFLINE);
  assert.equal(harness.manager.getStatus().owned, false);
});

test('stop never kills an engine started outside Bug Dhor', async () => {
  const harness = createManager({ healthResponses: [HEALTH_OK] });
  await harness.manager.start();

  assert.equal(await harness.manager.stop(), true);
  assert.equal(harness.spawnCalls.length, 0);
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.OFFLINE);
});

test('a missing bundled engine fails without spawning a process', async () => {
  const fileSystem = createFileSystem();
  fileSystem.files.delete(path.join(MODULE_ROOT, 'bugdhor', '__main__.py'));
  const harness = createManager({
    fileSystem,
    healthResponses: [new Error('offline')]
  });

  assert.equal(await harness.manager.start(), false);
  assert.equal(harness.spawnCalls.length, 0);
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.NOT_INSTALLED);
  assert.equal(harness.manager.getStatus().errorKind, ENGINE_ERROR_KINDS.ENGINE_STARTUP);
  assert.match(harness.manager.getStatus().detail, /Reinstall the extension/);
});

test('no compatible Python interpreter fails closed', async () => {
  const harness = createManager({
    settings: { pythonPath: '', manageRuntime: false },
    environment: {},
    probeCode: 1,
    healthResponses: [new Error('offline')]
  });

  assert.equal(await harness.manager.start(), false);
  assert.equal(engineSpawnCalls(harness.spawnCalls).length, 0);
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.FAILED);
  assert.match(harness.manager.getStatus().detail, /Python 3/);
});

test('automatic restarts are bounded and use exponential backoff', async () => {
  const harness = createManager({
    settings: {
      autoStart: true,
      maxRestarts: 2,
      restartBaseDelayMs: 100,
      restartMaxDelayMs: 1000
    },
    healthResponses: [new Error('offline')]
  });
  const restartCalls = [];
  const stateChanges = [];
  harness.manager.onStateChange((status) => stateChanges.push(status.state));
  harness.manager.start = async (options) => {
    restartCalls.push(options);
    return true;
  };
  harness.manager.setState(ENGINE_STATES.OFFLINE, 'offline');

  harness.manager.scheduleRestart();
  assert.equal(harness.manager.restartAttempt, 1);
  await delay(130);
  assert.deepEqual(restartCalls, [{ reason: 'restart' }]);

  harness.manager.setState(ENGINE_STATES.OFFLINE, 'offline');
  harness.manager.scheduleRestart();
  assert.equal(harness.manager.restartAttempt, 2);
  harness.manager.scheduleRestart();
  assert.equal(harness.manager.restartAttempt, 2, 'the restart budget must not be exceeded');

  await delay(230);
  assert.deepEqual(restartCalls, [{ reason: 'restart' }, { reason: 'restart' }]);
  assert.equal(
    harness.logger.entries.filter((entry) => entry.message.includes('restart the local engine'))
      .length,
    2
  );
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.FAILED);
  assert.ok(stateChanges.includes(ENGINE_STATES.OFFLINE));
  harness.manager.clearRestart();
});

test('duplicate engine managers are rejected per endpoint key', () => {
  const key = 'bugdhor.test.engine-manager';
  unregisterManager(key);
  const first = createManager().manager;
  const second = createManager().manager;

  assert.equal(registerManager(key, first), true);
  assert.equal(registerManager(key, second), false);
  unregisterManager(key);
  assert.equal(registerManager(key, second), true);
  unregisterManager(key);
});

test('startup publishes preparing-runtime, installing-dependencies and starting-engine states', async () => {
  const fileSystem = createFileSystem();
  const runtimePython = path.join('/storage', 'engine-runtime', 'bin', 'python');
  const harness = createManager({
    fileSystem,
    probeCode: 1,
    healthResponses: [new Error('offline'), HEALTH_OK],
    onSpawn: ({ args }) => {
      if (args[1] === 'venv') {
        fileSystem.files.add(runtimePython);
      }
    }
  });
  const states = [];
  harness.manager.onStateChange((status) => states.push(status.state));

  assert.equal(await harness.manager.start(), true);
  assert.ok(states.includes(ENGINE_STATES.PREPARING_RUNTIME), states.join(','));
  assert.ok(states.includes(ENGINE_STATES.INSTALLING_DEPENDENCIES), states.join(','));
  assert.ok(states.includes(ENGINE_STATES.STARTING_ENGINE), states.join(','));
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.ONLINE);
});

test('scan failures are classified and keep the backend request id', () => {
  const harness = createManager();
  const validationError = Object.assign(new Error('body.filePaths is invalid'), {
    name: 'ApiProblemError',
    code: 'E_VALIDATION',
    status: 422,
    requestId: '8f646075755d482fa8a3ac9e6d9507f5'
  });

  harness.manager.markScanFailure(validationError);
  let status = harness.manager.getStatus();
  assert.equal(status.state, ENGINE_STATES.SCAN_FAILED);
  assert.equal(status.errorKind, ENGINE_ERROR_KINDS.API_VALIDATION);
  assert.equal(status.requestId, '8f646075755d482fa8a3ac9e6d9507f5');
  assert.match(status.detail, /8f646075755d482fa8a3ac9e6d9507f5/);

  const connectionError = Object.assign(new Error('backend unreachable'), {
    name: 'BackendUnavailableError'
  });
  harness.manager.markScanFailure(connectionError);
  assert.equal(harness.manager.getStatus().errorKind, ENGINE_ERROR_KINDS.CONNECTION);

  harness.manager.markScanFailure(new Error('scanner crashed'));
  assert.equal(harness.manager.getStatus().errorKind, ENGINE_ERROR_KINDS.SCANNER_EXECUTION);

  harness.manager.markScanSuccess();
  status = harness.manager.getStatus();
  assert.equal(status.state, ENGINE_STATES.ONLINE);
  assert.equal(status.lastError, undefined);
});

test('environment builder uses an absolute module root for PYTHONPATH', () => {
  const environment = buildEngineEnvironment({
    environment: { PATH: '/usr/bin', PYTHONPATH: '/existing' },
    host: '127.0.0.1',
    port: 8765,
    moduleRoot: MODULE_ROOT
  });
  assert.equal(environment.PYTHONPATH, [MODULE_ROOT, '/existing'].join(path.delimiter));
  assert.equal(
    buildEngineEnvironment({ environment: {}, host: 'x', port: 1, moduleRoot: 'relative' })
      .PYTHONPATH,
    undefined
  );
});
