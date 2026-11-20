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
  buildEngineArguments,
  buildEngineEnvironment,
  discoverEngineSource,
  discoverPythonCandidates,
  ensureManagedRuntime,
  loopbackEndpoint,
  runFixedCommand,
  validatePythonExecutable
} = require('../../src/engine/engineRuntime');

const EXTENSION_PATH = '/extension';
const MODULE_ROOT = path.join(EXTENSION_PATH, 'engine', 'src');
const PYTHON = '/opt/python3/bin/python3';
const REQUIREMENTS = path.join(EXTENSION_PATH, 'engine', 'requirements.txt');
const HEALTH_OK = Object.freeze({ service: 'bugdhor-engine', status: 'ok' });

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createFileSystem() {
  const files = new Set([
    path.join(MODULE_ROOT, 'bugdhor', '__main__.py'),
    path.join(MODULE_ROOT, 'bugdhor', 'api', 'app.py'),
    PYTHON,
    REQUIREMENTS
  ]);
  const directories = new Set([path.dirname(REQUIREMENTS), path.join(EXTENSION_PATH, 'engine')]);
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

function createSpawn({ engineProcess, probeCode = 0 } = {}) {
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === '-m' && args[1] === 'bugdhor') {
      return engineProcess ?? createFakeProcess({ autoClose: false });
    }
    return createFakeProcess({ code: probeCode, stdout: 'ready' });
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
  const { spawn, calls } = createSpawn({ engineProcess, probeCode: options.probeCode ?? 0 });
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
    moduleRoot: MODULE_ROOT,
    source: 'bundled'
  });

  fileSystem.files.delete(path.join(MODULE_ROOT, 'bugdhor', '__main__.py'));
  assert.deepEqual(discoverEngineSource(options), {
    moduleRoot: path.join('/repository', 'security-engine', 'src'),
    source: 'development'
  });
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

test('managed runtime setup uses fixed venv and pip arguments', async () => {
  const calls = [];
  const runtimePython = path.join('/storage', 'engine-runtime', 'bin', 'python');
  let runtimeExists = false;
  const fileSystem = {
    existsSync(target) {
      return target === REQUIREMENTS || (target === runtimePython && runtimeExists);
    },
    mkdirSync() {},
    statSync() {
      throw new Error('unused');
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

  const result = await ensureManagedRuntime({
    python: 'python3',
    runtimeDirectory: path.join('/storage', 'engine-runtime'),
    requirementsPath: REQUIREMENTS,
    platform: 'darwin',
    fileSystem,
    spawn
  });

  assert.equal(result.python, runtimePython);
  assert.equal(result.installed, true);
  assert.deepEqual(
    calls.map((call) => call.args),
    [
      ['-m', 'venv', path.join('/storage', 'engine-runtime')],
      ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', REQUIREMENTS]
    ]
  );
  assert.ok(calls.every((call) => call.options.shell === false));
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
  assert.deepEqual(engineCall.options.stdio, ['ignore', 'ignore', 'pipe']);
  assert.equal(engineCall.options.env.BUGDHOR_HOST, '127.0.0.1');
  assert.equal(engineCall.options.env.BUGDHOR_PORT, '8765');

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
  assert.equal(harness.manager.getStatus().state, ENGINE_STATES.FAILED);
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
