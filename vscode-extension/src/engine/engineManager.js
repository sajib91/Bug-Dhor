'use strict';

/**
 * Automatic local security-engine lifecycle manager.
 *
 * The manager owns only the process it starts. It always checks the configured
 * loopback endpoint first, so an already-running engine (started by a user or
 * another tool) is adopted without spawning a duplicate. Every command uses a
 * fixed argv array and `shell: false`; workspace content is never executed.
 */

const path = require('node:path');
const {
  DEFAULT_PORT,
  DEFAULT_REQUIREMENTS,
  buildEngineArguments,
  buildEngineEnvironment,
  discoverEngineSource,
  discoverPythonCandidates,
  ensureManagedRuntime,
  loopbackEndpoint,
  runtimeDependenciesReady,
  safeErrorText
} = require('./engineRuntime');

const ENGINE_STATES = Object.freeze({
  STARTING: 'starting',
  ONLINE: 'online',
  OFFLINE: 'offline',
  FAILED: 'failed',
  STOPPING: 'stopping'
});

const DEFAULT_ENGINE_SETTINGS = Object.freeze({
  autoStart: true,
  manageRuntime: true,
  pythonPath: '',
  backendUrl: `http://127.0.0.1:${DEFAULT_PORT}`,
  startupTimeoutMs: 20_000,
  healthPollMs: 300,
  maxRestarts: 3,
  restartBaseDelayMs: 500,
  restartMaxDelayMs: 8_000
});

const MANAGER_REGISTRY = Symbol.for('bugdhor.engine.manager.registry');

function normalizeEngineSettings(raw = {}) {
  const source = raw && typeof raw === 'object' ? raw : {};
  /** @param {unknown} value @param {number} fallback @param {number} min @param {number} max */
  const integer = (value, fallback, min, max) =>
    Number.isFinite(value)
      ? Math.min(max, Math.max(min, Math.round(/** @type {number} */ (value))))
      : fallback;
  return Object.freeze({
    autoStart:
      typeof source.autoStart === 'boolean' ? source.autoStart : DEFAULT_ENGINE_SETTINGS.autoStart,
    manageRuntime:
      typeof source.manageRuntime === 'boolean'
        ? source.manageRuntime
        : DEFAULT_ENGINE_SETTINGS.manageRuntime,
    pythonPath: typeof source.pythonPath === 'string' ? source.pythonPath : '',
    backendUrl:
      typeof source.backendUrl === 'string' && source.backendUrl.length > 0
        ? source.backendUrl
        : DEFAULT_ENGINE_SETTINGS.backendUrl,
    startupTimeoutMs: integer(source.startupTimeoutMs, 20_000, 1_000, 120_000),
    healthPollMs: integer(source.healthPollMs, 300, 50, 5_000),
    maxRestarts: integer(source.maxRestarts, 3, 0, 10),
    restartBaseDelayMs: integer(source.restartBaseDelayMs, 500, 100, 10_000),
    restartMaxDelayMs: integer(source.restartMaxDelayMs, 8_000, 1_000, 60_000)
  });
}

/**
 * @param {{
 *   service: { health: (context?: object) => Promise<object> },
 *   logger: { info: Function, warn: Function, error: Function, debug?: Function },
 *   context?: { extensionPath?: string, globalStoragePath?: string },
 *   getSettings?: () => object,
 *   spawn?: typeof import('node:child_process').spawn,
 *   fileSystem?: typeof import('node:fs'),
 *   platform?: NodeJS.Platform,
 *   environment?: NodeJS.ProcessEnv,
 *   delay?: (ms: number) => Promise<void>
 * }} dependencies
 */
class EngineManager {
  constructor({
    service,
    logger,
    context = {},
    getSettings = () => ({}),
    spawn,
    fileSystem = require('node:fs'),
    platform = process.platform,
    environment = process.env,
    delay
  } = {}) {
    if (!service || typeof service.health !== 'function' || !logger) {
      throw new TypeError('EngineManager requires a health-capable service and a logger.');
    }
    this.service = service;
    this.logger = logger;
    this.context = context;
    this.getSettings = getSettings;
    this.settings = normalizeEngineSettings(getSettings());
    this.spawn = spawn ?? require('node:child_process').spawn;
    this.fileSystem = fileSystem;
    this.platform = platform;
    this.environment = environment;
    this.delay =
      typeof delay === 'function'
        ? delay
        : (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    this.state = ENGINE_STATES.OFFLINE;
    this.detail = 'Engine has not been started.';
    this.child = undefined;
    this.owned = false;
    this.pid = undefined;
    this.startedAt = undefined;
    this.restartAttempt = 0;
    this.disposed = false;
    this.startPromise = undefined;
    this.stopPromise = undefined;
    this.restartTimer = undefined;
    this.listeners = new Set();
    this.lastError = undefined;
  }

  /** @param {(status: object) => void} listener @returns {{ dispose: () => void }} */
  onStateChange(listener) {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }

  /** @returns {object} */
  getStatus() {
    return Object.freeze({
      state: this.state,
      detail: this.detail,
      owned: this.owned,
      ...(this.pid === undefined ? {} : { pid: this.pid }),
      ...(this.startedAt === undefined ? {} : { startedAt: this.startedAt }),
      restartAttempt: this.restartAttempt,
      ...(this.lastError ? { lastError: this.lastError } : {}),
      backendUrl: this.settings.backendUrl
    });
  }

  /**
   * @param {string} state
   * @param {string} detail
   * @param {{ error?: string }} [extra]
   */
  setState(state, detail, extra = {}) {
    this.state = state;
    this.detail = detail;
    if (extra.error) {
      this.lastError = extra.error;
    }
    const snapshot = this.getStatus();
    for (const listener of this.listeners) {
      try {
        listener(snapshot);
      } catch (error) {
        this.logger.warn(`An engine state listener failed: ${safeErrorText(error)}`);
      }
    }
  }

  updateSettings(raw = {}) {
    this.settings = normalizeEngineSettings({ ...this.getSettings(), ...raw });
  }

  /** @returns {Promise<boolean>} */
  async isHealthy() {
    try {
      const health = await this.service.health();
      return Boolean(health && typeof health === 'object');
    } catch {
      return false;
    }
  }

  /**
   * Start or adopt the engine. Concurrent callers share one startup promise.
   *
   * @param {{ reason?: string }} [options]
   * @returns {Promise<boolean>}
   */
  start(options = {}) {
    if (this.disposed) {
      return Promise.resolve(false);
    }
    if (this.state === ENGINE_STATES.ONLINE) {
      // ensure() verifies liveness before calling start(); avoid overlapping
      // startup work when the manager already owns a healthy engine.
      return Promise.resolve(true);
    }
    if (this.startPromise) {
      return this.startPromise;
    }
    const attempt = options.reason === 'restart' ? this.restartAttempt : 0;
    if (options.reason !== 'restart') {
      this.restartAttempt = 0;
    }
    void attempt;
    this.startPromise = this._start(options).finally(() => {
      this.startPromise = undefined;
    });
    return this.startPromise;
  }

  /** @returns {Promise<boolean>} */
  async _start(options = {}) {
    this.clearRestart();
    if (await this.isHealthy()) {
      this.setState(
        ENGINE_STATES.ONLINE,
        options.reason === 'restart'
          ? 'The existing local engine is reachable again.'
          : 'An already-running local engine was detected; no duplicate process was started.'
      );
      this.restartAttempt = 0;
      return true;
    }

    let endpoint;
    try {
      endpoint = loopbackEndpoint(this.settings.backendUrl);
    } catch (error) {
      const detail = safeErrorText(error);
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      return false;
    }

    const source = discoverEngineSource({
      extensionPath: this.context.extensionPath ?? '',
      repositoryRoot: this.context.repositoryRoot,
      fileSystem: this.fileSystem
    });
    if (!source) {
      const detail =
        'The bundled security engine is missing from this installation. Reinstall the extension.';
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      return false;
    }

    this.setState(
      ENGINE_STATES.STARTING,
      `Starting the local engine on ${endpoint.host}:${endpoint.port}.`
    );

    let python = await this.resolvePython(source);
    if (!python) {
      const detail =
        'No compatible Python 3 interpreter was found. Install Python 3.11 or newer, or set ' +
        'bugdhor.engine.pythonPath to an explicit interpreter path.';
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      return false;
    }

    const dependenciesReady = await runtimeDependenciesReady({
      python,
      cwd: source.moduleRoot,
      spawn: this.spawn
    });
    try {
      if (!dependenciesReady && this.settings.manageRuntime) {
        const runtime = await ensureManagedRuntime({
          python,
          runtimeDirectory: path.join(
            this.context.globalStoragePath ?? path.join(source.moduleRoot, '.bugdhor-runtime'),
            'engine-runtime'
          ),
          requirementsPath: path.join(this.context.extensionPath ?? '', DEFAULT_REQUIREMENTS),
          platform: this.platform,
          fileSystem: this.fileSystem,
          spawn: this.spawn
        });
        python = runtime.python;
        if (runtime.installed) {
          this.logger.info('Bug Dhor prepared a managed Python runtime for the local engine.');
        }
      }
    } catch (error) {
      const detail = safeErrorText(error);
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      return false;
    }

    const args = buildEngineArguments({
      python,
      moduleRoot: source.moduleRoot,
      host: endpoint.host,
      port: endpoint.port
    });
    const env = buildEngineEnvironment({
      environment: this.environment,
      host: endpoint.host,
      port: endpoint.port
    });

    /** @type {import('node:child_process').ChildProcess} */
    let child;
    try {
      child = this.spawn(python, args.slice(1), {
        cwd: source.moduleRoot,
        env,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'pipe']
      });
    } catch (error) {
      const detail = `Could not start the local engine: ${safeErrorText(error)}`;
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      return false;
    }

    this.child = child;
    this.owned = true;
    this.pid = typeof child.pid === 'number' ? child.pid : undefined;
    this.startedAt = new Date().toISOString();
    this.lastError = undefined;

    child.stderr?.on('data', (chunk) => {
      const text = safeErrorText(chunk);
      if (text.length > 0) {
        this.logger.debug(`Bug Dhor engine: ${text}`);
      }
    });
    child.once('error', (error) => {
      const detail = `The local engine process failed: ${safeErrorText(error)}`;
      this.lastError = detail;
      this.logger.warn(detail);
      this.handleUnexpectedExit();
    });
    child.once('exit', (code, signal) => {
      if (this.state === ENGINE_STATES.STOPPING || this.disposed) {
        this.owned = false;
        this.child = undefined;
        this.pid = undefined;
        return;
      }
      const detail = `The local engine exited unexpectedly (code ${code ?? 'unknown'}, signal ${signal ?? 'none'}).`;
      this.lastError = detail;
      this.logger.warn(detail);
      this.handleUnexpectedExit();
    });

    const ready = await this.waitForHealth();
    if (!ready && !this.disposed) {
      const detail =
        this.lastError ??
        `The local engine did not become ready within ${this.settings.startupTimeoutMs} ms.`;
      this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      await this.stop({ markOffline: false });
      this.scheduleRestart();
      return false;
    }
    if (this.disposed) {
      return false;
    }
    this.restartAttempt = 0;
    this.setState(ENGINE_STATES.ONLINE, 'The local security engine is online.');
    return true;
  }

  /**
   * Pick a Python interpreter that either has the runtime already or can be
   * used to build the managed runtime.
   *
   * @param {{ moduleRoot: string }} source
   * @returns {Promise<string | undefined>}
   */
  async resolvePython(source) {
    const candidates = discoverPythonCandidates({
      configured: this.settings.pythonPath,
      platform: this.platform,
      environment: this.environment,
      fileSystem: this.fileSystem
    });
    for (const candidate of candidates) {
      if (
        await runtimeDependenciesReady({
          python: candidate,
          cwd: source.moduleRoot,
          spawn: this.spawn
        })
      ) {
        return candidate;
      }
      if (!this.settings.manageRuntime) {
        continue;
      }
      // A command name is usable for managed-runtime setup only if the OS can
      // resolve it. Verify with an explicit, fixed argument list.
      if (candidate === 'python' || candidate === 'python3' || candidate === 'py') {
        try {
          const result = await require('./engineRuntime').runFixedCommand({
            command: candidate,
            args: ['--version'],
            timeoutMs: 5_000,
            spawn: this.spawn
          });
          if (result.code === 0) {
            return candidate;
          }
        } catch {
          // Try the next candidate.
        }
      } else if (this.fileSystem.existsSync(candidate)) {
        return candidate;
      }
    }
    return undefined;
  }

  /** @returns {Promise<boolean>} */
  async waitForHealth() {
    const deadline = Date.now() + this.settings.startupTimeoutMs;
    while (Date.now() < deadline) {
      if (await this.isHealthy()) {
        return true;
      }
      if (this.disposed || typeof this.child?.exitCode === 'number') {
        return false;
      }
      await this.delay(this.settings.healthPollMs);
    }
    return false;
  }

  /** Handle an unexpected exit with bounded, exponential-backoff restarts. */
  handleUnexpectedExit() {
    this.owned = false;
    this.child = undefined;
    this.pid = undefined;
    this.setState(ENGINE_STATES.OFFLINE, this.lastError ?? 'The local engine is offline.');
    this.scheduleRestart();
  }

  scheduleRestart() {
    if (
      !this.settings.autoStart ||
      this.disposed ||
      this.restartTimer ||
      this.restartAttempt >= this.settings.maxRestarts
    ) {
      if (this.restartAttempt >= this.settings.maxRestarts && this.state !== ENGINE_STATES.FAILED) {
        const detail =
          'The local engine failed after the maximum number of automatic restart attempts.';
        this.setState(ENGINE_STATES.FAILED, detail, { error: detail });
      }
      return;
    }
    this.restartAttempt += 1;
    const backoff = Math.min(
      this.settings.restartMaxDelayMs,
      this.settings.restartBaseDelayMs * 2 ** (this.restartAttempt - 1)
    );
    this.logger.warn(
      `Bug Dhor will restart the local engine in ${backoff} ms ` +
        `(attempt ${this.restartAttempt}/${this.settings.maxRestarts}).`
    );
    this.restartTimer = setTimeout(() => {
      this.restartTimer = undefined;
      if (!this.disposed && this.settings.autoStart) {
        void this.start({ reason: 'restart' });
      }
    }, backoff);
  }

  clearRestart() {
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = undefined;
    }
  }

  /**
   * Stop only the child process owned by this manager. An external engine is
   * never terminated.
   */
  stop({ markOffline = true } = {}) {
    if (this.stopPromise) {
      return this.stopPromise;
    }
    this.clearRestart();
    this.startPromise = undefined;
    if (!this.child) {
      if (markOffline && !this.disposed) {
        this.setState(ENGINE_STATES.OFFLINE, 'The local engine is not running.');
      }
      return Promise.resolve(true);
    }
    this.setState(ENGINE_STATES.STOPPING, 'Stopping the local engine started by Bug Dhor.');
    const child = this.child;
    this.stopPromise = new Promise((resolve) => {
      let done = false;
      const finish = () => {
        if (done) {
          return;
        }
        done = true;
        clearTimeout(forceTimer);
        this.owned = false;
        this.child = undefined;
        this.pid = undefined;
        if (markOffline && !this.disposed) {
          this.setState(ENGINE_STATES.OFFLINE, 'The local engine was stopped.');
        }
        resolve(true);
      };
      const forceTimer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // The child may already have exited.
        }
      }, 3_000);
      child.once('exit', finish);
      try {
        child.kill('SIGTERM');
      } catch {
        finish();
      }
      if (child.exitCode !== null) {
        finish();
      }
    }).finally(() => {
      this.stopPromise = undefined;
    });
    return this.stopPromise;
  }

  /**
   * Ensure the endpoint is usable, starting the managed engine when allowed.
   *
   * @param {{ reason?: string }} [options]
   */
  async ensure(options = {}) {
    this.updateSettings();
    if (await this.isHealthy()) {
      if (this.state !== ENGINE_STATES.ONLINE) {
        this.setState(ENGINE_STATES.ONLINE, 'The local security engine is reachable.');
      }
      return true;
    }
    if (!this.settings.autoStart) {
      this.setState(
        ENGINE_STATES.OFFLINE,
        'The local engine is offline and automatic start is disabled.'
      );
      return false;
    }
    return this.start(options);
  }

  dispose() {
    this.disposed = true;
    this.clearRestart();
    void this.stop({ markOffline: false });
    this.listeners.clear();
  }
}

/**
 * Register one manager per endpoint inside the extension host so duplicate
 * extension instances cannot start competing engines on the same port.
 *
 * @param {string} key
 * @param {EngineManager} manager
 * @returns {boolean}
 */
function registerManager(key, manager) {
  const registry = (globalThis[MANAGER_REGISTRY] ??= new Map());
  if (registry.has(key)) {
    return false;
  }
  registry.set(key, manager);
  return true;
}

function unregisterManager(key) {
  const registry = globalThis[MANAGER_REGISTRY];
  if (registry instanceof Map) {
    registry.delete(key);
  }
}

module.exports = {
  ENGINE_STATES,
  DEFAULT_ENGINE_SETTINGS,
  EngineManager,
  normalizeEngineSettings,
  registerManager,
  unregisterManager
};
