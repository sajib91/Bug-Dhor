'use strict';

/**
 * Safe discovery and validation helpers for the bundled local engine.
 *
 * This module intentionally has no `vscode` import. It never uses a shell and
 * never derives a command from workspace content: every executable is an
 * explicitly configured or bundled Python interpreter, and every argument is
 * assembled here from validated settings.
 */

const fs = require('node:fs');
const path = require('node:path');
const { redactText } = require('../security/redaction');

const DEFAULT_PORT = 8765;
const MAX_CAPTURE_BYTES = 8 * 1024;
const IMPORT_PROBE = 'import fastapi, uvicorn, pydantic, tree_sitter';

// The developer requirements file contains `-e .[dev,ml]`. It is never staged
// as the runtime requirements file and is never passed to the managed runtime.
const DEFAULT_REQUIREMENTS = 'engine/requirements-runtime.txt';
const ENGINE_MANIFEST = 'engine/pyproject.toml';
const LEGACY_REQUIREMENTS = 'engine/requirements.txt';

/**
 * Distinct failure categories so the UI and logs never conflate a broken
 * managed-runtime install with an engine that cannot start or a scan that the
 * backend rejected.
 */
const ENGINE_ERROR_KINDS = Object.freeze({
  RUNTIME_INSTALL: 'runtime-install',
  ENGINE_STARTUP: 'engine-startup',
  CONNECTION: 'connection',
  API_VALIDATION: 'api-validation',
  SCANNER_EXECUTION: 'scanner-execution'
});

class EngineError extends Error {
  /**
   * @param {string} kind
   * @param {string} message
   * @param {{
   *   code?: string,
   *   cause?: unknown,
   *   requestId?: string,
   *   stdout?: string,
   *   stderr?: string
   * }} [options]
   */
  constructor(kind, message, options = {}) {
    super(message);
    this.name = 'EngineError';
    this.kind = kind;
    this.code = options.code ?? `E_${kind.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`;
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
    if (typeof options.requestId === 'string' && options.requestId.length > 0) {
      this.requestId = options.requestId;
    }
    if (typeof options.stdout === 'string') {
      this.stdout = options.stdout;
    }
    if (typeof options.stderr === 'string') {
      this.stderr = options.stderr;
    }
  }
}

/**
 * @typedef {Object} EngineEndpoint
 * @property {string} host
 * @property {number} port
 */

/**
 * @typedef {Object} EngineLayout
 * @property {string} engineRoot
 * @property {string} moduleRoot
 * @property {string} manifestPath
 * @property {string} requirementsPath
 * @property {'bundled' | 'development'} source
 */

/**
 * Only a loopback backend can be started by the extension. A remote backend
 * remains user-managed so the extension never opens an unintended listener or
 * assumes it owns somebody else's service.
 *
 * @param {unknown} baseUrl
 * @returns {EngineEndpoint}
 */
function loopbackEndpoint(baseUrl) {
  if (typeof baseUrl !== 'string' || baseUrl.trim().length === 0) {
    throw new TypeError('A backend URL is required to discover the local engine.');
  }
  let parsed;
  try {
    parsed = new URL(baseUrl.trim());
  } catch {
    throw new TypeError('The configured backend URL is not a valid URL.');
  }
  const host = parsed.hostname.toLowerCase();
  if (!['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)) {
    throw new TypeError('Automatic engine start requires a loopback backend URL.');
  }
  const port = parsed.port
    ? Number(parsed.port)
    : parsed.protocol === 'https:'
      ? 443
      : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('The configured backend URL has an invalid port.');
  }
  return { host: host === 'localhost' ? '127.0.0.1' : host.replace(/^\[|\]$/g, ''), port };
}

/**
 * @param {string} value
 * @param {NodeJS.Platform} platform
 * @returns {boolean}
 */
function pythonNameAllowed(value, platform) {
  const pattern =
    platform === 'win32'
      ? /^(python|python3|pythonw|py)(\d{1,2})?(\.exe)?$/i
      : /^(python|python3|pythonw)(\.\d{1,2})?$/;
  return pattern.test(value);
}

/**
 * Validate a Python executable without ever invoking a shell.
 *
 * @param {unknown} configured
 * @param {{
 *   platform?: NodeJS.Platform,
 *   fileSystem?: Pick<typeof fs, 'existsSync' | 'statSync'>,
 *   allowCommandName?: boolean
 * }} [options]
 * @returns {string | undefined}
 */
function validatePythonExecutable(configured, options = {}) {
  if (typeof configured !== 'string' || configured.trim().length === 0) {
    return undefined;
  }
  const value = configured.trim();
  if (/[\0\r\n]/.test(value)) {
    return undefined;
  }
  const platform = options.platform ?? process.platform;
  const fileSystem = options.fileSystem ?? fs;
  const name = path.basename(value);
  if (!pythonNameAllowed(name, platform)) {
    return undefined;
  }
  if (path.isAbsolute(value)) {
    try {
      const stat = fileSystem.statSync(value);
      if (!stat.isFile()) {
        return undefined;
      }
    } catch {
      return undefined;
    }
    return value;
  }
  if (options.allowCommandName === false || value.includes(path.sep) || value.includes('/')) {
    return undefined;
  }
  return value;
}

/**
 * Candidate interpreters in preference order. Only paths from configuration,
 * the environment, or fixed platform locations are considered.
 *
 * @param {{
 *   configured?: unknown,
 *   platform?: NodeJS.Platform,
 *   environment?: NodeJS.ProcessEnv,
 *   homeDirectory?: string,
 *   fileSystem?: Pick<typeof fs, 'existsSync' | 'statSync'>
 * }} [options]
 * @returns {string[]}
 */
function discoverPythonCandidates(options = {}) {
  const platform = options.platform ?? process.platform;
  const environment = options.environment ?? process.env;
  const home = options.homeDirectory ?? environment.HOME ?? environment.USERPROFILE ?? '';
  const configured = validatePythonExecutable(options.configured, {
    platform,
    fileSystem: options.fileSystem
  });
  /** @type {string[]} */
  const candidates = [];
  if (configured) {
    candidates.push(configured);
  }
  const environmentPath = validatePythonExecutable(environment.BUGDHOR_PYTHON, {
    platform,
    fileSystem: options.fileSystem
  });
  if (environmentPath && !candidates.includes(environmentPath)) {
    candidates.push(environmentPath);
  }
  const commandNames = platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python'];
  for (const name of commandNames) {
    if (!candidates.includes(name)) {
      candidates.push(name);
    }
  }
  if (home) {
    const fixed =
      platform === 'win32'
        ? ['AppData\\Local\\Programs\\Python', 'AppData\\Local\\Microsoft\\WindowsApps']
        : ['.local/bin', 'bin'];
    for (const relative of fixed) {
      for (const name of commandNames) {
        const candidate = path.join(home, relative, name);
        if (!candidates.includes(candidate)) {
          candidates.push(candidate);
        }
      }
    }
  }
  return candidates;
}

/**
 * True only for an extension-controlled, absolute filesystem path. A `file:`
 * URL is deliberately rejected: pip and child processes must receive plain
 * absolute paths, never a URI (which used to resolve to `file:///`).
 *
 * @param {unknown} value
 * @returns {value is string}
 */
function isAbsoluteFilesystemPath(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(value) || /^(?:file|vscode|untitled):/i.test(value)) {
    return false;
  }
  return path.isAbsolute(value);
}

/**
 * Resolve the installed engine root from the extension location (or, in a
 * development checkout, the repository root) and validate its manifest and
 * runtime requirements. Every returned path is absolute.
 *
 * @param {{
 *   extensionPath?: string,
 *   extensionUri?: { fsPath?: string, path?: string },
 *   repositoryRoot?: string,
 *   fileSystem?: Pick<typeof fs, 'existsSync' | 'statSync'>
 * }} options
 * @returns {EngineLayout | undefined}
 */
function discoverEngineSource(options = {}) {
  const fileSystem = options.fileSystem ?? fs;
  const providedExtensionPath =
    options.extensionPath ?? options.extensionUri?.fsPath ?? options.extensionUri?.path;
  /** @type {Array<{ root: string, source: 'bundled' | 'development' }>} */
  const candidates = [];

  if (isAbsoluteFilesystemPath(providedExtensionPath)) {
    candidates.push({ root: path.resolve(providedExtensionPath), source: 'bundled' });
  }
  if (isAbsoluteFilesystemPath(options.repositoryRoot)) {
    candidates.push({
      root: path.resolve(/** @type {string} */ (options.repositoryRoot)),
      source: 'development'
    });
  }

  for (const candidate of candidates) {
    const engineRoot =
      candidate.source === 'bundled'
        ? path.join(candidate.root, 'engine')
        : path.join(candidate.root, 'security-engine');
    const layout = {
      engineRoot,
      moduleRoot: path.join(engineRoot, 'src'),
      manifestPath: path.join(engineRoot, path.basename(ENGINE_MANIFEST)),
      requirementsPath: path.join(engineRoot, path.basename(DEFAULT_REQUIREMENTS)),
      source: candidate.source
    };
    const requiredFiles = [
      path.join(layout.moduleRoot, 'bugdhor', '__main__.py'),
      path.join(layout.moduleRoot, 'bugdhor', 'api', 'app.py'),
      layout.manifestPath,
      layout.requirementsPath
    ];
    if (!requiredFiles.every((filePath) => isAbsoluteFilesystemPath(filePath))) {
      continue;
    }
    let valid = true;
    for (const filePath of requiredFiles) {
      try {
        if (!fileSystem.statSync(filePath).isFile()) {
          valid = false;
          break;
        }
      } catch {
        valid = false;
        break;
      }
    }
    if (valid) {
      return layout;
    }
  }
  return undefined;
}

/** Alias used by callers that prefer the more explicit name. */
const resolveEngineLayout = discoverEngineSource;

/**
 * Guard against ever handing a developer requirement file to pip. The managed
 * runtime must use only the bundled runtime list (absolute-safe, no editable
 * install, no optional extras).
 *
 * @param {string} content
 * @returns {string} the validated content
 */
function assertRuntimeRequirements(content) {
  if (typeof content !== 'string' || content.trim().length === 0) {
    throw new EngineError(
      ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
      'The bundled engine requirements file is empty.'
    );
  }
  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    if (/^(?:-e|--editable)(?:\s|=|$)/i.test(line)) {
      throw new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The bundled engine requirements file contains an editable install, which is not allowed ' +
          'for the managed runtime.'
      );
    }
    if (/^(?:\.{1,2}[/\\]|[a-z]:[/\\]|[/\\]|file:)/i.test(line)) {
      throw new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The bundled engine requirements file contains a local path requirement, which is not ' +
          'allowed for the managed runtime.'
      );
    }
    if (/(?:\[(?:dev|ml|analyzers|test|docs)\])/i.test(line)) {
      throw new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The bundled engine requirements file contains optional extras, which are not part of ' +
          'the runtime dependency set.'
      );
    }
  }
  return content;
}

/**
 * @param {unknown} error
 * @param {string} [fallback]
 * @returns {string}
 */
function safeErrorText(error, fallback) {
  const text = error instanceof Error ? error.message : String(error);
  const value = text && text.trim().length > 0 ? text : (fallback ?? '');
  return redactText(value, { limit: 300 });
}

/**
 * Run one fixed-argument process and capture bounded output. No shell is used.
 *
 * @param {{
 *   command: string,
 *   args: string[],
 *   cwd?: string,
 *   timeoutMs?: number,
 *   env?: NodeJS.ProcessEnv,
 *   spawn?: typeof import('node:child_process').spawn
 * }} options
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
function runFixedCommand({
  command,
  args,
  cwd,
  timeoutMs = 60_000,
  env = process.env,
  spawn = require('node:child_process').spawn
} = {}) {
  if (typeof command !== 'string' || command.length === 0 || !Array.isArray(args)) {
    return Promise.reject(new TypeError('A command and argument array are required.'));
  }
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        env,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (error) {
      reject(error);
      return;
    }
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result, error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    };
    const append = (/** @type {string} */ chunk, /** @type {'stdout' | 'b'} */ stream) => {
      const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
      const target = stream === 'stdout' ? stdout : stderr;
      const remaining = MAX_CAPTURE_BYTES - Buffer.byteLength(target, 'utf8');
      if (remaining <= 0) {
        return;
      }
      const clipped = text.slice(0, remaining);
      if (stream === 'stdout') {
        stdout += clipped;
      } else {
        stderr += clipped;
      }
    };
    child.stdout?.on('data', (chunk) => append(chunk, 'stdout'));
    child.stderr?.on('data', (chunk) => append(chunk, 'stderr'));
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish({ code: null, stdout, stderr }, new Error(`Command timed out after ${timeoutMs} ms.`));
    }, timeoutMs);
    child.once('error', (error) => finish({ code: null, stdout, stderr }, error));
    child.once('close', (code) => finish({ code, stdout, stderr }));
  });
}

/**
 * Check whether the interpreter already has the minimal runtime dependencies.
 *
 * @param {{
 *   python: string,
 *   cwd?: string,
 *   spawn?: typeof import('node:child_process').spawn
 * }} options
 * @returns {Promise<boolean>}
 */
async function runtimeDependenciesReady(options) {
  try {
    const result = await runFixedCommand({
      command: options.python,
      args: ['-c', IMPORT_PROBE],
      cwd: options.cwd,
      timeoutMs: 10_000,
      spawn: options.spawn
    });
    return result.code === 0;
  } catch {
    return false;
  }
}

/**
 * In-flight and completed managed-runtime installations, keyed by venv path and
 * requirements file. Concurrent start attempts (including separate managers in
 * one extension host) share a single install instead of racing over pip.
 *
 * @type {Map<string, Promise<{ python: string, installed: boolean, detail: string }>>}
 */
const RUNTIME_INSTALL_CACHE = new Map();

function runtimeCacheKey(runtimePython, requirementsPath) {
  return `${runtimePython}\u0000${requirementsPath}`;
}

/**
 * Create a managed virtual environment and install the bundled runtime
 * requirements. All inputs are extension-controlled absolute paths; no
 * workspace file is read as a command, URL, or requirement source. The install
 * runs with `cwd` set to the verified engine root so no relative requirement
 * (including an editable `.`) can ever resolve against the extension host's
 * working directory.
 *
 * @param {{
 *   python: string,
 *   runtimeDirectory: string,
 *   requirementsPath: string,
 *   engineRoot?: string,
 *   platform?: NodeJS.Platform,
 *   fileSystem?: typeof fs,
 *   spawn?: typeof import('node:child_process').spawn,
 *   timeoutMs?: number,
 *   onPhase?: (phase: 'preparing-runtime' | 'installing-dependencies') => void
 * }} options
 * @returns {Promise<{ python: string, installed: boolean, detail: string }>}
 */
function ensureManagedRuntime(options) {
  const platform = options.platform ?? process.platform;
  const fileSystem = options.fileSystem ?? fs;
  const spawn = options.spawn;

  if (!isAbsoluteFilesystemPath(options.runtimeDirectory)) {
    return Promise.reject(
      new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The managed runtime directory must be an absolute filesystem path.'
      )
    );
  }
  if (!isAbsoluteFilesystemPath(options.requirementsPath)) {
    return Promise.reject(
      new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The bundled engine requirements path must be an absolute filesystem path.'
      )
    );
  }
  if (options.engineRoot !== undefined && !isAbsoluteFilesystemPath(options.engineRoot)) {
    return Promise.reject(
      new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        'The bundled engine root must be an absolute filesystem path.'
      )
    );
  }

  const runtimePython = path.resolve(
    options.runtimeDirectory,
    platform === 'win32' ? 'Scripts' : 'bin',
    platform === 'win32' ? 'python.exe' : 'python'
  );
  const key = runtimeCacheKey(runtimePython, path.resolve(options.requirementsPath));
  const cached = RUNTIME_INSTALL_CACHE.get(key);
  if (cached) {
    return cached;
  }
  const pending = installManagedRuntime({
    ...options,
    platform,
    fileSystem,
    spawn,
    runtimePython,
    cwd: options.engineRoot ? path.resolve(options.engineRoot) : undefined
  }).catch((error) => {
    RUNTIME_INSTALL_CACHE.delete(key);
    throw error;
  });
  RUNTIME_INSTALL_CACHE.set(key, pending);
  return pending;
}

/**
 * @param {{
 *   python: string,
 *   runtimePython: string,
 *   runtimeDirectory: string,
 *   requirementsPath: string,
 *   cwd?: string,
 *   platform: NodeJS.Platform,
 *   fileSystem: typeof fs,
 *   spawn?: typeof import('node:child_process').spawn,
 *   timeoutMs?: number,
 *   onPhase?: (phase: 'preparing-runtime' | 'installing-dependencies') => void
 * }} options
 */
async function installManagedRuntime(options) {
  const { fileSystem, runtimePython, spawn } = options;
  options.onPhase?.('preparing-runtime');

  let alreadyReady = false;
  if (fileSystem.existsSync(runtimePython)) {
    alreadyReady = await runtimeDependenciesReady({ python: runtimePython, cwd: options.cwd, spawn });
    if (alreadyReady) {
      return {
        python: runtimePython,
        installed: false,
        detail: 'managed runtime already ready'
      };
    }
  } else {
    fileSystem.mkdirSync(options.runtimeDirectory, { recursive: true });
    const created = await runFixedCommand({
      command: options.python,
      args: ['-m', 'venv', options.runtimeDirectory],
      cwd: options.cwd,
      timeoutMs: options.timeoutMs ?? 120_000,
      spawn
    });
    if (created.code !== 0 || !fileSystem.existsSync(runtimePython)) {
      throw new EngineError(
        ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
        `Could not create a managed Python runtime: ${safeErrorText(created.stderr, created.stdout)}`,
        { stdout: created.stdout, stderr: created.stderr }
      );
    }
  }

  options.onPhase?.('installing-dependencies');
  if (!fileSystem.existsSync(options.requirementsPath)) {
    throw new EngineError(
      ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
      'The bundled engine requirements file is missing from this installation.'
    );
  }
  let content;
  try {
    content = fileSystem.readFileSync(options.requirementsPath, 'utf8');
  } catch (error) {
    throw new EngineError(
      ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
      `The bundled engine requirements file could not be read: ${safeErrorText(error)}`,
      { cause: error }
    );
  }
  assertRuntimeRequirements(typeof content === 'string' ? content : String(content));

  const installed = await runFixedCommand({
    command: runtimePython,
    args: [
      '-m',
      'pip',
      'install',
      '--disable-pip-version-check',
      '--no-input',
      '-r',
      options.requirementsPath
    ],
    cwd: options.cwd,
    timeoutMs: options.timeoutMs ?? 300_000,
    spawn
  });
  if (installed.code !== 0) {
    const detail = safeErrorText(installed.stderr, installed.stdout);
    throw new EngineError(
      ENGINE_ERROR_KINDS.RUNTIME_INSTALL,
      `Managed runtime dependency setup failed: ${detail}`,
      { stdout: installed.stdout, stderr: installed.stderr }
    );
  }
  return {
    python: runtimePython,
    installed: !alreadyReady,
    detail: 'managed runtime prepared'
  };
}

/** Test-only helper: clear the shared runtime installation cache. */
function clearRuntimeInstallCache() {
  RUNTIME_INSTALL_CACHE.clear();
}

/**
 * @param {{ python: string, host: string, port: number }} options
 * @returns {string[]}
 */
function buildEngineArguments({ python, host, port }) {
  return [python, '-m', 'bugdhor', '--host', host, '--port', String(port)];
}

/**
 * Build the child environment. Values are inherited from the extension host,
 * not from the workspace, and are never logged. The bundled engine's `src`
 * directory is always prepended as an absolute PYTHONPATH entry.
 *
 * @param {{
 *   environment?: NodeJS.ProcessEnv,
 *   host: string,
 *   port: number,
 *   moduleRoot?: string
 * }} options
 * @returns {NodeJS.ProcessEnv}
 */
function buildEngineEnvironment({ environment = process.env, host, port, moduleRoot }) {
  const result = {
    ...environment,
    PYTHONUNBUFFERED: '1',
    PYTHONNOUSERSITE: '1',
    BUGDHOR_HOST: host,
    BUGDHOR_PORT: String(port)
  };
  if (isAbsoluteFilesystemPath(moduleRoot)) {
    const existing = typeof result.PYTHONPATH === 'string' ? result.PYTHONPATH : '';
    const entries = existing
      .split(path.delimiter)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0 && entry !== path.resolve(/** @type {string} */ (moduleRoot)));
    result.PYTHONPATH = [path.resolve(/** @type {string} */ (moduleRoot)), ...entries].join(
      path.delimiter
    );
  }
  return result;
}

module.exports = {
  DEFAULT_PORT,
  DEFAULT_REQUIREMENTS,
  ENGINE_MANIFEST,
  LEGACY_REQUIREMENTS,
  ENGINE_ERROR_KINDS,
  EngineError,
  loopbackEndpoint,
  validatePythonExecutable,
  discoverPythonCandidates,
  discoverEngineSource,
  resolveEngineLayout,
  assertRuntimeRequirements,
  isAbsoluteFilesystemPath,
  runFixedCommand,
  runtimeDependenciesReady,
  ensureManagedRuntime,
  clearRuntimeInstallCache,
  buildEngineArguments,
  buildEngineEnvironment,
  safeErrorText
};
