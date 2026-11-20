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

/**
 * @typedef {Object} EngineEndpoint
 * @property {string} host
 * @property {number} port
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
 * Find the bundled (or development-checkout) engine source tree. The returned
 * `moduleRoot` is the directory passed to `python -m bugdhor`.
 *
 * @param {{
 *   extensionPath: string,
 *   repositoryRoot?: string,
 *   fileSystem?: Pick<typeof fs, 'existsSync' | 'statSync'>
 * }} options
 * @returns {{ moduleRoot: string, source: 'bundled' | 'development' } | undefined}
 */
function discoverEngineSource(options) {
  const fileSystem = options.fileSystem ?? fs;
  if (typeof options.extensionPath !== 'string' || options.extensionPath.length === 0) {
    return undefined;
  }
  const candidates = [
    {
      moduleRoot: path.join(options.extensionPath, 'engine', 'src'),
      source: /** @type {const} */ ('bundled')
    }
  ];
  if (typeof options.repositoryRoot === 'string' && options.repositoryRoot.length > 0) {
    candidates.push({
      moduleRoot: path.join(options.repositoryRoot, 'security-engine', 'src'),
      source: /** @type {const} */ ('development')
    });
  }
  for (const candidate of candidates) {
    const main = path.join(candidate.moduleRoot, 'bugdhor', '__main__.py');
    const app = path.join(candidate.moduleRoot, 'bugdhor', 'api', 'app.py');
    try {
      if (fileSystem.statSync(main).isFile() && fileSystem.statSync(app).isFile()) {
        return candidate;
      }
    } catch {
      // Try the next candidate; absence is not an error.
    }
  }
  return undefined;
}

/** @param {unknown} error @returns {string} */
function safeErrorText(error) {
  return redactText(error instanceof Error ? error.message : String(error), { limit: 300 });
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
 * Create a managed virtual environment and install the bundled runtime
 * requirements. All inputs are extension-controlled paths; no workspace file
 * is read as a command, URL, or requirement source.
 *
 * @param {{
 *   python: string,
 *   runtimeDirectory: string,
 *   requirementsPath: string,
 *   platform?: NodeJS.Platform,
 *   fileSystem?: typeof fs,
 *   spawn?: typeof import('node:child_process').spawn,
 *   timeoutMs?: number
 * }} options
 * @returns {Promise<{ python: string, installed: boolean, detail: string }>}
 */
async function ensureManagedRuntime(options) {
  const platform = options.platform ?? process.platform;
  const fileSystem = options.fileSystem ?? fs;
  const spawn = options.spawn;
  const runtimePython = path.join(
    options.runtimeDirectory,
    platform === 'win32' ? 'Scripts' : 'bin',
    platform === 'win32' ? 'python.exe' : 'python'
  );
  if (fileSystem.existsSync(runtimePython)) {
    if (await runtimeDependenciesReady({ python: runtimePython, spawn })) {
      return { python: runtimePython, installed: false, detail: 'managed runtime already ready' };
    }
  } else {
    fileSystem.mkdirSync(options.runtimeDirectory, { recursive: true });
    const created = await runFixedCommand({
      command: options.python,
      args: ['-m', 'venv', options.runtimeDirectory],
      timeoutMs: options.timeoutMs ?? 120_000,
      spawn
    });
    if (created.code !== 0 || !fileSystem.existsSync(runtimePython)) {
      throw new Error(
        `Could not create a managed Python runtime: ${safeErrorText(created.stderr)}`
      );
    }
  }
  if (!fileSystem.existsSync(options.requirementsPath)) {
    throw new Error('The bundled engine requirements file is missing from this installation.');
  }
  const installed = await runFixedCommand({
    command: runtimePython,
    args: ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', options.requirementsPath],
    timeoutMs: options.timeoutMs ?? 300_000,
    spawn
  });
  if (installed.code !== 0) {
    throw new Error(`Managed runtime dependency setup failed: ${safeErrorText(installed.stderr)}`);
  }
  return { python: runtimePython, installed: true, detail: 'managed runtime prepared' };
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
 * not from the workspace, and are never logged.
 *
 * @param {{ environment?: NodeJS.ProcessEnv, host: string, port: number }} options
 * @returns {NodeJS.ProcessEnv}
 */
function buildEngineEnvironment({ environment = process.env, host, port }) {
  return {
    ...environment,
    PYTHONUNBUFFERED: '1',
    PYTHONNOUSERSITE: '1',
    BUGDHOR_HOST: host,
    BUGDHOR_PORT: String(port)
  };
}

module.exports = {
  DEFAULT_PORT,
  DEFAULT_REQUIREMENTS: 'engine/requirements.txt',
  loopbackEndpoint,
  validatePythonExecutable,
  discoverPythonCandidates,
  discoverEngineSource,
  runFixedCommand,
  runtimeDependenciesReady,
  ensureManagedRuntime,
  buildEngineArguments,
  buildEngineEnvironment,
  safeErrorText
};
