'use strict';

/**
 * Cross-platform Python discovery used by the integration harness.
 *
 * Kept free of side effects so the same logic can be exercised on macOS,
 * Windows, and Linux in unit tests without creating a virtual environment.
 */

const path = require('node:path');

const FALLBACK_EXECUTABLE = Object.freeze({
  win32: 'python',
  darwin: 'python3',
  linux: 'python3'
});

/**
 * Resolve the Python interpreter used to launch the backend in integration
 * tests. Explicit environment overrides win, then the repository virtual
 * environment, then a platform-appropriate fallback.
 *
 * @param {{
 *   platform?: string,
 *   repositoryRoot: string,
 *   env?: Record<string, string | undefined>,
 *   exists?: (candidate: string) => boolean
 * }} options
 * @returns {string}
 */
function resolvePython(options) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const exists = options.exists ?? ((candidate) => require('node:fs').existsSync(candidate));

  const override = env.BUGDHOR_PYTHON;
  if (typeof override === 'string' && override.trim().length > 0) {
    return override.trim();
  }

  const isWindows = platform === 'win32';
  // Use the requested platform's separator rules rather than the host's so the
  // same logic can be verified on every CI runner.
  const pathApi = isWindows ? path.win32 : path.posix;
  const venvPython = isWindows
    ? pathApi.join(options.repositoryRoot, '.venv', 'Scripts', 'python.exe')
    : pathApi.join(options.repositoryRoot, '.venv', 'bin', 'python');
  if (exists(venvPython)) {
    return venvPython;
  }

  return FALLBACK_EXECUTABLE[platform] ?? 'python3';
}

module.exports = { resolvePython, FALLBACK_EXECUTABLE };
