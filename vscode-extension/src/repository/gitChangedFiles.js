'use strict';

/**
 * Read-only Git metadata for changed-file discovery.
 *
 * This module only asks Git for file names. It never executes repository code,
 * install scripts, hooks, or shell commands. All invocations use `execFile`
 * with a fixed executable and argument arrays.
 */

const { execFile } = require('node:child_process');
const path = require('node:path');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_PATHS = 50_000;

class GitChangedFilesError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'GitChangedFilesError';
    this.code = code;
  }
}

/** @param {unknown} token */
function isCancelled(token) {
  if (!token || typeof token !== 'object') {
    return false;
  }
  return (
    token.isCancellationRequested === true ||
    (typeof token.isCancellationRequested === 'function' && token.isCancellationRequested())
  );
}

/**
 * @param {string} cwd
 * @param {string[]} args
 * @param {number} timeoutMs
 * @returns {Promise<string>}
 */
async function defaultRunner(cwd, args, timeoutMs) {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd,
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true
    });
    return stdout;
  } catch (error) {
    const detail =
      error && typeof error === 'object' && typeof error.stderr === 'string'
        ? error.stderr
        : error instanceof Error
          ? error.message
          : String(error);
    throw new GitChangedFilesError(`Git metadata query failed: ${detail}`, 'E_GIT_QUERY', {
      cause: error
    });
  }
}

/**
 * @param {string} output
 * @returns {string[]}
 */
function parseNulPaths(output) {
  if (typeof output !== 'string') {
    return [];
  }
  return output
    .split('\0')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0 && entry !== '.' && !entry.startsWith('../'))
    .map((entry) => entry.replace(/^\.\//, '').split(path.sep).join('/'));
}

/**
 * Return tracked modifications, staged changes, and (optionally) untracked
 * files for one root. Paths are NUL-separated, resolved by Git relative to the
 * supplied root, and deduplicated.
 *
 * @param {string} rootPath
 * @param {{
 *   runner?: (cwd: string, args: string[], timeoutMs: number) => Promise<string>,
 *   includeUntracked?: boolean,
 *   timeoutMs?: number,
 *   maxPaths?: number,
 *   cancellationToken?: unknown
 * }} [options]
 */
async function gitChangedFilesForRoot(rootPath, options = {}) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath)) {
    throw new GitChangedFilesError('Git discovery requires an absolute root path.', 'E_INVALID_ROOT');
  }
  const runner = options.runner ?? defaultRunner;
  const timeoutMs =
    typeof options.timeoutMs === 'number' && Number.isFinite(options.timeoutMs)
      ? Math.min(60_000, Math.max(1000, Math.round(options.timeoutMs)))
      : DEFAULT_TIMEOUT_MS;
  const maxPaths =
    typeof options.maxPaths === 'number' && Number.isFinite(options.maxPaths)
      ? Math.min(DEFAULT_MAX_PATHS, Math.max(1, Math.floor(options.maxPaths)))
      : DEFAULT_MAX_PATHS;

  const commands = [
    ['diff', '--relative', '--name-only', '-z', '--diff-filter=ACMR', '--'],
    ['diff', '--relative', '--cached', '--name-only', '-z', '--diff-filter=ACMR', '--']
  ];
  if (options.includeUntracked !== false) {
    // `git ls-files` emits paths relative to the current directory by default
    // and does not accept `--relative`.
    commands.push(['ls-files', '--others', '--exclude-standard', '-z', '--']);
  }

  const seen = new Set();
  /** @type {string[]} */
  const relativePaths = [];
  for (const args of commands) {
    if (isCancelled(options.cancellationToken)) {
      return { available: true, cancelled: true, paths: [] };
    }
    let output;
    try {
      output = await runner(rootPath, args, timeoutMs);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (/not a git repository|outside repository|no such directory/i.test(detail)) {
        return { available: false, cancelled: false, paths: [] };
      }
      throw error;
    }
    for (const relative of parseNulPaths(output)) {
      const absolute = path.resolve(rootPath, relative);
      if (!isPathWithinRoot(absolute, rootPath) || seen.has(absolute)) {
        continue;
      }
      seen.add(absolute);
      relativePaths.push(absolute);
      if (relativePaths.length > maxPaths) {
        throw new GitChangedFilesError(
          `Changed-file discovery exceeds ${maxPaths} paths.`,
          'E_TOO_MANY_FILES'
        );
      }
    }
  }

  return { available: true, cancelled: false, paths: relativePaths };
}

/**
 * @param {string} filePath
 * @param {string} rootPath
 * @returns {boolean}
 */
function isPathWithinRoot(filePath, rootPath) {
  const relative = path.relative(path.resolve(rootPath), path.resolve(filePath));
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

/**
 * Collect changed files across one or more workspace roots. At least one root
 * must be inside a Git work tree; roots without Git metadata are skipped.
 *
 * @param {string[]} rootPaths
 * @param {Parameters<typeof gitChangedFilesForRoot>[1]} [options]
 */
async function collectGitChangedFiles(rootPaths, options = {}) {
  if (!Array.isArray(rootPaths) || rootPaths.length === 0) {
    throw new GitChangedFilesError(
      'Changed-file discovery requires at least one workspace root.',
      'E_NO_WORKSPACE'
    );
  }
  const seen = new Set();
  /** @type {string[]} */
  const paths = [];
  let available = false;
  for (const rootPath of rootPaths) {
    const result = await gitChangedFilesForRoot(rootPath, options);
    if (result.cancelled) {
      return { available, cancelled: true, paths: [] };
    }
    if (!result.available) {
      continue;
    }
    available = true;
    for (const filePath of result.paths) {
      if (seen.has(filePath)) {
        continue;
      }
      seen.add(filePath);
      paths.push(filePath);
    }
  }
  if (!available) {
    throw new GitChangedFilesError(
      'No open workspace folder is inside a Git repository.',
      'E_NOT_A_REPOSITORY'
    );
  }
  return { available: true, cancelled: false, paths };
}

module.exports = {
  GitChangedFilesError,
  gitChangedFilesForRoot,
  collectGitChangedFiles,
  parseNulPaths
};
