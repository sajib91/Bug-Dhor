'use strict';

const fs = require('node:fs');

/**
 * Resolve a path to its canonical on-disk form. Node's non-native realpath
 * preserves Windows 8.3 short names such as `RUNNER~1`, while the Python
 * backend reports the long form. The native resolver uses the OS API so the
 * harness and the backend compare the same path.
 *
 * The injectable filesystem/platform keep this logic unit-testable on every
 * host; production callers use the defaults.
 *
 * @param {string} target
 * @param {{
 *   fileSystem?: { realpathSync: typeof fs.realpathSync },
 *   platform?: NodeJS.Platform
 * }} [options]
 * @returns {string}
 */
function canonicalPath(target, options = {}) {
  const fileSystem = options.fileSystem ?? fs;
  const platform = options.platform ?? process.platform;

  let resolved;
  try {
    resolved = fileSystem.realpathSync.native(target);
  } catch {
    resolved = fileSystem.realpathSync(target);
  }

  // libuv normally strips the extended-length prefix, but keep the comparison
  // stable if a platform returns `\\?\C:\...` or `\\?\UNC\server\share`.
  if (platform === 'win32' && resolved.startsWith('\\\\?\\')) {
    resolved = resolved.slice(4);
    if (resolved.startsWith('UNC\\')) {
      resolved = `\\\\${resolved.slice(4)}`;
    }
  }

  return resolved;
}

/**
 * Compare a `file:` URI reported by the backend with a local filesystem path.
 * Python's `Path.as_uri()` and VS Code's `Uri.file().toString()` are both valid
 * but differ on Windows (drive-letter case and `:` escaping), so raw string
 * equality is not portable. Parse the URI and compare canonical filesystem
 * paths instead.
 *
 * @param {unknown} uriText
 * @param {string} filePath
 * @param {{
 *   parseUri: (value: string) => { scheme?: string, fsPath?: unknown },
 *   fileSystem?: { realpathSync: typeof fs.realpathSync },
 *   platform?: NodeJS.Platform
 * }} options
 * @returns {boolean}
 */
function fileUriMatchesPath(uriText, filePath, options) {
  if (typeof uriText !== 'string' || typeof options?.parseUri !== 'function') {
    return false;
  }
  try {
    const uri = options.parseUri(uriText);
    if (uri?.scheme !== 'file' || typeof uri.fsPath !== 'string') {
      return false;
    }
    const actual = canonicalPath(uri.fsPath, options);
    const expected = canonicalPath(filePath, options);
    // Windows filesystems are case-insensitive; drive-letter casing in
    // particular varies between Python and VS Code URI writers.
    return options.platform === 'win32'
      ? actual.toLowerCase() === expected.toLowerCase()
      : actual === expected;
  } catch {
    return false;
  }
}

module.exports = { canonicalPath, fileUriMatchesPath };
