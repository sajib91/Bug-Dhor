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

module.exports = { canonicalPath };
