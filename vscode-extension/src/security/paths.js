'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Return true when `filePath` is the root itself or a descendant of `rootPath`.
 * The check is lexical; callers that need symlink realpath checks must add them.
 *
 * @param {unknown} filePath
 * @param {unknown} rootPath
 * @returns {boolean}
 */
function isPathWithinRoot(filePath, rootPath) {
  if (typeof filePath !== 'string' || typeof rootPath !== 'string') {
    return false;
  }
  if (filePath.length === 0 || rootPath.length === 0) {
    return false;
  }

  const resolvedRoot = path.resolve(rootPath);
  const resolvedFile = path.resolve(filePath);
  const relative = path.relative(resolvedRoot, resolvedFile);

  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

/**
 * Return true when a file URI is inside one of the supplied workspace folders.
 * Non-file URIs are never accepted.
 *
 * @param {{ scheme?: string, fsPath?: string } | undefined} uri
 * @param {ReadonlyArray<{ uri?: { scheme?: string, fsPath?: string } }>} folders
 * @returns {boolean}
 */
function isFileUriWithinFolders(uri, folders) {
  if (!uri || uri.scheme !== 'file' || typeof uri.fsPath !== 'string') {
    return false;
  }
  return folders.some(
    (folder) =>
      folder?.uri?.scheme === 'file' &&
      typeof folder.uri.fsPath === 'string' &&
      isPathWithinRoot(uri.fsPath, folder.uri.fsPath)
  );
}

/**
 * Resolve a path to its canonical on-disk form. Windows exposes the same file
 * as an 8.3 short path (`RUNNER~1`) or a long path; VS Code workspace folders,
 * documents, and file watchers do not always use the same representation.
 * Realpath keeps containment checks and relative-path calculations stable.
 *
 * The injectable filesystem keeps this logic unit-testable on every host.
 *
 * @param {unknown} target
 * @param {{ fileSystem?: Pick<typeof fs, 'realpathSync'> }} [options]
 * @returns {string}
 */
function canonicalPath(target, options = {}) {
  if (typeof target !== 'string' || target.length === 0) {
    return typeof target === 'string' ? target : '';
  }
  const fileSystem = options.fileSystem ?? fs;
  const resolved = path.resolve(target);
  const realpath = (candidate) =>
    typeof fileSystem.realpathSync?.native === 'function'
      ? fileSystem.realpathSync.native(candidate)
      : fileSystem.realpathSync(candidate);

  try {
    return realpath(resolved);
  } catch {
    // A file may still be unsaved. Canonicalize its parent so a short/long
    // directory mismatch cannot turn a valid child into a `../` path.
    try {
      return path.join(realpath(path.dirname(resolved)), path.basename(resolved));
    } catch {
      return resolved;
    }
  }
}

/**
 * Containment check that also follows existing symlinks to their real paths.
 * Non-existent paths fall back to the lexical result so pre-write validation
 * remains usable; existing symlinks that escape the root are rejected.
 *
 * @param {unknown} filePath
 * @param {unknown} rootPath
 * @returns {boolean}
 */
function isRealPathWithinRoot(filePath, rootPath) {
  if (!isPathWithinRoot(filePath, rootPath)) {
    return false;
  }
  try {
    const realRoot = fs.realpathSync.native(path.resolve(/** @type {string} */ (rootPath)));
    const realFile = fs.realpathSync.native(path.resolve(/** @type {string} */ (filePath)));
    return isPathWithinRoot(realFile, realRoot);
  } catch {
    return true;
  }
}

module.exports = {
  isPathWithinRoot,
  isRealPathWithinRoot,
  isFileUriWithinFolders,
  canonicalPath
};
