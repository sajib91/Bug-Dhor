'use strict';

const fs = require('node:fs');

const DEFAULT_ATTEMPTS = 12;
const DEFAULT_DELAY_MS = 500;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function directoryExists(root) {
  try {
    return fs.existsSync(root);
  } catch {
    return false;
  }
}

/**
 * Remove a VS Code test temporary directory.
 *
 * On Windows the Extension Host can briefly keep files such as `exthost.log`
 * open after its process has exited. `fs.rmSync` rejects those entries with
 * EBUSY/EPERM, and a cleanup error must not turn a passing Extension Host run
 * into a failed CI job. Retry the whole removal because each attempt also
 * deletes whatever was unlocked since the previous one.
 *
 * @param {string} root
 * @param {{ attempts?: number, delayMs?: number }} [options]
 * @returns {Promise<boolean>} true when the directory is gone, false when it
 *   remained locked after the final attempt.
 */
async function removeTemporaryDirectory(root, options = {}) {
  const attempts = options.attempts ?? DEFAULT_ATTEMPTS;
  const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
      return true;
    } catch (error) {
      if (!directoryExists(root)) {
        return true;
      }
      if (attempt === attempts) {
        console.warn(
          `Temporary test directory ${root} could not be removed after ${attempts} attempts: ` +
            `${error instanceof Error ? error.message : String(error)}. ` +
            'The test result is unaffected; the operating system will reclaim it.'
        );
        return false;
      }
      await delay(delayMs);
    }
  }
  return !directoryExists(root);
}

module.exports = { removeTemporaryDirectory };
