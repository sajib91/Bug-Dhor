'use strict';

const { CommandValidationError } = require('./validation');

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isCancellation(error) {
  if (!error || typeof error !== 'object') {
    return false;
  }
  return (
    error.name === 'Canceled' ||
    error.name === 'CanceledError' ||
    error.name === 'AbortError' ||
    error.code === 'ERR_CANCELED'
  );
}

/**
 * @param {{ vscode: import('vscode'), logger: import('../logging/output').Logger }} dependencies
 * @param {string} commandTitle
 * @param {Error} error
 * @param {boolean} expected
 */
async function reportFailure({ vscode, logger }, commandTitle, error, expected) {
  const message = error instanceof Error ? error.message : String(error);
  if (expected) {
    logger.warn(`${commandTitle}: ${message}`);
  } else {
    logger.error(`${commandTitle} failed: ${message}`, error);
  }

  const action = await vscode.window.showErrorMessage(`Bug Dhor: ${message}`, 'Show Logs');
  if (action === 'Show Logs') {
    logger.show();
  }
}

/**
 * Run one engine-backed command with a cancellable progress notification and
 * consistent error handling. Assignments are only published after a validated
 * backend result is returned; transport failures never produce a success notice.
 *
 * @param {{ vscode: import('vscode'), logger: import('../logging/output').Logger }} dependencies
 * @param {{
 *   definition: { title: string, progressTitle: string },
 *   prepare: (context?: { token: import('vscode').CancellationToken, progress: import('vscode').Progress<{ message?: string }> }) => object | Promise<object>,
 *   invoke: (request: object, context: { token: import('vscode').CancellationToken, progress: import('vscode').Progress<{ message?: string }> }) => Promise<unknown>,
 *   onResult?: (result: unknown, request: object) => void | Promise<void>
 * }} command
 * @returns {Promise<unknown>}
 */
async function runEngineCommand(dependencies, { definition, prepare, invoke, onResult }) {
  const { vscode, logger } = dependencies;
  let cancellationToken;
  try {
    return await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: definition.progressTitle,
        cancellable: true
      },
      async (progress, token) => {
        cancellationToken = token;
        if (token.isCancellationRequested) {
          logger.info(`${definition.title} cancelled.`);
          return undefined;
        }
        // Preparation runs inside progress so repository inventory and other
        // potentially slow local work can report progress and observe the same
        // cancellation token as the backend request.
        const request = await prepare({ token, progress });
        if (token.isCancellationRequested) {
          logger.info(`${definition.title} cancelled.`);
          return undefined;
        }
        progress.report({ message: 'Contacting the Bug Dhor backend.' });
        const result = await invoke(request, { token, progress });
        if (token.isCancellationRequested) {
          logger.info(`${definition.title} cancelled.`);
          return undefined;
        }
        if (onResult) {
          await onResult(result, request);
        }
        return result;
      }
    );
  } catch (error) {
    if (cancellationToken?.isCancellationRequested || isCancellation(error)) {
      logger.info(`${definition.title} cancelled.`);
      return undefined;
    }
    await reportFailure(
      dependencies,
      definition.title,
      error,
      error instanceof CommandValidationError
    );
    return undefined;
  }
}

module.exports = { runEngineCommand, isCancellation };
