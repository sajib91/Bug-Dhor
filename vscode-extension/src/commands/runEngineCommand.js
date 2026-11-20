'use strict';

const { CommandValidationError } = require('./validation');
const { redactText } = require('../security/redaction');

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
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   trustGate?: { assertCapability: (operation?: string) => void }
 * }} dependencies
 * @param {string} commandTitle
 * @param {Error} error
 * @param {boolean} expected
 */
function reportFailure({ vscode, logger }, commandTitle, error, expected) {
  const message = redactText(error instanceof Error ? error.message : error);
  if (expected) {
    logger.warn(`${commandTitle}: ${message}`);
  } else {
    logger.error(`${commandTitle} failed: ${message}`, error);
  }

  // Notifications must never block command completion. An unattended VS Code
  // host (including integration tests) may never dismiss an error message.
  Promise.resolve(vscode.window.showErrorMessage(`Bug Dhor: ${message}`, 'Show Logs'))
    .then((action) => {
      if (action === 'Show Logs') {
        logger.show();
      }
    })
    .catch(() => {
      // A dismissed or failed notification must not surface a second error.
    });
}

/**
 * Run one engine-backed command with a cancellable progress notification and
 * consistent error handling. Assignments are only published after a validated
 * backend result is returned; transport failures never produce a success notice.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   trustGate?: { assertCapability: (operation?: string) => void }
 * }} dependencies
 * @param {{
 *   definition: { title: string, progressTitle: string },
 *   prepare: (context?: { token: import('vscode').CancellationToken, progress: import('vscode').Progress<{ message?: string }> }) => object | Promise<object>,
 *   invoke: (request: object, context: { token: import('vscode').CancellationToken, progress: import('vscode').Progress<{ message?: string }> }) => Promise<unknown>,
 *   onRequest?: (event: { definition: object, request: object, startedAt: string }) => unknown | Promise<unknown>,
 *   onResult?: (result: unknown, request: object, meta?: unknown) => void | Promise<void>,
 *   onError?: (event: { error: unknown, request: object, meta?: unknown }) => void | Promise<void>
 * }} command
 * @returns {Promise<unknown>}
 */
async function runEngineCommand(
  dependencies,
  { definition, prepare, invoke, onRequest, onResult, onError }
) {
  const { vscode, logger } = dependencies;
  let cancellationToken;
  let requestMeta;
  let lastRequest;

  /** Hooks are observability only; a hook failure must never alter a scan. */
  async function callHook(hook, ...args) {
    if (typeof hook !== 'function') {
      return undefined;
    }
    try {
      return await hook(...args);
    } catch (error) {
      logger.warn(`Command observer failed: ${redactText(error)}`);
      return undefined;
    }
  }
  try {
    dependencies.trustGate?.assertCapability?.('sourceAnalysis');
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
        lastRequest = request;
        if (token.isCancellationRequested) {
          logger.info(`${definition.title} cancelled.`);
          return undefined;
        }
        requestMeta = await callHook(onRequest, {
          definition,
          request,
          startedAt: new Date().toISOString()
        });
        progress.report({ message: 'Contacting the Bug Dhor backend.' });
        const result = await invoke(request, { token, progress });
        if (token.isCancellationRequested) {
          logger.info(`${definition.title} cancelled.`);
          return undefined;
        }
        await callHook(onResult, result, request, requestMeta);
        return result;
      }
    );
  } catch (error) {
    if (cancellationToken?.isCancellationRequested || isCancellation(error)) {
      logger.info(`${definition.title} cancelled.`);
      return undefined;
    }
    await callHook(onError, { error, request: lastRequest, meta: requestMeta, definition });
    reportFailure(dependencies, definition.title, error, error instanceof CommandValidationError);
    return undefined;
  }
}

module.exports = { runEngineCommand, isCancellation };
