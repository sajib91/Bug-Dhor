'use strict';

const { runEngineCommand } = require('./runEngineCommand');

/**
 * Bind one command definition to a service method.
 *
 * The service method is captured at registration time so a broken service
 * fails during activation instead of after the user starts a command.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   engineHooks?: {
 *     onRequest?: (event: { definition: object, request: object, startedAt: string }) => unknown,
 *     onResult?: (result: unknown, request: object, meta?: unknown) => void,
 *     onError?: (event: { error: unknown, request?: object, meta?: unknown, definition: object }) => void
 *   }
 * }} context
 * @param {{ id: string, title: string, progressTitle: string, serviceMethod: string | null }} definition
 * @param {(...args: unknown[]) => object | Promise<object>} prepare
 * @param {{
 *   onResult?: (result: unknown, request: object) => void | Promise<void>,
 *   passContextToPrepare?: boolean
 * }} [options]
 * @returns {import('vscode').Disposable}
 */
function registerEngineCommand(context, definition, prepare, options = {}) {
  const { vscode, service, logger, registry } = context;
  const globalHooks = context.engineHooks ?? {};
  const { serviceMethod } = definition;

  const compose = (first, second) => {
    if (typeof first !== 'function') {
      return second;
    }
    if (typeof second !== 'function') {
      return first;
    }
    return async (...args) => {
      await first(...args);
      await second(...args);
    };
  };

  if (!serviceMethod) {
    throw new Error(`Command ${definition.id} does not declare a service method.`);
  }
  const method = service?.[serviceMethod];
  if (typeof method !== 'function') {
    throw new TypeError(
      `SecurityEngineService.${serviceMethod} is required by ${definition.id} but is not implemented.`
    );
  }

  return registry.register(definition.id, (...args) =>
    runEngineCommand(
      { vscode, logger },
      {
        definition,
        // Only repository-style commands opt in to receiving the progress and
        // cancellation context. Other commands keep their original args so an
        // optional finding argument is never replaced by the engine context.
        prepare: (context) =>
          options.passContextToPrepare ? prepare(...args, context) : prepare(...args),
        invoke: (request, engineContext) => method.call(service, request, engineContext),
        onRequest: compose(globalHooks.onRequest, options.onRequest),
        onResult: compose(globalHooks.onResult, options.onResult),
        onError: compose(globalHooks.onError, options.onError)
      }
    )
  );
}

module.exports = { registerEngineCommand };
