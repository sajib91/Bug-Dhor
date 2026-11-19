'use strict';

/**
 * VS Code-aware workspace trust gate.
 *
 * The gate reads `vscode.workspace.isTrusted`, subscribes to trust changes, and
 * exposes one enforcement point used by the service, monitor, commands, and
 * configuration. A missing trust API fails closed.
 */

const {
  applyWorkspaceTrustToSettings,
  endpointPolicyViolation,
  isOperationAllowed,
  isTrustedValue
} = require('./trustPolicy');

class WorkspaceTrustError extends Error {
  /** @param {string} operation */
  constructor(operation) {
    super(
      `Bug Dhor cannot run ${operation} in an untrusted workspace. Trust the workspace ` +
        'before requesting source analysis, background scans, or sandboxed execution.'
    );
    this.name = 'WorkspaceTrustError';
    this.code = 'E_WORKSPACE_TRUST_REQUIRED';
  }
}

/**
 * @param {unknown} vscode
 * @returns {boolean}
 */
function readWorkspaceTrust(vscode) {
  return isTrustedValue(vscode?.workspace?.isTrusted);
}

/**
 * Wrap a service so every capability is checked on each call. `health` remains
 * available because it sends no source and only reports backend liveness.
 *
 * @param {any} service
 * @param {() => boolean} isTrusted
 * @returns {any}
 */
function createTrustedService(service, isTrusted) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('createTrustedService requires a service object.');
  }
  return new Proxy(service, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function' || typeof property !== 'string') {
        return value;
      }
      return (...args) => {
        if (!isOperationAllowed({ trusted: isTrusted(), operation: property })) {
          throw new WorkspaceTrustError(property);
        }
        return value.apply(target, args);
      };
    }
  });
}

/**
 * Create the shared trust gate.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger?: import('../logging/output').Logger
 * }} dependencies
 */
function createTrustGate({ vscode, logger } = {}) {
  if (!vscode || !vscode.workspace) {
    throw new TypeError('createTrustGate requires the VS Code workspace API.');
  }

  let trusted = readWorkspaceTrust(vscode);
  /** @type {Set<(isTrusted: boolean) => void>} */
  const listeners = new Set();

  const subscription =
    typeof vscode.workspace.onDidChangeWorkspaceTrust === 'function'
      ? vscode.workspace.onDidChangeWorkspaceTrust((event) => {
          const next = isTrustedValue(event?.isTrusted);
          if (next === trusted) {
            return;
          }
          trusted = next;
          logger?.info(
            trusted
              ? 'Workspace trust granted. Bug Dhor source analysis is enabled.'
              : 'Workspace trust revoked. Bug Dhor source analysis is blocked.'
          );
          for (const listener of listeners) {
            try {
              listener(trusted);
            } catch (error) {
              logger?.error('A workspace trust listener failed.', error);
            }
          }
        })
      : { dispose() {} };

  return Object.freeze({
    /** @returns {boolean} */
    isTrusted() {
      return trusted;
    },
    /** @param {string} [operation] */
    assertCapability(operation = 'sourceAnalysis') {
      if (!isOperationAllowed({ trusted, operation })) {
        throw new WorkspaceTrustError(operation);
      }
    },
    /** @param {unknown} baseUrl */
    assertEndpoint(baseUrl) {
      const violation = endpointPolicyViolation({ baseUrl, trusted });
      if (violation) {
        const error = new Error(
          violation === 'E_UNTRUSTED_REMOTE_ENDPOINT'
            ? 'Untrusted workspaces may use only a loopback backend endpoint.'
            : violation === 'E_INSECURE_REMOTE_ENDPOINT'
              ? 'A non-loopback backend endpoint must use HTTPS.'
              : 'The configured backend endpoint is invalid.'
        );
        error.name = 'WorkspaceTrustError';
        /** @type {any} */ (error).code = violation;
        throw error;
      }
    },
    /** @param {Record<string, any>} [settings] */
    sanitizeSettings(settings = {}) {
      return applyWorkspaceTrustToSettings(settings, trusted);
    },
    /** @param {any} service */
    createTrustedService(service) {
      return createTrustedService(service, () => trusted);
    },
    /** @param {(isTrusted: boolean) => void} listener */
    onChange(listener) {
      listeners.add(listener);
      return { dispose: () => listeners.delete(listener) };
    },
    dispose() {
      listeners.clear();
      subscription?.dispose?.();
    }
  });
}

module.exports = {
  WorkspaceTrustError,
  createTrustedService,
  createTrustGate,
  readWorkspaceTrust
};
