'use strict';

/**
 * Pure workspace-trust policy for Bug Dhor.
 *
 * This module has no VS Code dependency so the deny-by-default rules can be
 * unit tested with plain Node. It is the single source of truth for what an
 * untrusted workspace may do and which backend endpoints are acceptable.
 */

const UNTRUSTED_ALLOWED_OPERATIONS = Object.freeze(new Set(['health']));

/** @param {unknown} value */
function isTrustedValue(value) {
  return value === true;
}

/**
 * Untrusted workspaces may check liveness only. Every operation that can read
 * source, transmit it, or execute code is denied before any request is formed.
 *
 * @param {{ trusted?: unknown, operation?: string }} input
 * @returns {boolean}
 */
function isOperationAllowed({ trusted, operation = 'sourceAnalysis' } = {}) {
  if (!isTrustedValue(trusted)) {
    return UNTRUSTED_ALLOWED_OPERATIONS.has(operation);
  }
  return true;
}

/**
 * Force all source-egress, background, automatic, and execution settings off in
 * an untrusted workspace. The returned object is a shallow copy.
 *
 * @param {Record<string, any>} settings
 * @param {unknown} trusted
 * @returns {Record<string, any>}
 */
function applyWorkspaceTrustToSettings(settings = {}, trusted = false) {
  const result = { ...settings };
  if (isTrustedValue(trusted)) {
    return result;
  }
  Object.assign(result, {
    sendSourceText: false,
    allowRemoteSourceSharing: false,
    monitoringEnabled: false,
    monitoringAllowAutomaticSourceSharing: false,
    repositoryAutoScanOnWorkspaceOpen: false,
    recommendationAllowSandboxedExecution: false,
    localEngineEnabled: false,
    localEngineAllowSourceWrite: false,
    assistantProvider: 'editor',
    assistantOpenAiEndpoint: '',
    assistantLocalModelPath: '',
    assistantExtensionManifestPath: '',
    assistantSaeEnabled: false,
    assistantCounterfactualEnabled: false,
    'privacy.sendSourceText': false,
    'privacy.allowRemoteSourceSharing': false,
    'monitoring.enabled': false,
    'monitoring.allowAutomaticSourceSharing': false,
    'repository.autoScanOnWorkspaceOpen': false,
    'recommendations.allowSandboxedExecution': false,
    'localEngine.enabled': false,
    'localEngine.allowSourceWrite': false
  });
  return result;
}

/**
 * @param {unknown} baseUrl
 * @returns {{ hostname: string, protocol: string } | undefined}
 */
function parseEndpoint(baseUrl) {
  try {
    const parsed = new URL(String(baseUrl));
    return { hostname: parsed.hostname.toLowerCase(), protocol: parsed.protocol };
  } catch {
    return undefined;
  }
}

/**
 * Loopback HTTP is the local-development default. Non-loopback endpoints require
 * HTTPS and are forbidden outright in untrusted workspaces.
 *
 * @param {{ baseUrl: unknown, trusted?: unknown }} input
 * @returns {string | undefined} an error code, or undefined when allowed
 */
function endpointPolicyViolation({ baseUrl, trusted } = {}) {
  const endpoint = parseEndpoint(baseUrl);
  if (!endpoint) {
    return 'E_INVALID_BACKEND_URL';
  }
  const loopback =
    endpoint.hostname === 'localhost' ||
    endpoint.hostname === '127.0.0.1' ||
    endpoint.hostname === '::1' ||
    endpoint.hostname === '[::1]';
  if (loopback) {
    return undefined;
  }
  if (!isTrustedValue(trusted)) {
    return 'E_UNTRUSTED_REMOTE_ENDPOINT';
  }
  if (endpoint.protocol !== 'https:') {
    return 'E_INSECURE_REMOTE_ENDPOINT';
  }
  return undefined;
}

module.exports = {
  UNTRUSTED_ALLOWED_OPERATIONS,
  applyWorkspaceTrustToSettings,
  endpointPolicyViolation,
  isOperationAllowed,
  isTrustedValue,
  parseEndpoint
};
