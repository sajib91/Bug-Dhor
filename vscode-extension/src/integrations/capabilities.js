'use strict';

const { ProviderCapabilityError } = require('./errors');

/**
 * Capability taxonomy for AI coding assistant integrations.
 *
 * A: code monitoring (ordinary editor/change observation)
 * B: generation request access
 * C: generation response access
 * D: model internal activation access
 * E: sparse-autoencoder integration backed by real activations and a validated SAE
 * F: activation steering backed by D and E plus an explicit intervention contract
 */
const CAPABILITIES = Object.freeze(['A', 'B', 'C', 'D', 'E', 'F']);

/** @type {Readonly<Record<string, { name: string, summary: string }>>} */
const CAPABILITY_DEFINITIONS = Object.freeze({
  A: {
    name: 'Code monitoring',
    summary:
      'Observes saved or edited source through documented editor events. It never infers author or model identity.'
  },
  B: {
    name: 'Generation request access',
    summary:
      'Receives prompts or request metadata through a documented, configured API. It is not author attribution.'
  },
  C: {
    name: 'Generation response access',
    summary: 'Receives generated text or response metadata through a documented, configured API.'
  },
  D: {
    name: 'Model internal activation access',
    summary:
      'Reads real internal activations from a local model through an explicitly validated accessor.'
  },
  E: {
    name: 'SAE integration',
    summary: 'Requires D and a separately validated SAE artifact with a documented feature mapping.'
  },
  F: {
    name: 'Activation steering',
    summary:
      'Requires D and E plus an explicitly configured intervention contract with measured effects.'
  }
});

/** Hosted assistants cannot expose model internals, regardless of API surface. */
const HOSTED_CAPABILITIES = Object.freeze(['A', 'B', 'C']);

/**
 * @param {unknown} value
 * @returns {string[]}
 */
function asCapabilityList(value) {
  if (value === undefined || value === null) {
    return [];
  }
  const entries = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(entries)) {
    throw new ProviderCapabilityError('Capabilities must be an array or a single letter.');
  }
  return entries.map((entry) => {
    if (typeof entry !== 'string') {
      throw new ProviderCapabilityError('Each capability must be a string.');
    }
    const normalized = entry.trim().toUpperCase();
    if (!CAPABILITIES.includes(normalized)) {
      throw new ProviderCapabilityError(`Unknown capability: ${entry}.`, undefined, entry);
    }
    return normalized;
  });
}

/**
 * Validate capability invariants without discarding evidence.
 *
 * @param {unknown} value
 * @param {{ hosted?: boolean }} [options]
 * @returns {{ capabilities: string[], errors: string[] }}
 */
function validateCapabilities(value, options = {}) {
  let capabilities;
  try {
    capabilities = [...new Set(asCapabilityList(value))];
  } catch (error) {
    return {
      capabilities: [],
      errors: [error instanceof Error ? error.message : String(error)]
    };
  }

  const errors = [];
  const has = (capability) => capabilities.includes(capability);

  if (has('E') && !has('D')) {
    errors.push('Capability E (SAE integration) requires capability D (real activation access).');
  }
  if (has('F') && !has('D')) {
    errors.push(
      'Capability F (activation steering) requires capability D (real activation access).'
    );
  }
  if (has('F') && !has('E')) {
    errors.push('Capability F (activation steering) requires capability E (validated SAE).');
  }
  if (options.hosted === true) {
    for (const capability of capabilities) {
      if (!HOSTED_CAPABILITIES.includes(capability)) {
        errors.push(
          `Hosted providers cannot claim capability ${capability}; model internals are not observable.`
        );
      }
    }
  }

  return { capabilities: [...capabilities].sort(), errors };
}

/**
 * Normalize capabilities or throw with the first invariant violation.
 *
 * @param {unknown} value
 * @param {{ hosted?: boolean, providerId?: string }} [options]
 * @returns {string[]}
 */
function normalizeCapabilities(value, options = {}) {
  const result = validateCapabilities(value, { hosted: options.hosted === true });
  if (result.errors.length > 0) {
    throw new ProviderCapabilityError(
      result.errors[0],
      options.providerId,
      result.errors[0].match(/capability ([A-F])/)?.[1]
    );
  }
  return result.capabilities;
}

/**
 * @param {readonly string[]} capabilities
 * @param {string} capability
 * @returns {boolean}
 */
function hasCapability(capabilities, capability) {
  return Array.isArray(capabilities) && capabilities.includes(capability);
}

/**
 * @param {readonly string[]} capabilities
 * @returns {Array<{ capability: string, name: string, summary: string }>}
 */
function describeCapabilities(capabilities) {
  return [...capabilities].sort().map((capability) => ({
    capability,
    ...CAPABILITY_DEFINITIONS[capability]
  }));
}

module.exports = {
  CAPABILITIES,
  CAPABILITY_DEFINITIONS,
  HOSTED_CAPABILITIES,
  asCapabilityList,
  validateCapabilities,
  normalizeCapabilities,
  hasCapability,
  describeCapabilities
};
