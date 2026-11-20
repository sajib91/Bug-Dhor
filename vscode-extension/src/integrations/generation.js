'use strict';

const crypto = require('node:crypto');
const { ProviderGenerationError } = require('./errors');
const { hasCapability, normalizeCapabilities } = require('./capabilities');

/**
 * Generation request/response interfaces shared by all model adapters.
 *
 * @typedef {Object} GenerationMessage
 * @property {'system'|'user'|'assistant'} role
 * @property {string} content
 */

/**
 * @typedef {Object} GenerationRequest
 * @property {string} providerId
 * @property {string} modelId
 * @property {GenerationMessage[]} messages
 * @property {number} maxTokens
 * @property {number} temperature
 * @property {string[]} stop
 * @property {string} requestId
 * @property {string} requestHash
 * @property {Record<string, string|number|boolean>} metadata
 */

/**
 * @typedef {Object} GenerationResponse
 * @property {string} text
 * @property {string} finishReason
 * @property {{ promptTokens?: number, completionTokens?: number, totalTokens?: number }} usage
 * @property {{ providerId: string, modelId: string, requestId: string, capabilities: string[] }} provenance
 */

const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TEMPERATURE = 0;
const MAX_MESSAGES = 64;
const MAX_CONTENT_CHARS = 100_000;

/** @param {unknown} value @param {string} field @returns {string} */
function requireText(value, field) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ProviderGenerationError(`${field} must be a non-empty string.`);
  }
  if (value.length > MAX_CONTENT_CHARS) {
    throw new ProviderGenerationError(`${field} exceeds the maximum supported length.`);
  }
  return value;
}

/** @param {unknown} value @param {string} field @returns {number} */
function requireInteger(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new ProviderGenerationError(
      `${field} must be an integer between ${minimum} and ${maximum}.`
    );
  }
  return Number(value);
}

/** @param {unknown} value @param {string} field @returns {number} */
function requireNumber(value, field, minimum, maximum) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
    throw new ProviderGenerationError(
      `${field} must be a number between ${minimum} and ${maximum}.`
    );
  }
  return value;
}

/**
 * Build a normalized generation request. Source text is not added here; callers
 * decide explicitly what may be included and under which consent setting.
 *
 * @param {{
 *   providerId: string,
 *   modelId: string,
 *   messages: Array<{role: string, content: string}>,
 *   maxTokens?: number,
 *   temperature?: number,
 *   topP?: number,
 *   stop?: string[],
 *   metadata?: Record<string, unknown>
 * }} input
 * @returns {GenerationRequest}
 */
function createGenerationRequest(input) {
  if (!input || typeof input !== 'object') {
    throw new ProviderGenerationError('A generation request object is required.');
  }
  const providerId = requireText(input.providerId, 'providerId');
  const modelId = requireText(input.modelId, 'modelId');
  if (!Array.isArray(input.messages) || input.messages.length === 0) {
    throw new ProviderGenerationError('messages must be a non-empty array.');
  }
  if (input.messages.length > MAX_MESSAGES) {
    throw new ProviderGenerationError(`messages must contain at most ${MAX_MESSAGES} entries.`);
  }

  const messages = input.messages.map((message, index) => {
    if (!message || typeof message !== 'object') {
      throw new ProviderGenerationError(`messages[${index}] must be an object.`);
    }
    if (!['system', 'user', 'assistant'].includes(message.role)) {
      throw new ProviderGenerationError(`messages[${index}].role is not supported.`);
    }
    return {
      role: message.role,
      content: requireText(message.content, `messages[${index}].content`)
    };
  });

  const stop = input.stop ?? [];
  if (!Array.isArray(stop) || stop.some((item) => typeof item !== 'string')) {
    throw new ProviderGenerationError('stop must be an array of strings.');
  }

  /** @type {Record<string, string|number|boolean>} */
  const metadata = {};
  if (input.metadata && typeof input.metadata === 'object' && !Array.isArray(input.metadata)) {
    for (const [key, value] of Object.entries(input.metadata)) {
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        metadata[key] = value;
      }
    }
  }

  const requestHash = crypto
    .createHash('sha256')
    .update(JSON.stringify({ providerId, modelId, messages, stop }))
    .digest('hex');
  const requestId = `gen-${requestHash.slice(0, 16)}`;

  return {
    providerId,
    modelId,
    messages,
    maxTokens: requireInteger(input.maxTokens ?? DEFAULT_MAX_TOKENS, 'maxTokens', 1, 32_000),
    temperature: requireNumber(input.temperature ?? DEFAULT_TEMPERATURE, 'temperature', 0, 2),
    stop: stop.slice(0, 16),
    requestId,
    requestHash,
    metadata
  };
}

/**
 * Normalize a provider response. The adapter must supply the model identity;
 * a missing identity is rejected rather than guessed.
 *
 * @param {unknown} raw
 * @param {{ providerId: string, modelId: string, requestId: string, capabilities?: readonly string[] }} context
 * @returns {GenerationResponse}
 */
function normalizeGenerationResponse(raw, context) {
  let text;
  if (typeof raw === 'string') {
    text = raw;
  } else if (raw && typeof raw === 'object') {
    const candidate = /** @type {Record<string, unknown>} */ (raw);
    if (typeof candidate.text === 'string') {
      text = candidate.text;
    } else if (typeof candidate.content === 'string') {
      text = candidate.content;
    }
  }
  if (typeof text !== 'string' || text.length === 0) {
    throw new ProviderGenerationError(
      'The provider returned no generated text.',
      context.providerId
    );
  }

  const rawUsage =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? /** @type {Record<string, unknown>} */ (raw).usage
      : undefined;
  /** @type {GenerationResponse['usage']} */
  const usage = {};
  if (rawUsage && typeof rawUsage === 'object' && !Array.isArray(rawUsage)) {
    const values = /** @type {Record<string, unknown>} */ (rawUsage);
    for (const key of ['promptTokens', 'completionTokens', 'totalTokens']) {
      if (Number.isInteger(values[key]) && Number(values[key]) >= 0) {
        usage[key] = Number(values[key]);
      }
    }
  }

  const finishReason =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? /** @type {Record<string, unknown>} */ (raw).finishReason
      : undefined;

  return {
    text,
    finishReason:
      typeof finishReason === 'string' && finishReason.length > 0 ? finishReason : 'unknown',
    usage,
    provenance: {
      providerId: requireText(context.providerId, 'providerId'),
      modelId: requireText(context.modelId, 'modelId'),
      requestId: requireText(context.requestId, 'requestId'),
      capabilities: normalizeCapabilities(context.capabilities ?? ['B', 'C'])
    }
  };
}

/**
 * Create the common model adapter interface used by concrete providers.
 *
 * @param {{
 *   providerId: string,
 *   modelId: string,
 *   capabilities?: readonly string[],
 *   infer: (request: GenerationRequest, context?: object) => Promise<unknown>|unknown
 * }} options
 */
function createGenerationAdapter(options) {
  if (!options || typeof options.infer !== 'function') {
    throw new ProviderGenerationError('A generation adapter requires an infer function.');
  }
  const providerId = requireText(options.providerId, 'providerId');
  const modelId = requireText(options.modelId, 'modelId');
  const capabilities = normalizeCapabilities(options.capabilities ?? ['B', 'C'], { providerId });
  if (!hasCapability(capabilities, 'B') || !hasCapability(capabilities, 'C')) {
    throw new ProviderGenerationError(
      'A generation adapter requires capabilities B and C.',
      providerId
    );
  }

  return {
    providerId,
    modelId,
    capabilities,
    /** @param {object} request @param {object} [context] @returns {Promise<GenerationResponse>} */
    async generate(request, context = {}) {
      const normalized = createGenerationRequest({
        ...request,
        providerId,
        modelId
      });
      const raw = await options.infer(normalized, context);
      return normalizeGenerationResponse(raw, {
        providerId,
        modelId,
        requestId: normalized.requestId,
        capabilities
      });
    }
  };
}

module.exports = {
  createGenerationRequest,
  normalizeGenerationResponse,
  createGenerationAdapter,
  DEFAULT_MAX_TOKENS
};
