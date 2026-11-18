'use strict';

/**
 * Provider-specific errors used by the assistant integration layer.
 *
 * Every error keeps the provider identity and a stable machine-readable code.
 * They never contain source text so they are safe to log and display.
 */

class ProviderError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {{
   *   providerId?: string,
   *   capability?: string,
   *   retryable?: boolean,
   *   cause?: unknown
   * }} [options]
   */
  constructor(message, code, options = {}) {
    super(message);
    this.name = 'ProviderError';
    this.code = code;
    this.providerId = options.providerId;
    this.capability = options.capability;
    this.retryable = options.retryable === true;
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }

  /** @returns {Record<string, unknown>} */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      providerId: this.providerId ?? null,
      capability: this.capability ?? null,
      retryable: this.retryable
    };
  }
}

class ProviderConfigurationError extends ProviderError {
  /** @param {string} message @param {string} [providerId] @param {unknown} [cause] */
  constructor(message, providerId, cause) {
    super(message, 'E_PROVIDER_CONFIGURATION', { providerId, cause });
    this.name = 'ProviderConfigurationError';
  }
}

class ProviderCapabilityError extends ProviderError {
  /**
   * @param {string} message
   * @param {string} [providerId]
   * @param {string} [capability]
   */
  constructor(message, providerId, capability) {
    super(message, 'E_PROVIDER_CAPABILITY', { providerId, capability });
    this.name = 'ProviderCapabilityError';
  }
}

class ProviderUnsupportedCapabilityError extends ProviderError {
  /**
   * @param {string} message
   * @param {string} [providerId]
   * @param {string} [capability]
   */
  constructor(message, providerId, capability) {
    super(message, 'E_UNSUPPORTED_CAPABILITY', { providerId, capability });
    this.name = 'ProviderUnsupportedCapabilityError';
  }
}

class ProviderGenerationError extends ProviderError {
  /**
   * @param {string} message
   * @param {string} [providerId]
   * @param {string} [code]
   * @param {unknown} [cause]
   */
  constructor(message, providerId, code = 'E_GENERATION_FAILED', cause) {
    super(message, code, { providerId, capability: 'C', cause });
    this.name = 'ProviderGenerationError';
  }
}

class ProviderTransportError extends ProviderGenerationError {
  /** @param {string} message @param {string} [providerId] @param {unknown} [cause] */
  constructor(message, providerId, cause) {
    super(message, providerId, 'E_PROVIDER_TRANSPORT', cause);
    this.name = 'ProviderTransportError';
    this.retryable = true;
  }
}

class ProviderTimeoutError extends ProviderGenerationError {
  /** @param {string} message @param {string} [providerId] @param {unknown} [cause] */
  constructor(message, providerId, cause) {
    super(message, providerId, 'E_PROVIDER_TIMEOUT', cause);
    this.name = 'ProviderTimeoutError';
    this.retryable = true;
  }
}

class ProviderAuthenticationError extends ProviderGenerationError {
  /** @param {string} message @param {string} [providerId] */
  constructor(message, providerId) {
    super(message, providerId, 'E_PROVIDER_AUTHENTICATION');
    this.name = 'ProviderAuthenticationError';
  }
}

class ProviderRateLimitError extends ProviderGenerationError {
  /** @param {string} message @param {string} [providerId] @param {unknown} [cause] */
  constructor(message, providerId, cause) {
    super(message, providerId, 'E_PROVIDER_RATE_LIMIT', cause);
    this.name = 'ProviderRateLimitError';
    this.retryable = true;
  }
}

class ProviderInternalActivationError extends ProviderError {
  /**
   * @param {string} message
   * @param {string} [providerId]
   * @param {string} [capability]
   */
  constructor(message, providerId, capability = 'D') {
    super(message, 'E_INTERNAL_ACTIVATION_UNAVAILABLE', { providerId, capability });
    this.name = 'ProviderInternalActivationError';
  }
}

module.exports = {
  ProviderError,
  ProviderConfigurationError,
  ProviderCapabilityError,
  ProviderUnsupportedCapabilityError,
  ProviderGenerationError,
  ProviderTransportError,
  ProviderTimeoutError,
  ProviderAuthenticationError,
  ProviderRateLimitError,
  ProviderInternalActivationError
};
