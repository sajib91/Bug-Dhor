'use strict';

const { createGenerationAdapter } = require('../generation');
const { createModelMetadata } = require('../modelMetadata');
const { normalizeCapabilities } = require('../capabilities');
const {
  ProviderAuthenticationError,
  ProviderConfigurationError,
  ProviderGenerationError,
  ProviderRateLimitError,
  ProviderTimeoutError,
  ProviderTransportError,
  ProviderUnsupportedCapabilityError
} = require('../errors');

const DOCUMENTED_API = 'OpenAI-compatible POST /chat/completions';

/**
 * @param {string} endpoint
 * @returns {string}
 */
function normalizeEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.trim().length === 0) {
    throw new ProviderConfigurationError('An OpenAI-compatible endpoint is required.');
  }
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new ProviderConfigurationError('The OpenAI-compatible endpoint must be a valid URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ProviderConfigurationError('The endpoint must use http: or https:.');
  }
  if (parsed.username || parsed.password) {
    throw new ProviderConfigurationError('The endpoint must not embed credentials.');
  }
  const base = parsed.pathname.replace(/\/+$/, '');
  const path = base.endsWith('/chat/completions') ? `${base}` : `${base}/chat/completions`;
  return `${parsed.origin}${path}`;
}

/**
 * @param {{
 *   endpoint: string,
 *   model: string,
 *   apiKey?: string,
 *   providerId?: string,
 *   fetch?: typeof globalThis.fetch
 * }} options
 */
function createOpenAiCompatibleProvider(options) {
  const providerId = options?.providerId ?? 'openai-compatible';
  if (!options || typeof options.model !== 'string' || options.model.trim().length === 0) {
    throw new ProviderConfigurationError(
      'An OpenAI-compatible model name is required.',
      providerId
    );
  }
  const url = normalizeEndpoint(options.endpoint);
  const fetchImpl = typeof options.fetch === 'function' ? options.fetch : globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new ProviderConfigurationError(
      'A fetch implementation is required for an OpenAI-compatible provider.',
      providerId
    );
  }
  const capabilities = normalizeCapabilities(['B', 'C'], { hosted: true, providerId });
  const metadata = createModelMetadata({
    id: options.model.trim(),
    displayName: options.model.trim(),
    source: 'openai-compatible',
    capabilities,
    limitations: [
      'A hosted endpoint cannot expose model internals, SAE features, or steering.',
      'Prompt and response access is limited to the configured API contract.'
    ]
  });

  const adapter = createGenerationAdapter({
    providerId,
    modelId: metadata.id,
    capabilities,
    infer: async (request, context = {}) => {
      const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
      const signal = controller?.signal;
      const token = context.token;
      if (token && typeof token.onCancellationRequested === 'function') {
        token.onCancellationRequested(() => controller?.abort());
      }
      const timeoutMs =
        Number.isInteger(context.timeoutMs) && context.timeoutMs > 0 ? context.timeoutMs : 30_000;
      /** @type {ReturnType<typeof setTimeout> | undefined} */
      let timer;
      if (controller && typeof setTimeout === 'function') {
        timer = setTimeout(() => controller.abort(), timeoutMs);
      }

      const headers = { 'content-type': 'application/json' };
      if (typeof options.apiKey === 'string' && options.apiKey.length > 0) {
        headers.authorization = `Bearer ${options.apiKey}`;
      }
      const body = {
        model: metadata.id,
        messages: request.messages.map(({ role, content }) => ({ role, content })),
        max_tokens: request.maxTokens,
        temperature: request.temperature,
        stream: false
      };
      if (request.stop.length > 0) {
        body.stop = request.stop;
      }

      let response;
      try {
        response = await fetchImpl(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
          ...(signal ? { signal } : {})
        });
      } catch (error) {
        if (error?.name === 'AbortError' || controller?.signal?.aborted) {
          throw new ProviderTimeoutError(
            'The OpenAI-compatible request timed out.',
            providerId,
            error
          );
        }
        throw new ProviderTransportError(
          `The OpenAI-compatible request failed: ${error instanceof Error ? error.message : String(error)}`,
          providerId,
          error
        );
      } finally {
        if (timer) {
          clearTimeout(timer);
        }
      }

      if (response.status === 401 || response.status === 403) {
        throw new ProviderAuthenticationError(
          'The OpenAI-compatible endpoint rejected the configured credentials.',
          providerId
        );
      }
      if (response.status === 429) {
        throw new ProviderRateLimitError(
          'The OpenAI-compatible endpoint rate-limited the request.',
          providerId
        );
      }
      if (!response.ok) {
        throw new ProviderGenerationError(
          `The OpenAI-compatible endpoint returned HTTP ${response.status}.`,
          providerId,
          'E_PROVIDER_TRANSPORT'
        );
      }

      /** @type {any} */
      let payload;
      try {
        payload = await response.json();
      } catch (error) {
        throw new ProviderTransportError(
          'The OpenAI-compatible endpoint returned invalid JSON.',
          providerId,
          error
        );
      }
      const choice = Array.isArray(payload?.choices) ? payload.choices[0] : undefined;
      const text = choice?.message?.content ?? choice?.text;
      if (typeof text !== 'string') {
        throw new ProviderGenerationError(
          'The OpenAI-compatible response did not contain generated text.',
          providerId
        );
      }
      return {
        text,
        finishReason: typeof choice.finish_reason === 'string' ? choice.finish_reason : 'stop',
        usage: payload?.usage
          ? {
              promptTokens: payload.usage.prompt_tokens,
              completionTokens: payload.usage.completion_tokens,
              totalTokens: payload.usage.total_tokens
            }
          : undefined
      };
    }
  });

  return {
    providerId,
    kind: 'openai-compatible',
    hosted: true,
    status: 'available',
    capabilities,
    model: metadata,
    documentedApi: DOCUMENTED_API,
    limitations: [...metadata.limitations],
    generate: adapter.generate,
    async extractActivations() {
      throw new ProviderUnsupportedCapabilityError(
        'A hosted OpenAI-compatible endpoint cannot expose internal activations.',
        providerId,
        'D'
      );
    }
  };
}

module.exports = { createOpenAiCompatibleProvider, normalizeEndpoint, DOCUMENTED_API };
