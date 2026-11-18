'use strict';

const crypto = require('node:crypto');
const { hasCapability } = require('./capabilities');
const { ProviderUnsupportedCapabilityError } = require('./errors');

const MAX_OBSERVATIONS = 100;

/** @param {string} text */
function hashText(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

/**
 * Editor-facing hooks for the assisted-analysis workflow.
 *
 * These hooks record provenance and capability status only. They never create
 * findings, infer an assistant/model from an edit, or simulate model internals.
 * Vulnerability diagnostics continue to come exclusively from validated
 * backend scan results.
 */
class SecurityHooks {
  /**
   * @param {{
   *   registry: ReturnType<import('./registry').createProviderRegistry>,
   *   logger?: import('../logging/output').Logger,
   *   settings?: { sae?: { enabled?: boolean }, counterfactual?: { enabled?: boolean } }
   * }} dependencies
   */
  constructor({ registry, logger, settings } = {}) {
    if (!registry || typeof registry.getProvider !== 'function') {
      throw new TypeError('SecurityHooks requires a provider registry.');
    }
    this.registry = registry;
    this.logger = logger;
    this.settings = settings ?? {};
    /** @type {any[]} */
    this.observations = [];
    /** @type {{ sae: any|null, counterfactual: any|null }} */
    this.optionalProviders = { sae: null, counterfactual: null };
  }

  /** @param {object} settings */
  updateSettings(settings) {
    this.settings = settings ?? {};
  }

  /**
   * Called by the realtime monitor before every scan of a changed document.
   *
   * @param {{ uri?: string, version?: number, ranges?: unknown[], reason?: string }} event
   */
  observeChange(event) {
    const provider = this.registry.getProvider('editor-monitor');
    const observation = Object.freeze({
      type: 'editor_change',
      providerId: 'editor-monitor',
      capability: 'A',
      uri: typeof event?.uri === 'string' ? event.uri : null,
      version: Number.isInteger(event?.version) ? event.version : null,
      rangeCount: Array.isArray(event?.ranges) ? event.ranges.length : 0,
      reason: typeof event?.reason === 'string' ? event.reason : 'unknown',
      origin: 'document_event',
      authorAttribution: 'none',
      modelAttribution: 'none',
      at: Date.now()
    });
    this.remember(observation);
    return {
      ...observation,
      available: provider?.status === 'available',
      capabilities: [...(provider?.capabilities ?? [])]
    };
  }

  /**
   * @param {string} providerId
   * @param {{ requestId?: string, requestHash?: string, modelId?: string, metadata?: object }} request
   */
  observeGenerationRequest(providerId, request) {
    const provider = this.requireCapability(providerId, 'B', 'generation request access');
    const observation = Object.freeze({
      type: 'generation_request',
      providerId,
      capability: 'B',
      requestId: typeof request?.requestId === 'string' ? request.requestId : null,
      requestHash: typeof request?.requestHash === 'string' ? request.requestHash : null,
      modelId: typeof request?.modelId === 'string' ? request.modelId : provider.model?.id ?? null,
      at: Date.now()
    });
    this.remember(observation);
    return observation;
  }

  /**
   * @param {string} providerId
   * @param {{ requestId?: string, text?: string, finishReason?: string, provenance?: object }} response
   */
  observeGenerationResponse(providerId, response) {
    this.requireCapability(providerId, 'C', 'generation response access');
    const observation = Object.freeze({
      type: 'generation_response',
      providerId,
      capability: 'C',
      requestId: typeof response?.requestId === 'string' ? response.requestId : null,
      responseHash: typeof response?.text === 'string' ? hashText(response.text) : null,
      finishReason: typeof response?.finishReason === 'string' ? response.finishReason : 'unknown',
      modelId:
        typeof response?.provenance?.modelId === 'string' ? response.provenance.modelId : null,
      at: Date.now()
    });
    this.remember(observation);
    return observation;
  }

  /**
   * Wrap a provider's generate method so B/C access is recorded without
   * retaining prompt or generated source text.
   *
   * @param {string} providerId
   * @param {(request: object, context?: object) => Promise<any>} generate
   */
  wrapGeneration(providerId, generate) {
    if (typeof generate !== 'function') {
      throw new TypeError('A generation function is required.');
    }
    return async (request, context) => {
      this.observeGenerationRequest(providerId, request);
      try {
        const response = await generate(request, context);
        this.observeGenerationResponse(providerId, response);
        return response;
      } catch (error) {
        this.remember(
          Object.freeze({
            type: 'generation_error',
            providerId,
            capability: 'C',
            code: error?.code ?? 'E_GENERATION_FAILED',
            at: Date.now()
          })
        );
        throw error;
      }
    };
  }

  /**
   * Attach a real SAE provider only when the active integration has validated
   * D and E capabilities. Anything else stays unavailable.
   *
   * @param {{ providerId?: string, artifactId?: string, extract: Function }} provider
   */
  attachSaeProvider(provider) {
    if (this.settings.sae?.enabled !== true) {
      return { status: 'skipped', reasonCode: 'E_SAE_NOT_ENABLED', provider: null };
    }
    const capabilities = this.registry.capabilities();
    if (!hasCapability(capabilities, 'D') || !hasCapability(capabilities, 'E')) {
      return { status: 'unavailable', reasonCode: 'E_SAE_CAPABILITY_REQUIRED', provider: null };
    }
    if (!provider || typeof provider.extract !== 'function' || !provider.artifactId) {
      return { status: 'unavailable', reasonCode: 'E_SAE_PROVIDER_INVALID', provider: null };
    }
    this.optionalProviders.sae = provider;
    return { status: 'available', reasonCode: null, provider };
  }

  /**
   * Attach a real counterfactual provider only when D, E, and F are validated.
   *
   * @param {{ providerId?: string, run: Function }} provider
   */
  attachCounterfactualProvider(provider) {
    if (this.settings.counterfactual?.enabled !== true) {
      return { status: 'skipped', reasonCode: 'E_COUNTERFACTUAL_NOT_ENABLED', provider: null };
    }
    const capabilities = this.registry.capabilities();
    if (
      !hasCapability(capabilities, 'D') ||
      !hasCapability(capabilities, 'E') ||
      !hasCapability(capabilities, 'F')
    ) {
      return {
        status: 'unavailable',
        reasonCode: 'E_COUNTERFACTUAL_CAPABILITY_REQUIRED',
        provider: null
      };
    }
    if (!provider || typeof provider.run !== 'function') {
      return { status: 'unavailable', reasonCode: 'E_COUNTERFACTUAL_PROVIDER_INVALID', provider: null };
    }
    this.optionalProviders.counterfactual = provider;
    return { status: 'available', reasonCode: null, provider };
  }

  /** @param {string} providerId @param {string} capability @param {string} label */
  requireCapability(providerId, capability, label) {
    const provider = this.registry.getProvider(providerId);
    if (!provider || provider.status !== 'available') {
      throw new ProviderUnsupportedCapabilityError(
        `Provider ${providerId} is unavailable; ${label} cannot be observed.`,
        providerId,
        capability
      );
    }
    if (!hasCapability(provider.capabilities ?? [], capability)) {
      throw new ProviderUnsupportedCapabilityError(
        `Provider ${providerId} does not expose ${label}.`,
        providerId,
        capability
      );
    }
    return provider;
  }

  /** @param {object} observation */
  remember(observation) {
    this.observations.push(observation);
    if (this.observations.length > MAX_OBSERVATIONS) {
      this.observations.shift();
    }
  }

  /** Observability for tests and the dashboard. Contains metadata only. */
  getStatus() {
    const active = this.registry.getProvider();
    const counts = {};
    for (const item of this.observations) {
      counts[item.type] = (counts[item.type] ?? 0) + 1;
    }
    return {
      activeProvider: active?.providerId ?? 'editor-monitor',
      capabilities: [...(active?.capabilities ?? [])],
      observationCounts: counts,
      sae: {
        status: this.optionalProviders.sae ? 'available' : 'unavailable',
        reasonCode: this.optionalProviders.sae ? null : 'E_SAE_PROVIDER_REQUIRED'
      },
      counterfactual: {
        status: this.optionalProviders.counterfactual ? 'available' : 'unavailable',
        reasonCode: this.optionalProviders.counterfactual
          ? null
          : 'E_COUNTERFACTUAL_PROVIDER_REQUIRED'
      },
      authorAttribution: 'none',
      findingsPublishedByHooks: 0
    };
  }
}

module.exports = { SecurityHooks, hashText };
