'use strict';

const { createGenerationAdapter } = require('../generation');
const { readLocalHuggingFaceMetadata } = require('../modelMetadata');
const { normalizeCapabilities } = require('../capabilities');
const {
  ProviderCapabilityError,
  ProviderConfigurationError,
  ProviderInternalActivationError,
  ProviderUnsupportedCapabilityError
} = require('../errors');

/**
 * Direct local Hugging Face model provider.
 *
 * Model files and metadata are read from disk. Generation is only available
 * through an explicitly injected local adapter. Internal activations, SAE
 * features, and steering are never inferred from file contents; they require
 * real, independently validated local accessors.
 */
function createLocalHuggingFaceProvider(options) {
  const providerId = options?.providerId ?? 'local-hugging-face';
  const modelPath = options?.modelPath;
  if (typeof modelPath !== 'string' || modelPath.trim().length === 0) {
    throw new ProviderConfigurationError(
      'A local Hugging Face model path is required.',
      providerId
    );
  }

  const metadata = readLocalHuggingFaceMetadata({
    modelPath,
    fileSystem: options.fileSystem,
    providerId
  });
  const generationAdapter = options.generationAdapter;
  const activationAccessor = options.activationAccessor;
  const hasGeneration =
    typeof generationAdapter === 'function' || typeof generationAdapter?.generate === 'function';

  /** @type {string[]} */
  const capabilities = [];
  if (hasGeneration) {
    capabilities.push('B', 'C');
  }
  if (activationAccessor?.validated === true) {
    if (
      typeof activationAccessor.readActivations !== 'function' ||
      typeof activationAccessor.artifactId !== 'string' ||
      typeof activationAccessor.method !== 'string'
    ) {
      throw new ProviderCapabilityError(
        'A validated activation accessor must provide readActivations, artifactId, and method.',
        providerId,
        'D'
      );
    }
    capabilities.push('D');
    if (
      activationAccessor.saeArtifact?.validated === true &&
      typeof activationExtractor(activationAccessor) === 'function' &&
      typeof activationAccessor.saeArtifact.artifactId === 'string' &&
      typeof activationAccessor.saeArtifact.mapping === 'string'
    ) {
      capabilities.push('E');
    }
    if (
      capabilities.includes('E') &&
      activationAccessor.steeringContract?.configured === true &&
      typeof activationAccessor.steeringContract.run === 'function' &&
      typeof activationAccessor.steeringContract.effectMetric === 'string'
    ) {
      capabilities.push('F');
    }
  }
  const normalizedCapabilities = normalizeCapabilities(capabilities, { providerId });

  const limitations = [
    ...metadata.limitations,
    'A local model path does not by itself grant generation, activation, SAE, or steering access.',
    ...(hasGeneration
      ? []
      : ['No local generation adapter was injected; generation is unavailable.']),
    ...(capabilities.includes('D')
      ? []
      : ['No validated local activation accessor was provided; D/E/F remain unavailable.'])
  ];

  /** @type {ReturnType<typeof createGenerationAdapter> | undefined} */
  let adapter;
  if (hasGeneration) {
    adapter = createGenerationAdapter({
      providerId,
      modelId: metadata.id,
      capabilities: ['B', 'C'],
      infer: (request, context) =>
        typeof generationAdapter === 'function'
          ? generationAdapter(request, context)
          : generationAdapter.generate(request, context)
    });
  }

  return {
    providerId,
    kind: 'local-hugging-face',
    hosted: false,
    status: 'available',
    capabilities: normalizedCapabilities,
    model: { ...metadata, capabilities: normalizedCapabilities, limitations },
    modelPath: options.modelPath,
    documentedApi: 'local Hugging Face config files plus injected local adapters',
    limitations,
    async generate(request, context) {
      if (!adapter) {
        throw new ProviderUnsupportedCapabilityError(
          'No local generation adapter is configured.',
          providerId,
          'B'
        );
      }
      return adapter.generate(request, context);
    },
    /**
     * @param {object} request
     * @returns {Promise<object>}
     */
    async extractActivations(request) {
      if (!normalizedCapabilities.includes('D')) {
        throw new ProviderInternalActivationError(
          'No validated local activation accessor is configured.',
          providerId,
          'D'
        );
      }
      const payload = await activationAccessor.readActivations(request);
      if (!payload || typeof payload !== 'object') {
        throw new ProviderInternalActivationError(
          'The activation accessor did not return a real activation payload.',
          providerId,
          'D'
        );
      }
      return {
        providerId,
        artifactId: activationAccessor.artifactId,
        method: activationAccessor.method,
        payload
      };
    }
  };
}

/** @param {any} accessor */
function activationExtractor(accessor) {
  return accessor?.saeArtifact?.extractFeatures;
}

module.exports = { createLocalHuggingFaceProvider };
