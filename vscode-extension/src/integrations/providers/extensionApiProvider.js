'use strict';

const path = require('node:path');
const nodeFs = require('node:fs');
const { createGenerationAdapter } = require('../generation');
const { createModelMetadata } = require('../modelMetadata');
const { normalizeCapabilities } = require('../capabilities');
const {
  ProviderConfigurationError,
  ProviderInternalActivationError,
  ProviderUnsupportedCapabilityError
} = require('../errors');

const DOCUMENTED_API = 'official extension API declared by a local capability manifest';

/** @param {unknown} value @param {string} field @returns {string} */
function requiredString(value, field, providerId) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ProviderConfigurationError(`Extension manifest ${field} must be a non-empty string.`, providerId);
  }
  return value.trim();
}

/** @param {unknown} value @returns {string} */
function documentationUrl(value, providerId) {
  const text = requiredString(value, 'documentationUrl', providerId);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new ProviderConfigurationError(
      'Extension manifest documentationUrl must be an absolute URL.',
      providerId
    );
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ProviderConfigurationError(
      'Extension manifest documentationUrl must use http: or https:.',
      providerId
    );
  }
  return text;
}

/**
 * Validate an explicit, official API manifest. Undocumented or reverse-
 * engineered access is rejected outright.
 *
 * @param {Record<string, unknown>} raw
 * @param {string} providerId
 */
function validateExtensionManifest(raw, providerId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ProviderConfigurationError('An extension API manifest object is required.', providerId);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*$/.test(raw.extensionId ?? '')) {
    throw new ProviderConfigurationError(
      'Extension manifest extensionId must use publisher.name form.',
      providerId
    );
  }
  const manifest = {
    extensionId: requiredString(raw.extensionId, 'extensionId', providerId),
    apiVersion: requiredString(raw.apiVersion, 'apiVersion', providerId),
    documentationUrl: documentationUrl(raw.documentationUrl, providerId),
    modelId:
      raw.modelId === undefined || raw.modelId === null
        ? undefined
        : requiredString(raw.modelId, 'modelId', providerId),
    hosted: raw.hosted !== false,
    generationMethod:
      raw.generationMethod === undefined || raw.generationMethod === null
        ? undefined
        : requiredString(raw.generationMethod, 'generationMethod', providerId),
    internalActivationContract:
      raw.internalActivationContract && typeof raw.internalActivationContract === 'object'
        ? {
            method: requiredString(
              raw.internalActivationContract.method,
              'internalActivationContract.method',
              providerId
            ),
            documentationUrl: documentationUrl(
              raw.internalActivationContract.documentationUrl,
              providerId
            ),
            validationMethod: requiredString(
              raw.internalActivationContract.validationMethod,
              'internalActivationContract.validationMethod',
              providerId
            ),
            artifactId:
              raw.internalActivationContract.artifactId === undefined ||
              raw.internalActivationContract.artifactId === null
                ? undefined
                : requiredString(
                    raw.internalActivationContract.artifactId,
                    'internalActivationContract.artifactId',
                    providerId
                  )
          }
        : undefined,
    capabilities: raw.capabilities
  };
  return manifest;
}

/**
 * @param {{
 *   vscode?: import('vscode'),
 *   manifest?: object,
 *   manifestPath?: string,
 *   fileSystem?: typeof nodeFs,
 *   getExtensionApi?: () => unknown|Promise<unknown>,
 *   providerId?: string
 * }} options
 */
async function createExtensionApiProvider(options) {
  const providerId = options?.providerId ?? 'extension-api';
  let rawManifest = options?.manifest;
  if (!rawManifest && typeof options?.manifestPath === 'string' && options.manifestPath.length > 0) {
    const fileSystem = options.fileSystem ?? nodeFs;
    try {
      rawManifest = JSON.parse(fileSystem.readFileSync(path.resolve(options.manifestPath), 'utf8'));
    } catch (error) {
      return unavailableProvider(
        providerId,
        'E_MANIFEST_UNREADABLE',
        'The extension API manifest could not be read or parsed.',
        error
      );
    }
  }
  if (!rawManifest) {
    return unavailableProvider(
      providerId,
      'E_MANIFEST_REQUIRED',
      'An official extension API manifest is required.'
    );
  }

  /** @type {ReturnType<typeof validateExtensionManifest>} */
  let manifest;
  try {
    manifest = validateExtensionManifest(rawManifest, providerId);
  } catch (error) {
    return unavailableProvider(
      providerId,
      error instanceof ProviderConfigurationError ? error.code : 'E_MANIFEST_INVALID',
      error instanceof Error ? error.message : String(error),
      error
    );
  }

  let api = options?.getExtensionApi ? await options.getExtensionApi() : undefined;
  if (api === undefined && options?.vscode?.extensions?.getExtension) {
    const extension = options.vscode.extensions.getExtension(manifest.extensionId);
    if (!extension) {
      return unavailableProvider(
        providerId,
        'E_EXTENSION_NOT_INSTALLED',
        `The official extension ${manifest.extensionId} is not installed.`
      );
    }
    api = extension.exports ?? (await extension.activate?.());
  }
  if (!api || typeof api !== 'object') {
    return unavailableProvider(
      providerId,
      'E_EXTENSION_API_UNAVAILABLE',
      `The official extension ${manifest.extensionId} did not expose an API object.`
    );
  }

  let declared;
  try {
    declared = normalizeCapabilities(manifest.capabilities ?? [], { providerId });
  } catch (error) {
    return unavailableProvider(
      providerId,
      'E_CAPABILITIES_INVALID',
      error instanceof Error ? error.message : String(error),
      error
    );
  }
  if (manifest.hosted && declared.some((capability) => ['D', 'E', 'F'].includes(capability))) {
    return unavailableProvider(
      providerId,
      'E_HOSTED_INTERNALS_FORBIDDEN',
      'Hosted extensions cannot expose internal activations, SAE features, or steering.'
    );
  }
  /** @type {string[]} */
  const capabilities = [];
  if (declared.includes('B') || declared.includes('C')) {
    if (!manifest.generationMethod || typeof api[manifest.generationMethod] !== 'function') {
      return unavailableProvider(
        providerId,
        'E_GENERATION_METHOD_MISSING',
        'The manifest generation method is not exposed by the official extension API.'
      );
    }
    capabilities.push('B', 'C');
  }
  if (declared.some((capability) => ['D', 'E', 'F'].includes(capability))) {
    const contract = manifest.internalActivationContract;
    if (!contract || typeof api[contract.method] !== 'function') {
      return unavailableProvider(
        providerId,
        'E_ACTIVATION_CONTRACT_MISSING',
        'The manifest internal activation method is not exposed by the official extension API.'
      );
    }
    capabilities.push(...declared.filter((capability) => ['D', 'E', 'F'].includes(capability)));
  }

  const normalizedCapabilities = normalizeCapabilities(capabilities, { providerId });
  const modelId = manifest.modelId ?? manifest.extensionId;
  const metadata = createModelMetadata({
    id: modelId,
    displayName: manifest.extensionId,
    source: 'extension-api',
    capabilities: normalizedCapabilities,
    limitations: [
      'Only the method names explicitly listed in the official manifest are used.',
      'No undocumented or reverse-engineered extension interface is accessed.'
    ]
  });

  /** @type {ReturnType<typeof createGenerationAdapter> | undefined} */
  let adapter;
  if (normalizedCapabilities.includes('B') && normalizedCapabilities.includes('C')) {
    adapter = createGenerationAdapter({
      providerId,
      modelId,
      capabilities: ['B', 'C'],
      infer: (request, context) => api[manifest.generationMethod](request, context)
    });
  }

  const contract = manifest.internalActivationContract;
  return {
    providerId,
    kind: 'extension-api',
    hosted: manifest.hosted,
    status: 'available',
    capabilities: normalizedCapabilities,
    model: metadata,
    documentedApi: `${DOCUMENTED_API} (${manifest.documentationUrl}, apiVersion ${manifest.apiVersion})`,
    manifest: {
      extensionId: manifest.extensionId,
      apiVersion: manifest.apiVersion,
      documentationUrl: manifest.documentationUrl
    },
    limitations: [...metadata.limitations],
    async generate(request, context) {
      if (!adapter) {
        throw new ProviderUnsupportedCapabilityError(
          'The manifest does not expose generation.',
          providerId,
          'B'
        );
      }
      return adapter.generate(request, context);
    },
    async extractActivations(request) {
      if (!normalizedCapabilities.includes('D') || !contract) {
        throw new ProviderInternalActivationError(
          'No validated internal activation contract is configured.',
          providerId,
          'D'
        );
      }
      const payload = await api[contract.method](request);
      if (!payload || typeof payload !== 'object') {
        throw new ProviderInternalActivationError(
          'The official activation method returned no real activation payload.',
          providerId,
          'D'
        );
      }
      return {
        providerId,
        artifactId: contract.artifactId ?? null,
        validationMethod: contract.validationMethod,
        payload
      };
    }
  };
}

/**
 * @param {string} providerId
 * @param {string} reasonCode
 * @param {string} detail
 * @param {unknown} [cause]
 */
function unavailableProvider(providerId, reasonCode, detail, cause) {
  return {
    providerId,
    kind: 'extension-api',
    hosted: true,
    status: 'unavailable',
    reasonCode,
    detail,
    cause,
    capabilities: [],
    model: undefined,
    limitations: [detail],
    async generate() {
      throw new ProviderUnsupportedCapabilityError(detail, providerId, 'B');
    },
    async extractActivations() {
      throw new ProviderInternalActivationError(detail, providerId, 'D');
    }
  };
}

module.exports = {
  createExtensionApiProvider,
  validateExtensionManifest,
  DOCUMENTED_API
};
