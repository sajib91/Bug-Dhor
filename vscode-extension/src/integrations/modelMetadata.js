'use strict';

const path = require('node:path');
const nodeFs = require('node:fs');
const { ProviderConfigurationError } = require('./errors');
const { normalizeCapabilities } = require('./capabilities');

/**
 * @param {{
 *   id: string,
 *   displayName: string,
 *   source: 'local'|'vscode-lm'|'openai-compatible'|'extension-api'|'editor',
 *   family?: string,
 *   version?: string,
 *   parameters?: string,
 *   capabilities?: readonly string[],
 *   limitations?: string[]
 * }} input
 */
function createModelMetadata(input) {
  if (!input || typeof input.id !== 'string' || input.id.trim().length === 0) {
    throw new ProviderConfigurationError('Model metadata requires a non-empty id.');
  }
  if (typeof input.displayName !== 'string' || input.displayName.trim().length === 0) {
    throw new ProviderConfigurationError('Model metadata requires a non-empty displayName.');
  }
  return Object.freeze({
    id: input.id.trim(),
    displayName: input.displayName.trim(),
    source: input.source,
    family: typeof input.family === 'string' ? input.family : undefined,
    version: typeof input.version === 'string' ? input.version : undefined,
    parameters: typeof input.parameters === 'string' ? input.parameters : undefined,
    capabilities: normalizeCapabilities(input.capabilities ?? []),
    limitations: Object.freeze(
      Array.isArray(input.limitations) ? input.limitations.filter((item) => typeof item === 'string') : []
    )
  });
}

/**
 * Read local Hugging Face model configuration. Only public config files are
 * read; no weights are loaded and no activations are inferred from metadata.
 *
 * @param {{ modelPath: string, fileSystem?: typeof nodeFs, providerId?: string }} options
 */
function readLocalHuggingFaceMetadata(options) {
  if (!options || typeof options.modelPath !== 'string' || options.modelPath.trim().length === 0) {
    throw new ProviderConfigurationError(
      'A local Hugging Face model path is required.',
      options?.providerId
    );
  }
  const modelPath = path.resolve(options.modelPath);
  const fileSystem = options.fileSystem ?? nodeFs;
  const configPath = path.join(modelPath, 'config.json');
  let rawConfig;
  try {
    rawConfig = fileSystem.readFileSync(configPath, 'utf8');
  } catch (error) {
    throw new ProviderConfigurationError(
      'The local Hugging Face model has no readable config.json.',
      options.providerId,
      error
    );
  }

  /** @type {Record<string, unknown>} */
  let config;
  try {
    config = JSON.parse(rawConfig);
  } catch (error) {
    throw new ProviderConfigurationError(
      'The local Hugging Face config.json is not valid JSON.',
      options.providerId,
      error
    );
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new ProviderConfigurationError(
      'The local Hugging Face config.json must be an object.',
      options.providerId
    );
  }

  const family = typeof config.model_type === 'string' ? config.model_type : undefined;
  const version =
    typeof config.transformers_version === 'string' ? config.transformers_version : undefined;
  const layers = Number.isInteger(config.num_hidden_layers)
    ? Number(config.num_hidden_layers)
    : undefined;
  const hidden = Number.isInteger(config.hidden_size) ? Number(config.hidden_size) : undefined;

  return createModelMetadata({
    id: `local-hf:${path.basename(modelPath)}`,
    displayName: path.basename(modelPath),
    source: 'local',
    family,
    version,
    parameters: layers && hidden ? `${layers} layers x ${hidden} hidden` : undefined,
    capabilities: [],
    limitations: [
      'Model metadata does not prove generation access or internal activation access.',
      'Architectures and parameter counts are taken from the local config file only.'
    ]
  });
}

/** @param {readonly string[]} ids @returns {string[]} */
function uniqueIds(ids) {
  return [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0))];
}

module.exports = {
  createModelMetadata,
  readLocalHuggingFaceMetadata,
  uniqueIds
};
