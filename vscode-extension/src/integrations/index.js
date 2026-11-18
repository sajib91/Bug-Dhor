'use strict';

const {
  CAPABILITIES,
  CAPABILITY_DEFINITIONS,
  validateCapabilities,
  normalizeCapabilities,
  hasCapability
} = require('./capabilities');
const {
  createGenerationRequest,
  normalizeGenerationResponse,
  createGenerationAdapter
} = require('./generation');
const { createModelMetadata, readLocalHuggingFaceMetadata } = require('./modelMetadata');
const {
  PROVIDER_COMPATIBILITY,
  toCompatibilityMatrix,
  renderCompatibilityMatrixMarkdown,
  summarizeModel
} = require('./compatibilityMatrix');
const { createProviderRegistry, PROVIDER_KINDS } = require('./registry');
const { SecurityHooks } = require('./securityHooks');
const { createEditorProvider } = require('./providers/editorProvider');
const { createVscodeLanguageModelProvider } = require('./providers/vscodeLanguageModelProvider');
const { createOpenAiCompatibleProvider } = require('./providers/openAiCompatibleProvider');
const { createLocalHuggingFaceProvider } = require('./providers/localHuggingFaceProvider');
const {
  createExtensionApiProvider,
  validateExtensionManifest
} = require('./providers/extensionApiProvider');
const errors = require('./errors');

module.exports = {
  CAPABILITIES,
  CAPABILITY_DEFINITIONS,
  validateCapabilities,
  normalizeCapabilities,
  hasCapability,
  createGenerationRequest,
  normalizeGenerationResponse,
  createGenerationAdapter,
  createModelMetadata,
  readLocalHuggingFaceMetadata,
  PROVIDER_COMPATIBILITY,
  toCompatibilityMatrix,
  renderCompatibilityMatrixMarkdown,
  summarizeModel,
  createProviderRegistry,
  PROVIDER_KINDS,
  SecurityHooks,
  createEditorProvider,
  createVscodeLanguageModelProvider,
  createOpenAiCompatibleProvider,
  createLocalHuggingFaceProvider,
  createExtensionApiProvider,
  validateExtensionManifest,
  errors
};
