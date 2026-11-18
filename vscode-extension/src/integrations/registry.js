'use strict';

const { createEditorProvider } = require('./providers/editorProvider');
const { createVscodeLanguageModelProvider } = require('./providers/vscodeLanguageModelProvider');
const { createOpenAiCompatibleProvider } = require('./providers/openAiCompatibleProvider');
const { createLocalHuggingFaceProvider } = require('./providers/localHuggingFaceProvider');
const { createExtensionApiProvider } = require('./providers/extensionApiProvider');
const { summarizeModel } = require('./compatibilityMatrix');

const PROVIDER_KINDS = Object.freeze([
  'editor',
  'vscode-language-model',
  'openai-compatible',
  'local-hugging-face',
  'extension-api'
]);

/**
 * @param {unknown} value
 * @returns {string}
 */
function normalizeKind(value) {
  return typeof value === 'string' && PROVIDER_KINDS.includes(value) ? value : 'editor';
}

/**
 * @param {unknown} error
 * @returns {{ reasonCode: string, detail: string }}
 */
function errorDetail(error) {
  return {
    reasonCode: error?.code ?? 'E_PROVIDER_DISCOVERY_FAILED',
    detail: error instanceof Error ? error.message : String(error)
  };
}

/**
 * Build providers from explicit settings. Discovery failures become
 * unavailable records; they never become silent empty capabilities.
 */
function createProviderRegistry(options = {}) {
  /** @type {Map<string, any>} */
  const providers = new Map();
  const currentSettings = () =>
    typeof options.getSettings === 'function' ? options.getSettings() ?? {} : options.settings ?? {};
  let selectedKind = normalizeKind(currentSettings().provider);
  let refreshedAt = null;

  /** @param {any} provider @param {string} kind */
  function remember(provider, kind) {
    providers.set(provider.providerId, { ...provider, kind });
    return provider;
  }

  /** @param {string} providerId @param {string} kind @param {unknown} error */
  function rememberFailure(providerId, kind, error) {
    const { reasonCode, detail } = errorDetail(error);
    return remember(
      {
        providerId,
        hosted: false,
        status: 'unavailable',
        reasonCode,
        detail,
        capabilities: [],
        limitations: [detail],
        async generate() {
          throw error;
        },
        async extractActivations() {
          throw error;
        }
      },
      kind
    );
  }

  async function refresh() {
    providers.clear();
    const settings = currentSettings();
    selectedKind = normalizeKind(settings.provider);
    remember(createEditorProvider(), 'editor');

    try {
      if (selectedKind === 'vscode-language-model') {
        await remember(
          await createVscodeLanguageModelProvider({
            vscode: options.vscode,
            selector: settings.vscodeLanguageModel?.selector ?? settings.vscodeLanguageModel
          }),
          selectedKind
        );
      } else if (selectedKind === 'openai-compatible') {
        const config = settings.openAiCompatible ?? {};
        const apiKeyVariable =
          typeof config.apiKeyEnvironmentVariable === 'string' &&
          config.apiKeyEnvironmentVariable.length > 0
            ? config.apiKeyEnvironmentVariable
            : 'BUGDHOR_LLM_API_KEY';
        const apiKey =
          typeof config.apiKey === 'string'
            ? config.apiKey
            : options.environment?.[apiKeyVariable] ?? process.env?.[apiKeyVariable];
        remember(
          createOpenAiCompatibleProvider({
            endpoint: config.endpoint,
            model: config.model,
            apiKey,
            providerId: config.providerId,
            fetch: options.fetch
          }),
          selectedKind
        );
      } else if (selectedKind === 'local-hugging-face') {
        remember(
          createLocalHuggingFaceProvider({
            modelPath: settings.localHuggingFace?.modelPath,
            generationAdapter:
              options.localGenerationAdapter ?? settings.localHuggingFace?.generationAdapter,
            activationAccessor:
              options.activationAccessor ?? settings.localHuggingFace?.activationAccessor,
            fileSystem: options.fileSystem,
            providerId: settings.localHuggingFace?.providerId
          }),
          selectedKind
        );
      } else if (selectedKind === 'extension-api') {
        await remember(
          await createExtensionApiProvider({
            vscode: options.vscode,
            manifest: settings.extensionApi?.manifest ?? options.extensionManifest,
            manifestPath: settings.extensionApi?.manifestPath,
            fileSystem: options.fileSystem,
            getExtensionApi: options.getExtensionApi,
            providerId: settings.extensionApi?.providerId
          }),
          selectedKind
        );
      }
    } catch (error) {
      rememberFailure(`${selectedKind}-unavailable`, selectedKind, error);
    }

    refreshedAt = Date.now();
    options.logger?.debug?.(
      `Bug Dhor assistant provider discovery completed for ${selectedKind}: ` +
        `${providers.size} provider record(s).`
    );
    return api();
  }

  /** @param {string} [providerId] */
  function getProvider(providerId) {
    return providers.get(providerId ?? activeProviderId());
  }

  function activeProviderId() {
    for (const [id, provider] of providers) {
      if (provider.kind === selectedKind && provider.status === 'available') {
        return id;
      }
    }
    return 'editor-monitor';
  }

  /** @returns {any[]} */
  function records() {
    return [...providers.values()].map((provider) => ({
      providerId: provider.providerId,
      kind: provider.kind,
      hosted: provider.hosted === true,
      status: provider.status,
      capabilities: [...(provider.capabilities ?? [])],
      reasonCode: provider.reasonCode ?? null,
      detail: provider.detail ?? null,
      model: provider.model ? summarizeModel(provider.model) : null,
      documentedApi: provider.documentedApi ?? null,
      limitations: [...(provider.limitations ?? [])]
    }));
  }

  function api() {
    return {
      refresh,
      records,
      getProvider,
      activeProviderId,
      getActiveProvider: () => getProvider(),
      capabilities: (providerId) => [...(getProvider(providerId)?.capabilities ?? [])],
      get selectedKind() {
        return selectedKind;
      },
      get refreshedAt() {
        return refreshedAt;
      },
      toJSON: () => ({
        selectedKind,
        refreshedAt,
        activeProvider: activeProviderId(),
        providers: records()
      })
    };
  }

  return api();
}

module.exports = { createProviderRegistry, PROVIDER_KINDS };
