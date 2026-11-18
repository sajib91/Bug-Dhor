'use strict';

const { createGenerationAdapter } = require('../generation');
const { createModelMetadata } = require('../modelMetadata');
const { normalizeCapabilities } = require('../capabilities');
const {
  ProviderGenerationError,
  ProviderUnsupportedCapabilityError
} = require('../errors');

const DOCUMENTED_API = 'vscode.lm.selectChatModels + LanguageModelChat.sendRequest';

/**
 * Discover a language model through the documented VS Code Language Model API.
 * Capabilities B and C are reported only when an actual model was selected.
 * D/E/F are never claimed for a hosted model.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   selector?: { vendor?: string, family?: string, id?: string, version?: string },
 *   providerId?: string
 * }} options
 */
async function createVscodeLanguageModelProvider(options) {
  const providerId = options?.providerId ?? 'vscode-language-model';
  const vscode = options?.vscode;
  if (!vscode?.lm || typeof vscode.lm.selectChatModels !== 'function') {
    return unavailableProvider(
      providerId,
      'E_VSCODE_LM_API_UNAVAILABLE',
      'This VS Code version does not expose the documented Language Model API.'
    );
  }

  /** @type {import('vscode').LanguageModelChat[]} */
  let models;
  try {
    models = await vscode.lm.selectChatModels(options.selector ?? {});
  } catch (error) {
    return unavailableProvider(
      providerId,
      'E_VSCODE_LM_SELECTION_FAILED',
      `Language model selection failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (!Array.isArray(models) || models.length === 0) {
    return unavailableProvider(
      providerId,
      'E_VSCODE_LM_NO_MODEL',
      'No language model matched the configured selector.'
    );
  }

  const model = models[0];
  if (
    typeof model !== 'object' ||
    model === null ||
    typeof model.sendRequest !== 'function' ||
    typeof model.id !== 'string'
  ) {
    return unavailableProvider(
      providerId,
      'E_VSCODE_LM_INVALID_MODEL',
      'The selected object does not implement the documented LanguageModelChat surface.'
    );
  }

  const capabilities = normalizeCapabilities(['B', 'C'], { hosted: true, providerId });
  const metadata = createModelMetadata({
    id: model.id,
    displayName: model.name || model.id,
    source: 'vscode-lm',
    family: typeof model.family === 'string' ? model.family : undefined,
    version: typeof model.version === 'string' ? model.version : undefined,
    capabilities,
    limitations: [
      'The VS Code Language Model API exposes prompts and responses, not model internals.',
      'Consent and availability are controlled by the editor and may change at any time.'
    ]
  });

  const adapter = createGenerationAdapter({
    providerId,
    modelId: model.id,
    capabilities,
    infer: async (request, context = {}) => {
      const Message = vscode.LanguageModelChatMessage;
      if (!Message || typeof Message.User !== 'function' || typeof Message.Assistant !== 'function') {
        throw new ProviderGenerationError(
          'The documented LanguageModelChatMessage constructors are unavailable.',
          providerId
        );
      }
      // The VS Code Language Model API does not support system messages; fold
      // them into the first user message instead of dropping instructions.
      const messages = [];
      let pendingSystem = '';
      for (const item of request.messages) {
        if (item.role === 'system') {
          pendingSystem += `${item.content}\n`;
          continue;
        }
        const content = pendingSystem + item.content;
        pendingSystem = '';
        messages.push(
          item.role === 'assistant' ? Message.Assistant(content) : Message.User(content)
        );
      }
      if (pendingSystem) {
        messages.push(Message.User(pendingSystem.trimEnd()));
      }

      const response = await model.sendRequest(messages, {}, context.token);
      if (!response || typeof response.text?.[Symbol.asyncIterator] !== 'function') {
        throw new ProviderGenerationError(
          'The language model response does not expose the documented async text stream.',
          providerId
        );
      }
      let text = '';
      for await (const fragment of response.text) {
        const value = typeof fragment === 'string' ? fragment : fragment?.value;
        if (typeof value === 'string') {
          text += value;
        }
      }
      if (text.length === 0) {
        throw new ProviderGenerationError('The language model returned an empty response.', providerId);
      }
      return { text, finishReason: 'stop' };
    }
  });

  return {
    providerId,
    kind: 'vscode-language-model',
    hosted: true,
    status: 'available',
    capabilities,
    model: metadata,
    documentedApi: DOCUMENTED_API,
    limitations: [...metadata.limitations],
    generate: adapter.generate,
    async extractActivations() {
      throw new ProviderUnsupportedCapabilityError(
        'Hosted language models do not expose internal activations.',
        providerId,
        'D'
      );
    }
  };
}

/**
 * @param {string} providerId
 * @param {string} reasonCode
 * @param {string} detail
 */
function unavailableProvider(providerId, reasonCode, detail) {
  return {
    providerId,
    kind: 'vscode-language-model',
    hosted: true,
    status: 'unavailable',
    reasonCode,
    detail,
    capabilities: [],
    model: undefined,
    documentedApi: DOCUMENTED_API,
    limitations: [detail],
    async generate() {
      throw new ProviderUnsupportedCapabilityError(detail, providerId, 'B');
    },
    async extractActivations() {
      throw new ProviderUnsupportedCapabilityError(detail, providerId, 'D');
    }
  };
}

module.exports = { createVscodeLanguageModelProvider, DOCUMENTED_API };
