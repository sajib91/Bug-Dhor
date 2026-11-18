'use strict';

const { CAPABILITIES, CAPABILITY_DEFINITIONS } = require('./capabilities');

/**
 * Static, honest compatibility matrix. "conditional" never means available by
 * default: it requires the explicit documented access and validation described
 * by the corresponding provider adapter.
 */
const PROVIDER_COMPATIBILITY = Object.freeze([
  {
    kind: 'editor',
    label: 'VS Code editor monitoring',
    A: 'supported',
    B: 'not-supported',
    C: 'not-supported',
    D: 'not-supported',
    E: 'not-supported',
    F: 'not-supported',
    note: 'Universal fallback using documented document-change events only.'
  },
  {
    kind: 'vscode-language-model',
    label: 'VS Code Language Model API',
    A: 'editor-fallback',
    B: 'conditional',
    C: 'conditional',
    D: 'not-supported',
    E: 'not-supported',
    F: 'not-supported',
    note: 'Requires selectChatModels and user consent. Hosted models have no internals.'
  },
  {
    kind: 'openai-compatible',
    label: 'OpenAI-compatible endpoint',
    A: 'editor-fallback',
    B: 'conditional',
    C: 'conditional',
    D: 'not-supported',
    E: 'not-supported',
    F: 'not-supported',
    note: 'Requires a configured endpoint and model. Hosted endpoints have no internals.'
  },
  {
    kind: 'local-hugging-face',
    label: 'Direct local Hugging Face model',
    A: 'editor-fallback',
    B: 'conditional',
    C: 'conditional',
    D: 'conditional',
    E: 'conditional',
    F: 'conditional',
    note:
      'D requires a real local activation accessor; E requires D plus a validated SAE; F requires E plus a configured intervention contract.'
  },
  {
    kind: 'extension-api',
    label: 'Official extension-specific API',
    A: 'editor-fallback',
    B: 'conditional',
    C: 'conditional',
    D: 'conditional',
    E: 'conditional',
    F: 'conditional',
    note:
      'Requires an explicit official API manifest with documentation. Undocumented interfaces are never used.'
  }
]);

/** @param {any} model */
function summarizeModel(model) {
  if (!model) {
    return null;
  }
  return {
    id: model.id,
    displayName: model.displayName,
    source: model.source,
    family: model.family ?? null,
    version: model.version ?? null,
    capabilities: [...(model.capabilities ?? [])],
    limitations: [...(model.limitations ?? [])]
  };
}

/**
 * @param {Array<{ kind?: string, status?: string, capabilities?: string[] }>} [records]
 */
function toCompatibilityMatrix(records = []) {
  return PROVIDER_COMPATIBILITY.map((entry) => {
    const matching = records.filter((record) => record.kind === entry.kind);
    const capabilitySet = new Set(matching.flatMap((record) => record.capabilities ?? []));
    return {
      ...entry,
      discovered:
        matching.length === 0
          ? []
          : matching.map((record) => ({
              providerId: record.providerId,
              status: record.status ?? 'unknown',
              capabilities: [...(record.capabilities ?? [])]
            })),
      discoveredCapabilities: [...capabilitySet].sort()
    };
  });
}

/** @param {Array<{ kind?: string, status?: string, capabilities?: string[] }>} [records] */
function renderCompatibilityMatrixMarkdown(records = []) {
  const header = `| Provider | ${CAPABILITIES.join(' | ')} | Notes |\n|---|---|---|---|---|---|---|`;
  const rows = toCompatibilityMatrix(records).map(
    (entry) =>
      `| ${entry.label} | ${CAPABILITIES.map((capability) => entry[capability]).join(' | ')} | ${
        entry.note
      } |`
  );
  const legend = CAPABILITIES.map(
    (capability) => `- **${capability} — ${CAPABILITY_DEFINITIONS[capability].name}**: ${CAPABILITY_DEFINITIONS[capability].summary}`
  );
  return [`# Assistant integration capability matrix`, '', header, ...rows, '', '## Legend', ...legend].join(
    '\n'
  );
}

module.exports = {
  PROVIDER_COMPATIBILITY,
  summarizeModel,
  toCompatibilityMatrix,
  renderCompatibilityMatrixMarkdown
};
