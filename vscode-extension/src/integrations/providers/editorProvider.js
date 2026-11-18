'use strict';

const { createModelMetadata } = require('../modelMetadata');
const { normalizeCapabilities } = require('../capabilities');
const { ProviderUnsupportedCapabilityError } = require('../errors');

/**
 * Universal fallback. It uses only documented editor events and never claims
 * to know which assistant, agent, or model produced a change.
 */
function createEditorProvider() {
  const providerId = 'editor-monitor';
  const capabilities = normalizeCapabilities(['A'], { providerId });

  return {
    providerId,
    kind: 'editor',
    hosted: false,
    status: 'available',
    capabilities,
    model: createModelMetadata({
      id: providerId,
      displayName: 'VS Code editor monitoring',
      source: 'editor',
      capabilities,
      limitations: [
        'Document events are not author attribution.',
        'No model identity, generation prompt, response, or internal activation is observed.'
      ]
    }),
    limitations: [
      'Capability A is editor-level monitoring and applies to every document change.',
      'Vulnerability findings still come only from the Bug Dhor backend.'
    ],
    /**
     * @param {{ document?: any, uri?: string, ranges?: unknown[] }} event
     */
    observeChange(event) {
      return {
        providerId,
        capability: 'A',
        uri: typeof event?.uri === 'string' ? event.uri : undefined,
        version: Number.isInteger(event?.document?.version) ? event.document.version : undefined,
        ranges: Array.isArray(event?.ranges) ? event.ranges.length : 0,
        origin: 'editor_change',
        authorAttribution: 'none'
      };
    },
    async generate() {
      throw new ProviderUnsupportedCapabilityError(
        'Editor monitoring has no generation request or response access.',
        providerId,
        'B'
      );
    },
    async extractActivations() {
      throw new ProviderUnsupportedCapabilityError(
        'Editor monitoring has no model internal activation access.',
        providerId,
        'D'
      );
    }
  };
}

module.exports = { createEditorProvider };
