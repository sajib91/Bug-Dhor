'use strict';

/**
 * Tracks only patches that Bug Dhor actually applied after explicit approval.
 *
 * This tracker never infers authorship from an editor event. Its sole purpose
 * is to suppress the immediate analysis caused by our own WorkspaceEdit, then
 * allow exactly one bounded follow-up rescan so the feedback loop terminates.
 */

const MAX_PENDING_PER_URI = 8;
const MAX_HISTORY = 50;

/** @param {unknown} value */
function normalizeUri(value) {
  return typeof value === 'string' && value.length > 0 ? value : '';
}

/** @param {string} text */
function hashText(text) {
  // A lightweight identity is sufficient here; callers already use SHA-256 for
  // security-sensitive snapshot validation. Node's crypto is avoided so this
  // module remains trivially unit-testable and dependency-free.
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

class PatchOriginTracker {
  /** @param {{ logger?: import('../logging/output').Logger }} [dependencies] */
  constructor({ logger } = {}) {
    this.logger = logger;
    /** @type {Map<string, Array<Record<string, any>>>} */
    this.pending = new Map();
    /** @type {Record<string, any>[]} */
    this.history = [];
  }

  /**
   * @param {{
   *   documentUri: string,
   *   patch?: string,
   *   patchHash?: string,
   *   appliedHash?: string,
   *   findingId?: string | null,
   *   source?: string
   * }} input
   * @returns {Record<string, any>}
   */
  recordAppliedPatch({ documentUri, patch, patchHash, appliedHash, findingId, source } = {}) {
    const uri = normalizeUri(documentUri);
    if (!uri) {
      throw new TypeError('A document URI is required to record an applied patch.');
    }
    if (typeof appliedHash !== 'string' || appliedHash.length === 0) {
      throw new TypeError('An applied content hash is required to record an applied patch.');
    }
    const entry = Object.freeze({
      documentUri: uri,
      appliedHash,
      patchHash:
        typeof patchHash === 'string' && patchHash.length > 0
          ? patchHash
          : typeof patch === 'string'
            ? hashText(patch)
            : null,
      findingId: typeof findingId === 'string' && findingId.length > 0 ? findingId : null,
      source: typeof source === 'string' && source.length > 0 ? source : 'extension',
      at: new Date().toISOString()
    });
    const list = this.pending.get(uri) ?? [];
    list.push(entry);
    this.pending.set(uri, list.slice(-MAX_PENDING_PER_URI));
    this.history.unshift(entry);
    this.history = this.history.slice(0, MAX_HISTORY);
    this.logger?.debug?.(`Bug Dhor recorded an applied patch for ${uri}.`);
    return entry;
  }

  /**
   * Consume a pending applied-patch hash. A hash is suppressed at most once.
   *
   * @param {{ documentUri: string, hash?: string }} input
   * @returns {{ suppress: boolean, followUp: boolean, reason?: string, patch?: Record<string, any> }}
   */
  beforeScan({ documentUri, hash } = {}) {
    const uri = normalizeUri(documentUri);
    if (!uri || typeof hash !== 'string' || hash.length === 0) {
      return { suppress: false, followUp: false };
    }
    const list = this.pending.get(uri);
    if (!list || list.length === 0) {
      return { suppress: false, followUp: false };
    }
    const index = list.findIndex((entry) => entry.appliedHash === hash);
    if (index === -1) {
      return { suppress: false, followUp: false };
    }
    const [patch] = list.splice(index, 1);
    if (list.length === 0) {
      this.pending.delete(uri);
    } else {
      this.pending.set(uri, list);
    }
    return {
      suppress: true,
      followUp: true,
      reason: 'bugdhor-applied-patch',
      patch
    };
  }

  /** @param {string} uri */
  clearUri(uri) {
    this.pending.delete(normalizeUri(uri));
  }

  /** @returns {Record<string, any>[]} */
  getHistory() {
    return this.history.map((entry) => ({ ...entry }));
  }
}

module.exports = { PatchOriginTracker, hashText };
