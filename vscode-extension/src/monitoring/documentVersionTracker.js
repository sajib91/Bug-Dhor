'use strict';

/**
 * Per-document version and change tracking for real-time monitoring.
 *
 * The tracker keeps only small metadata: versions, half-open line ranges, and
 * timestamps. It never retains document text, never attributes an edit to an
 * AI model or assistant, and ignores repeated or out-of-order version events
 * so a single edit cannot schedule duplicate scans.
 */

const { isBulkInsert, mergeRanges, rangeFromContentChange } = require('./changeAnalyzer');

const DEFAULT_MAX_RANGES = 50;
const DEFAULT_MAX_DOCUMENTS = 200;

class DocumentVersionTracker {
  /**
   * @param {{ maxRanges?: number, maxDocuments?: number }} [options]
   */
  constructor(options = {}) {
    this.maxRanges = Number.isInteger(options.maxRanges) ? options.maxRanges : DEFAULT_MAX_RANGES;
    this.maxDocuments = Number.isInteger(options.maxDocuments)
      ? options.maxDocuments
      : DEFAULT_MAX_DOCUMENTS;
    /** @type {Map<string, object>} */
    this.documents = new Map();
  }

  /**
   * Record a content change. Returns `ignored: true` for duplicate/stale
   * versions so callers do not schedule another analysis for the same buffer.
   *
   * @param {{
   *   uri: string,
   *   version: number,
   *   lineCount?: number,
   *   contentChanges?: unknown[],
   *   timestamp?: number
   * }} event
   */
  observeChange(event) {
    const uri = event?.uri;
    const version = event?.version;
    if (typeof uri !== 'string' || uri.length === 0 || !Number.isInteger(version) || version < 0) {
      return { ignored: true, reason: 'invalid', state: undefined };
    }

    const previous = /** @type {any} */ (this.documents.get(uri));
    if (previous && version <= previous.version) {
      return { ignored: true, reason: 'stale', state: previous };
    }

    const lineCount = Number.isInteger(event.lineCount) ? event.lineCount : 1;
    const contentChanges = Array.isArray(event.contentChanges) ? event.contentChanges : [];
    /** @type {Array<{ startLine: number, endLine: number }>} */
    let ranges = [];
    let fullDocument = contentChanges.length === 0;
    let bulkInsert = false;

    for (const change of contentChanges) {
      if (isBulkInsert(change)) {
        bulkInsert = true;
      }
      const hasRange =
        change &&
        typeof change === 'object' &&
        Number.isInteger(change.range?.start?.line) &&
        Number.isInteger(change.range?.end?.line);
      if (!hasRange) {
        fullDocument = true;
        continue;
      }
      ranges.push(rangeFromContentChange(change, lineCount));
    }

    if (fullDocument || ranges.length === 0) {
      ranges = [{ startLine: 0, endLine: Math.max(1, lineCount) }];
    }

    const state = {
      uri,
      version,
      lineCount,
      ranges: mergeRanges(ranges).slice(0, Math.max(1, this.maxRanges)),
      fullDocument,
      // Edit-shape description only; no claim about the author or model.
      bulkInsert,
      savedVersion: typeof previous?.savedVersion === 'number' ? previous.savedVersion : undefined,
      lastSeenAt: Number.isFinite(event.timestamp) ? event.timestamp : Date.now()
    };
    this.store(uri, state);
    return { ignored: false, reason: undefined, state };
  }

  /**
   * Record a document save. The version is not advanced; a save is a trigger
   * for a bounded file-level confirmation scan of the already-tracked buffer.
   *
   * @param {{ uri: string, version: number, timestamp?: number }} event
   */
  observeSave(event) {
    const uri = event?.uri;
    const version = event?.version;
    if (typeof uri !== 'string' || uri.length === 0 || !Number.isInteger(version)) {
      return { ignored: true, state: undefined };
    }
    const previous = /** @type {any} */ (this.documents.get(uri));
    const state = previous
      ? { ...previous, savedVersion: version, lastSeenAt: event.timestamp ?? Date.now() }
      : {
          uri,
          version,
          lineCount: 1,
          ranges: [],
          fullDocument: true,
          bulkInsert: false,
          savedVersion: version,
          lastSeenAt: event.timestamp ?? Date.now()
        };
    this.store(uri, state);
    return { ignored: false, state };
  }

  /** @param {string} uri */
  get(uri) {
    return this.documents.get(uri);
  }

  /** @param {string} uri */
  forget(uri) {
    this.documents.delete(uri);
  }

  /** @param {string} uri @param {object} state */
  store(uri, state) {
    if (!this.documents.has(uri) && this.documents.size >= this.maxDocuments) {
      let oldestKey;
      let oldestTime = Number.POSITIVE_INFINITY;
      for (const [key, value] of this.documents) {
        const time = /** @type {any} */ (value).lastSeenAt ?? 0;
        if (time < oldestTime) {
          oldestTime = time;
          oldestKey = key;
        }
      }
      if (oldestKey) {
        this.documents.delete(oldestKey);
      }
    }
    this.documents.set(uri, state);
  }

  clear() {
    this.documents.clear();
  }
}

module.exports = { DocumentVersionTracker, DEFAULT_MAX_RANGES, DEFAULT_MAX_DOCUMENTS };
