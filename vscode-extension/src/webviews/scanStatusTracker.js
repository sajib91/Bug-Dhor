'use strict';

/**
 * Tracks only observed scan events. A file becomes pending when a real VS Code
 * event or an explicit scan request names it, and it becomes scanned only after
 * the security engine returns a completed response. Transport failures and
 * unavailable analysis are recorded as failures, never as clean scans.
 */

const { uriToFilePath } = require('./liveFindingState');

/** @param {unknown} value */
function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Convert a URI object/string or absolute path into a stable file path key.
 *
 * @param {unknown} value
 * @returns {string | null}
 */
function pathKey(value) {
  if (typeof value === 'string') {
    return uriToFilePath(value) ?? value;
  }
  if (value && typeof value === 'object') {
    const fsPath = stringOrNull(/** @type {any} */ (value).fsPath);
    if (fsPath) {
      return fsPath;
    }
    const text = stringOrNull(/** @type {any} */ (value).toString?.());
    if (text) {
      return uriToFilePath(text) ?? text;
    }
  }
  return null;
}

/**
 * @param {unknown} request
 * @param {unknown[]} [scopeUris]
 * @returns {string[]}
 */
function scopeKeys(request, scopeUris) {
  const source = request && typeof request === 'object' && !Array.isArray(request) ? request : {};
  const candidates = [
    source.documentUri,
    source.filePath,
    ...(Array.isArray(source.filePaths) ? source.filePaths : []),
    ...(Array.isArray(source.scope?.uris) ? source.scope.uris : []),
    ...(Array.isArray(scopeUris) ? scopeUris : [])
  ];
  const keys = new Set();
  for (const candidate of candidates) {
    const key = pathKey(candidate);
    if (key) {
      keys.add(key);
    }
  }
  return [...keys];
}

function isCancellation(error) {
  if (!error || typeof error !== 'object') {
    return false;
  }
  return (
    error.name === 'Canceled' ||
    error.name === 'CanceledError' ||
    error.name === 'AbortError' ||
    error.code === 'ERR_CANCELED'
  );
}

class ScanStatusTracker {
  constructor() {
    this.pending = new Set();
    this.completed = new Set();
    this.failed = new Set();
    this.discovered = new Set();
    this.inventoryAvailable = false;
    this.failedScans = 0;
    this.lastScanAt = null;
    this.lastFailureAt = null;
    this.observed = false;
    this.sequence = 0;
  }

  /** @param {unknown} inventory */
  updateInventory(inventory) {
    if (!inventory || typeof inventory !== 'object') {
      return this.getState();
    }
    const files = Array.isArray(inventory.files) ? inventory.files : [];
    this.discovered = new Set(
      files
        .map((file) => pathKey(file?.fsPath ?? file?.filePath ?? file))
        .filter((key) => key !== null)
    );
    this.inventoryAvailable = inventory.available === true;
    return this.getState();
  }

  /**
   * Record real editor file events. Deletes and the old side of a rename clear
   * any stale status; creates and modifications make the file pending until a
   * real backend response arrives.
   *
   * @param {{
   *   type: 'create' | 'change' | 'delete' | 'rename' | 'save' | 'open',
   *   uris?: unknown[],
   *   oldUri?: unknown,
   *   newUri?: unknown
   * }} event
   */
  observeEvent(event) {
    const type = event?.type;
    // This method is called only after the extension host has validated a real
    // VS Code file event, so any call here is an observed scan state change.
    this.observed = true;
    const remove = (key) => {
      this.pending.delete(key);
      this.completed.delete(key);
      this.failed.delete(key);
    };
    if (type === 'delete' || type === 'rename') {
      for (const uri of Array.isArray(event.oldUri) ? event.oldUri : [event.oldUri]) {
        const key = pathKey(uri);
        if (key) {
          remove(key);
        }
      }
    }
    if (type === 'delete') {
      for (const uri of Array.isArray(event.uris) ? event.uris : []) {
        const key = pathKey(uri);
        if (key) {
          remove(key);
        }
      }
      return this.getState();
    }

    const uris = [...(Array.isArray(event.uris) ? event.uris : []), event.newUri].filter(
      (uri) => uri !== undefined
    );
    for (const uri of uris) {
      const key = pathKey(uri);
      if (!key) {
        continue;
      }
      this.completed.delete(key);
      this.failed.delete(key);
      this.pending.add(key);
    }
    return this.getState();
  }

  /**
   * Begin an explicit engine scan. Returns metadata that must be passed to
   * `complete` so durations and IDs come from the observed request.
   *
   * @param {{ request?: object, definition?: object, scopeUris?: unknown[] }} options
   */
  begin({ request, scopeUris } = {}) {
    this.observed = true;
    const keys = scopeKeys(request, scopeUris);
    for (const key of keys) {
      this.completed.delete(key);
      this.failed.delete(key);
      this.pending.add(key);
    }
    this.sequence += 1;
    const startedAt = new Date().toISOString();
    return {
      id: `scan-${this.sequence}-${Date.now()}`,
      startedAt,
      keys
    };
  }

  /**
   * Complete an explicit scan only when the backend returned a complete,
   * analysis-capable response.
   *
   * @param {{
   *   request?: object,
   *   result?: unknown,
   *   meta?: { keys?: string[], startedAt?: string },
   *   scopeUris?: unknown[]
   * }} options
   */
  complete({ request, result, meta, scopeUris } = {}) {
    this.observed = true;
    const keys = meta?.keys?.length
      ? meta.keys
      : scopeKeys(request, scopeUris ?? result?.scope?.uris);
    const record = result && typeof result === 'object' ? result : {};
    const completed =
      record.analysisAvailable === true &&
      record.status !== 'unavailable' &&
      record.status !== 'failed' &&
      record.status !== 'cancelled';
    for (const key of keys) {
      this.pending.delete(key);
      if (completed) {
        this.failed.delete(key);
        this.completed.add(key);
      } else {
        this.completed.delete(key);
        this.failed.add(key);
      }
    }
    if (completed) {
      this.lastScanAt = meta?.startedAt ?? new Date().toISOString();
    } else {
      this.failedScans += 1;
      this.lastFailureAt = new Date().toISOString();
    }
    return this.getState();
  }

  /**
   * @param {{ request?: object, error?: unknown, meta?: { keys?: string[] }, scopeUris?: unknown[] }} options
   */
  fail({ request, error, meta, scopeUris } = {}) {
    if (isCancellation(error)) {
      const keys = meta?.keys ?? scopeKeys(request, scopeUris);
      for (const key of keys) {
        this.pending.delete(key);
      }
      return this.getState();
    }
    this.observed = true;
    const keys = meta?.keys?.length ? meta.keys : scopeKeys(request, scopeUris);
    for (const key of keys) {
      this.pending.delete(key);
      this.completed.delete(key);
      this.failed.add(key);
    }
    this.failedScans += 1;
    this.lastFailureAt = new Date().toISOString();
    return this.getState();
  }

  getState() {
    const inDiscovered = (key) => !this.inventoryAvailable || this.discovered.has(key);
    const completed = [...this.completed].filter(inDiscovered).length;
    const pending = [...this.pending].filter(inDiscovered).length;
    const failedFiles = [...this.failed].filter(inDiscovered).length;
    return {
      discoveredFiles: this.inventoryAvailable ? this.discovered.size : null,
      scannedFiles: this.observed ? completed : null,
      pendingFiles: this.observed ? pending : null,
      failedFiles: this.observed ? failedFiles : null,
      failedScans: this.observed ? this.failedScans : null,
      lastScanAt: this.lastScanAt
    };
  }

  getDetailedStats() {
    return {
      ...this.getState(),
      pendingKeys: [...this.pending],
      completedKeys: [...this.completed],
      failedKeys: [...this.failed],
      lastFailureAt: this.lastFailureAt
    };
  }
}

module.exports = { ScanStatusTracker, pathKey, scopeKeys };
