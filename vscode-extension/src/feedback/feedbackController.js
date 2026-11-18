'use strict';

const { FindingLifecycle } = require('./findingLifecycle');
const { PatchOriginTracker } = require('./patchOriginTracker');

/**
 * Composition layer that connects validated diagnostics, patch provenance,
 * rescanning, verification, and lifecycle notifications.
 *
 * The controller never publishes findings and never marks a finding resolved
 * from a hook or document event. It only records evidence supplied by validated
 * scan results, explicit patch application, and independent verification.
 */
class FeedbackController {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   logger: import('../logging/output').Logger,
   *   getSettings?: () => object
   * }} dependencies
   */
  constructor({ vscode, logger, getSettings } = {}) {
    if (!vscode || !logger) {
      throw new TypeError('FeedbackController requires vscode and logger.');
    }
    this.vscode = vscode;
    this.logger = logger;
    this.getSettings = typeof getSettings === 'function' ? getSettings : () => ({});
    this.lifecycle = new FindingLifecycle({ logger });
    this.patches = new PatchOriginTracker({ logger });
    /** @type {Set<(snapshot: Record<string, any>) => void>} */
    this.listeners = new Set();
    this.stats = {
      scans: 0,
      suppressed: 0,
      followUpRescans: 0,
      patches: 0,
      verifications: 0,
      resolutions: 0
    };
    this.lastScanKey = null;
    /** @type {Set<string>} */
    this.countedResolutions = new Set();
  }

  /** @param {(snapshot: Record<string, any>) => void} listener */
  subscribe(listener) {
    if (typeof listener !== 'function') {
      throw new TypeError('A feedback listener must be a function.');
    }
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Count and announce each transition into `resolved` exactly once. A scan
   * can resolve a finding after verification has already passed, while a
   * verification can resolve a finding after a clean rescan has already been
   * observed, so this cannot live in only one recording method.
   *
   * @param {Record<string, any>} snapshot
   */
  syncResolutions(snapshot) {
    for (const entry of snapshot.findings) {
      if (entry.state !== 'resolved') {
        this.countedResolutions.delete(entry.key);
        continue;
      }
      if (this.countedResolutions.has(entry.key)) {
        continue;
      }
      this.countedResolutions.add(entry.key);
      this.stats.resolutions += 1;
      if (this.getSettings().notifyOnResolution === true) {
        void this.vscode.window?.showInformationMessage?.(
          `Bug Dhor finding ${entry.findingId ?? ''} is resolved after a clean rescan ` +
            'and passing verification.'
        );
      }
    }
  }

  emit() {
    const snapshot = this.getSnapshot();
    this.syncResolutions(snapshot);
    for (const listener of this.listeners) {
      try {
        listener(snapshot);
      } catch (error) {
        this.logger.warn(
          `Bug Dhor feedback listener failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  }

  /**
   * @param {{ documentUri: string, hash?: string, documentVersion?: number }} input
   * @returns {{ suppress: boolean, followUp: boolean, reason?: string }}
   */
  beforeScan(input) {
    const decision = this.patches.beforeScan(input);
    if (decision.suppress) {
      this.stats.suppressed += 1;
      if (decision.followUp) {
        this.stats.followUpRescans += 1;
      }
      this.logger.debug(
        `Suppressed one immediate scan after an applied Bug Dhor patch for ${input.documentUri}.`
      );
    }
    return decision;
  }

  /**
   * Record only findings already accepted by the diagnostics controller.
   *
   * @param {{
   *   documentUri?: string,
   *   findings?: unknown[],
   *   scopeUris?: string[],
   *   snapshotHash?: string
   * }} input
   * @returns {Record<string, any>[]}
   */
  afterScan(input = {}) {
    const scopes = Array.isArray(input.scopeUris) ? [...input.scopeUris].sort().join(',') : '';
    const requestId = input.response?.requestId;
    const scanKey = typeof requestId === 'string' && requestId.length > 0 ? `${requestId}|${scopes}` : null;
    if (scanKey && scanKey === this.lastScanKey) {
      return this.getSnapshot().findings;
    }
    this.lastScanKey = scanKey;
    this.stats.scans += 1;
    const snapshot = this.lifecycle.observeScan(input);
    this.emit();
    return snapshot;
  }

  /**
   * @param {{
   *   documentUri: string,
   *   findingId?: string | null,
   *   patch?: string,
   *   patchHash?: string,
   *   appliedHash?: string,
   *   source?: string
   * }} input
   */
  recordAppliedPatch(input = {}) {
    const entry = this.patches.recordAppliedPatch(input);
    this.lifecycle.recordPatch({ ...input, patchHash: entry.patchHash, source: entry.source });
    this.stats.patches += 1;
    this.emit();
    if (this.getSettings().notifyOnPatchApplied === true) {
      void this.vscode.window?.showInformationMessage?.(
        'Bug Dhor recorded the applied patch. The finding stays open until a clean rescan and ' +
          'passing verification are recorded.'
      );
    }
    return entry;
  }

  /**
   * @param {{
   *   documentUri?: string,
   *   findingId?: string | null,
   *   verdict?: string,
   *   passed?: boolean,
   *   detail?: string
   * }} input
   */
  recordVerification(input = {}) {
    const outcome = this.lifecycle.recordVerification(input);
    this.stats.verifications += 1;
    this.emit();
    return outcome;
  }

  /** @param {string} uri */
  clearUri(uri) {
    for (const entry of this.lifecycle.getSnapshot()) {
      if (entry.documentUri === uri) {
        this.countedResolutions.delete(entry.key);
      }
    }
    this.patches.clearUri(uri);
    this.lifecycle.clearUri(uri);
  }

  /** @returns {Record<string, any>} */
  getSnapshot() {
    return {
      findings: this.lifecycle.getSnapshot(),
      patchHistory: this.patches.getHistory(),
      stats: { ...this.stats }
    };
  }
}

module.exports = { FeedbackController };
