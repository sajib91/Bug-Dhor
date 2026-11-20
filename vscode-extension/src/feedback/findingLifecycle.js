'use strict';

/**
 * Finding lifecycle for the continuous security feedback loop.
 *
 * A finding is only marked resolved after all three conditions are recorded:
 * an explicitly applied Bug Dhor patch, a clean rescan that no longer reports
 * the finding, and a passing verification result. Ordinary editor changes and
 * hook metadata never create or resolve findings.
 */

const OBSERVED_STATES = Object.freeze([
  'open',
  'patched',
  'rescanning',
  'rescan_clean',
  'verification_passed',
  'verification_failed',
  'regressed',
  'not_observed',
  'resolved'
]);

/** @param {unknown} finding */
function findingKey(finding) {
  if (finding && typeof finding === 'object') {
    const id = finding.findingId ?? finding.id;
    if (typeof id === 'string' && id.trim().length > 0) {
      return `id:${id.trim()}`;
    }
    const uri = typeof finding.documentUri === 'string' ? finding.documentUri : '';
    const start = finding.range?.start ?? {};
    const location = [uri, start.line, start.character, finding.cwe, finding.ruleId]
      .map((value) => (value === undefined || value === null ? '' : String(value)))
      .join('|');
    if (location.replace(/\|/g, '').length > 0) {
      return `location:${location}`;
    }
  }
  return null;
}

/** @param {string} value */
function normalizeUri(value) {
  return typeof value === 'string' && value.length > 0 ? value : '';
}

/** @param {unknown} value @returns {Record<string, any>} */
function plainFinding(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  const source = /** @type {Record<string, any>} */ (value);
  const result = {};
  for (const field of [
    'id',
    'findingId',
    'message',
    'severity',
    'severityKind',
    'cwe',
    'ruleId',
    'documentUri',
    'range',
    'evidence',
    'explanation',
    'verificationStatus',
    'repairEligible'
  ]) {
    if (source[field] !== undefined) {
      result[field] = source[field];
    }
  }
  return result;
}

class FindingLifecycle {
  /** @param {{ logger?: import('../logging/output').Logger }} [dependencies] */
  constructor({ logger } = {}) {
    this.logger = logger;
    /** @type {Map<string, Record<string, any>>} */
    this.entries = new Map();
  }

  /**
   * Record the findings accepted by the diagnostics controller from a validated
   * backend scan result. Findings absent from a scoped clean rescan only move
   * a previously patched finding toward resolution.
   *
   * @param {{
   *   documentUri?: string,
   *   findings?: unknown[],
   *   scopeUris?: string[],
   *   snapshotHash?: string
   * }} input
   * @returns {Record<string, any>[]}
   */
  observeScan({ documentUri, findings, scopeUris, snapshotHash } = {}) {
    const seen = new Set();
    const observed = Array.isArray(findings) ? findings.map(plainFinding) : [];

    for (const finding of observed) {
      const key = findingKey(finding);
      if (!key) {
        continue;
      }
      seen.add(key);
      const existing = this.entries.get(key);
      const previousState = existing?.state;
      const entry = existing ?? {
        key,
        findingId: finding.findingId ?? finding.id ?? null,
        documentUri: normalizeUri(finding.documentUri ?? documentUri),
        state: 'open',
        firstSeenAt: new Date().toISOString()
      };

      if (
        ['patched', 'rescanning', 'verification_passed', 'rescan_clean'].includes(previousState)
      ) {
        entry.state = 'regressed';
        entry.regressedAt = new Date().toISOString();
        entry.resolvedAt = null;
        entry.verificationPassedAt = null;
      } else if (previousState === 'resolved') {
        entry.state = 'regressed';
        entry.regressedAt = new Date().toISOString();
        entry.resolvedAt = null;
        entry.verificationPassedAt = null;
      } else if (!OBSERVED_STATES.includes(previousState)) {
        entry.state = 'open';
      }

      Object.assign(entry, {
        findingId: finding.findingId ?? finding.id ?? entry.findingId,
        documentUri: normalizeUri(finding.documentUri ?? documentUri ?? entry.documentUri),
        message: finding.message ?? entry.message,
        severity: finding.severity ?? entry.severity,
        cwe: finding.cwe ?? entry.cwe,
        ruleId: finding.ruleId ?? entry.ruleId,
        range: finding.range ?? entry.range,
        lastSeenAt: new Date().toISOString(),
        lastSnapshotHash: typeof snapshotHash === 'string' ? snapshotHash : entry.lastSnapshotHash
      });
      this.entries.set(key, entry);
    }

    const scopes = new Set(
      [...(Array.isArray(scopeUris) ? scopeUris : []), documentUri]
        .map(normalizeUri)
        .filter((value) => value.length > 0)
    );
    if (scopes.size > 0) {
      for (const entry of this.entries.values()) {
        if (!scopes.has(entry.documentUri) || seen.has(entry.key)) {
          continue;
        }
        if (entry.state === 'resolved' || entry.state === 'not_observed') {
          continue;
        }
        const wasPatched = typeof entry.patchedAt === 'string';
        const wasVerified = typeof entry.verificationPassedAt === 'string';
        if (wasPatched && wasVerified) {
          entry.state = 'resolved';
          entry.resolvedAt = new Date().toISOString();
        } else if (wasPatched) {
          entry.state = 'rescan_clean';
          entry.rescanCleanAt = new Date().toISOString();
        } else {
          entry.state = 'not_observed';
          entry.notObservedAt = new Date().toISOString();
        }
        this.entries.set(entry.key, entry);
      }
    }

    return this.getSnapshot();
  }

  /**
   * Record a patch that the extension applied after explicit user approval.
   * Unknown or externally produced edits are never recorded here.
   *
   * @param {{
   *   documentUri: string,
   *   findingId?: string | null,
   *   patchHash?: string,
   *   appliedHash?: string,
   *   source?: string
   * }} input
   * @returns {Record<string, any> | undefined}
   */
  recordPatch({ documentUri, findingId, patchHash, appliedHash, source } = {}) {
    const uri = normalizeUri(documentUri);
    const directKey =
      typeof findingId === 'string' && findingId.length > 0 ? `id:${findingId}` : null;
    const targets = [];
    if (directKey && this.entries.has(directKey)) {
      targets.push(this.entries.get(directKey));
    } else {
      for (const entry of this.entries.values()) {
        if (entry.documentUri === uri && entry.state !== 'resolved') {
          targets.push(entry);
        }
      }
    }
    if (targets.length === 0 && directKey) {
      targets.push({
        key: directKey,
        findingId,
        documentUri: uri,
        state: 'patched',
        firstSeenAt: new Date().toISOString()
      });
    }

    for (const entry of targets) {
      entry.state = 'patched';
      entry.patchedAt = new Date().toISOString();
      entry.patchHash = typeof patchHash === 'string' ? patchHash : null;
      entry.appliedHash = typeof appliedHash === 'string' ? appliedHash : null;
      entry.patchSource = typeof source === 'string' ? source : 'extension';
      entry.verificationPassedAt = null;
      entry.rescanCleanAt = null;
      entry.resolvedAt = null;
      this.entries.set(entry.key, entry);
    }
    return targets[0];
  }

  /**
   * Record an independent verification result. Passing verification before a
   * clean rescan is remembered but never resolves the finding on its own.
   *
   * @param {{
   *   documentUri?: string,
   *   findingId?: string | null,
   *   verdict?: string,
   *   passed?: boolean,
   *   detail?: string
   * }} input
   * @returns {{ entry: Record<string, any> | undefined, resolvedNow: boolean }}
   */
  recordVerification({ documentUri, findingId, verdict, passed, detail } = {}) {
    const key = typeof findingId === 'string' && findingId.length > 0 ? `id:${findingId}` : null;
    const entry =
      (key ? this.entries.get(key) : undefined) ??
      [...this.entries.values()].find(
        (candidate) =>
          normalizeUri(documentUri) && candidate.documentUri === normalizeUri(documentUri)
      );
    if (!entry) {
      return { entry: undefined, resolvedNow: false };
    }
    const didPass = passed === true || verdict === 'passed';
    const before = entry.state;
    entry.lastVerification = {
      verdict: typeof verdict === 'string' ? verdict : didPass ? 'passed' : 'failed',
      detail: typeof detail === 'string' ? detail : '',
      at: new Date().toISOString()
    };
    if (!didPass) {
      entry.state = 'verification_failed';
      entry.verificationPassedAt = null;
    } else {
      entry.verificationPassedAt = new Date().toISOString();
      if (typeof entry.patchedAt === 'string' && entry.state === 'rescan_clean') {
        entry.state = 'resolved';
        entry.resolvedAt = new Date().toISOString();
      } else if (typeof entry.patchedAt === 'string') {
        entry.state = 'verification_passed';
      }
    }
    this.entries.set(entry.key, entry);
    return { entry, resolvedNow: before !== 'resolved' && entry.state === 'resolved' };
  }

  /** @returns {Record<string, any>[]} */
  getSnapshot() {
    return [...this.entries.values()]
      .sort((left, right) => String(left.key).localeCompare(String(right.key)))
      .map((entry) => ({ ...entry }));
  }

  /** @param {string} uri */
  clearUri(uri) {
    const normalized = normalizeUri(uri);
    if (!normalized) {
      return;
    }
    for (const [key, entry] of this.entries) {
      if (entry.documentUri === normalized) {
        this.entries.delete(key);
      }
    }
  }
}

module.exports = { FindingLifecycle, findingKey, OBSERVED_STATES };
