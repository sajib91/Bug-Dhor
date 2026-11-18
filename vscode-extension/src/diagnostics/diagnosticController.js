'use strict';

const {
  DIAGNOSTIC_SOURCE,
  FindingValidationError,
  normalizeScanResult,
  normalizeFileUri,
  findingContainsPosition,
  severityLabel,
  cweUrl
} = require('./findingModel');
const { isFileUriWithinFolders } = require('../security/paths');

const DIAGNOSTIC_COLLECTION_NAME = 'bugdhor';

/**
 * Compact Problems-panel text. Full details remain in the native hover.
 *
 * @param {object} finding
 * @returns {string}
 */
function buildDiagnosticMessage(finding) {
  const parts = [
    finding.message,
    `${severityLabel(finding.severity)} severity`,
    finding.cwe ? finding.cwe : 'CWE not provided'
  ];
  if (finding.detectionMethod) {
    parts.push(`scanner: ${finding.detectionMethod}`);
  }
  return `Bug Dhor: ${parts.join(' · ')}`;
}

/**
 * @param {import('vscode')} vscode
 * @param {import('vscode').Uri} uri
 * @returns {boolean}
 */
function defaultIsWithinWorkspace(vscode, uri) {
  if (typeof vscode.workspace?.getWorkspaceFolder === 'function') {
    if (vscode.workspace.getWorkspaceFolder(uri)) {
      return true;
    }
  }
  return isFileUriWithinFolders(uri, vscode.workspace?.workspaceFolders ?? []);
}

/**
 * Owns the Bug Dhor DiagnosticCollection and the finding store used by the
 * hover and code-action providers.
 *
 * Only findings supplied by a backend scan result are published. Invalid or
 * out-of-workspace findings are rejected, logged, and never synthesized.
 */
class DiagnosticController {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   logger: import('../logging/output').Logger,
   *   isWithinWorkspace?: (uri: import('vscode').Uri) => boolean,
   *   onFindingsPublished?: (event: object) => void,
   *   decorations?: import('./decorationController').DecorationController
   * }} dependencies
   */
  constructor({ vscode, logger, isWithinWorkspace, onFindingsPublished, decorations }) {
    if (!vscode) {
      throw new TypeError('DiagnosticController requires a vscode API object.');
    }
    if (!logger) {
      throw new TypeError('DiagnosticController requires a logger.');
    }
    if (!vscode.languages || typeof vscode.languages.createDiagnosticCollection !== 'function') {
      throw new TypeError(
        'vscode.languages.createDiagnosticCollection is required for diagnostics.'
      );
    }
    if (
      !vscode.Uri ||
      typeof vscode.Uri.parse !== 'function' ||
      typeof vscode.Diagnostic !== 'function' ||
      typeof vscode.Range !== 'function' ||
      typeof vscode.Location !== 'function' ||
      typeof vscode.DiagnosticRelatedInformation !== 'function' ||
      !vscode.DiagnosticSeverity
    ) {
      throw new TypeError('The VS Code diagnostic APIs are required for diagnostics.');
    }

    this.vscode = vscode;
    this.logger = logger;
    this.collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    this.isWithinWorkspace =
      typeof isWithinWorkspace === 'function'
        ? isWithinWorkspace
        : (uri) => defaultIsWithinWorkspace(vscode, uri);
    this.onFindingsPublished =
      typeof onFindingsPublished === 'function' ? onFindingsPublished : null;
    this.decorations = decorations ?? null;

    /**
     * @type {Map<string, {
     *   uri: import('vscode').Uri,
     *   findings: object[],
     *   diagnostics: import('vscode').Diagnostic[]
     * }>}
     */
    this.entries = new Map();
    this.disposed = false;
  }

  /**
   * Validate and publish one backend scan result.
   *
   * `options.scopeUris` identifies files covered by the scan. Diagnostics for
   * those files are replaced even when the new result has no findings. A
   * result-level `scope.uris` is honoured as well. Files outside the workspace
   * are ignored.
   *
   * @param {unknown} result
   * @param {{ scopeUris?: string[] }} [options]
   * @returns {{
   *   published: number,
   *   files: string[],
   *   findings: object[],
   *   rejected: Array<{ index: number | null, code: string, reason: string }>
   * }}
   */
  publishScanResult(result, options = {}) {
    this.assertActive();
    const normalized = normalizeScanResult(result);
    const rejected = [...normalized.rejected];
    const explicitScope = options.scopeUris ?? [];
    if (!Array.isArray(explicitScope)) {
      throw new FindingValidationError(
        'Diagnostic scope URIs must be an array.',
        'E_INVALID_DIAGNOSTIC_SCOPE'
      );
    }

    /** @type {Array<object & { documentUri: string, uri: import('vscode').Uri }>} */
    const accepted = [];
    const seenLocations = new Set();

    for (const finding of normalized.findings) {
      const uri = this.vscode.Uri.parse(finding.documentUri);
      const locationKey = [
        finding.documentUri,
        finding.range.start.line,
        finding.range.start.character,
        finding.range.end.line,
        finding.range.end.character,
        finding.severity,
        finding.message,
        finding.cwe ?? ''
      ].join('|');
      if (seenLocations.has(locationKey)) {
        rejected.push({
          index: null,
          code: 'E_DUPLICATE_LOCATION',
          reason: `Duplicate Bug Dhor finding at the same source range: ${finding.id}`
        });
        continue;
      }
      seenLocations.add(locationKey);
      if (!this.isAllowedUri(uri)) {
        rejected.push({
          index: null,
          code: 'E_OUTSIDE_WORKSPACE',
          reason: `Finding ${finding.id} points outside the workspace: ${finding.documentUri}`
        });
        continue;
      }
      accepted.push({ ...finding, documentUri: uri.toString(), uri });
    }

    /** @type {Map<string, { uri: import('vscode').Uri, findings: object[], diagnostics: import('vscode').Diagnostic[] }>} */
    const groups = new Map();
    for (const finding of accepted) {
      let group = groups.get(finding.documentUri);
      if (!group) {
        group = { uri: finding.uri, findings: [], diagnostics: [] };
        groups.set(finding.documentUri, group);
      }
      group.findings.push(finding);
      group.diagnostics.push(this.createDiagnostic(finding));
    }

    const scopeKeys = new Set();
    const scopeUris = [...normalized.scopeUris, ...explicitScope];
    scopeUris.forEach((value, index) => {
      const uriText = normalizeFileUri(value, `scopeUris[${index}]`);
      const uri = this.vscode.Uri.parse(uriText);
      if (!this.isAllowedUri(uri)) {
        this.logger.warn(`Discarded an out-of-workspace Bug Dhor diagnostic scope URI: ${uriText}`);
        return;
      }
      scopeKeys.add(uri.toString());
    });

    for (const key of scopeKeys) {
      if (!groups.has(key)) {
        this.clearEntry(key);
      }
    }

    for (const [key, group] of groups) {
      this.entries.set(key, group);
      this.collection.set(group.uri, group.diagnostics);
      this.decorations?.setFindings(group.uri, group.findings);
    }

    if (accepted.length > 0) {
      this.logger.info(
        `Published ${accepted.length} Bug Dhor finding(s) across ${groups.size} file(s).`
      );
    } else {
      this.logger.debug('No Bug Dhor findings were published for this scan result.');
    }
    if (rejected.length > 0) {
      const preview = rejected
        .slice(0, 5)
        .map((entry) => entry.reason)
        .join('; ');
      this.logger.warn(
        `Discarded ${rejected.length} invalid Bug Dhor finding(s): ${preview}` +
          (rejected.length > 5 ? '; ...' : '')
      );
    }

    const publishedFindings = accepted.map((finding) => {
      const copy = { ...finding };
      delete copy.uri;
      return copy;
    });
    if (this.onFindingsPublished) {
      try {
        this.onFindingsPublished({
          findings: publishedFindings,
          scopeUris: [...scopeKeys],
          response: result
        });
      } catch (error) {
        // Feedback bookkeeping must never prevent diagnostics publication.
        this.logger.warn(
          `Bug Dhor finding feedback failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }

    return {
      published: accepted.length,
      files: [...groups.keys()],
      findings: publishedFindings,
      rejected
    };
  }

  /**
   * @param {object & { documentUri: string, uri: import('vscode').Uri }} finding
   * @returns {import('vscode').Diagnostic}
   */
  createDiagnostic(finding) {
    const diagnostic = new this.vscode.Diagnostic(
      this.toRange(finding.range),
      buildDiagnosticMessage(finding),
      this.toSeverity(finding.severityKind)
    );
    diagnostic.source = DIAGNOSTIC_SOURCE;

    if (finding.cwe) {
      diagnostic.code = {
        value: finding.cwe,
        target: this.vscode.Uri.parse(cweUrl(finding.cwe))
      };
    } else if (finding.ruleId) {
      diagnostic.code = finding.ruleId;
    }

    const relatedInformation = this.createRelatedInformation(finding);
    if (relatedInformation.length > 0) {
      diagnostic.relatedInformation = relatedInformation;
    }

    return diagnostic;
  }

  /**
   * @param {object & { uri: import('vscode').Uri, range: object, evidence?: string, sourceReferences: object[] }} finding
   * @returns {import('vscode').DiagnosticRelatedInformation[]}
   */
  createRelatedInformation(finding) {
    const related = [];
    const findingRange = this.toRange(finding.range);
    const anchor = () => new this.vscode.Location(finding.uri, findingRange);
    const add = (message) =>
      related.push(new this.vscode.DiagnosticRelatedInformation(anchor(), message));

    add(`Severity: ${severityLabel(finding.severity)} (backend value: ${finding.severity})`);
    add(`CWE: ${finding.cwe ?? 'not provided by the backend'}`);
    add(
      `Scanner: ${finding.detectionMethod ?? 'not provided by the backend'}` +
        (finding.ruleId ? ` · Rule: ${finding.ruleId}` : '')
    );
    add(`Explanation: ${finding.explanation ?? 'not provided by the backend'}`);
    add(`Evidence: ${finding.evidence ?? 'not provided by the backend'}`);
    add(
      `Suggested fix: ${
        finding.suggestedRemediation ?? finding.repair?.description ?? 'not provided by the backend'
      }`
    );

    if (finding.confidence) {
      const basis = finding.confidenceBasis ? ` · Basis: ${finding.confidenceBasis}` : '';
      add(`Confidence: ${finding.confidence}${basis}`);
    }
    if (Array.isArray(finding.uncertainty) && finding.uncertainty.length > 0) {
      add(`Uncertainty: ${finding.uncertainty.join('; ')}`);
    }
    if (finding.verificationStatus) {
      add(`Verification: ${finding.verificationStatus} (from backend evidence)`);
    }

    for (const reference of finding.sourceReferences) {
      let locationUri = finding.uri;
      let locationRange = findingRange;
      let suffix = '';

      if (reference.uri) {
        const referenceUri = this.vscode.Uri.parse(reference.uri);
        if (this.isAllowedUri(referenceUri)) {
          locationUri = referenceUri;
          locationRange = reference.range ? this.toRange(reference.range) : findingRange;
        } else {
          // Never link a source reference outside the workspace; keep the text
          // visible but anchor it to the finding's own location.
          suffix = ` (${reference.uri})`;
        }
      } else if (reference.url) {
        suffix = ` (${reference.url})`;
      }

      related.push(
        new this.vscode.DiagnosticRelatedInformation(
          new this.vscode.Location(locationUri, locationRange),
          `Source: ${reference.label}${suffix}`
        )
      );
    }

    return related;
  }

  /**
   * @param {{ start: { line: number, character: number }, end: { line: number, character: number } }} range
   * @returns {import('vscode').Range}
   */
  toRange(range) {
    return new this.vscode.Range(
      range.start.line,
      range.start.character,
      range.end.line,
      range.end.character
    );
  }

  /**
   * @param {'error' | 'warning' | 'information' | 'hint'} kind
   * @returns {import('vscode').DiagnosticSeverity}
   */
  toSeverity(kind) {
    const { DiagnosticSeverity } = this.vscode;
    switch (kind) {
      case 'error':
        return DiagnosticSeverity.Error;
      case 'warning':
        return DiagnosticSeverity.Warning;
      case 'information':
        return DiagnosticSeverity.Information;
      case 'hint':
        return DiagnosticSeverity.Hint;
      default:
        throw new FindingValidationError(`Unsupported diagnostic severity kind: ${kind}.`);
    }
  }

  /**
   * @param {import('vscode').Uri} uri
   * @returns {boolean}
   */
  isAllowedUri(uri) {
    if (!uri || uri.scheme !== 'file') {
      return false;
    }
    try {
      return Boolean(this.isWithinWorkspace(uri));
    } catch (error) {
      this.logger.warn(
        `Unable to verify workspace containment for ${uri.toString()}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      return false;
    }
  }

  /**
   * @param {string | import('vscode').Uri} value
   * @returns {string | undefined}
   */
  toUriKey(value) {
    if (typeof value === 'string') {
      return value;
    }
    if (value && typeof value.toString === 'function') {
      return value.toString();
    }
    return undefined;
  }

  /**
   * @param {string | import('vscode').Uri} value
   * @returns {object[]}
   */
  getFindingsForUri(value) {
    const key = this.toUriKey(value);
    return key ? (this.entries.get(key)?.findings ?? []) : [];
  }

  /**
   * @param {string | import('vscode').Uri} value
   * @param {{ line: number, character: number }} position
   * @returns {object[]}
   */
  findAt(value, position) {
    return this.getFindingsForUri(value).filter((finding) =>
      findingContainsPosition(finding, position)
    );
  }

  /**
   * Return workspace file URIs that currently have published Bug Dhor
   * findings. Used only to scope an explicit user-invoked rescan.
   *
   * @returns {string[]}
   */
  getPublishedUris() {
    return [...this.entries.keys()].filter((key) => key.startsWith('file:'));
  }

  /**
   * @param {string | import('vscode').Uri} value
   * @returns {import('vscode').Diagnostic[]}
   */
  getDiagnosticsForUri(value) {
    const key = this.toUriKey(value);
    return key ? (this.entries.get(key)?.diagnostics ?? []) : [];
  }

  /**
   * @param {object} finding
   * @returns {import('vscode').Diagnostic | undefined}
   */
  getDiagnosticForFinding(finding) {
    const entry = this.entries.get(finding.documentUri);
    if (!entry) {
      return undefined;
    }
    const index = entry.findings.findIndex(
      (candidate) => candidate.id === finding.id && candidate.documentUri === finding.documentUri
    );
    return index === -1 ? undefined : entry.diagnostics[index];
  }

  /**
   * @param {string | import('vscode').Uri} value
   */
  clearUri(value) {
    this.assertActive();
    const key = this.toUriKey(value);
    if (key) {
      this.clearEntry(key);
    }
  }

  /** Clear every published Bug Dhor diagnostic. */
  clearAll() {
    this.assertActive();
    this.collection.clear();
    this.entries.clear();
    this.decorations?.clearAll();
  }

  /** @param {string} key */
  clearEntry(key) {
    const entry = this.entries.get(key);
    if (entry) {
      this.collection.delete(entry.uri);
      this.entries.delete(key);
      this.decorations?.clearUri(entry.uri);
    }
  }

  assertActive() {
    if (this.disposed) {
      throw new Error('The Bug Dhor diagnostic controller has been disposed.');
    }
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    try {
      this.collection.clear();
      this.collection.dispose();
    } finally {
      this.entries.clear();
      this.decorations?.dispose();
    }
  }
}

module.exports = {
  DiagnosticController,
  DIAGNOSTIC_COLLECTION_NAME,
  defaultIsWithinWorkspace,
  buildDiagnosticMessage
};
