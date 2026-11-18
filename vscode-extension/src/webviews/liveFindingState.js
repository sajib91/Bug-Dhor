'use strict';

const { languageForPath } = require('../monitoring/fileFilter');

const DASHBOARD_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low']);

/**
 * Convert a backend `file:` URI into the filesystem path expected by the
 * dashboard's source-location message. `filePath` from the backend is preferred
 * because it is already the engine's canonical path.
 *
 * @param {string | undefined} uriText
 * @returns {string | undefined}
 */
function uriToFilePath(uriText) {
  if (typeof uriText !== 'string' || uriText.length === 0) {
    return undefined;
  }
  try {
    const parsed = new URL(uriText);
    if (parsed.protocol !== 'file:' || !parsed.pathname) {
      return undefined;
    }
    const decoded = decodeURIComponent(parsed.pathname);
    return decoded.replace(/^\/([A-Za-z]:)/, '$1');
  } catch {
    return undefined;
  }
}

/** @param {unknown} value */
function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** @param {unknown} value */
function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Map one already-normalized diagnostic finding into the additive dashboard
 * finding shape. No title, severity, explanation, or status is synthesized.
 *
 * @param {object} finding
 * @returns {object}
 */
function toDashboardFinding(finding) {
  const filePath = stringOrNull(finding.filePath) ?? uriToFilePath(finding.documentUri);
  const range = isRecord(finding.range) ? finding.range : undefined;
  const start = isRecord(range?.start) ? range.start : undefined;
  const end = isRecord(range?.end) ? range.end : undefined;
  const zeroStartLine =
    typeof finding.startLine === 'number'
      ? finding.startLine
      : typeof start?.line === 'number'
        ? start.line
        : null;
  const zeroStartColumn =
    typeof finding.startColumn === 'number'
      ? finding.startColumn
      : typeof start?.character === 'number'
        ? start.character
        : null;
  const zeroEndLine =
    typeof finding.endLine === 'number'
      ? finding.endLine
      : typeof end?.line === 'number'
        ? end.line
        : null;
  const zeroEndColumn =
    typeof finding.endColumn === 'number'
      ? finding.endColumn
      : typeof end?.character === 'number'
        ? end.character
        : null;
  const line = zeroStartLine === null ? null : zeroStartLine + 1;
  const column = zeroStartColumn === null ? null : zeroStartColumn + 1;
  const endLine = zeroEndLine === null ? null : zeroEndLine + 1;
  const endColumn = zeroEndColumn === null ? null : zeroEndColumn + 1;

  // The short card description must come from the backend. Prefer the
  // explanation, then the suggested fix, then the evidence, then the title.
  const summary =
    stringOrNull(finding.explanation) ??
    stringOrNull(finding.suggestedRemediation) ??
    stringOrNull(finding.evidence) ??
    stringOrNull(finding.message);

  // The backend does not report a language on each finding. A conservative
  // file-extension label is added for filtering only and marked as such; no
  // parser or analysis capability is inferred from it.
  const language = languageForPath(filePath);

  return {
    id: finding.id,
    title: finding.message,
    ...(summary === null ? {} : { summary }),
    severity: finding.severity,
    language: language ?? 'unknown',
    languageSource: language === undefined ? 'not-reported' : 'file-extension',
    ...(stringOrNull(finding.category) === null ? {} : { category: finding.category }),
    ...(stringOrNull(finding.cwe) === null ? {} : { cwe: finding.cwe }),
    ...(stringOrNull(finding.ruleId) === null ? {} : { ruleId: finding.ruleId }),
    ...(filePath === undefined ? {} : { file: filePath, path: filePath }),
    ...(line === null ? {} : { line }),
    ...(column === null ? {} : { column }),
    ...(endLine === null ? {} : { endLine }),
    ...(endColumn === null ? {} : { endColumn }),
    ...(zeroStartLine === null ? {} : { startLine: zeroStartLine }),
    ...(zeroStartColumn === null ? {} : { startColumn: zeroStartColumn }),
    ...(zeroEndLine === null ? {} : { endLineZeroBased: zeroEndLine }),
    ...(zeroEndColumn === null ? {} : { endColumnZeroBased: zeroEndColumn }),
    documentUri: finding.documentUri,
    status: stringOrNull(finding.verificationStatus) ?? 'not-reported',
    ...(stringOrNull(finding.verificationStatus) === null
      ? {}
      : { verificationStatus: finding.verificationStatus }),
    ...(stringOrNull(finding.evidence) === null ? {} : { evidence: finding.evidence }),
    ...(stringOrNull(finding.explanation) === null ? {} : { explanation: finding.explanation }),
    ...(stringOrNull(finding.suggestedRemediation) === null
      ? {}
      : { suggestedRemediation: finding.suggestedRemediation }),
    ...(stringOrNull(finding.confidence) === null ? {} : { confidence: finding.confidence }),
    ...(stringOrNull(finding.confidenceBasis) === null
      ? {}
      : { confidenceBasis: finding.confidenceBasis }),
    ...(Array.isArray(finding.uncertainty) ? { uncertainty: [...finding.uncertainty] } : {}),
    ...(stringOrNull(finding.detectionMethod) === null
      ? {}
      : { detectionMethod: finding.detectionMethod, scanner: finding.detectionMethod }),
    ...(Array.isArray(finding.sourceReferences)
      ? { sourceReferences: finding.sourceReferences.map((entry) => ({ ...entry })) }
      : {}),
    repairEligible: finding.repairEligible === true,
    ...(isRecord(finding.riskAssessment) ? { riskAssessment: { ...finding.riskAssessment } } : {})
  };
}

/**
 * Build a live dashboard patch from the findings already normalized and
 * accepted by `DiagnosticController`. This deliberately avoids a second
 * normalization pass over the raw backend result.
 *
 * @param {{
 *   result?: unknown,
 *   findings?: unknown,
 *   generatedAt?: string,
 *   scanHistory?: unknown
 * }} options
 * @returns {Record<string, unknown>}
 */
function buildLiveScanDashboardPatch({ result, findings, generatedAt, scanHistory } = {}) {
  const accepted = Array.isArray(findings) ? findings.filter(isRecord) : [];
  const severity = Object.fromEntries(DASHBOARD_SEVERITIES.map((key) => [key, 0]));
  const categories = {};
  const statuses = {};

  for (const finding of accepted) {
    if (Object.prototype.hasOwnProperty.call(severity, finding.severity)) {
      severity[finding.severity] += 1;
    }
    const category = stringOrNull(finding.category) ?? 'Uncategorized';
    categories[category] = (categories[category] ?? 0) + 1;
    const status = stringOrNull(finding.verificationStatus) ?? 'not-reported';
    statuses[status] = (statuses[status] ?? 0) + 1;
  }

  const resultRecord = isRecord(result) ? result : {};
  const timestamp = stringOrNull(generatedAt) ?? new Date().toISOString();

  return {
    vulnerabilities: accepted.map(toDashboardFinding),
    ...(Array.isArray(scanHistory) ? { scanHistory: scanHistory.filter(isRecord) } : {}),
    summary: {
      totalFindings: accepted.length,
      severity,
      categories,
      statuses,
      lastScanAt: timestamp,
      ...(stringOrNull(resultRecord.workspaceName)
        ? { workspaceName: resultRecord.workspaceName }
        : {}),
      analysisAvailable: resultRecord.analysisAvailable === true,
      ...(Number.isInteger(resultRecord.filesScanned)
        ? { filesScanned: resultRecord.filesScanned }
        : {})
    },
    generatedAt: timestamp
  };
}

/**
 * Merge a new accepted scan result into the existing live set. Findings for
 * the scanned scope are replaced; findings for other files remain visible.
 *
 * @param {unknown} previous
 * @param {unknown} incoming
 * @param {unknown} [scopeUris]
 * @returns {object[]}
 */
function mergeLiveFindings(previous, incoming, scopeUris) {
  const before = Array.isArray(previous) ? previous.filter(isRecord) : [];
  const next = Array.isArray(incoming) ? incoming.filter(isRecord) : [];
  const scopeKeys = new Set(
    (Array.isArray(scopeUris) ? scopeUris : [])
      .map((value) => (typeof value === 'string' ? value : value?.toString?.()))
      .filter((value) => typeof value === 'string' && value.length > 0)
  );

  // An unscoped result represents a complete scan; replace the aggregate set.
  // A scoped result replaces only findings belonging to the rescanned files.
  const retained =
    scopeKeys.size === 0
      ? []
      : before.filter((finding) => !scopeKeys.has(uriKey(finding.documentUri)));
  const merged = new Map();
  for (const finding of [...retained, ...next]) {
    merged.set(findingIdentity(finding), finding);
  }
  return [...merged.values()];
}

/** @param {unknown} value */
function uriKey(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value && typeof value.toString === 'function') {
    return value.toString();
  }
  return '';
}

/** @param {object} finding */
function findingIdentity(finding) {
  return [
    uriKey(finding.id),
    uriKey(finding.documentUri),
    finding.startLine,
    finding.startColumn,
    finding.endLine,
    finding.endColumn,
    uriKey(finding.severity)
  ].join('|');
}

/**
 * Build an honest history row for a completed scan. Missing duration is left
 * absent instead of being estimated.
 *
 * @param {{
 *   result?: unknown,
 *   findings?: unknown,
 *   scopeUris?: unknown,
 *   generatedAt?: string,
 *   status?: string,
 *   durationMs?: unknown
 * }} options
 * @returns {object}
 */
function buildLiveScanHistoryEntry({
  result,
  findings,
  scopeUris,
  generatedAt,
  status,
  durationMs
} = {}) {
  const resultRecord = isRecord(result) ? result : {};
  const timestamp = stringOrNull(generatedAt) ?? new Date().toISOString();
  const accepted = Array.isArray(findings) ? findings.filter(isRecord) : [];
  const scopeTexts = (Array.isArray(scopeUris) ? scopeUris : [])
    .map((value) => uriKey(value))
    .filter((value) => value.length > 0);
  const responseScopes = Array.isArray(resultRecord.scope?.uris)
    ? resultRecord.scope.uris.map(uriKey).filter((value) => value.length > 0)
    : [];
  const scope =
    scopeTexts.length > 0
      ? scopeTexts.join(', ')
      : responseScopes.length > 0
        ? responseScopes.join(', ')
        : (stringOrNull(resultRecord.workspaceName) ?? 'Workspace');
  const validStatus = ['completed', 'partial', 'unavailable', 'cancelled'].includes(status)
    ? status
    : resultRecord.analysisAvailable === true
      ? 'completed'
      : 'unavailable';

  return {
    id: `scan-${timestamp}-${accepted.length}-${scopeTexts.length}`,
    startedAt: timestamp,
    scope,
    status: validStatus,
    findings: accepted.length,
    ...(typeof durationMs === 'number' && Number.isFinite(durationMs) && durationMs >= 0
      ? { durationMs }
      : {})
  };
}

/**
 * @param {unknown} history
 * @param {object} entry
 * @param {number} [limit]
 * @returns {object[]}
 */
function appendLiveScanHistory(history, entry, limit = 100) {
  const previous = Array.isArray(history) ? history.filter(isRecord) : [];
  const capped = Number.isInteger(limit) && limit > 0 ? limit : 100;
  return [entry, ...previous].slice(0, capped);
}

module.exports = {
  DASHBOARD_SEVERITIES,
  uriToFilePath,
  toDashboardFinding,
  buildLiveScanDashboardPatch,
  mergeLiveFindings,
  buildLiveScanHistoryEntry,
  appendLiveScanHistory
};
