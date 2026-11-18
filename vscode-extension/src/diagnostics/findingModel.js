'use strict';

/**
 * Canonical finding contract for diagnostics.
 *
 * Backend scan results are the only source of findings. This module validates
 * their shape and never fills in a vulnerability, severity, location, score,
 * explanation, or repair decision that the backend did not supply.
 *
 * Expected result shape (a bare findings array is also accepted):
 *
 * {
 *   findings: [{
 *     id: string,
 *     message: string,                      // backend finding title
 *     severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
 *     category?: string,                    // backend bug category
 *     cwe?: string,                         // CWE-89
 *     ruleId?: string,
 *     filePath?: string,
 *     startLine?: number,                   // zero-based, when supplied by backend
 *     startColumn?: number,
 *     endLine?: number,
 *     endColumn?: number,
 *     location: {
 *       uri: string,                        // file: URI
 *       range: {                            // zero-based, like VS Code/LSP
 *         start: { line: number, character: number },
 *         end: { line: number, character: number }
 *       }
 *     },
 *     evidence?: string,
 *     explanation?: string,
 *     suggestedRemediation?: string,
 *     confidence?: 'observation' | 'inference' | 'hypothesis',
 *     confidenceBasis?: string,
 *     uncertainty?: string[],
 *     detectionMethod?: string,             // backend scanner or method name
 *     verificationStatus?: 'confirmed' | 'potential',
 *     sourceReferences?: [{
 *       label: string,
 *       url?: string,                       // http: or https:
 *       uri?: string,                       // file: URI
 *       range?: object                      // same zero-based range shape
 *     }],
 *     repair?: { eligible: boolean, description?: string },
 *     riskAssessment?: {                    // optional backend-only enrichment
 *       index: number | null,
 *       scoreKind: 'heuristic_index',
 *       band: string,
 *       probability: number | null,
 *       probabilityKind: 'calibrated_probability' | null,
 *       components: object,
 *       uncertainty: object,
 *       configHash: string | null,
 *       evidenceCount: number,
 *       excludedEvidenceCount: number,
 *       explanation: string[]
 *     }
 *   }],
 *   scope?: { uris: string[] }              // files covered by this scan
 * }
 */

/** @typedef {'critical' | 'high' | 'medium' | 'low' | 'info'} FindingSeverity */
/** @typedef {'error' | 'warning' | 'information' | 'hint'} SeverityKind */
/** @typedef {'observation' | 'inference' | 'hypothesis'} FindingConfidence */
/** @typedef {'heuristic_index'} RiskScoreKind */
/** @typedef {'calibrated_probability' | null} ProbabilityKind */

const DIAGNOSTIC_SOURCE = 'Bug Dhor';

/** @type {Readonly<Record<FindingSeverity, SeverityKind>>} */
const SEVERITY_KINDS = Object.freeze({
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'information',
  info: 'hint'
});

/** @type {Readonly<Record<FindingSeverity, string>>} */
const SEVERITY_LABELS = Object.freeze({
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
});

class FindingValidationError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'E_INVALID_FINDING') {
    super(message);
    this.name = 'FindingValidationError';
    this.code = code;
  }
}

/** @param {unknown} value */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {{ allowEmpty?: boolean }} [options]
 * @returns {string}
 */
function requireString(value, field, options = {}) {
  if (typeof value !== 'string') {
    throw new FindingValidationError(`${field} must be a string.`);
  }
  const text = value.trim();
  if (!options.allowEmpty && text.length === 0) {
    throw new FindingValidationError(`${field} must not be empty.`);
  }
  return text;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string | undefined}
 */
function optionalString(value, field) {
  if (value === undefined || value === null) {
    return undefined;
  }
  return requireString(value, field);
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {number | undefined}
 */
function optionalNonNegativeInteger(value, field) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Number.isInteger(value) || value < 0) {
    throw new FindingValidationError(`${field} must be a non-negative integer.`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {FindingConfidence | undefined}
 */
function normalizeConfidence(value) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (value !== 'observation' && value !== 'inference' && value !== 'hypothesis') {
    throw new FindingValidationError(
      "confidence must be 'observation', 'inference', or 'hypothesis' when supplied."
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {string[] | undefined}
 */
function normalizeUncertainty(value) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new FindingValidationError('uncertainty must be an array when supplied.');
  }
  return value.map((entry, index) =>
    requireString(entry, `uncertainty[${index}]`, { allowEmpty: true })
  );
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {FindingSeverity}
 */
function normalizeSeverity(value, field = 'severity') {
  if (typeof value !== 'string') {
    throw new FindingValidationError(`${field} must be a string.`);
  }
  const severity = value.trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_KINDS, severity)) {
    throw new FindingValidationError(
      `${field} must be one of ${Object.keys(SEVERITY_KINDS).join(', ')}.`
    );
  }
  return /** @type {FindingSeverity} */ (severity);
}

/**
 * @param {string} severity
 * @returns {SeverityKind}
 */
function severityToKind(severity) {
  return SEVERITY_KINDS[/** @type {FindingSeverity} */ (severity)];
}

/**
 * @param {string} severity
 * @returns {string}
 */
function severityLabel(severity) {
  return SEVERITY_LABELS[/** @type {FindingSeverity} */ (severity)];
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string}
 */
function normalizeCwe(value, field = 'cwe') {
  if (typeof value !== 'string') {
    throw new FindingValidationError(`${field} must be a string.`);
  }
  const match = /^CWE-(\d+)$/i.exec(value.trim());
  if (!match) {
    throw new FindingValidationError(`${field} must use the form CWE-<number>.`);
  }
  const number = Number(match[1]);
  if (!Number.isSafeInteger(number) || number < 1) {
    throw new FindingValidationError(`${field} must contain a positive CWE number.`);
  }
  return `CWE-${number}`;
}

/**
 * @param {string} cwe
 * @returns {string}
 */
function cweUrl(cwe) {
  const match = /^CWE-(\d+)$/.exec(cwe);
  if (!match) {
    throw new FindingValidationError('A normalized finding must carry a valid CWE identifier.');
  }
  return `https://cwe.mitre.org/data/definitions/${match[1]}.html`;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string}
 */
function normalizeFileUri(value, field = 'location.uri') {
  const text = requireString(value, field);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new FindingValidationError(`${field} must be a valid absolute URI.`);
  }
  if (parsed.protocol !== 'file:') {
    throw new FindingValidationError(`${field} must use the file: scheme.`);
  }
  if (!parsed.pathname) {
    throw new FindingValidationError(`${field} must contain a file path.`);
  }
  return text;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string}
 */
function normalizeHttpUrl(value, field = 'url') {
  const text = requireString(value, field);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new FindingValidationError(`${field} must be a valid absolute URL.`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new FindingValidationError(`${field} must use the http: or https: scheme.`);
  }
  return text;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {{ line: number, character: number }}
 */
function normalizePosition(value, field) {
  if (!isPlainObject(value)) {
    throw new FindingValidationError(`${field} must be an object.`);
  }
  const { line, character } = value;
  if (!Number.isInteger(line) || line < 0) {
    throw new FindingValidationError(`${field}.line must be a non-negative integer.`);
  }
  if (!Number.isInteger(character) || character < 0) {
    throw new FindingValidationError(`${field}.character must be a non-negative integer.`);
  }
  return { line, character };
}

/**
 * @param {unknown} value
 * @param {string} [field]
 * @returns {{ start: { line: number, character: number }, end: { line: number, character: number } }}
 */
function normalizeRange(value, field = 'range') {
  if (!isPlainObject(value)) {
    throw new FindingValidationError(`${field} must be an object.`);
  }
  const start = normalizePosition(value.start, `${field}.start`);
  const end = normalizePosition(value.end, `${field}.end`);
  const endIsBeforeStart =
    end.line < start.line || (end.line === start.line && end.character < start.character);
  if (endIsBeforeStart) {
    throw new FindingValidationError(`${field}.end must not precede ${field}.start.`);
  }
  return { start, end };
}

/**
 * @param {unknown} value
 * @returns {{ uri: string, range: ReturnType<typeof normalizeRange> }}
 */
function normalizeLocation(value) {
  if (!isPlainObject(value)) {
    throw new FindingValidationError('location must be an object.');
  }
  return {
    uri: normalizeFileUri(value.uri, 'location.uri'),
    range: normalizeRange(value.range, 'location.range')
  };
}

/**
 * @param {unknown} value
 * @param {number} index
 * @returns {{ label: string, url?: string, uri?: string, range?: ReturnType<typeof normalizeRange> }}
 */
function normalizeSourceReference(value, index) {
  const field = `sourceReferences[${index}]`;
  if (!isPlainObject(value)) {
    throw new FindingValidationError(`${field} must be an object.`);
  }
  const label = requireString(value.label, `${field}.label`);
  /** @type {{ label: string, url?: string, uri?: string, range?: ReturnType<typeof normalizeRange> }} */
  const reference = { label };

  // The backend serializes absent optional fields as null. Treat null exactly
  // as absent; only values that are actually supplied are validated.
  if (value.url !== undefined && value.url !== null) {
    reference.url = normalizeHttpUrl(value.url, `${field}.url`);
  }
  if (value.uri !== undefined && value.uri !== null) {
    reference.uri = normalizeFileUri(value.uri, `${field}.uri`);
  }
  if (value.range !== undefined && value.range !== null) {
    if (!reference.uri) {
      throw new FindingValidationError(`${field}.range requires ${field}.uri.`);
    }
    reference.range = normalizeRange(value.range, `${field}.range`);
  }
  return reference;
}

/**
 * @param {unknown} value
 * @returns {'confirmed' | 'potential' | undefined}
 */
function normalizeVerificationStatus(value) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (value !== 'confirmed' && value !== 'potential') {
    throw new FindingValidationError(
      "verificationStatus must be 'confirmed' or 'potential' when supplied."
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {{ eligible: boolean, description?: string } | undefined}
 */
function normalizeRepair(value) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isPlainObject(value)) {
    throw new FindingValidationError('repair must be an object when supplied.');
  }
  if (typeof value.eligible !== 'boolean') {
    throw new FindingValidationError('repair.eligible must be a boolean.');
  }
  const description = optionalString(value.description, 'repair.description');
  return description === undefined
    ? { eligible: value.eligible }
    : { eligible: value.eligible, description };
}

/**
 * Validate the backend's unified-risk enrichment. The extension never computes
 * this value. A non-null probability is accepted only when explicitly paired
 * with a calibrated-probability kind; the hover renderer still does not show it
 * as a calibrated result.
 *
 * @param {unknown} value
 * @param {string} [field]
 * @returns {{
 *   index: number | null,
 *   scoreKind: RiskScoreKind,
 *   band: string,
 *   probability: number | null,
 *   probabilityKind: ProbabilityKind,
 *   components: Record<string, unknown>,
 *   uncertainty: Record<string, unknown>,
 *   configHash: string | null,
 *   evidenceCount: number,
 *   excludedEvidenceCount: number,
 *   explanation: string[]
 * } | undefined}
 */
function normalizeRiskAssessment(value, field = 'riskAssessment') {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isPlainObject(value)) {
    throw new FindingValidationError(`${field} must be an object.`);
  }
  if (value.scoreKind !== 'heuristic_index') {
    throw new FindingValidationError(`${field}.scoreKind must be "heuristic_index".`);
  }
  if (!isPlainObject(value.components)) {
    throw new FindingValidationError(`${field}.components must be an object.`);
  }
  if (!isPlainObject(value.uncertainty)) {
    throw new FindingValidationError(`${field}.uncertainty must be an object.`);
  }

  const index = value.index === null ? null : value.index;
  if (
    index !== null &&
    (typeof index !== 'number' || !Number.isFinite(index) || index < 0 || index > 1)
  ) {
    throw new FindingValidationError(`${field}.index must be null or a number between 0 and 1.`);
  }
  const probability =
    value.probability === null || value.probability === undefined ? null : value.probability;
  if (
    probability !== null &&
    (typeof probability !== 'number' ||
      !Number.isFinite(probability) ||
      probability < 0 ||
      probability > 1)
  ) {
    throw new FindingValidationError(
      `${field}.probability must be null or a number between 0 and 1.`
    );
  }
  const probabilityKind =
    value.probabilityKind === null || value.probabilityKind === undefined
      ? null
      : value.probabilityKind;
  if (probability !== null && probabilityKind !== 'calibrated_probability') {
    throw new FindingValidationError(
      `${field}.probability requires probabilityKind "calibrated_probability".`
    );
  }
  if (probability === null && probabilityKind !== null) {
    throw new FindingValidationError(`${field}.probabilityKind requires a non-null probability.`);
  }

  const configHash =
    value.configHash === null || value.configHash === undefined
      ? null
      : requireString(value.configHash, `${field}.configHash`);
  if (
    !Number.isInteger(value.evidenceCount) ||
    value.evidenceCount < 0 ||
    !Number.isInteger(value.excludedEvidenceCount) ||
    value.excludedEvidenceCount < 0
  ) {
    throw new FindingValidationError(
      `${field}.evidenceCount and ${field}.excludedEvidenceCount must be non-negative integers.`
    );
  }
  if (!Array.isArray(value.explanation)) {
    throw new FindingValidationError(`${field}.explanation must be an array.`);
  }
  return {
    index,
    scoreKind: 'heuristic_index',
    band: requireString(value.band, `${field}.band`),
    probability,
    probabilityKind,
    components: { ...value.components },
    uncertainty: { ...value.uncertainty },
    configHash,
    evidenceCount: value.evidenceCount,
    excludedEvidenceCount: value.excludedEvidenceCount,
    explanation: value.explanation.map((entry, entryIndex) =>
      requireString(entry, `${field}.explanation[${entryIndex}]`, { allowEmpty: true })
    )
  };
}

/**
 * @param {unknown} rawFinding
 * @returns {{
 *   id: string,
 *   message: string,
 *   severity: FindingSeverity,
 *   severityKind: SeverityKind,
 *   category?: string,
 *   cwe?: string,
 *   ruleId?: string,
 *   filePath?: string,
 *   startLine?: number,
 *   startColumn?: number,
 *   endLine?: number,
 *   endColumn?: number,
 *   documentUri: string,
 *   range: ReturnType<typeof normalizeRange>,
 *   evidence?: string,
 *   explanation?: string,
 *   suggestedRemediation?: string,
 *   confidence?: FindingConfidence,
 *   confidenceBasis?: string,
 *   uncertainty?: string[],
 *   detectionMethod?: string,
 *   verificationStatus?: 'confirmed' | 'potential',
 *   sourceReferences: ReturnType<typeof normalizeSourceReference>[],
 *   repair?: { eligible: boolean, description?: string },
 *   repairEligible: boolean,
 *   riskAssessment?: ReturnType<typeof normalizeRiskAssessment>
 * }}
 */
function normalizeFinding(rawFinding) {
  if (!isPlainObject(rawFinding)) {
    throw new FindingValidationError('Each finding must be an object.');
  }

  const id = requireString(rawFinding.id, 'id');
  const message = requireString(rawFinding.message, 'message');
  const severity = normalizeSeverity(rawFinding.severity, 'severity');
  const location = normalizeLocation(rawFinding.location);
  const category = optionalString(rawFinding.category, 'category');
  const filePath = optionalString(rawFinding.filePath, 'filePath');
  const startLine = optionalNonNegativeInteger(rawFinding.startLine, 'startLine');
  const startColumn = optionalNonNegativeInteger(rawFinding.startColumn, 'startColumn');
  const endLine = optionalNonNegativeInteger(rawFinding.endLine, 'endLine');
  const endColumn = optionalNonNegativeInteger(rawFinding.endColumn, 'endColumn');

  /** @type {string | undefined} */
  let cwe;
  if (rawFinding.cwe !== undefined && rawFinding.cwe !== null) {
    cwe = normalizeCwe(rawFinding.cwe);
  }

  /** @type {string | undefined} */
  let ruleId;
  if (rawFinding.ruleId !== undefined && rawFinding.ruleId !== null) {
    ruleId = requireString(rawFinding.ruleId, 'ruleId');
  }

  const evidence = optionalString(rawFinding.evidence, 'evidence');
  const explanation = optionalString(rawFinding.explanation, 'explanation');
  const suggestedRemediation = optionalString(
    rawFinding.suggestedRemediation,
    'suggestedRemediation'
  );
  const confidence = normalizeConfidence(rawFinding.confidence);
  const confidenceBasis = optionalString(rawFinding.confidenceBasis, 'confidenceBasis');
  const uncertainty = normalizeUncertainty(rawFinding.uncertainty);
  const detectionMethod = optionalString(rawFinding.detectionMethod, 'detectionMethod');
  const verificationStatus = normalizeVerificationStatus(rawFinding.verificationStatus);

  let sourceReferences = [];
  if (rawFinding.sourceReferences !== undefined && rawFinding.sourceReferences !== null) {
    if (!Array.isArray(rawFinding.sourceReferences)) {
      throw new FindingValidationError('sourceReferences must be an array when supplied.');
    }
    sourceReferences = rawFinding.sourceReferences.map(normalizeSourceReference);
  }

  const repair = normalizeRepair(rawFinding.repair);
  const riskAssessment = normalizeRiskAssessment(rawFinding.riskAssessment);

  return {
    id,
    message,
    severity,
    severityKind: severityToKind(severity),
    ...(category === undefined ? {} : { category }),
    ...(cwe === undefined ? {} : { cwe }),
    ...(ruleId === undefined ? {} : { ruleId }),
    ...(filePath === undefined ? {} : { filePath }),
    ...(startLine === undefined ? {} : { startLine }),
    ...(startColumn === undefined ? {} : { startColumn }),
    ...(endLine === undefined ? {} : { endLine }),
    ...(endColumn === undefined ? {} : { endColumn }),
    documentUri: location.uri,
    range: location.range,
    ...(evidence === undefined ? {} : { evidence }),
    ...(explanation === undefined ? {} : { explanation }),
    ...(suggestedRemediation === undefined ? {} : { suggestedRemediation }),
    ...(confidence === undefined ? {} : { confidence }),
    ...(confidenceBasis === undefined ? {} : { confidenceBasis }),
    ...(uncertainty === undefined ? {} : { uncertainty }),
    ...(detectionMethod === undefined ? {} : { detectionMethod }),
    ...(verificationStatus === undefined ? {} : { verificationStatus }),
    sourceReferences,
    ...(repair === undefined ? {} : { repair }),
    repairEligible: repair?.eligible === true,
    ...(riskAssessment === undefined ? {} : { riskAssessment })
  };
}

/**
 * @param {unknown} value
 * @returns {string[]}
 */
function normalizeScanScope(value) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!isPlainObject(value)) {
    throw new FindingValidationError('scope must be an object when supplied.', 'E_INVALID_SCOPE');
  }
  const uris = value.uris;
  if (uris === undefined || uris === null) {
    return [];
  }
  if (!Array.isArray(uris)) {
    throw new FindingValidationError('scope.uris must be an array.', 'E_INVALID_SCOPE');
  }
  return uris.map((uri, index) => normalizeFileUri(uri, `scope.uris[${index}]`));
}

/**
 * Validate one backend scan result.
 *
 * Invalid findings are returned in `rejected` and are never converted into
 * diagnostics. A malformed result envelope or scope rejects the whole result.
 *
 * @param {unknown} rawResult
 * @returns {{
 *   findings: ReturnType<typeof normalizeFinding>[],
 *   rejected: Array<{ index: number | null, code: string, reason: string }>,
 *   scopeUris: string[]
 * }}
 */
function normalizeScanResult(rawResult) {
  let rawFindings;
  let scopeUris = [];

  if (Array.isArray(rawResult)) {
    rawFindings = rawResult;
  } else if (isPlainObject(rawResult) && Array.isArray(rawResult.findings)) {
    rawFindings = rawResult.findings;
    scopeUris = normalizeScanScope(rawResult.scope);
  } else {
    throw new FindingValidationError(
      'The backend scan result must contain a findings array.',
      'E_INVALID_SCAN_RESULT'
    );
  }

  /** @type {ReturnType<typeof normalizeFinding>[]} */
  const findings = [];
  const rejected = [];
  const seenIds = new Set();

  rawFindings.forEach((rawFinding, index) => {
    try {
      const finding = normalizeFinding(rawFinding);
      if (seenIds.has(finding.id)) {
        throw new FindingValidationError(`Duplicate finding id: ${finding.id}.`);
      }
      seenIds.add(finding.id);
      findings.push(finding);
    } catch (error) {
      rejected.push({
        index,
        code: error instanceof FindingValidationError ? error.code : 'E_INVALID_FINDING',
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  });

  return { findings, rejected, scopeUris };
}

/**
 * @param {{ line: number, character: number }} left
 * @param {{ line: number, character: number }} right
 * @returns {number}
 */
function comparePositions(left, right) {
  if (left.line !== right.line) {
    return left.line < right.line ? -1 : 1;
  }
  if (left.character !== right.character) {
    return left.character < right.character ? -1 : 1;
  }
  return 0;
}

/**
 * @param {ReturnType<typeof normalizeRange>} range
 * @param {{ line: number, character: number }} position
 * @returns {boolean}
 */
function rangeContainsPosition(range, position) {
  const afterStart = comparePositions(position, range.start) >= 0;
  const beforeEnd = comparePositions(position, range.end) < 0;
  const emptyAtStart =
    comparePositions(range.start, range.end) === 0 && comparePositions(position, range.start) === 0;
  return afterStart && (beforeEnd || emptyAtStart);
}

/**
 * @param {{ range: ReturnType<typeof normalizeRange> }} finding
 * @param {{ line: number, character: number }} position
 * @returns {boolean}
 */
function findingContainsPosition(finding, position) {
  return rangeContainsPosition(finding.range, position);
}

/**
 * @param {ReturnType<typeof normalizeRange>} left
 * @param {ReturnType<typeof normalizeRange>} right
 * @returns {boolean}
 */
function rangesIntersect(left, right) {
  return (
    comparePositions(left.start, right.end) <= 0 && comparePositions(right.start, left.end) <= 0
  );
}

module.exports = {
  DIAGNOSTIC_SOURCE,
  SEVERITY_KINDS,
  SEVERITY_LABELS,
  FindingValidationError,
  normalizeFinding,
  normalizeScanResult,
  normalizeSeverity,
  normalizeConfidence,
  normalizeUncertainty,
  normalizeVerificationStatus,
  normalizeCwe,
  normalizeFileUri,
  normalizeRange,
  normalizeRiskAssessment,
  severityToKind,
  severityLabel,
  cweUrl,
  comparePositions,
  rangeContainsPosition,
  findingContainsPosition,
  rangesIntersect
};
