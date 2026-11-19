'use strict';

/**
 * Shared redaction helpers for extension errors, logs, and user-facing details.
 *
 * These helpers are intentionally conservative: they bound output length and
 * remove common secret-bearing key/value pairs before a backend problem or
 * child-process error is shown to a developer or written to output logs.
 */

const MAX_REDACTED_LENGTH = 2_000;

const SENSITIVE_KEYS = new Set([
  'api_key',
  'apikey',
  'authorization',
  'credential',
  'credentials',
  'hf_token',
  'password',
  'passwd',
  'secret',
  'token'
]);

const SECRET_PATTERNS = [
  {
    pattern:
      /(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|credential)(\s*[:=]\s*)([^\s,;'"}]+)/gi,
    valueGroup: 3
  },
  { pattern: /(bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, valueGroup: 2 },
  { pattern: /(authorization\s*[:=]\s*)([^\s,;]+)/gi, valueGroup: 2 }
];

/**
 * @param {unknown} value
 * @param {{ limit?: number }} [options]
 * @returns {string}
 */
function redactText(value, { limit = MAX_REDACTED_LENGTH } = {}) {
  if (value === undefined || value === null) {
    return '';
  }
  let text = String(value).replace(/[\x00-\x09\x0b-\x1f\x7f]/g, ' ');
  for (const { pattern, valueGroup } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    text = text.replace(pattern, (...args) => {
      const groups = args.slice(1, -2);
      const prefix = groups.slice(0, valueGroup - 1).join('');
      return `${prefix}[REDACTED]`;
    });
  }
  if (text.length > limit) {
    return `${text.slice(0, limit)}...[TRUNCATED]`;
  }
  return text;
}

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function redactObject(value) {
  if (Array.isArray(value)) {
    return value.map(redactObject);
  }
  if (value !== null && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = SENSITIVE_KEYS.has(key.toLowerCase()) ? '[REDACTED]' : redactObject(item);
    }
    return result;
  }
  if (typeof value === 'string') {
    return redactText(value);
  }
  return value;
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function redactError(error) {
  if (error instanceof Error) {
    return redactText(error.message);
  }
  return redactText(error);
}

/**
 * Redact details attached to child-process failures before logging or display.
 *
 * @param {unknown} error
 * @returns {string | undefined}
 */
function redactProcessDetail(error) {
  if (!error || typeof error !== 'object') {
    return redactText(error) || undefined;
  }
  const candidate = /** @type {any} */ (error);
  const detail = candidate.stderr || candidate.stdout || candidate.message;
  const redacted = redactText(detail);
  return redacted.length > 0 ? redacted : undefined;
}

module.exports = {
  MAX_REDACTED_LENGTH,
  redactError,
  redactObject,
  redactProcessDetail,
  redactText
};
