'use strict';

/**
 * Normalized settings for model-independent workspace monitoring.
 *
 * Every value has a safe default. Monitoring is disabled by default, automatic
 * source sharing needs a separate explicit opt-in, and opening a document is
 * deliberately not a scan trigger by default. No setting refers to an AI
 * provider: monitoring observes files, not their author.
 */

const {
  ANALYSIS_SCOPES,
  DEFAULT_EXCLUDE_GLOBS,
  DEFAULT_SUPPORTED_LANGUAGES
} = require('./changeAnalyzer');

const DEFAULT_MONITORING_SETTINGS = Object.freeze({
  // Master switch and event coverage.
  enabled: false,
  watchWorkspaceFiles: true,
  scanNewFiles: true,
  scanOnOpen: false,
  fullScanOnWorkspaceChange: false,
  onSaveOnly: false,

  // Scheduling and bounded work.
  debounceMs: 750,
  fullScanDebounceMs: 2000,
  maxConcurrentScans: 2,
  analysisScope: 'function',
  maxFileBytes: 1_048_576,
  maxChangedLines: 500,
  maxWorkspaceFiles: 2000,

  // What is eligible for analysis.
  languages: DEFAULT_SUPPORTED_LANGUAGES,
  excludeGlobs: DEFAULT_EXCLUDE_GLOBS,
  excludeBinaryFiles: true,
  excludeGeneratedFiles: true,

  // Privacy and UI.
  allowAutomaticSourceSharing: false,
  sendSourceText: true,
  notifyOnFindings: true
});

/** @param {unknown} value @param {boolean} fallback @returns {boolean} */
function booleanSetting(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} minimum
 * @param {number} maximum
 * @returns {number}
 */
function integerSetting(value, fallback, minimum, maximum) {
  const number = typeof value === 'string' && value.trim().length > 0 ? Number(value) : value;
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(maximum, Math.max(minimum, Math.round(number)));
}

/** @param {unknown} value @param {readonly string[]} fallback @returns {string[]} */
function stringArraySetting(value, fallback) {
  if (!Array.isArray(value)) {
    return [...fallback];
  }
  const entries = value.filter((entry) => typeof entry === 'string' && entry.trim().length > 0);
  return entries.length > 0 ? entries.map((entry) => entry.trim()) : [...fallback];
}

/**
 * @param {unknown} raw
 * @returns {Readonly<typeof DEFAULT_MONITORING_SETTINGS & { languages: string[], excludeGlobs: string[] }>}
 */
function normalizeMonitoringSettings(raw) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const scope = ANALYSIS_SCOPES.includes(source.analysisScope)
    ? source.analysisScope
    : DEFAULT_MONITORING_SETTINGS.analysisScope;
  return Object.freeze({
    enabled: booleanSetting(source.enabled, DEFAULT_MONITORING_SETTINGS.enabled),
    watchWorkspaceFiles: booleanSetting(
      source.watchWorkspaceFiles,
      DEFAULT_MONITORING_SETTINGS.watchWorkspaceFiles
    ),
    scanNewFiles: booleanSetting(source.scanNewFiles, DEFAULT_MONITORING_SETTINGS.scanNewFiles),
    scanOnOpen: booleanSetting(source.scanOnOpen, DEFAULT_MONITORING_SETTINGS.scanOnOpen),
    fullScanOnWorkspaceChange: booleanSetting(
      source.fullScanOnWorkspaceChange,
      DEFAULT_MONITORING_SETTINGS.fullScanOnWorkspaceChange
    ),
    onSaveOnly: booleanSetting(source.onSaveOnly, DEFAULT_MONITORING_SETTINGS.onSaveOnly),
    debounceMs: integerSetting(source.debounceMs, DEFAULT_MONITORING_SETTINGS.debounceMs, 100, 10_000),
    fullScanDebounceMs: integerSetting(
      source.fullScanDebounceMs,
      DEFAULT_MONITORING_SETTINGS.fullScanDebounceMs,
      100,
      60_000
    ),
    maxConcurrentScans: integerSetting(
      source.maxConcurrentScans,
      DEFAULT_MONITORING_SETTINGS.maxConcurrentScans,
      1,
      8
    ),
    analysisScope: scope,
    maxFileBytes: integerSetting(
      source.maxFileBytes,
      DEFAULT_MONITORING_SETTINGS.maxFileBytes,
      1024,
      10 * 1024 * 1024
    ),
    maxChangedLines: integerSetting(
      source.maxChangedLines,
      DEFAULT_MONITORING_SETTINGS.maxChangedLines,
      1,
      10_000
    ),
    maxWorkspaceFiles: integerSetting(
      source.maxWorkspaceFiles,
      DEFAULT_MONITORING_SETTINGS.maxWorkspaceFiles,
      100,
      50_000
    ),
    languages: stringArraySetting(source.languages, DEFAULT_MONITORING_SETTINGS.languages),
    excludeGlobs: stringArraySetting(source.excludeGlobs, DEFAULT_MONITORING_SETTINGS.excludeGlobs),
    excludeBinaryFiles: booleanSetting(
      source.excludeBinaryFiles,
      DEFAULT_MONITORING_SETTINGS.excludeBinaryFiles
    ),
    excludeGeneratedFiles: booleanSetting(
      source.excludeGeneratedFiles,
      DEFAULT_MONITORING_SETTINGS.excludeGeneratedFiles
    ),
    allowAutomaticSourceSharing: booleanSetting(
      source.allowAutomaticSourceSharing,
      DEFAULT_MONITORING_SETTINGS.allowAutomaticSourceSharing
    ),
    sendSourceText: booleanSetting(source.sendSourceText, DEFAULT_MONITORING_SETTINGS.sendSourceText),
    notifyOnFindings: booleanSetting(
      source.notifyOnFindings,
      DEFAULT_MONITORING_SETTINGS.notifyOnFindings
    )
  });
}

module.exports = { DEFAULT_MONITORING_SETTINGS, normalizeMonitoringSettings };
