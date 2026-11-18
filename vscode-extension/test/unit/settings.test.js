'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_MONITORING_SETTINGS,
  normalizeMonitoringSettings
} = require('../../src/monitoring/settings');

test('monitoring defaults are conservative and provider independent', () => {
  assert.equal(DEFAULT_MONITORING_SETTINGS.enabled, false);
  assert.equal(DEFAULT_MONITORING_SETTINGS.allowAutomaticSourceSharing, false);
  assert.equal(DEFAULT_MONITORING_SETTINGS.scanOnOpen, false);
  assert.equal(DEFAULT_MONITORING_SETTINGS.fullScanOnWorkspaceChange, false);
  assert.equal(DEFAULT_MONITORING_SETTINGS.watchWorkspaceFiles, true);
  assert.equal(DEFAULT_MONITORING_SETTINGS.scanNewFiles, true);
  assert.equal(DEFAULT_MONITORING_SETTINGS.excludeBinaryFiles, true);
  assert.equal(DEFAULT_MONITORING_SETTINGS.excludeGeneratedFiles, true);
  assert.deepEqual(DEFAULT_MONITORING_SETTINGS.languages, ['python', 'javascript']);
});

test('normalizeMonitoringSettings clamps numeric values and validates scope', () => {
  const settings = normalizeMonitoringSettings({
    debounceMs: 10,
    fullScanDebounceMs: 0,
    maxConcurrentScans: 99,
    maxWorkspaceFiles: -5,
    maxFileBytes: 'not-a-number',
    analysisScope: 'invalid'
  });

  assert.equal(settings.debounceMs, 100);
  assert.equal(settings.fullScanDebounceMs, 100);
  assert.equal(settings.maxConcurrentScans, 8);
  assert.equal(settings.maxWorkspaceFiles, 100);
  assert.equal(settings.maxFileBytes, DEFAULT_MONITORING_SETTINGS.maxFileBytes);
  assert.equal(settings.analysisScope, 'function');
  assert.ok(Object.isFrozen(settings));
});

test('normalizeMonitoringSettings preserves booleans and non-empty arrays', () => {
  const settings = normalizeMonitoringSettings({
    enabled: true,
    scanOnOpen: true,
    languages: ['typescript', '', 'python'],
    excludeGlobs: ['**/custom/**']
  });

  assert.equal(settings.enabled, true);
  assert.equal(settings.scanOnOpen, true);
  assert.deepEqual(settings.languages, ['typescript', 'python']);
  assert.deepEqual(settings.excludeGlobs, ['**/custom/**']);
});
