'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_MONITORING_SETTINGS,
  normalizeMonitoringSettings
} = require('../../src/monitoring/settings');
const {
  extensionOf,
  isBinaryPath,
  isGeneratedPath,
  languageForPath,
  isWithinWorkspace,
  evaluateFileEligibility
} = require('../../src/monitoring/fileFilter');

const FOLDERS = [{ uri: { scheme: 'file', fsPath: '/workspace' } }];
const SETTINGS = normalizeMonitoringSettings(DEFAULT_MONITORING_SETTINGS);

/** @param {Partial<Record<string, unknown>>} overrides */
function eligibility(overrides = {}) {
  return evaluateFileEligibility({
    fsPath: '/workspace/src/app.py',
    languageId: 'python',
    settings: SETTINGS,
    workspaceFolders: FOLDERS,
    ...overrides
  });
}

test('classifies extensions without reading file content', () => {
  assert.equal(extensionOf('/workspace/App.PY'), '.py');
  assert.equal(languageForPath('/workspace/app.py'), 'python');
  assert.equal(languageForPath('/workspace/app.mjs'), 'javascript');
  assert.equal(languageForPath('/workspace/app.unknown'), undefined);
  assert.equal(isBinaryPath('/workspace/image.png'), true);
  assert.equal(isBinaryPath('/workspace/app.py'), false);
  assert.equal(isGeneratedPath('/workspace/app.min.js'), true);
  assert.equal(isGeneratedPath('/workspace/package-lock.json'), true);
  assert.equal(isGeneratedPath('/workspace/app.js'), false);
});

test('accepts eligible source files inside the workspace', () => {
  assert.deepEqual(eligibility(), { eligible: true });
  assert.equal(isWithinWorkspace('/workspace/src/app.py', FOLDERS), true);
  assert.equal(isWithinWorkspace('/other/app.py', FOLDERS), false);
});

test('rejects generated, vendored, virtual-environment, and binary paths by default', () => {
  const cases = [
    ['/workspace/node_modules/pkg/index.js', 'excluded-path'],
    ['/workspace/.git/hooks/pre-commit', 'excluded-path'],
    ['/workspace/.venv/lib/x.py', 'excluded-path'],
    ['/workspace/site-packages/x.py', 'excluded-path'],
    ['/workspace/dist/bundle.js', 'excluded-path'],
    ['/workspace/build/generated.py', 'excluded-path'],
    ['/workspace/src/app.pyc', 'binary-file'],
    ['/workspace/image.png', 'binary-file'],
    ['/workspace/app.min.js', 'generated-file'],
    ['/workspace/package-lock.json', 'generated-file']
  ];

  for (const [fsPath, reason] of cases) {
    assert.deepEqual(eligibility({ fsPath }), { eligible: false, reason });
  }
});

test('rejects unsupported languages, oversized files, and paths outside the workspace', () => {
  assert.deepEqual(eligibility({ languageId: 'ruby' }), {
    eligible: false,
    reason: 'unsupported-language'
  });
  assert.deepEqual(eligibility({ sizeBytes: SETTINGS.maxFileBytes + 1 }), {
    eligible: false,
    reason: 'file-too-large'
  });
  assert.deepEqual(eligibility({ fsPath: '/elsewhere/app.py' }), {
    eligible: false,
    reason: 'outside-workspace'
  });
  assert.deepEqual(eligibility({ fsPath: '/elsewhere/app.py', requireWorkspace: false }), {
    eligible: true
  });
});

test('optional filters can be disabled while path and language rules remain', () => {
  const settings = normalizeMonitoringSettings({
    excludeBinaryFiles: false,
    excludeGeneratedFiles: false
  });
  assert.deepEqual(
    evaluateFileEligibility({
      fsPath: '/workspace/app.min.js',
      languageId: 'javascript',
      settings,
      workspaceFolders: FOLDERS
    }),
    { eligible: true }
  );
});
