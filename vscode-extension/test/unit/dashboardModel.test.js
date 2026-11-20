'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { COMMANDS } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const {
  DASHBOARD_SCHEMA_VERSION,
  DASHBOARD_SECTIONS,
  DASHBOARD_ACTIONS,
  ENGINE_UNAVAILABLE,
  buildDashboardState,
  createEmptyDashboardState,
  normalizeEngine,
  normalizeSettings
} = require('../../src/webviews/dashboardModel');

const SECTION_IDS = [
  'overview',
  'scan',
  'vulnerabilities',
  'saeFeatures',
  'featureInteractions',
  'securitySteering',
  'explanations',
  'automatedRepair',
  'verification',
  'researchReports',
  'settings'
];

test('dashboard sections are canonical and complete', () => {
  assert.deepEqual(
    DASHBOARD_SECTIONS.map((section) => section.id),
    SECTION_IDS
  );
  assert.equal(new Set(SECTION_IDS).size, 11);
  for (const section of DASHBOARD_SECTIONS) {
    assert.equal(typeof section.label, 'string');
    assert.ok(section.label.length > 1);
    assert.equal(typeof section.description, 'string');
    assert.ok(section.description.length > 0);
  }
});

test('dashboard actions only reference engine-backed commands', () => {
  const engineCommands = new Set(
    COMMAND_DEFINITIONS.filter((definition) => definition.serviceMethod).map(
      (definition) => definition.id
    )
  );

  assert.ok(DASHBOARD_ACTIONS.length > 0);
  assert.equal(
    new Set(DASHBOARD_ACTIONS.map((action) => action.id)).size,
    DASHBOARD_ACTIONS.length
  );

  for (const action of DASHBOARD_ACTIONS) {
    assert.ok(engineCommands.has(action.command), `${action.command} must be engine-backed`);
    assert.ok(SECTION_IDS.includes(action.section));
    assert.equal(typeof action.title, 'string');
    assert.equal(typeof action.description, 'string');
    assert.equal(typeof action.meta, 'string');
  }

  const commands = DASHBOARD_ACTIONS.map((action) => action.command);
  assert.ok(commands.includes(COMMANDS.scanCurrentFile));
  assert.ok(commands.includes(COMMANDS.scanWorkspace));
  assert.ok(commands.includes(COMMANDS.verifyRepair));
});

test('empty dashboard state reports unknowns as null, never zero', () => {
  const state = createEmptyDashboardState({ generatedAt: '2026-11-11T12:00:00.000Z' });

  assert.equal(state.schemaVersion, DASHBOARD_SCHEMA_VERSION);
  assert.equal(state.dataMode, 'empty');
  assert.equal(state.demoNotice, undefined);
  assert.equal(state.generatedAt, '2026-11-11T12:00:00.000Z');
  assert.equal(state.sections, DASHBOARD_SECTIONS);
  assert.equal(state.actions, DASHBOARD_ACTIONS);
  assert.equal(state.summary.totalFindings, null);
  assert.deepEqual(state.summary.severity, {
    critical: null,
    high: null,
    medium: null,
    low: null
  });
  assert.equal(state.summary.lastScanAt, null);
  assert.equal(state.summary.workspaceName, null);
  assert.deepEqual(state.workspace, {
    available: false,
    name: null,
    path: null,
    folders: []
  });
  assert.deepEqual(state.inventory, {
    available: false,
    totalFiles: null,
    languages: {},
    truncated: null
  });
  assert.deepEqual(state.scanStatus, {
    discoveredFiles: null,
    scannedFiles: null,
    pendingFiles: null,
    failedFiles: null,
    failedScans: null
  });
  assert.deepEqual(state.repairHistory, []);
  assert.deepEqual(state.vulnerabilityDistribution, []);
  assert.deepEqual(state.cweDistribution, []);
  assert.deepEqual(state.scanHistory, []);
  assert.deepEqual(state.vulnerabilities, []);
  assert.deepEqual(state.explanations, []);
  assert.deepEqual(state.repairs, []);
  assert.deepEqual(state.reports, []);
  assert.equal(state.sae.available, false);
  assert.deepEqual(state.sae.features, []);
  assert.equal(state.featureInteractions.available, false);
  assert.deepEqual(state.featureInteractions.items, []);
  assert.equal(state.featureInteractions.baselineRisk, null);
  assert.deepEqual(state.featureInteractions.singleFeatureEffects, []);
  assert.deepEqual(state.featureInteractions.pairwiseEffects, []);
  assert.deepEqual(state.featureInteractions.higherOrderEffects, []);
  assert.deepEqual(state.featureInteractions.activationChanges, []);
  assert.deepEqual(state.featureInteractions.cweResults, []);
  assert.equal(state.featureInteractions.metadata, null);
  assert.equal(state.steering.available, false);
  assert.deepEqual(state.steering.controls, []);
  assert.equal(state.verification.status, 'not-run');
  assert.equal(state.verification.label, 'Not run');
  assert.deepEqual(state.verification.checks, []);
  assert.equal(state.verification.executionSandbox.available, false);
  assert.deepEqual(state.engine, ENGINE_UNAVAILABLE);
});

test('dashboard state contains no sample findings, scan history, or research results', () => {
  const state = createEmptyDashboardState({ generatedAt: '2026-11-11T12:00:00.000Z' });

  assert.equal(state.summary.totalFindings, null);
  assert.equal(state.scanStatus.scannedFiles, null);
  assert.equal(state.scanStatus.pendingFiles, null);
  assert.equal(state.scanStatus.failedFiles, null);
  assert.deepEqual(state.scanHistory, []);
  assert.deepEqual(state.vulnerabilities, []);
  assert.deepEqual(state.cweDistribution, []);
  assert.deepEqual(state.vulnerabilityDistribution, []);
  assert.deepEqual(state.repairHistory, []);
  assert.deepEqual(state.explanations, []);
  assert.deepEqual(state.repairs, []);
  assert.deepEqual(state.recommendations, []);
  assert.deepEqual(state.reports, []);
  assert.equal(state.sae.available, false);
  assert.deepEqual(state.sae.features, []);
  assert.equal(state.featureInteractions.available, false);
  assert.deepEqual(state.featureInteractions.items, []);
  assert.equal(state.steering.available, false);
  assert.deepEqual(state.steering.controls, []);
  assert.equal(state.verification.status, 'not-run');
  assert.deepEqual(state.verification.checks, []);
  assert.equal(state.verification.executionSandbox.available, false);
  assert.ok(!/\bdemo\b/i.test(JSON.stringify(state)), 'no demo marker may be serialized');
});

test('buildDashboardState never invents live or demo data', () => {
  const generatedAt = '2026-11-11T12:00:00.000Z';
  const empty = buildDashboardState({ dataMode: 'empty', generatedAt });
  const live = buildDashboardState({ dataMode: 'live', generatedAt });
  const unsupported = buildDashboardState({ dataMode: 'demo', generatedAt });

  for (const state of [empty, live, unsupported]) {
    assert.equal(state.dataMode, 'empty');
    assert.equal(state.demoNotice, undefined);
    assert.equal(state.summary.totalFindings, null);
    assert.equal(state.summary.lastScanAt, null);
    assert.deepEqual(state.vulnerabilities, []);
    assert.deepEqual(state.scanHistory, []);
    assert.deepEqual(state.repairHistory, []);
    assert.ok(!/\bdemo\b/i.test(JSON.stringify(state)), 'no demo marker may be serialized');
  }
});

test('settings and engine normalization reject unsupported values', () => {
  assert.deepEqual(normalizeSettings(), {
    pythonPath: '',
    autoStart: false,
    logLevel: 'info',
    showStatusBarItem: true
  });
  assert.deepEqual(
    normalizeSettings({
      pythonPath: '/usr/bin/python3',
      autoStart: true,
      logLevel: 'trace',
      showStatusBarItem: false
    }),
    {
      pythonPath: '/usr/bin/python3',
      autoStart: true,
      logLevel: 'trace',
      showStatusBarItem: false
    }
  );
  assert.equal(normalizeSettings({ logLevel: 'verbose' }).logLevel, 'info');
  assert.equal(normalizeSettings({ showStatusBarItem: null }).showStatusBarItem, true);

  assert.deepEqual(normalizeEngine({ status: 'ready', label: 'Ready', detail: 'OK' }), {
    status: 'ready',
    label: 'Ready',
    detail: 'OK'
  });
  assert.deepEqual(normalizeEngine(), ENGINE_UNAVAILABLE);
});

test('state options inject settings without changing other sections', () => {
  const state = createEmptyDashboardState({
    settings: {
      pythonPath: '/custom/python',
      autoStart: true,
      logLevel: 'warn',
      showStatusBarItem: false
    },
    engine: { status: 'ready', label: 'Engine ready', detail: 'Capabilities loaded.' }
  });

  assert.equal(state.settings.pythonPath, '/custom/python');
  assert.equal(state.settings.autoStart, true);
  assert.equal(state.settings.logLevel, 'warn');
  assert.equal(state.settings.showStatusBarItem, false);
  assert.equal(state.engine.status, 'ready');
  assert.deepEqual(state.vulnerabilities, []);
});
