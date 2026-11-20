'use strict';

const { COMMANDS } = require('../constants');

const DASHBOARD_SCHEMA_VERSION = 1;

/**
 * Canonical dashboard navigation. The webview shell, client renderer, and
 * tests all use this list so section labels cannot drift.
 */
const DASHBOARD_SECTIONS = Object.freeze([
  Object.freeze({
    id: 'overview',
    label: 'Overview',
    icon: 'overview',
    description: 'Security posture, findings, verification, and recent activity.'
  }),
  Object.freeze({
    id: 'scan',
    label: 'Security Scan',
    icon: 'scan',
    description: 'Start a scan and review scan history.'
  }),
  Object.freeze({
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    icon: 'vulnerabilities',
    description: 'Findings by severity, CWE, location, and status.'
  }),
  Object.freeze({
    id: 'saeFeatures',
    label: 'SAE Features',
    icon: 'features',
    description: 'Features measured from a genuine SAE and white-box model.'
  }),
  Object.freeze({
    id: 'featureInteractions',
    label: 'Feature Interactions',
    icon: 'interactions',
    description: 'Counterfactual feature comparisons and their evidence.'
  }),
  Object.freeze({
    id: 'securitySteering',
    label: 'Security Steering',
    icon: 'steering',
    description: 'Capability-gated activation steering controls.'
  }),
  Object.freeze({
    id: 'explanations',
    label: 'Explanations',
    icon: 'explanations',
    description: 'Evidence-backed explanations for reported findings.'
  }),
  Object.freeze({
    id: 'automatedRepair',
    label: 'Automated Repair',
    icon: 'repair',
    description: 'Reviewable repair proposals; source is never modified silently.'
  }),
  Object.freeze({
    id: 'verification',
    label: 'Verification',
    icon: 'verification',
    description: 'Static, functional, and isolated execution verification.'
  }),
  Object.freeze({
    id: 'researchReports',
    label: 'Research Reports',
    icon: 'reports',
    description: 'Reports generated from recorded runs with full provenance.'
  }),
  Object.freeze({
    id: 'settings',
    label: 'Settings',
    icon: 'settings',
    description: 'Extension settings and dashboard data mode.'
  })
]);

/**
 * Commands the dashboard may request. Only engine-backed commands are listed;
 * the panel controller independently rejects anything outside its allowlist.
 */
const DASHBOARD_ACTIONS = Object.freeze([
  Object.freeze({
    id: 'scan-current-file',
    section: 'scan',
    command: COMMANDS.scanCurrentFile,
    title: 'Scan current file',
    description: 'Analyze the saved active editor for security-relevant evidence.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'scan-selection',
    section: 'scan',
    command: COMMANDS.scanSelection,
    title: 'Scan selection',
    description: 'Analyze the selected region of the active saved editor.',
    meta: 'Requires a non-empty selection'
  }),
  Object.freeze({
    id: 'scan-workspace',
    section: 'scan',
    command: COMMANDS.scanWorkspace,
    title: 'Scan workspace',
    description: 'Analyze every open workspace folder.',
    meta: 'Requires an open workspace'
  }),
  Object.freeze({
    id: 'analyze-security-features',
    section: 'saeFeatures',
    command: COMMANDS.analyzeSecurityFeatures,
    title: 'Analyze security features',
    description: 'Extract features from a compatible model and genuine SAE artifact.',
    meta: 'Requires model and SAE access'
  }),
  Object.freeze({
    id: 'counterfactual-analysis',
    section: 'featureInteractions',
    command: COMMANDS.counterfactualAnalysis,
    title: 'Run counterfactual analysis',
    description: 'Compare the selected region with defined model interventions.',
    meta: 'Requires measured features'
  }),
  Object.freeze({
    id: 'explain-vulnerability',
    section: 'explanations',
    command: COMMANDS.explainVulnerability,
    title: 'Explain vulnerability',
    description: 'Build an evidence graph around a reported finding.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'generate-secure-code',
    section: 'automatedRepair',
    command: COMMANDS.generateSecureCode,
    title: 'Generate secure code',
    description: 'Ask the engine for a secure alternative to the current context.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'propose-repair',
    section: 'automatedRepair',
    command: COMMANDS.repairVulnerability,
    title: 'Propose repair',
    description: 'Generate a reviewable patch proposal; no source is modified automatically.',
    meta: 'Requires a saved file'
  }),
  Object.freeze({
    id: 'verify-repair',
    section: 'verification',
    command: COMMANDS.verifyRepair,
    title: 'Verify repair',
    description: 'Run independent security and functional verification on an approved patch.',
    meta: 'Requires an open workspace'
  })
]);

const ENGINE_UNAVAILABLE = Object.freeze({
  status: 'unavailable',
  label: 'Backend not connected',
  detail:
    'The dashboard renders only results supplied by a connected local backend. Parsing, ' +
    'program analysis, detection, explanation, repair, and verification are wired backend ' +
    'paths; model-internal SAE, counterfactual, and steering results require configured ' +
    'compatible artifacts and are never simulated.'
});

const DEFAULT_SETTINGS = Object.freeze({
  pythonPath: '',
  autoStart: false,
  logLevel: 'info',
  showStatusBarItem: true
});

const LOG_LEVELS = Object.freeze(['trace', 'debug', 'info', 'warn', 'error', 'off']);

/**
 * @param {Partial<typeof DEFAULT_SETTINGS>} [settings]
 */
function normalizeSettings(settings = {}) {
  return {
    pythonPath: typeof settings.pythonPath === 'string' ? settings.pythonPath : '',
    autoStart: Boolean(settings.autoStart),
    logLevel: LOG_LEVELS.includes(settings.logLevel) ? settings.logLevel : 'info',
    showStatusBarItem: settings.showStatusBarItem !== false
  };
}

/**
 * @param {{ status?: string, label?: string, detail?: string }} [engine]
 */
function normalizeEngine(engine = ENGINE_UNAVAILABLE) {
  return {
    status: typeof engine.status === 'string' ? engine.status : 'unavailable',
    label: typeof engine.label === 'string' ? engine.label : ENGINE_UNAVAILABLE.label,
    detail: typeof engine.detail === 'string' ? engine.detail : ENGINE_UNAVAILABLE.detail
  };
}

/** @returns {object} */
function unavailableSaeState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'SAE features require a compatible SAE artifact and a white-box model with accessible ' +
      'activations. No activation values are simulated or inferred.',
    provenance: null,
    features: []
  };
}

/** @returns {object} */
function unavailableInteractionState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'Feature interactions require measured activations and a counterfactual run. Estimated ' +
      'effects are not real-world causal claims.',
    items: [],
    baselineRisk: null,
    singleFeatureEffects: [],
    pairwiseEffects: [],
    higherOrderEffects: [],
    activationChanges: [],
    cweResults: [],
    metadata: null,
    unavailableEvidence: ['No counterfactual experiment has supplied measured results.']
  };
}

/** @returns {object} */
function unavailableSteeringState() {
  return {
    available: false,
    statusLabel: 'Unavailable',
    message:
      'Activation steering requires a compatible white-box model, accessible activations, and a ' +
      'steering-capable SAE. No steering is performed in this build.',
    controls: []
  };
}

/** @returns {object} */
function executionSandboxState() {
  return {
    available: false,
    label: 'Execution sandbox unavailable',
    detail:
      'Execution-based verification requires an isolated sandbox with workspace containment, a ' +
      'scrubbed environment, resource limits, and process-group termination. None is configured.'
  };
}

/** @returns {object} */
function notRunVerificationState() {
  return {
    status: 'not-run',
    label: 'Not run',
    summary: 'No verification has been run for this workspace.',
    checks: [],
    lastRunAt: null,
    executionSandbox: executionSandboxState()
  };
}

/** @returns {object} */
function emptyFeedbackState() {
  return {
    findings: [],
    patchHistory: [],
    stats: {
      scans: 0,
      suppressed: 0,
      followUpRescans: 0,
      patches: 0,
      verifications: 0,
      resolutions: 0
    }
  };
}

/**
 * @param {{
 *   settings?: Partial<typeof DEFAULT_SETTINGS>,
 *   engine?: { status?: string, label?: string, detail?: string },
 *   generatedAt?: string
 * }} [options]
 */
function createEmptyDashboardState(options = {}) {
  return {
    schemaVersion: DASHBOARD_SCHEMA_VERSION,
    dataMode: 'empty',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    sections: DASHBOARD_SECTIONS,
    actions: DASHBOARD_ACTIONS,
    engine: normalizeEngine(options.engine),
    // All of these are unknown until the extension host supplies observed data.
    // A missing value is never replaced with a zero or a sample record.
    workspace: {
      available: false,
      name: null,
      path: null,
      folders: []
    },
    inventory: {
      available: false,
      totalFiles: null,
      languages: {},
      truncated: null
    },
    scanStatus: {
      discoveredFiles: null,
      scannedFiles: null,
      pendingFiles: null,
      failedFiles: null,
      failedScans: null
    },
    summary: {
      totalFindings: null,
      severity: { critical: null, high: null, medium: null, low: null },
      categories: {},
      statuses: {},
      lastScanAt: null,
      workspaceName: null
    },
    vulnerabilityDistribution: [],
    cweDistribution: [],
    scanHistory: [],
    vulnerabilities: [],
    findingReviews: {},
    sae: unavailableSaeState(),
    featureInteractions: unavailableInteractionState(),
    steering: unavailableSteeringState(),
    explanations: [],
    repairs: [],
    repairHistory: [],
    recommendations: [],
    recommendationHistory: [],
    feedback: emptyFeedbackState(),
    verification: notRunVerificationState(),
    reports: [],
    settings: normalizeSettings(options.settings)
  };
}

/**
 * @param {{
 *   dataMode?: 'empty' | 'live',
 *   settings?: Partial<typeof DEFAULT_SETTINGS>,
 *   engine?: { status?: string, label?: string, detail?: string },
 *   generatedAt?: string
 * }} [options]
 */
function buildDashboardState(options = {}) {
  // There is no sample-data mode. The panel overlays only results that the
  // extension host observed; this function never invents a scan result.
  return createEmptyDashboardState(options);
}

module.exports = {
  DASHBOARD_SCHEMA_VERSION,
  DASHBOARD_SECTIONS,
  DASHBOARD_ACTIONS,
  ENGINE_UNAVAILABLE,
  DEFAULT_SETTINGS,
  LOG_LEVELS,
  normalizeSettings,
  normalizeEngine,
  createEmptyDashboardState,
  emptyFeedbackState,
  buildDashboardState
};
