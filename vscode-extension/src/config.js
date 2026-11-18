'use strict';

const vscode = require('vscode');

const {
  SECTION,
  DEFAULT_BACKEND_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEALTH_TIMEOUT_MS
} = require('./api/configurationService');
const { DEFAULT_MONITORING_SETTINGS } = require('./monitoring/settings');

/**
 * @typedef {Object} ExtensionSettings
 * @property {string} pythonPath
 * @property {boolean} autoStart
 * @property {string} backendUrl
 * @property {number} requestTimeoutMs
 * @property {number} healthTimeoutMs
 * @property {boolean} sendSourceText
 * @property {string} logLevel
 * @property {boolean} showStatusBarItem
 * @property {boolean} monitoringEnabled
 * @property {boolean} monitoringOnSaveOnly
 * @property {number} monitoringDebounceMs
 * @property {string[]} monitoringLanguages
 * @property {string} monitoringAnalysisScope
 * @property {number} monitoringMaxFileBytes
 * @property {number} monitoringMaxChangedLines
 * @property {boolean} monitoringAllowAutomaticSourceSharing
 * @property {boolean} monitoringNotifyOnFindings
 * @property {string[]} monitoringExcludeGlobs
 * @property {boolean} monitoringWatchWorkspaceFiles
 * @property {boolean} monitoringScanNewFiles
 * @property {boolean} monitoringScanOnOpen
 * @property {boolean} monitoringFullScanOnWorkspaceChange
 * @property {number} monitoringFullScanDebounceMs
 * @property {number} monitoringMaxConcurrentScans
 * @property {number} monitoringMaxWorkspaceFiles
 * @property {boolean} monitoringExcludeBinaryFiles
 * @property {boolean} monitoringExcludeGeneratedFiles
 * @property {string} assistantProvider
 * @property {object} assistantVscodeLanguageModelSelector
 * @property {string} assistantOpenAiEndpoint
 * @property {string} assistantOpenAiModel
 * @property {string} assistantOpenAiApiKeyEnvironmentVariable
 * @property {string} assistantLocalModelPath
 * @property {string} assistantExtensionManifestPath
 * @property {boolean} assistantSaeEnabled
 * @property {boolean} assistantCounterfactualEnabled
 * @property {boolean} feedbackNotifyOnPatchApplied
 * @property {boolean} feedbackNotifyOnResolution
 * @property {boolean} recommendationRunFunctionalTests
 * @property {boolean} recommendationAllowSandboxedExecution
 * @property {string[]} recommendationTestCommand
 * @property {number} recommendationTestTimeoutSeconds
 */

/** @returns {vscode.WorkspaceConfiguration} */
function getConfiguration() {
  return vscode.workspace.getConfiguration(SECTION);
}

/** @returns {ExtensionSettings} */
function readSettings() {
  const configuration = getConfiguration();
  return {
    pythonPath: configuration.get('backend.pythonPath', ''),
    autoStart: configuration.get('backend.autoStart', false),
    backendUrl: configuration.get('backend.url', DEFAULT_BACKEND_URL),
    requestTimeoutMs: configuration.get('backend.requestTimeoutMs', DEFAULT_REQUEST_TIMEOUT_MS),
    healthTimeoutMs: configuration.get('backend.healthTimeoutMs', DEFAULT_HEALTH_TIMEOUT_MS),
    sendSourceText: configuration.get('privacy.sendSourceText', true),
    logLevel: configuration.get('logging.level', 'info'),
    showStatusBarItem: configuration.get('ui.showStatusBarItem', true),
    monitoringEnabled: configuration.get('monitoring.enabled', DEFAULT_MONITORING_SETTINGS.enabled),
    monitoringOnSaveOnly: configuration.get(
      'monitoring.onSaveOnly',
      DEFAULT_MONITORING_SETTINGS.onSaveOnly
    ),
    monitoringDebounceMs: configuration.get(
      'monitoring.debounceMs',
      DEFAULT_MONITORING_SETTINGS.debounceMs
    ),
    monitoringLanguages: configuration.get('monitoring.languages', [
      ...DEFAULT_MONITORING_SETTINGS.languages
    ]),
    monitoringAnalysisScope: configuration.get(
      'monitoring.analysisScope',
      DEFAULT_MONITORING_SETTINGS.analysisScope
    ),
    monitoringMaxFileBytes: configuration.get(
      'monitoring.maxFileBytes',
      DEFAULT_MONITORING_SETTINGS.maxFileBytes
    ),
    monitoringMaxChangedLines: configuration.get(
      'monitoring.maxChangedLines',
      DEFAULT_MONITORING_SETTINGS.maxChangedLines
    ),
    monitoringAllowAutomaticSourceSharing: configuration.get(
      'monitoring.allowAutomaticSourceSharing',
      DEFAULT_MONITORING_SETTINGS.allowAutomaticSourceSharing
    ),
    monitoringNotifyOnFindings: configuration.get(
      'monitoring.notifyOnFindings',
      DEFAULT_MONITORING_SETTINGS.notifyOnFindings
    ),
    monitoringExcludeGlobs: configuration.get('monitoring.excludeGlobs', [
      ...DEFAULT_MONITORING_SETTINGS.excludeGlobs
    ]),
    monitoringWatchWorkspaceFiles: configuration.get(
      'monitoring.watchWorkspaceFiles',
      DEFAULT_MONITORING_SETTINGS.watchWorkspaceFiles
    ),
    monitoringScanNewFiles: configuration.get(
      'monitoring.scanNewFiles',
      DEFAULT_MONITORING_SETTINGS.scanNewFiles
    ),
    monitoringScanOnOpen: configuration.get(
      'monitoring.scanOnOpen',
      DEFAULT_MONITORING_SETTINGS.scanOnOpen
    ),
    monitoringFullScanOnWorkspaceChange: configuration.get(
      'monitoring.fullScanOnWorkspaceChange',
      DEFAULT_MONITORING_SETTINGS.fullScanOnWorkspaceChange
    ),
    monitoringFullScanDebounceMs: configuration.get(
      'monitoring.fullScanDebounceMs',
      DEFAULT_MONITORING_SETTINGS.fullScanDebounceMs
    ),
    monitoringMaxConcurrentScans: configuration.get(
      'monitoring.maxConcurrentScans',
      DEFAULT_MONITORING_SETTINGS.maxConcurrentScans
    ),
    monitoringMaxWorkspaceFiles: configuration.get(
      'monitoring.maxWorkspaceFiles',
      DEFAULT_MONITORING_SETTINGS.maxWorkspaceFiles
    ),
    monitoringExcludeBinaryFiles: configuration.get(
      'monitoring.excludeBinaryFiles',
      DEFAULT_MONITORING_SETTINGS.excludeBinaryFiles
    ),
    monitoringExcludeGeneratedFiles: configuration.get(
      'monitoring.excludeGeneratedFiles',
      DEFAULT_MONITORING_SETTINGS.excludeGeneratedFiles
    ),
    assistantProvider: configuration.get('assistant.provider', 'editor'),
    assistantVscodeLanguageModelSelector: configuration.get(
      'assistant.vscodeLanguageModel.selector',
      {}
    ),
    assistantOpenAiEndpoint: configuration.get('assistant.openAiCompatible.endpoint', ''),
    assistantOpenAiModel: configuration.get('assistant.openAiCompatible.model', ''),
    assistantOpenAiApiKeyEnvironmentVariable: configuration.get(
      'assistant.openAiCompatible.apiKeyEnvironmentVariable',
      'BUGDHOR_LLM_API_KEY'
    ),
    assistantLocalModelPath: configuration.get('assistant.localHuggingFace.modelPath', ''),
    assistantExtensionManifestPath: configuration.get('assistant.extensionApi.manifestPath', ''),
    assistantSaeEnabled: configuration.get('assistant.sae.enabled', false),
    assistantCounterfactualEnabled: configuration.get('assistant.counterfactual.enabled', false),
    feedbackNotifyOnPatchApplied: configuration.get('feedback.notifyOnPatchApplied', true),
    feedbackNotifyOnResolution: configuration.get('feedback.notifyOnResolution', true),
    recommendationRunFunctionalTests: configuration.get('recommendations.runFunctionalTests', true),
    recommendationAllowSandboxedExecution: configuration.get(
      'recommendations.allowSandboxedExecution',
      false
    ),
    recommendationTestCommand: configuration.get('recommendations.testCommand', []),
    recommendationTestTimeoutSeconds: configuration.get(
      'recommendations.testTimeoutSeconds',
      120
    )
  };
}

/**
 * Subscribe to Bug Dhor configuration changes.
 *
 * @param {(event: vscode.ConfigurationChangeEvent, settings: ExtensionSettings) => void} listener
 * @returns {vscode.Disposable}
 */
function onSettingsChanged(listener) {
  return vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration(SECTION)) {
      listener(event, readSettings());
    }
  });
}

module.exports = { SECTION, getConfiguration, readSettings, onSettingsChanged };
