'use strict';

const vscode = require('vscode');

const {
  SECTION,
  DEFAULT_BACKEND_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEALTH_TIMEOUT_MS
} = require('./api/configurationService');
const { DEFAULT_MONITORING_SETTINGS } = require('./monitoring/settings');
const { DEFAULT_EXCLUDE_GLOBS } = require('./monitoring/changeAnalyzer');

/**
 * @typedef {Object} ExtensionSettings
 * @property {string} pythonPath
 * @property {boolean} autoStart
 * @property {boolean} engineManageRuntime
 * @property {number} engineStartupTimeoutMs
 * @property {number} engineHealthPollMs
 * @property {number} engineMaxRestarts
 * @property {number} engineRestartBaseDelayMs
 * @property {number} engineRestartMaxDelayMs
 * @property {string} backendUrl
 * @property {number} requestTimeoutMs
 * @property {number} healthTimeoutMs
 * @property {boolean} sendSourceText
 * @property {string} logLevel
 * @property {boolean} showStatusBarItem
 * @property {boolean} monitoringEnabled
 * @property {boolean} monitoringOnSaveOnly
 * @property {boolean} monitoringScanOnSave
 * @property {number} monitoringDebounceMs
 * @property {string[]} monitoringLanguages
 * @property {string} monitoringAnalysisScope
 * @property {number} monitoringMaxFileBytes
 * @property {number} monitoringMaxChangedLines
 * @property {boolean} monitoringAllowAutomaticSourceSharing
 * @property {boolean} monitoringNotifyOnFindings
 * @property {string[]} monitoringExcludeGlobs
 * @property {boolean} monitoringWatchWorkspaceFiles
 * @property {boolean} monitoringWatchExternalFiles
 * @property {boolean} monitoringWatchRenames
 * @property {boolean} monitoringScanNewFiles
 * @property {boolean} monitoringScanOnOpen
 * @property {boolean} monitoringFullScanOnWorkspaceChange
 * @property {number} monitoringFullScanDebounceMs
 * @property {number} monitoringMaxConcurrentScans
 * @property {number} monitoringMaxWorkspaceFiles
 * @property {boolean} monitoringExcludeBinaryFiles
 * @property {boolean} monitoringExcludeGeneratedFiles
 * @property {string[]} scanExcludeGlobs
 * @property {boolean} repairRequireApproval
 * @property {number} repositoryMaxFiles
 * @property {number} repositoryMaxFileBytes
 * @property {string[]} repositoryExcludeGlobs
 * @property {boolean} repositoryIncludeUntrackedFiles
 * @property {number} repositoryGitTimeoutMs
 * @property {boolean} repositoryNotifyOnWorkspaceOpen
 * @property {boolean} repositoryAutoScanOnWorkspaceOpen
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

/**
 * Read the first explicitly configured alias. Manifest defaults are ignored so
 * a legacy user setting still wins over a newly introduced alias default.
 *
 * @param {vscode.WorkspaceConfiguration} configuration
 * @param {string[]} keys
 * @param {unknown} fallback
 * @returns {unknown}
 */
function firstConfiguredValue(configuration, keys, fallback) {
  for (const key of keys) {
    const inspected = configuration.inspect?.(key);
    if (!inspected) {
      const value = configuration.get?.(key, undefined);
      if (value !== undefined) {
        return value;
      }
      continue;
    }
    for (const scope of [
      'workspaceFolderValue',
      'workspaceValue',
      'globalValue',
      'languageValue'
    ]) {
      if (inspected[scope] !== undefined) {
        return inspected[scope];
      }
    }
  }
  return fallback;
}

/** @returns {ExtensionSettings} */
function readSettings() {
  const configuration = getConfiguration();
  return {
    pythonPath: firstConfiguredValue(
      configuration,
      ['engine.pythonPath', 'backend.pythonPath'],
      ''
    ),
    autoStart: firstConfiguredValue(configuration, ['engine.autoStart', 'backend.autoStart'], true),
    engineManageRuntime: configuration.get('engine.manageRuntime', true),
    engineStartupTimeoutMs: configuration.get('engine.startupTimeoutMs', 20000),
    engineHealthPollMs: configuration.get('engine.healthPollMs', 300),
    engineMaxRestarts: configuration.get('engine.maxRestarts', 3),
    engineRestartBaseDelayMs: configuration.get('engine.restartBaseDelayMs', 500),
    engineRestartMaxDelayMs: configuration.get('engine.restartMaxDelayMs', 8000),
    backendUrl: configuration.get('backend.url', DEFAULT_BACKEND_URL),
    requestTimeoutMs: configuration.get('backend.requestTimeoutMs', DEFAULT_REQUEST_TIMEOUT_MS),
    healthTimeoutMs: configuration.get('backend.healthTimeoutMs', DEFAULT_HEALTH_TIMEOUT_MS),
    sendSourceText: configuration.get('privacy.sendSourceText', true),
    logLevel: configuration.get('logging.level', 'info'),
    showStatusBarItem: configuration.get('ui.showStatusBarItem', true),
    monitoringEnabled: configuration.get('monitoring.enabled', DEFAULT_MONITORING_SETTINGS.enabled),
    monitoringOnSaveOnly: firstConfiguredValue(
      configuration,
      ['monitoring.scanOnSave', 'monitoring.onSaveOnly'],
      DEFAULT_MONITORING_SETTINGS.onSaveOnly
    ),
    monitoringScanOnSave: firstConfiguredValue(
      configuration,
      ['monitoring.scanOnSave', 'monitoring.onSaveOnly'],
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
    monitoringExcludeGlobs: firstConfiguredValue(
      configuration,
      ['scan.exclude', 'monitoring.excludeGlobs'],
      [...DEFAULT_MONITORING_SETTINGS.excludeGlobs]
    ),
    scanExcludeGlobs: firstConfiguredValue(
      configuration,
      ['scan.exclude', 'monitoring.excludeGlobs'],
      [...DEFAULT_MONITORING_SETTINGS.excludeGlobs]
    ),
    repairRequireApproval: configuration.get('repair.requireApproval', true),
    monitoringWatchWorkspaceFiles: configuration.get(
      'monitoring.watchWorkspaceFiles',
      DEFAULT_MONITORING_SETTINGS.watchWorkspaceFiles
    ),
    monitoringWatchExternalFiles: configuration.get(
      'monitoring.watchExternalFiles',
      DEFAULT_MONITORING_SETTINGS.watchExternalFiles
    ),
    monitoringWatchRenames: configuration.get(
      'monitoring.watchRenames',
      DEFAULT_MONITORING_SETTINGS.watchRenames
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
    repositoryMaxFiles: configuration.get('repository.maxFiles', 2000),
    repositoryMaxFileBytes: configuration.get('repository.maxFileBytes', 1_048_576),
    repositoryExcludeGlobs: configuration.get('repository.excludeGlobs', [
      ...DEFAULT_EXCLUDE_GLOBS
    ]),
    repositoryIncludeUntrackedFiles: configuration.get('repository.includeUntrackedFiles', true),
    repositoryGitTimeoutMs: configuration.get('repository.gitTimeoutMs', 10000),
    repositoryNotifyOnWorkspaceOpen: configuration.get('repository.notifyOnWorkspaceOpen', true),
    repositoryAutoScanOnWorkspaceOpen: configuration.get(
      'repository.autoScanOnWorkspaceOpen',
      false
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
    recommendationTestTimeoutSeconds: configuration.get('recommendations.testTimeoutSeconds', 120)
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

module.exports = {
  SECTION,
  getConfiguration,
  firstConfiguredValue,
  readSettings,
  onSettingsChanged
};
