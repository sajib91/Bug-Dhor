'use strict';

const vscode = require('vscode');
const { createSecurityEngineService } = require('./api/securityEngineService');
const { createConfigurationService, isLoopbackBackendUrl } = require('./api/configurationService');
const { createLogger } = require('./logging/output');
const { createStatusBar } = require('./views/statusBar');
const { registerCommands } = require('./commands');
const { registerSidebarView } = require('./webviews/sidebarView');
const { DashboardPanelController } = require('./webviews/dashboardPanel');
const { buildDashboardState } = require('./webviews/dashboardModel');
const { registerDiagnostics } = require('./diagnostics');
const { RealtimeMonitor } = require('./monitoring/realtimeMonitor');
const { onSettingsChanged, readSettings } = require('./config');
const { createProviderRegistry, SecurityHooks } = require('./integrations');

/** @type {import('./logging/output').Logger | undefined} */
let logger;

/**
 * Map extension settings to the monitoring feature's normalized input shape.
 *
 * @returns {object}
 */
function getMonitoringSettings() {
  const settings = readSettings();
  return {
    enabled: settings.monitoringEnabled,
    onSaveOnly: settings.monitoringOnSaveOnly,
    debounceMs: settings.monitoringDebounceMs,
    languages: settings.monitoringLanguages,
    analysisScope: settings.monitoringAnalysisScope,
    maxFileBytes: settings.monitoringMaxFileBytes,
    maxChangedLines: settings.monitoringMaxChangedLines,
    allowAutomaticSourceSharing: settings.monitoringAllowAutomaticSourceSharing,
    notifyOnFindings: settings.monitoringNotifyOnFindings,
    excludeGlobs: settings.monitoringExcludeGlobs,
    sendSourceText: settings.sendSourceText
  };
}

/**
 * Map extension settings to the assistant integration registry input. API keys
 * are read from the environment by name, never from a persisted setting.
 *
 * @returns {object}
 */
function getAssistantSettings() {
  const settings = readSettings();
  return {
    provider: settings.assistantProvider,
    vscodeLanguageModel: {
      selector: settings.assistantVscodeLanguageModelSelector
    },
    openAiCompatible: {
      endpoint: settings.assistantOpenAiEndpoint,
      model: settings.assistantOpenAiModel,
      apiKeyEnvironmentVariable: settings.assistantOpenAiApiKeyEnvironmentVariable
    },
    localHuggingFace: {
      modelPath: settings.assistantLocalModelPath
    },
    extensionApi: {
      manifestPath: settings.assistantExtensionManifestPath
    },
    sae: { enabled: settings.assistantSaeEnabled },
    counterfactual: { enabled: settings.assistantCounterfactualEnabled }
  };
}

/**
 * Activate the Bug Dhor extension.
 *
 * This starts no Python process and performs no analysis. It connects to an
 * already-running backend, checks its health without sending source code, and
 * creates the dashboard, command registry, sidebar launcher, and status bar.
 *
 * @param {import('vscode').ExtensionContext} context
 */
function activate(context) {
  logger = createLogger();
  logger.info('Activating Bug Dhor Security Framework.');

  const statusBar = createStatusBar();
  const configurationService = createConfigurationService({ vscode });
  const service = createSecurityEngineService({ configurationService, logger });

  /**
   * Check liveness without sending source. The result only controls status
   * text; analysis availability is reported by each backend operation.
   *
   * @returns {Promise<object | undefined>}
   */
  async function checkBackendHealth() {
    statusBar.setBackendStatus('checking');
    try {
      const health = await service.health({});
      const detail =
        `Bug Dhor backend v${health.version} reachable. ` +
        'Analysis stages are reported individually by the backend.';
      statusBar.setBackendStatus('reachable', detail);
      logger.info(
        `Bug Dhor backend v${health.version} reachable at the configured URL ` +
          `(API ${health.apiVersion}).`
      );
      const settings = readSettings();
      if (!isLoopbackBackendUrl(settings.backendUrl)) {
        logger.warn(
          'bugdhor.backend.url points outside loopback. Source text is sent only for explicit ' +
            'user-invoked commands and only when bugdhor.privacy.sendSourceText is enabled.'
        );
      }
      return health;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      statusBar.setBackendStatus('unavailable', message);
      logger.warn(`Bug Dhor backend health check failed: ${message}`);
      return undefined;
    }
  }

  const diagnostics = registerDiagnostics({ vscode, logger });
  const dashboard = new DashboardPanelController({
    vscode,
    extensionUri: context.extensionUri,
    logger,
    getState: (dataMode) =>
      buildDashboardState({
        dataMode,
        settings: readSettings()
      })
  });
  // Assistant integrations are capability-scoped. Provider discovery is
  // asynchronous but never starts a model, sends source text, or claims
  // capabilities that were not discovered.
  const assistantRegistry = createProviderRegistry({
    vscode,
    logger,
    getSettings: getAssistantSettings
  });
  const assistantHooks = new SecurityHooks({
    registry: assistantRegistry,
    logger,
    settings: getAssistantSettings()
  });
  void assistantRegistry.refresh();

  const commandRegistry = registerCommands({
    vscode,
    service,
    logger,
    dashboard,
    diagnostics: diagnostics.controller,
    assistantRegistry
  });
  const sidebarRegistration = registerSidebarView(context, logger);

  const monitor = new RealtimeMonitor({
    vscode,
    service,
    logger,
    diagnostics: diagnostics.controller,
    getSettings: getMonitoringSettings,
    hooks: assistantHooks
  }).start();

  const settingsSubscription = onSettingsChanged((event) => {
    if (event.affectsConfiguration('bugdhor.logging.level')) {
      logger.applySettings();
    }
    if (event.affectsConfiguration('bugdhor.ui.showStatusBarItem')) {
      statusBar.applySettings();
    }
    if (event.affectsConfiguration('bugdhor')) {
      dashboard.refresh();
    }
    if (
      event.affectsConfiguration('bugdhor.backend.url') ||
      event.affectsConfiguration('bugdhor.backend.requestTimeoutMs') ||
      event.affectsConfiguration('bugdhor.backend.healthTimeoutMs')
    ) {
      void checkBackendHealth();
    }
    monitor.updateSettings(getMonitoringSettings());
    if (event.affectsConfiguration('bugdhor.assistant')) {
      assistantHooks.updateSettings(getAssistantSettings());
      void assistantRegistry.refresh();
    }
    logger.debug('Bug Dhor settings updated.');
  });

  context.subscriptions.push(
    logger,
    statusBar,
    dashboard,
    diagnostics,
    sidebarRegistration,
    settingsSubscription,
    commandRegistry,
    monitor
  );

  if (readSettings().autoStart) {
    logger.warn(
      'bugdhor.backend.autoStart is reserved for a future process manager. The extension ' +
        'connects to an already-running backend and does not start one.'
    );
  }

  void checkBackendHealth();
  logger.info('Bug Dhor activated.');

  return {
    service,
    configurationService,
    checkBackendHealth,
    monitor,
    assistantRegistry,
    assistantHooks
  };
}

/**
 * VS Code disposes the registered subscriptions after this hook. The logger is
 * only used to record the transition.
 */
function deactivate() {
  if (logger) {
    logger.info('Bug Dhor deactivated.');
    logger = undefined;
  }
}

module.exports = { activate, deactivate };
