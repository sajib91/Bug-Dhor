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
const {
  appendLiveScanHistory,
  buildLiveScanDashboardPatch,
  buildLiveScanHistoryEntry,
  mergeLiveFindings
} = require('./webviews/liveFindingState');
const { registerDiagnostics } = require('./diagnostics');
const { WorkspaceMonitor } = require('./monitoring/workspaceMonitor');
const { onSettingsChanged, readSettings } = require('./config');
const { createProviderRegistry, SecurityHooks } = require('./integrations');
const { FeedbackController } = require('./feedback');
const { offerWorkspaceScan } = require('./commands/repositoryCommands');
const { createTrustGate } = require('./security/trustGate');

/** @type {import('./logging/output').Logger | undefined} */
let logger;

/**
 * Map extension settings to the monitoring feature's normalized input shape.
 *
 * @returns {object}
 */
function getMonitoringSettings(trustGate) {
  const settings = trustGate?.sanitizeSettings?.(readSettings()) ?? readSettings();
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
    watchWorkspaceFiles: settings.monitoringWatchWorkspaceFiles,
    scanNewFiles: settings.monitoringScanNewFiles,
    scanOnOpen: settings.monitoringScanOnOpen,
    fullScanOnWorkspaceChange: settings.monitoringFullScanOnWorkspaceChange,
    fullScanDebounceMs: settings.monitoringFullScanDebounceMs,
    maxConcurrentScans: settings.monitoringMaxConcurrentScans,
    maxWorkspaceFiles: settings.monitoringMaxWorkspaceFiles,
    excludeBinaryFiles: settings.monitoringExcludeBinaryFiles,
    excludeGeneratedFiles: settings.monitoringExcludeGeneratedFiles,
    sendSourceText: settings.sendSourceText
  };
}

/**
 * Map extension settings to the assistant integration registry input. API keys
 * are read from the environment by name, never from a persisted setting.
 *
 * @returns {object}
 */
function getAssistantSettings(trustGate) {
  const settings = trustGate?.sanitizeSettings?.(readSettings()) ?? readSettings();
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
 * Map user-controlled feedback settings to the feedback controller.
 *
 * @returns {object}
 */
function getFeedbackSettings(trustGate) {
  const settings = trustGate?.sanitizeSettings?.(readSettings()) ?? readSettings();
  return {
    notifyOnPatchApplied: settings.feedbackNotifyOnPatchApplied,
    notifyOnResolution: settings.feedbackNotifyOnResolution
  };
}

/**
 * Map user-controlled recommendation settings to the secure-code workflow.
 * Sandboxed execution is opt-in and never grants network, privileged, or
 * destructive permissions.
 *
 * @returns {object}
 */
function getRecommendationSettings(trustGate) {
  const settings = trustGate?.sanitizeSettings?.(readSettings()) ?? readSettings();
  return {
    runFunctionalTests: settings.recommendationRunFunctionalTests,
    allowSandboxedExecution: settings.recommendationAllowSandboxedExecution,
    testCommand: settings.recommendationTestCommand,
    testTimeoutSeconds: settings.recommendationTestTimeoutSeconds
  };
}

/**
 * Map settings used by bounded repository inventory and explicit-path scans.
 *
 * @returns {object}
 */
function getRepositorySettings(trustGate) {
  const settings = trustGate?.sanitizeSettings?.(readSettings()) ?? readSettings();
  return {
    backendUrl: settings.backendUrl,
    sendSourceText: settings.sendSourceText,
    monitoringAllowAutomaticSourceSharing: settings.monitoringAllowAutomaticSourceSharing,
    repositoryMaxFiles: settings.repositoryMaxFiles,
    repositoryMaxFileBytes: settings.repositoryMaxFileBytes,
    repositoryExcludeGlobs: settings.repositoryExcludeGlobs,
    repositoryIncludeUntrackedFiles: settings.repositoryIncludeUntrackedFiles,
    repositoryGitTimeoutMs: settings.repositoryGitTimeoutMs,
    repositoryNotifyOnWorkspaceOpen: settings.repositoryNotifyOnWorkspaceOpen,
    repositoryAutoScanOnWorkspaceOpen: settings.repositoryAutoScanOnWorkspaceOpen
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
  const trustGate = createTrustGate({ vscode, logger });
  const configurationService = createConfigurationService({ vscode, trustGate });
  const service = trustGate.createTrustedService(
    createSecurityEngineService({ configurationService, logger })
  );
  const feedback = new FeedbackController({
    vscode,
    logger,
    getSettings: () => getFeedbackSettings(trustGate)
  });

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
      const settings = trustGate.sanitizeSettings(readSettings());
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

  const dashboard = new DashboardPanelController({
    vscode,
    extensionUri: context.extensionUri,
    logger,
    feedback,
    memento: context.globalState,
    getState: (dataMode) =>
      buildDashboardState({
        dataMode,
        settings: trustGate.sanitizeSettings(readSettings())
      })
  });
  /** @type {object[]} */
  let liveFindings = [];

  const diagnostics = registerDiagnostics({
    vscode,
    extensionUri: context.extensionUri,
    logger,
    onFindingsPublished: (event) => {
      const findings = Array.isArray(event?.findings) ? event.findings : [];
      // These are the already-normalized findings accepted by diagnostics, so
      // the dashboard never re-parses the raw backend response. Scoped scans
      // replace only their own findings; an unscoped scan replaces the set.
      liveFindings = mergeLiveFindings(liveFindings, findings, event?.scopeUris ?? []);
      const generatedAt = new Date().toISOString();
      const historyEntry = buildLiveScanHistoryEntry({
        result: event?.response,
        findings,
        scopeUris: event?.scopeUris ?? [],
        generatedAt,
        status:
          typeof event?.response?.status === 'string' &&
          ['partial', 'unavailable', 'cancelled'].includes(event.response.status)
            ? event.response.status
            : undefined
      });
      const scanHistory = appendLiveScanHistory(dashboard.liveData?.scanHistory, historyEntry);
      dashboard.updateLiveState(
        buildLiveScanDashboardPatch({
          result: event?.response,
          findings: liveFindings,
          generatedAt,
          scanHistory
        })
      );
      feedback.afterScan({
        documentUri: findings[0]?.documentUri ?? event?.scopeUris?.[0],
        findings,
        scopeUris: event?.scopeUris ?? [],
        response: event?.response
      });
    }
  });
  const feedbackSubscription = feedback.subscribe((snapshot) => {
    dashboard.updateLiveState({ feedback: snapshot });
  });
  // Assistant integrations are capability-scoped. Provider discovery is
  // asynchronous but never starts a model, sends source text, or claims
  // capabilities that were not discovered.
  const assistantRegistry = createProviderRegistry({
    vscode,
    logger,
    getSettings: () => getAssistantSettings(trustGate)
  });
  const assistantHooks = new SecurityHooks({
    registry: assistantRegistry,
    logger,
    settings: getAssistantSettings(trustGate)
  });
  if (trustGate.isTrusted()) {
    void assistantRegistry.refresh();
  } else {
    logger.warn('Assistant provider discovery is disabled in an untrusted workspace.');
  }

  const commandRegistry = registerCommands({
    vscode,
    service,
    logger,
    dashboard,
    diagnostics: diagnostics.controller,
    assistantRegistry,
    assistantHooks,
    feedback,
    getRecommendationSettings: () => getRecommendationSettings(trustGate),
    getRepositorySettings: () => getRepositorySettings(trustGate),
    trustGate
  });
  const sidebarRegistration = registerSidebarView(context, logger);

  const monitor = new WorkspaceMonitor({
    vscode,
    service,
    logger,
    diagnostics: diagnostics.controller,
    getSettings: () => getMonitoringSettings(trustGate),
    hooks: assistantHooks,
    feedback
  });
  if (trustGate.isTrusted()) {
    monitor.start();
  } else {
    monitor.updateSettings(getMonitoringSettings(trustGate));
    logger.warn('Workspace monitoring is disabled in an untrusted workspace.');
  }

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
    monitor.updateSettings(getMonitoringSettings(trustGate));
    if (event.affectsConfiguration('bugdhor.assistant')) {
      assistantHooks.updateSettings(getAssistantSettings(trustGate));
      if (trustGate.isTrusted()) {
        void assistantRegistry.refresh();
      }
    }
    logger.debug('Bug Dhor settings updated.');
  });

  const trustSubscription = trustGate.onChange(() => {
    if (trustGate.isTrusted()) {
      monitor.start();
      void assistantRegistry.refresh();
    }
    monitor.updateSettings(getMonitoringSettings(trustGate));
    assistantHooks.updateSettings(getAssistantSettings(trustGate));
    dashboard.refresh();
  });

  context.subscriptions.push(
    logger,
    statusBar,
    dashboard,
    diagnostics,
    sidebarRegistration,
    settingsSubscription,
    trustSubscription,
    trustGate,
    commandRegistry,
    monitor,
    feedbackSubscription,
    feedback
  );

  if (readSettings().autoStart) {
    logger.warn(
      'bugdhor.backend.autoStart is reserved for a future process manager. The extension ' +
        'connects to an already-running backend and does not start one.'
    );
  }

  if (trustGate.isTrusted()) {
    void checkBackendHealth().then((health) =>
      offerWorkspaceScan({
        vscode,
        logger,
        memento: context.globalState,
        settings: getRepositorySettings(trustGate),
        backendReachable: Boolean(health)
      })
    );
  }
  logger.info('Bug Dhor activated.');

  return {
    service,
    configurationService,
    checkBackendHealth,
    monitor,
    feedback,
    assistantRegistry,
    assistantHooks,
    trustGate
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
