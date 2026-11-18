'use strict';

const { COMMANDS } = require('../constants');

const UTILITY_COMMANDS = Object.freeze([
  COMMANDS.showStatus,
  COMMANDS.showLogs,
  COMMANDS.showAssistantCapabilities
]);

/**
 * @param {object} health
 * @returns {string}
 */
function describeHealth(health) {
  if (!health || health.status !== 'ok') {
    return 'The Bug Dhor backend responded, but its health state is unknown.';
  }
  const capabilities =
    health.capabilities && typeof health.capabilities === 'object' ? health.capabilities : {};
  const available = Object.keys(capabilities).filter((key) => capabilities[key] === true);
  const unavailable = Object.keys(capabilities).filter((key) => capabilities[key] === false);
  const availableText = available.length > 0 ? available.join(', ') : 'none declared';
  const unavailableText = unavailable.length > 0 ? unavailable.join(', ') : 'none declared';
  return (
    `Bug Dhor backend v${health.version} is reachable (API ${health.apiVersion}). ` +
    `Declared available capabilities: ${availableText}. ` +
    `Declared unavailable capabilities: ${unavailableText}. ` +
    'Capability flags describe wired paths, not provider availability or measured research results.'
  );
}

/**
 * Register the status and log commands.
 *
 * The status command checks the real backend and reports an error when it
 * cannot be reached. It never claims that an analysis succeeded.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   assistantRegistry?: ReturnType<import('../integrations/registry').createProviderRegistry>
 * }} context
 */
function registerUtilityCommands({ vscode, service, logger, registry, assistantRegistry }) {
  registry.register(COMMANDS.showStatus, async () => {
    let health;
    try {
      health = await service.health({});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn(`Backend health check failed: ${message}`);
      const action = await vscode.window.showErrorMessage(
        `Bug Dhor: ${message}`,
        'Show Logs',
        'Open Settings'
      );
      if (action === 'Show Logs') {
        logger.show();
      } else if (action === 'Open Settings') {
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'bugdhor.backend.url'
        );
      }
      return;
    }

    const action = await vscode.window.showInformationMessage(
      describeHealth(health),
      'Open Security Dashboard',
      'Show Logs'
    );

    if (action === 'Open Security Dashboard') {
      await vscode.commands.executeCommand(COMMANDS.openSecurityDashboard);
    } else if (action === 'Show Logs') {
      logger.show();
    }
  });

  registry.register(COMMANDS.showLogs, () => {
    logger.show();
  });

  registry.register(COMMANDS.showAssistantCapabilities, () => {
    const snapshot = assistantRegistry?.toJSON?.() ?? {
      selectedKind: 'editor',
      activeProvider: 'editor-monitor',
      providers: []
    };
    logger.info(`Bug Dhor assistant capabilities: ${JSON.stringify(snapshot)}`);
    return snapshot;
  });
}

module.exports = { registerUtilityCommands, describeHealth, UTILITY_COMMANDS };
