'use strict';

const { COMMANDS } = require('../constants');
const { ENGINE_STATES } = require('../engine/engineManager');

const ENGINE_COMMANDS = Object.freeze([
  COMMANDS.startEngine,
  COMMANDS.stopEngine,
  COMMANDS.debugProject,
  COMMANDS.viewFindings,
  COMMANDS.reviewFixes
]);

/**
 * Register lifecycle, debug, and navigation commands. These commands are
 * deliberately thin: they either call the owned engine manager or delegate to
 * an already-registered, user-visible command. They never spawn a process
 * directly and never execute workspace-derived commands.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   engineManager?: import('../engine/engineManager').EngineManager,
 *   dashboard?: import('../webviews/dashboardPanel').DashboardPanelController,
 *   trustGate?: { isTrusted: () => boolean }
 * }} context
 */
function registerEngineCommands({ vscode, logger, registry, engineManager, dashboard, trustGate }) {
  /** @param {string} detail */
  const reportUntrusted = async (detail) => {
    logger.warn(detail);
    const action = await vscode.window?.showWarningMessage?.(detail, 'Manage Workspace Trust');
    if (action === 'Manage Workspace Trust') {
      await vscode.commands?.executeCommand?.('workbench.action.trustWorkspace');
    }
  };

  registry.register(COMMANDS.startEngine, async () => {
    if (trustGate && !trustGate.isTrusted()) {
      await reportUntrusted(
        'Bug Dhor cannot start the local engine in an untrusted workspace. Trust the workspace first.'
      );
      return false;
    }
    if (!engineManager) {
      logger.warn('The local engine manager is unavailable.');
      return false;
    }
    const started = await engineManager.start({ reason: 'command' });
    const status = engineManager.getStatus();
    if (started) {
      logger.info(`Bug Dhor local engine is online: ${status.detail}`);
    } else {
      logger.warn(`Bug Dhor local engine did not start: ${status.detail}`);
    }
    return started;
  });

  registry.register(COMMANDS.stopEngine, async () => {
    if (!engineManager) {
      logger.warn('The local engine manager is unavailable.');
      return false;
    }
    const status = engineManager.getStatus();
    if (!status.owned) {
      const message =
        status.state === ENGINE_STATES.ONLINE
          ? 'The reachable engine was started outside Bug Dhor, so it was left running.'
          : 'No Bug Dhor-owned engine is running.';
      logger.info(message);
      void vscode.window?.showInformationMessage?.(`Bug Dhor: ${message}`);
      return true;
    }
    await engineManager.stop();
    logger.info('Stopped the Bug Dhor-owned local engine.');
    return true;
  });

  registry.register(COMMANDS.debugProject, async () => {
    if (trustGate && !trustGate.isTrusted()) {
      await reportUntrusted(
        'Project debugging requires a trusted workspace. Source analysis is disabled in untrusted workspaces.'
      );
      return false;
    }
    if (engineManager) {
      await engineManager.ensure({ reason: 'debugProject' });
    }
    logger.show();
    logger.info('Bug Dhor project debug requested. Running an explicit full repository scan.');
    await vscode.commands.executeCommand(COMMANDS.scanRepository);
    return true;
  });

  registry.register(COMMANDS.viewFindings, async () => {
    if (!dashboard || typeof dashboard.open !== 'function') {
      logger.warn('The security dashboard is unavailable.');
      return false;
    }
    dashboard.open();
    dashboard.focusSection?.('vulnerabilities');
    return true;
  });

  registry.register(COMMANDS.reviewFixes, async () => {
    if (!dashboard || typeof dashboard.open !== 'function') {
      logger.warn('The security dashboard is unavailable.');
      return false;
    }
    dashboard.open();
    dashboard.focusSection?.('automatedRepair');
    return true;
  });
}

module.exports = { registerEngineCommands, ENGINE_COMMANDS };
