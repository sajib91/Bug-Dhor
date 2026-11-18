'use strict';

const { COMMANDS } = require('../constants');
const { comparePositions } = require('../diagnostics/findingModel');

const UTILITY_COMMANDS = Object.freeze([
  COMMANDS.showStatus,
  COMMANDS.showLogs,
  COMMANDS.showAssistantCapabilities,
  COMMANDS.nextFinding,
  COMMANDS.previousFinding
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
 * Navigate only among findings that the diagnostics controller accepted from a
 * backend scan. The active editor's current position selects the neighbor.
 *
 * @param {import('vscode')} vscode
 * @param {import('../diagnostics/diagnosticController').DiagnosticController | undefined} diagnostics
 * @param {'next' | 'previous'} direction
 */
async function navigateFindings(vscode, diagnostics, direction) {
  const editor = vscode.window?.activeTextEditor;
  if (!editor?.document?.uri) {
    void vscode.window?.showInformationMessage?.(
      'Open a source file to navigate Bug Dhor findings.'
    );
    return undefined;
  }

  const findings = diagnostics?.getFindingsForUri?.(editor.document.uri) ?? [];
  if (!Array.isArray(findings) || findings.length === 0) {
    void vscode.window?.showInformationMessage?.(
      'Bug Dhor has no findings in the active file to navigate.'
    );
    return undefined;
  }

  const sorted = [...findings].sort(
    (left, right) =>
      comparePositions(left.range.start, right.range.start) ||
      comparePositions(left.range.end, right.range.end)
  );
  const selection = editor.selection ?? {};
  const current = selection.active ?? selection.start ?? { line: 0, character: 0 };

  const target =
    direction === 'next'
      ? (sorted.find((finding) => comparePositions(finding.range.start, current) > 0) ?? sorted[0])
      : ([...sorted]
          .reverse()
          .find((finding) => comparePositions(finding.range.start, current) < 0) ?? sorted.at(-1));

  if (!target) {
    return undefined;
  }

  const { start, end } = target.range;
  const range = new vscode.Range(start.line, start.character, end.line, end.character);
  await vscode.window.showTextDocument(editor.document, {
    selection: range,
    preserveFocus: false,
    preview: false
  });
  return target;
}

/**
 * Register the status, log, and finding-navigation commands.
 *
 * The status command checks the real backend and reports an error when it
 * cannot be reached. It never claims that an analysis succeeded.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   diagnostics?: import('../diagnostics/diagnosticController').DiagnosticController,
 *   assistantRegistry?: ReturnType<import('../integrations/registry').createProviderRegistry>
 * }} context
 */
function registerUtilityCommands({
  vscode,
  service,
  logger,
  registry,
  diagnostics,
  assistantRegistry
}) {
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

  registry.register(COMMANDS.nextFinding, () => navigateFindings(vscode, diagnostics, 'next'));

  registry.register(COMMANDS.previousFinding, () =>
    navigateFindings(vscode, diagnostics, 'previous')
  );
}

module.exports = {
  registerUtilityCommands,
  describeHealth,
  navigateFindings,
  UTILITY_COMMANDS
};
