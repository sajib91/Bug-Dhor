'use strict';

const { COMMAND_DEFINITIONS } = require('./definitions');
const { CommandRegistry } = require('./registry');
const { registerScanCommands } = require('./scanCommands');
const { registerRepositoryCommands } = require('./repositoryCommands');
const { registerAnalysisCommands } = require('./analysisCommands');
const { registerRepairCommands } = require('./repairCommands');
const { registerPhase6Commands } = require('./phase6Commands');
const { registerEngineCommands, ENGINE_COMMANDS } = require('./engineCommands');
const { registerDashboardCommand } = require('./dashboardCommand');
const { registerUtilityCommands, UTILITY_COMMANDS } = require('./utilityCommands');

/**
 * Registration order is deliberate: feature commands first, then the dashboard
 * and utility commands. A single registry owns every disposable.
 */
const COMMAND_REGISTRARS = Object.freeze([
  registerScanCommands,
  registerRepositoryCommands,
  registerAnalysisCommands,
  registerRepairCommands,
  registerPhase6Commands,
  registerEngineCommands,
  registerDashboardCommand,
  registerUtilityCommands
]);

/**
 * @returns {Set<string>}
 */
function expectedCommandIds() {
  return new Set([
    ...COMMAND_DEFINITIONS.map((definition) => definition.id),
    ...ENGINE_COMMANDS,
    ...UTILITY_COMMANDS
  ]);
}

/**
 * Activation must never leave a partially registered command set. This check
 * also catches a definition that was added without a registrar.
 *
 * @param {CommandRegistry} registry
 */
function assertCompleteRegistry(registry) {
  const expected = expectedCommandIds();
  const actual = new Set(registry.ids());

  const missing = [...expected].filter((commandId) => !actual.has(commandId));
  if (missing.length > 0) {
    throw new Error(`Bug Dhor commands were not registered: ${missing.join(', ')}`);
  }

  const unexpected = [...actual].filter((commandId) => !expected.has(commandId));
  if (unexpected.length > 0) {
    throw new Error(`Bug Dhor registered undeclared commands: ${unexpected.join(', ')}`);
  }
}

/**
 * Register every Bug Dhor command.
 *
 * Dependencies are injected so unit tests can register commands against fake
 * VS Code and service objects without importing the VS Code runtime.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   dashboard: import('../webviews/dashboardPanel').DashboardPanelController,
 *   diagnostics: import('../diagnostics/diagnosticController').DiagnosticController,
 *   assistantRegistry?: ReturnType<import('../integrations/registry').createProviderRegistry>,
 *   assistantHooks?: import('../integrations/securityHooks').SecurityHooks,
 *   feedback?: import('../feedback/feedbackController').FeedbackController,
 *   engineManager?: import('../engine/engineManager').EngineManager,
 *   getRecommendationSettings?: () => object,
 *   getRepositorySettings?: () => object,
 *   trustGate?: { assertCapability: (operation?: string) => void },
 *   gitRunner?: (cwd: string, args: string[], timeoutMs: number) => Promise<string>,
 *   phase6Runner?: (command: string, args: string[], options: object) => Promise<{ stdout: string, stderr: string }>
 * }} dependencies
 * @returns {CommandRegistry} One disposable that owns every registration.
 */
function registerCommands({
  vscode,
  service,
  logger,
  dashboard,
  diagnostics,
  assistantRegistry,
  assistantHooks,
  feedback,
  engineManager,
  getRecommendationSettings,
  getRepositorySettings,
  trustGate,
  gitRunner,
  phase6Runner
}) {
  if (!vscode) {
    throw new TypeError('registerCommands requires a vscode API object.');
  }
  if (!service) {
    throw new TypeError('registerCommands requires a SecurityEngineService.');
  }
  if (typeof service.health !== 'function') {
    throw new TypeError('SecurityEngineService.health is required for backend status checks.');
  }
  if (!logger) {
    throw new TypeError('registerCommands requires a logger.');
  }
  if (!dashboard || typeof dashboard.open !== 'function') {
    throw new TypeError('registerCommands requires a dashboard controller.');
  }
  if (!diagnostics || typeof diagnostics.publishScanResult !== 'function') {
    throw new TypeError('registerCommands requires a diagnostics controller.');
  }

  const registry = new CommandRegistry(vscode, logger);
  const context = {
    vscode,
    service,
    logger,
    dashboard,
    diagnostics,
    registry,
    assistantRegistry,
    assistantHooks,
    feedback,
    engineManager,
    getSettings: getRecommendationSettings,
    getRepositorySettings:
      getRepositorySettings ?? (() => ({ backendUrl: 'http://127.0.0.1:8765' })),
    trustGate,
    gitRunner,
    phase6Runner
  };

  try {
    for (const register of COMMAND_REGISTRARS) {
      register(context);
    }
    assertCompleteRegistry(registry);
  } catch (error) {
    registry.dispose();
    throw error;
  }

  logger.debug(`Registered ${registry.size} Bug Dhor commands.`);
  return registry;
}

module.exports = { registerCommands, assertCompleteRegistry, expectedCommandIds };
