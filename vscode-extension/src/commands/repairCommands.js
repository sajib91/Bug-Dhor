'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const { runEngineCommand } = require('./runEngineCommand');
const { createSecureCodeGenerator } = require('../recommendations/secureCodeGeneration');
const {
  requireActiveEditor,
  createEditorRequest,
  createRepairRequest,
  createVerificationRequest
} = require('./validation');

/**
 * Register the generation, repair, and verification commands.
 *
 * Generation and repair use the active saved editor as context. Verification
 * works at workspace scope and does not require an editor.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   assistantRegistry?: any,
 *   assistantHooks?: import('../integrations/securityHooks').SecurityHooks,
 *   feedback?: import('../feedback/feedbackController').FeedbackController
 * }} context
 */
function registerRepairCommands(context) {
  const { vscode, dashboard } = context;
  const recordRepair = (result, request) => {
    if (typeof dashboard?.recordRepairResult === 'function') {
      return dashboard.recordRepairResult(result, request);
    }
    return undefined;
  };
  const recordRecommendation = (result, request) => {
    if (typeof dashboard?.recordRecommendationResult === 'function') {
      return dashboard.recordRecommendationResult(result, request);
    }
    return undefined;
  };

  const secureCodeDefinition = getCommandDefinition(COMMANDS.generateSecureCode);
  context.registry.register(secureCodeDefinition.id, () =>
    runEngineCommand(context, {
      definition: secureCodeDefinition,
      prepare: () => {
        const editor = requireActiveEditor(vscode);
        return { ...createEditorRequest(vscode, editor), editor };
      },
      invoke: createSecureCodeGenerator(context),
      onResult: recordRecommendation
    })
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.repairVulnerability),
    (finding) => createRepairRequest(vscode, finding),
    {
      onResult: recordRepair
    }
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.verifyRepair),
    () => createVerificationRequest(vscode),
    {
      onResult: (result, request) => {
        if (typeof context.feedback?.recordVerification !== 'function') {
          return undefined;
        }
        return context.feedback.recordVerification({
          documentUri: request.documentUri,
          findingId: request.finding?.findingId ?? result?.result?.findingId ?? null,
          verdict: result?.result?.verdict,
          passed: result?.result?.verdict === 'passed',
          detail: result?.result?.classification ?? result?.result?.state ?? ''
        });
      }
    }
  );
}

module.exports = { registerRepairCommands };
