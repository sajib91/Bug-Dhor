'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const { runEngineCommand } = require('./runEngineCommand');
const { createSecureCodeGenerator } = require('../recommendations/secureCodeGeneration');
const { createRepairGenerator } = require('../repair/repairGeneration');
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

  // Repair is a provider-backed workflow, not a direct engine call. The
  // backend builds the repository-aware prompt, only a configured B/C provider
  // may generate a candidate, and the backend verifies the candidate before a
  // proposal is returned for review.
  const repairDefinition = getCommandDefinition(COMMANDS.repairVulnerability);
  context.registry.register(repairDefinition.id, (finding) =>
    runEngineCommand(context, {
      definition: repairDefinition,
      prepare: () => {
        const editor = requireActiveEditor(vscode);
        return { ...createRepairRequest(vscode, finding), editor };
      },
      invoke: createRepairGenerator({
        ...context,
        getSettings: context.getRecommendationSettings
      }),
      onResult: recordRepair
    })
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.verifyRepair),
    (target) => {
      const request = createVerificationRequest(vscode);
      if (!target || typeof target !== 'object' || Array.isArray(target)) {
        return request;
      }
      // Verification requires an explicit, caller-supplied target. Nothing is
      // inferred from a repair proposal and no source file is modified here.
      if (typeof target.repairId === 'string' && target.repairId.trim().length > 0) {
        request.repairId = target.repairId.trim();
      }
      if (typeof target.patch === 'string' && target.patch.length > 0) {
        request.patch = target.patch;
      }
      if (typeof target.patchedSource === 'string' && target.patchedSource.length > 0) {
        request.patchedSource = target.patchedSource;
      }
      for (const key of ['cwe', 'findingId']) {
        if (typeof target[key] === 'string' && target[key].length > 0) {
          request[key] = target[key];
        }
      }
      if (target.profile === 'static_only' || target.profile === 'sandbox') {
        request.profile = target.profile;
      }
      if (typeof target.runExecution === 'boolean') {
        request.runExecution = target.runExecution;
      }
      return request;
    },
    {
      onResult: async (result, request) => {
        if (typeof dashboard?.recordVerificationResult === 'function') {
          await dashboard.recordVerificationResult(result, request);
        }
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
