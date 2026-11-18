'use strict';

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const { requireActiveEditor, requireSelection, createEditorRequest } = require('./validation');

/**
 * Register the explanation, security-feature, and counterfactual commands.
 *
 * Explanation and feature analysis can operate on a saved file and include a
 * selection when one exists. Counterfactual analysis requires an explicit
 * selection so the engine can compare a concrete code region.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry
 * }} context
 */
function registerAnalysisCommands(context) {
  const { vscode, dashboard } = context;
  const updateDashboard = (patch) => {
    if (typeof dashboard?.updateLiveState === 'function') {
      dashboard.updateLiveState(patch);
    }
  };

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.explainVulnerability),
    (target) => {
      const request = createEditorRequest(vscode, requireActiveEditor(vscode));
      if (!target || typeof target !== 'object' || Array.isArray(target)) {
        return request;
      }
      // An explanation must name a real backend finding. The client never
      // constructs one; a caller may only forward an existing identifier.
      if (typeof target.findingId === 'string' && target.findingId.trim().length > 0) {
        request.findingId = target.findingId.trim();
      } else if (target.finding && typeof target.finding === 'object') {
        request.finding = target.finding;
      }
      return request;
    },
    {
      onResult: (response) =>
        updateDashboard({
          explanations: response?.result ? [response.result] : [],
          generatedAt: new Date().toISOString()
        })
    }
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.analyzeSecurityFeatures),
    () => createEditorRequest(vscode, requireActiveEditor(vscode)),
    {
      onResult: (response) =>
        updateDashboard({
          saeFeatures: response?.result ?? null,
          generatedAt: new Date().toISOString()
        })
    }
  );

  registerEngineCommand(
    context,
    getCommandDefinition(COMMANDS.counterfactualAnalysis),
    () => {
      const editor = requireActiveEditor(vscode);
      requireSelection(editor);
      return createEditorRequest(vscode, editor);
    },
    {
      onResult: (response) =>
        updateDashboard({
          featureInteractions: response?.result ?? null,
          generatedAt: new Date().toISOString()
        })
    }
  );
}

module.exports = { registerAnalysisCommands };
