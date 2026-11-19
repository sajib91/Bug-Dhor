'use strict';

const { COMMANDS } = require('../constants');

/**
 * Canonical feature command definitions. package.json and the command
 * registry must both match this list; tests enforce the drift check.
 */
const COMMAND_DEFINITIONS = Object.freeze([
  Object.freeze({
    id: COMMANDS.scanCurrentFile,
    title: 'Scan Current File',
    progressTitle: 'Bug Dhor: Scanning current file',
    serviceMethod: 'scanFile'
  }),
  Object.freeze({
    id: COMMANDS.scanSelection,
    title: 'Scan Selection',
    progressTitle: 'Bug Dhor: Scanning selection',
    serviceMethod: 'scanSelection'
  }),
  Object.freeze({
    id: COMMANDS.scanWorkspace,
    title: 'Scan Workspace',
    progressTitle: 'Bug Dhor: Scanning workspace',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.scanRepository,
    title: 'Scan Full Repository',
    progressTitle: 'Bug Dhor: Scanning full repository',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.scanChangedFiles,
    title: 'Scan Changed Files',
    progressTitle: 'Bug Dhor: Scanning changed files',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.scanSelectedFolder,
    title: 'Scan Selected Folder',
    progressTitle: 'Bug Dhor: Scanning selected folder',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.scanIncremental,
    title: 'Scan Incremental Findings',
    progressTitle: 'Bug Dhor: Rescanning incremental findings',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.rescanAll,
    title: 'Rescan All',
    progressTitle: 'Bug Dhor: Rescanning all findings',
    serviceMethod: 'scanWorkspace'
  }),
  Object.freeze({
    id: COMMANDS.explainVulnerability,
    title: 'Explain Vulnerability',
    progressTitle: 'Bug Dhor: Explaining vulnerability',
    serviceMethod: 'explainVulnerability'
  }),
  Object.freeze({
    id: COMMANDS.analyzeSecurityFeatures,
    title: 'Analyze Security Features',
    progressTitle: 'Bug Dhor: Analyzing security features',
    serviceMethod: 'analyzeSecurityFeatures'
  }),
  Object.freeze({
    id: COMMANDS.counterfactualAnalysis,
    title: 'Counterfactual Analysis',
    progressTitle: 'Bug Dhor: Running counterfactual analysis',
    serviceMethod: 'counterfactualAnalysis'
  }),
  Object.freeze({
    id: COMMANDS.generateSecureCode,
    title: 'Generate Secure Code',
    progressTitle: 'Bug Dhor: Generating secure code',
    serviceMethod: 'generateSecureCode'
  }),
  Object.freeze({
    id: COMMANDS.repairVulnerability,
    title: 'Repair Vulnerability',
    progressTitle: 'Bug Dhor: Generating repair proposal',
    serviceMethod: 'repairVulnerability'
  }),
  Object.freeze({
    id: COMMANDS.verifyRepair,
    title: 'Verify Repair',
    progressTitle: 'Bug Dhor: Verifying repair',
    serviceMethod: 'verifyRepair'
  }),
  Object.freeze({
    id: COMMANDS.openSecurityDashboard,
    title: 'Open Security Dashboard',
    progressTitle: 'Bug Dhor: Opening security dashboard',
    serviceMethod: null
  }),
  Object.freeze({
    key: 'explainFindingPhase6',
    id: COMMANDS.explainFindingPhase6,
    title: 'Explain Finding (Local Engine)',
    progressTitle: 'Bug Dhor: Explaining finding with the local engine',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'suggestRepairPhase6',
    id: COMMANDS.suggestRepairPhase6,
    title: 'Suggest Repair (Local Engine)',
    progressTitle: 'Bug Dhor: Suggesting repair with the local engine',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'previewRepairPhase6',
    id: COMMANDS.previewRepairPhase6,
    title: 'Preview Repair (Local Engine)',
    progressTitle: 'Bug Dhor: Previewing repair with the local engine',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'applyRepairPhase6',
    id: COMMANDS.applyRepairPhase6,
    title: 'Apply Reviewed Patch (Local Engine)',
    progressTitle: 'Bug Dhor: Applying a reviewed local patch',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'verifyRepairPhase6',
    id: COMMANDS.verifyRepairPhase6,
    title: 'Verify Applied Repair (Local Engine)',
    progressTitle: 'Bug Dhor: Verifying a local repair',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'revertRepairPhase6',
    id: COMMANDS.revertRepairPhase6,
    title: 'Revert Applied Patch (Local Engine)',
    progressTitle: 'Bug Dhor: Reverting a local patch',
    serviceMethod: null,
    localEngine: true
  }),
  Object.freeze({
    key: 'showRepairHistoryPhase6',
    id: COMMANDS.showRepairHistoryPhase6,
    title: 'Show Repair History (Local Engine)',
    progressTitle: 'Bug Dhor: Showing local repair history',
    serviceMethod: null,
    localEngine: true
  })
]);

const DEFINITIONS_BY_ID = new Map(
  COMMAND_DEFINITIONS.map((definition) => [definition.id, definition])
);

/**
 * @param {string} commandId
 * @returns {typeof COMMAND_DEFINITIONS[number]}
 */
function getCommandDefinition(commandId) {
  const definition = DEFINITIONS_BY_ID.get(commandId);
  if (!definition) {
    throw new Error(`No command definition registered for ${commandId}`);
  }
  return definition;
}

module.exports = { COMMAND_DEFINITIONS, getCommandDefinition };
