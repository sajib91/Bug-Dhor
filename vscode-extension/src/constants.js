'use strict';

/** Shared identifiers that must stay in sync with package.json. */
const CONTAINER_ID = 'bugdhor';
const VIEW_ID = 'bugdhor.sidebar';
const COMMANDS = Object.freeze({
  showStatus: 'bugdhor.showStatus',
  showLogs: 'bugdhor.showLogs',
  startEngine: 'bugdhor.startEngine',
  stopEngine: 'bugdhor.stopEngine',
  debugProject: 'bugdhor.debugProject',
  viewFindings: 'bugdhor.viewFindings',
  reviewFixes: 'bugdhor.reviewFixes',
  scanCurrentFile: 'bugdhor.scanCurrentFile',
  scanSelection: 'bugdhor.scanSelection',
  scanWorkspace: 'bugdhor.scanWorkspace',
  scanRepository: 'bugdhor.scanRepository',
  scanChangedFiles: 'bugdhor.scanChangedFiles',
  scanSelectedFolder: 'bugdhor.scanSelectedFolder',
  scanIncremental: 'bugdhor.scanIncremental',
  rescanAll: 'bugdhor.rescanAll',
  explainVulnerability: 'bugdhor.explainVulnerability',
  analyzeSecurityFeatures: 'bugdhor.analyzeSecurityFeatures',
  counterfactualAnalysis: 'bugdhor.counterfactualAnalysis',
  generateSecureCode: 'bugdhor.generateSecureCode',
  repairVulnerability: 'bugdhor.repairVulnerability',
  verifyRepair: 'bugdhor.verifyRepair',
  openSecurityDashboard: 'bugdhor.openSecurityDashboard',
  showAssistantCapabilities: 'bugdhor.showAssistantCapabilities',
  nextFinding: 'bugdhor.nextFinding',
  previousFinding: 'bugdhor.previousFinding',
  explainFindingPhase6: 'bugdhor.explainFindingPhase6',
  suggestRepairPhase6: 'bugdhor.suggestRepairPhase6',
  previewRepairPhase6: 'bugdhor.previewRepairPhase6',
  applyRepairPhase6: 'bugdhor.applyRepairPhase6',
  verifyRepairPhase6: 'bugdhor.verifyRepairPhase6',
  revertRepairPhase6: 'bugdhor.revertRepairPhase6',
  showRepairHistoryPhase6: 'bugdhor.showRepairHistoryPhase6'
});

module.exports = { CONTAINER_ID, VIEW_ID, COMMANDS };
