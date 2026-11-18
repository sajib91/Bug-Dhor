'use strict';

/** Shared identifiers that must stay in sync with package.json. */
const CONTAINER_ID = 'bugdhor';
const VIEW_ID = 'bugdhor.sidebar';
const COMMANDS = Object.freeze({
  showStatus: 'bugdhor.showStatus',
  showLogs: 'bugdhor.showLogs',
  scanCurrentFile: 'bugdhor.scanCurrentFile',
  scanSelection: 'bugdhor.scanSelection',
  scanWorkspace: 'bugdhor.scanWorkspace',
  explainVulnerability: 'bugdhor.explainVulnerability',
  analyzeSecurityFeatures: 'bugdhor.analyzeSecurityFeatures',
  counterfactualAnalysis: 'bugdhor.counterfactualAnalysis',
  generateSecureCode: 'bugdhor.generateSecureCode',
  repairVulnerability: 'bugdhor.repairVulnerability',
  verifyRepair: 'bugdhor.verifyRepair',
  openSecurityDashboard: 'bugdhor.openSecurityDashboard',
  showAssistantCapabilities: 'bugdhor.showAssistantCapabilities'
});

module.exports = { CONTAINER_ID, VIEW_ID, COMMANDS };
