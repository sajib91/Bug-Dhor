'use strict';

/**
 * Sidebar welcome launcher script.
 *
 * The sidebar can only request a small allowlist of host commands. It cannot
 * execute arbitrary commands, read analysis data, or write source files.
 */
(function sidebar() {
  const vscode = acquireVsCodeApi();
  const bindings = [
    ['open-dashboard', 'openDashboard'],
    ['start-engine', 'startEngine'],
    ['debug-project', 'debugProject'],
    ['view-findings', 'viewFindings'],
    ['review-fixes', 'reviewFixes']
  ];

  for (const [id, type] of bindings) {
    const button = document.getElementById(id);
    if (button) {
      button.addEventListener('click', () => {
        vscode.postMessage({ type });
      });
    }
  }
})();
