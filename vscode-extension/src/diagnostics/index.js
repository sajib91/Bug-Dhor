'use strict';

const { DiagnosticController } = require('./diagnosticController');
const { DecorationController } = require('./decorationController');
const { FindingHoverProvider } = require('./hoverProvider');
const { FindingCodeActionProvider } = require('./codeActionProvider');

/**
 * Create the diagnostic collection and register the hover and code-action
 * providers for file documents.
 *
 * The returned object is a single disposable so activation can register one
 * feature and deactivation releases the collection, hover provider, and
 * Quick Fix provider together.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   extensionUri?: import('vscode').Uri,
 *   logger: import('../logging/output').Logger,
 *   onFindingsPublished?: (event: object) => void
 * }} dependencies
 * @returns {{
 *   controller: DiagnosticController,
 *   decorations: DecorationController | null,
 *   hoverProvider: FindingHoverProvider,
 *   codeActionProvider: FindingCodeActionProvider,
 *   dispose: () => void
 * }}
 */
function registerDiagnostics({ vscode, extensionUri, logger, onFindingsPublished }) {
  if (
    !vscode?.languages ||
    typeof vscode.languages.registerHoverProvider !== 'function' ||
    typeof vscode.languages.registerCodeActionsProvider !== 'function'
  ) {
    throw new TypeError('registerDiagnostics requires the VS Code language provider APIs.');
  }

  let decorations = null;
  if (extensionUri && typeof vscode.window?.createTextEditorDecorationType === 'function') {
    decorations = new DecorationController({ vscode, extensionUri, logger });
  }

  let controller;
  try {
    controller = new DiagnosticController({ vscode, logger, onFindingsPublished, decorations });
  } catch (error) {
    decorations?.dispose();
    throw error;
  }
  const hoverProvider = new FindingHoverProvider({ vscode, findings: controller });
  const codeActionProvider = new FindingCodeActionProvider({ vscode, findings: controller });
  const disposables = [controller];

  try {
    disposables.push(
      vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider),
      vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, codeActionProvider, {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
      })
    );
  } catch (error) {
    for (const disposable of disposables.reverse()) {
      disposable.dispose();
    }
    throw error;
  }

  logger.debug('Registered Bug Dhor diagnostics, hover explanations, and repair code actions.');

  let disposed = false;
  return {
    controller,
    decorations,
    hoverProvider,
    codeActionProvider,
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      for (const disposable of [...disposables].reverse()) {
        try {
          disposable.dispose();
        } catch (error) {
          logger.error('Failed to dispose a Bug Dhor diagnostics registration.', error);
        }
      }
    }
  };
}

module.exports = { registerDiagnostics };
