'use strict';

const vscode = require('vscode');
const { COMMANDS, VIEW_ID } = require('../constants');
const { createNonce } = require('./csp');
const { createSidebarHtml } = require('./sidebarHtml');

const SIDEBAR_MESSAGE_COMMANDS = Object.freeze({
  openDashboard: COMMANDS.openSecurityDashboard,
  startEngine: COMMANDS.startEngine,
  debugProject: COMMANDS.debugProject,
  viewFindings: COMMANDS.viewFindings,
  reviewFixes: COMMANDS.reviewFixes
});

class SidebarViewProvider {
  /**
   * @param {vscode.Uri} extensionUri
   * @param {import('../logging/output').Logger} logger
   */
  constructor(extensionUri, logger) {
    this.extensionUri = extensionUri;
    this.logger = logger;
  }

  /**
   * @param {vscode.WebviewView} webviewView
   */
  resolveWebviewView(webviewView) {
    const mediaRoot = vscode.Uri.joinPath(this.extensionUri, 'media');
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [mediaRoot]
    };

    const nonce = createNonce();
    const styleUri = webviewView.webview.asWebviewUri(
      vscode.Uri.joinPath(mediaRoot, 'sidebar.css')
    );
    const scriptUri = webviewView.webview.asWebviewUri(
      vscode.Uri.joinPath(mediaRoot, 'sidebar.js')
    );

    const messageSubscription = webviewView.webview.onDidReceiveMessage(async (message) => {
      const command =
        message && typeof message === 'object' ? SIDEBAR_MESSAGE_COMMANDS[message.type] : undefined;
      if (typeof command !== 'string') {
        this.logger.debug('Ignored an unknown Bug Dhor sidebar message.');
        return;
      }

      try {
        await vscode.commands.executeCommand(command);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        this.logger.error(`Unable to run the requested sidebar command: ${detail}`, error);
      }
    });

    webviewView.onDidDispose(() => {
      messageSubscription.dispose();
    });

    webviewView.webview.html = createSidebarHtml({
      cspSource: webviewView.webview.cspSource,
      styleUri: styleUri.toString(),
      scriptUri: scriptUri.toString(),
      nonce
    });

    this.logger.debug('Resolved the Bug Dhor sidebar launcher webview.');
  }
}

/**
 * @param {vscode.ExtensionContext} context
 * @param {import('../logging/output').Logger} logger
 * @returns {vscode.Disposable}
 */
function registerSidebarView(context, logger) {
  const provider = new SidebarViewProvider(context.extensionUri, logger);
  return vscode.window.registerWebviewViewProvider(VIEW_ID, provider, {
    webviewOptions: { retainContextWhenHidden: false }
  });
}

module.exports = { SidebarViewProvider, registerSidebarView };
