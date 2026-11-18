'use strict';

const vscode = require('vscode');
const { readSettings } = require('../config');
const { COMMANDS } = require('../constants');

class StatusBar {
  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.name = 'Bug Dhor';
    this.item.text = '$(shield) Bug Dhor';
    this.item.tooltip = 'Bug Dhor Security Framework. Click to check backend status.';
    this.item.command = COMMANDS.showStatus;
    this.applySettings();
  }

  /**
   * Reflect the last known backend connection state. Capability facts come
   * from backend health responses, never from this label.
   *
   * @param {'checking' | 'reachable' | 'unavailable'} state
   * @param {string} [detail]
   */
  setBackendStatus(state, detail) {
    if (state === 'checking') {
      this.item.text = '$(sync~spin) Bug Dhor';
      this.item.tooltip = 'Checking the Bug Dhor backend connection.';
    } else if (state === 'reachable') {
      this.item.text = '$(shield) Bug Dhor';
      this.item.tooltip =
        detail ??
        'Bug Dhor backend reachable. Run Bug Dhor: Show Status for the declared capability flags.';
    } else {
      this.item.text = '$(shield) Bug Dhor';
      this.item.tooltip =
        detail ?? 'Bug Dhor backend unavailable. Click for status and troubleshooting.';
    }
  }

  applySettings() {
    const { showStatusBarItem } = readSettings();
    if (showStatusBarItem) {
      this.item.show();
    } else {
      this.item.hide();
    }
  }

  dispose() {
    this.item.dispose();
  }
}

/** @returns {StatusBar} */
function createStatusBar() {
  return new StatusBar();
}

module.exports = { StatusBar, createStatusBar };
