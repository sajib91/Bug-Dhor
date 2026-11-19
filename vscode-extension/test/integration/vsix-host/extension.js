'use strict';

/**
 * Empty development extension used only as the Extension Host entry point for
 * the VSIX smoke test. The extension under test is installed from the VSIX.
 */

function activate() {
  return {};
}

function deactivate() {}

module.exports = { activate, deactivate };
