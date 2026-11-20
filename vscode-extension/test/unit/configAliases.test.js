'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const configPath = require.resolve('../../src/config');
const state = {
  values: {},
  inspections: {}
};
const configuration = {
  get(key, fallback) {
    return Object.prototype.hasOwnProperty.call(state.values, key) ? state.values[key] : fallback;
  },
  inspect(key) {
    return state.inspections[key];
  }
};
const vscode = {
  workspace: {
    getConfiguration(section) {
      assert.equal(section, 'bugdhor');
      return configuration;
    },
    onDidChangeConfiguration() {
      return { dispose() {} };
    }
  }
};

const originalLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  if (request === 'vscode') {
    return vscode;
  }
  return originalLoad.call(this, request, parent, isMain);
};
let configModule;
try {
  delete require.cache[configPath];
  configModule = require(configPath);
} finally {
  Module._load = originalLoad;
  delete require.cache[configPath];
}
const { firstConfiguredValue, readSettings } = configModule;

function resetState() {
  state.values = {};
  state.inspections = {};
}

test('firstConfiguredValue returns the fallback when no alias is configured', () => {
  const value = firstConfiguredValue(
    configuration,
    ['engine.autoStart', 'backend.autoStart'],
    true
  );
  assert.equal(value, true);
});

test('firstConfiguredValue reads explicit primary values from any scope before legacy values', () => {
  state.inspections = {
    'engine.autoStart': { globalValue: undefined, workspaceValue: false },
    'backend.autoStart': { globalValue: true }
  };
  assert.equal(
    firstConfiguredValue(configuration, ['engine.autoStart', 'backend.autoStart'], true),
    false
  );

  state.inspections = {
    'engine.autoStart': { globalValue: undefined, workspaceValue: undefined },
    'backend.autoStart': { globalValue: false }
  };
  assert.equal(
    firstConfiguredValue(configuration, ['engine.autoStart', 'backend.autoStart'], true),
    false
  );

  state.inspections = {};
  state.values = { 'backend.autoStart': false };
  assert.equal(
    firstConfiguredValue(configuration, ['engine.autoStart', 'backend.autoStart'], true),
    false
  );
});

test('readSettings applies configured alias precedence and keeps manifest defaults out of the way', () => {
  resetState();
  assert.equal(readSettings().autoStart, true);

  state.inspections = {
    'engine.autoStart': { globalValue: false },
    'backend.autoStart': { globalValue: true }
  };
  state.values = {
    'scan.exclude': ['**/primary-generated/**'],
    'monitoring.excludeGlobs': ['**/legacy-generated/**']
  };
  state.inspections['monitoring.scanOnSave'] = { workspaceValue: false };
  state.inspections['monitoring.onSaveOnly'] = { workspaceValue: true };

  const settings = readSettings();
  assert.equal(settings.autoStart, false);
  assert.deepEqual(settings.monitoringExcludeGlobs, ['**/primary-generated/**']);
  assert.deepEqual(settings.scanExcludeGlobs, ['**/primary-generated/**']);
  assert.equal(settings.monitoringOnSaveOnly, false);
  assert.equal(settings.monitoringScanOnSave, false);
});
