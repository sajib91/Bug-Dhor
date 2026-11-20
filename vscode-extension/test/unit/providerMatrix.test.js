'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  OBSERVATION,
  ATTRIBUTION,
  WORKSPACE_EVENTS,
  WORKSPACE_PROVIDER_MATRIX,
  toWorkspaceProviderMatrix,
  renderWorkspaceProviderMatrixMarkdown
} = require('../../src/monitoring/providerMatrix');

test('matrix covers every required source and workflow', () => {
  const ids = WORKSPACE_PROVIDER_MATRIX.map((entry) => entry.id);
  for (const id of [
    'github-copilot',
    'cursor',
    'claude',
    'chatgpt',
    'opencode',
    'other-assistants',
    'manual-code'
  ]) {
    assert.ok(ids.includes(id), `${id} must be represented`);
  }
  assert.equal(ids.length, new Set(ids).size);
});

test('every row uses official document observation and no attribution', () => {
  for (const entry of toWorkspaceProviderMatrix()) {
    assert.equal(entry.workspaceMonitoring, 'supported');
    assert.equal(entry.observation, OBSERVATION);
    assert.equal(entry.attribution, ATTRIBUTION);
    assert.ok(Array.isArray(entry.optionalAdapters));
  }
});

test('matrix lists only official workspace events', () => {
  assert.deepEqual(
    [...WORKSPACE_EVENTS],
    [
      'onDidOpenTextDocument',
      'onDidChangeTextDocument',
      'onDidSaveTextDocument',
      'onDidCreateFiles',
      'onDidDeleteFiles',
      'onDidChangeWorkspaceFolders'
    ]
  );
});

test('rendered markdown is honest about attribution and private APIs', () => {
  const markdown = renderWorkspaceProviderMatrixMarkdown();
  assert.match(markdown, /Workspace monitoring provider matrix/);
  assert.match(markdown, /GitHub Copilot/);
  assert.match(markdown, /Manually written code/);
  assert.match(markdown, /Attribution is always `none`/);
  assert.match(markdown, /Private APIs and reverse-engineered extension internals are never used/);
});
