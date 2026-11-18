'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { DecorationController } = require('../../src/diagnostics/decorationController');
const { registerDiagnostics } = require('../../src/diagnostics');
const { createFinding, createFakeVscode, createUri } = require('./diagnosticsFake');

const EXTENSION_URI = createUri('file:///workspace/extension');
const DOCUMENT_URI = 'file:///workspace/src/app.js';

function createEditor() {
  const calls = [];
  const editor = {
    document: { uri: createUri(DOCUMENT_URI) },
    setDecorations(type, options) {
      calls.push({ type, options });
    }
  };
  return { editor, calls };
}

function lastOptions(calls, type) {
  const matching = calls.filter((call) => call.type === type);
  return matching.length > 0 ? matching.at(-1).options : undefined;
}

function createController(options = {}) {
  const fake = createFakeVscode(options);
  const controller = new DecorationController({
    vscode: fake.vscode,
    extensionUri: EXTENSION_URI,
    logger: fake.logger
  });
  return { ...fake, controller };
}

function createFindings() {
  return [
    createFinding({
      id: 'critical-finding',
      severity: 'critical',
      detectionMethod: 'ast-taint-analysis',
      explanation: 'Untrusted input reaches the query.',
      location: {
        uri: DOCUMENT_URI,
        range: {
          start: { line: 1, character: 2 },
          end: { line: 1, character: 12 }
        }
      }
    }),
    createFinding({
      id: 'medium-finding',
      severity: 'medium',
      location: {
        uri: DOCUMENT_URI,
        range: {
          start: { line: 3, character: 4 },
          end: { line: 3, character: 14 }
        }
      }
    }),
    createFinding({
      id: 'info-finding',
      severity: 'info',
      location: {
        uri: DOCUMENT_URI,
        range: {
          start: { line: 5, character: 0 },
          end: { line: 5, character: 8 }
        }
      }
    })
  ];
}

test('creates static severity decorations with local gutter icons', () => {
  const harness = createController();
  const [error, warning, information] = harness.decorationTypes;

  assert.deepEqual(Object.keys(harness.controller.types), ['error', 'warning', 'information']);
  assert.equal(harness.decorationTypes.length, 3);

  assert.equal(error.options.textDecoration, 'underline');
  assert.equal(error.options.borderStyle, 'solid');
  assert.equal(error.options.borderColor.id, 'charts.red');
  assert.equal(error.options.overviewRulerLane, 7);
  assert.match(error.options.gutterIconPath.toString(), /gutter-critical\.svg$/);
  assert.equal(warning.options.borderColor.id, 'charts.yellow');
  assert.match(warning.options.gutterIconPath.toString(), /gutter-medium\.svg$/);
  assert.equal(information.options.borderColor.id, 'charts.blue');
  assert.match(information.options.gutterIconPath.toString(), /gutter-low\.svg$/);
  assert.equal(harness.visibleEditorListeners.length, 1);

  harness.controller.dispose();
});

test('applies exact ranges and native hover details to visible editors', () => {
  const { editor, calls } = createEditor();
  const harness = createController({ visibleTextEditors: [editor] });
  const findings = createFindings();

  harness.controller.setFindings(createUri(DOCUMENT_URI), findings);

  assert.equal(calls.length, 3);
  const errorOptions = lastOptions(calls, harness.controller.types.error);
  const warningOptions = lastOptions(calls, harness.controller.types.warning);
  const informationOptions = lastOptions(calls, harness.controller.types.information);

  assert.deepEqual(
    errorOptions.map((entry) => entry.range.start),
    [{ line: 1, character: 2 }]
  );
  assert.deepEqual(
    errorOptions.map((entry) => entry.range.end),
    [{ line: 1, character: 12 }]
  );
  assert.equal(errorOptions[0].hoverMessage.isTrusted, false);
  assert.match(errorOptions[0].hoverMessage.value, /Bug Dhor: User input reaches a SQL query/);
  assert.match(errorOptions[0].hoverMessage.value, /ast\\-taint\\-analysis/);
  assert.match(errorOptions[0].hoverMessage.value, /Untrusted input reaches the query/);
  assert.deepEqual(
    warningOptions.map((entry) => entry.range.start),
    [{ line: 3, character: 4 }]
  );
  assert.deepEqual(
    informationOptions.map((entry) => entry.range.start),
    [{ line: 5, character: 0 }]
  );

  harness.controller.dispose();
});

test('refreshes newly visible editors and clears decorations safely', () => {
  const first = createEditor();
  const harness = createController({ visibleTextEditors: [first.editor] });
  const findings = createFindings();
  harness.controller.setFindings(createUri(DOCUMENT_URI), findings);

  const second = createEditor();
  harness.visibleTextEditors.push(second.editor);
  for (const listener of harness.visibleEditorListeners) {
    listener([...harness.visibleTextEditors]);
  }
  assert.equal(second.calls.length, 3);
  assert.equal(lastOptions(second.calls, harness.controller.types.error).length, 1);

  harness.controller.clearUri(DOCUMENT_URI);
  assert.deepEqual(lastOptions(first.calls, harness.controller.types.error), []);
  assert.deepEqual(lastOptions(second.calls, harness.controller.types.error), []);

  harness.controller.setFindings(createUri(DOCUMENT_URI), findings);
  harness.controller.clearAll();
  assert.deepEqual(lastOptions(first.calls, harness.controller.types.warning), []);

  harness.controller.dispose();
  assert.ok(harness.decorationTypes.every((type) => type.disposed));
  assert.ok(harness.visibleEditorSubscriptions.every((subscription) => subscription.disposed));
  assert.throws(
    () => harness.controller.setFindings(createUri(DOCUMENT_URI), findings),
    /has been disposed/
  );
});

test('registerDiagnostics creates decorations only when given an extension URI', () => {
  const withoutUri = createFakeVscode();
  const withoutDecorations = registerDiagnostics({
    vscode: withoutUri.vscode,
    logger: withoutUri.logger
  });
  assert.equal(withoutDecorations.decorations, null);
  withoutDecorations.dispose();

  const withUri = createFakeVscode();
  const withDecorations = registerDiagnostics({
    vscode: withUri.vscode,
    extensionUri: EXTENSION_URI,
    logger: withUri.logger
  });
  assert.ok(withDecorations.decorations instanceof DecorationController);
  assert.equal(withUri.decorationTypes.length, 3);

  withDecorations.dispose();
  assert.ok(withUri.decorationTypes.every((type) => type.disposed));
});
