'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_EXCLUDE_GLOBS,
  DEFAULT_SUPPORTED_LANGUAGES,
  buildAnalysisPlan,
  findFunctionRanges,
  findJavaScriptFunctions,
  findPythonFunctions,
  isBulkInsert,
  isPathExcluded,
  isSupportedLanguage,
  mergeRanges,
  normalizeLanguage,
  rangeFromContentChange,
  textForPlan
} = require('../../src/monitoring/changeAnalyzer');

test('normalizes Python and JavaScript language identifiers', () => {
  assert.equal(normalizeLanguage('Python'), 'python');
  assert.equal(normalizeLanguage('py'), 'python');
  assert.equal(normalizeLanguage('javascriptreact'), 'javascript');
  assert.equal(normalizeLanguage('js'), 'javascript');
  assert.equal(normalizeLanguage(''), undefined);
  assert.equal(isSupportedLanguage('python', DEFAULT_SUPPORTED_LANGUAGES), true);
  assert.equal(isSupportedLanguage('javascript', DEFAULT_SUPPORTED_LANGUAGES), true);
  assert.equal(isSupportedLanguage('ruby', DEFAULT_SUPPORTED_LANGUAGES), false);
});

test('excludes generated directories with dependency-free globs', () => {
  assert.equal(isPathExcluded('/repo/node_modules/pkg/index.js', DEFAULT_EXCLUDE_GLOBS), true);
  assert.equal(isPathExcluded('/repo/.venv/lib/mod.py', DEFAULT_EXCLUDE_GLOBS), true);
  assert.equal(isPathExcluded('/repo/src/app.js', DEFAULT_EXCLUDE_GLOBS), false);
  assert.equal(isPathExcluded('C:\\repo\\dist\\bundle.js', DEFAULT_EXCLUDE_GLOBS), true);
});

test('maps content changes to bounded half-open line ranges', () => {
  assert.deepEqual(
    rangeFromContentChange(
      { text: 'x', range: { start: { line: 3, character: 0 }, end: { line: 3, character: 1 } } },
      10
    ),
    { startLine: 3, endLine: 4 }
  );
  assert.deepEqual(
    rangeFromContentChange(
      {
        text: 'one\ntwo\nthree\n',
        range: { start: { line: 1, character: 0 }, end: { line: 1, character: 0 } }
      },
      10
    ),
    { startLine: 1, endLine: 5 }
  );
});

test('describes a multi-line insertion as a bulk edit without attribution', () => {
  assert.equal(isBulkInsert({ text: 'a\nb\nc\n' }), true);
  assert.equal(isBulkInsert({ text: 'x'.repeat(64) }), true);
  assert.equal(isBulkInsert({ text: 'x' }), false);
});

test('merges overlapping and adjacent line ranges', () => {
  assert.deepEqual(
    mergeRanges([
      { startLine: 5, endLine: 7 },
      { startLine: 7, endLine: 9 },
      { startLine: 1, endLine: 2 },
      { startLine: 20, endLine: 21 }
    ]),
    [
      { startLine: 1, endLine: 2 },
      { startLine: 5, endLine: 9 },
      { startLine: 20, endLine: 21 }
    ]
  );
});

test('finds Python function spans from indentation', () => {
  const text = [
    'import os',
    '',
    'def first():',
    '    return 1',
    '',
    'async def second(x):',
    '    if x:',
    '        return x',
    '    return 0',
    '',
    'VALUE = 2'
  ].join('\n');
  const functions = findPythonFunctions(text.split('\n'));
  assert.deepEqual(
    functions.map((fn) => [fn.name, fn.startLine, fn.endLine]),
    [
      ['first', 2, 4],
      ['second', 5, 9]
    ]
  );
});

test('finds JavaScript function spans with brace counting', () => {
  const text = [
    'const add = (a, b) => {',
    '  return a + b;',
    '};',
    '',
    'function greet(name) {',
    '  // return { message: name };',
    '  return `hello ${name}`;',
    '}',
    '',
    'const value = 1;'
  ].join('\n');
  const functions = findJavaScriptFunctions(text.split('\n'));
  assert.deepEqual(
    functions.map((fn) => [fn.name, fn.startLine, fn.endLine]),
    [
      ['add', 0, 3],
      ['greet', 4, 8]
    ]
  );
});

test('selects enclosing functions and keeps uncovered top-level changes', () => {
  const text = [
    'TOP = 1',
    '',
    'def first():',
    '    return TOP',
    '',
    'def second():',
    '    return 2'
  ].join('\n');
  const ranges = [
    { startLine: 0, endLine: 1 },
    { startLine: 3, endLine: 4 }
  ];
  const selected = findFunctionRanges(text, 'python', ranges);
  assert.equal(selected.length, 2);
  assert.equal(selected[0].startLine, 0);
  assert.equal(selected[0].name, undefined);
  assert.equal(selected[1].name, 'first');
});

test('builds a function-scoped incremental plan for a changed line', () => {
  const text = [
    'def add(a, b):',
    '    value = a + b',
    '    return value',
    '',
    'print(add(1, 2))'
  ].join('\n');
  const plan = buildAnalysisPlan({
    text,
    lineCount: 5,
    languageId: 'python',
    ranges: [{ startLine: 1, endLine: 2 }],
    settings: { analysisScope: 'function', maxChangedLines: 100 },
    reason: 'change'
  });
  assert.equal(plan.kind, 'function');
  assert.deepEqual(plan.selection, {
    start: { line: 0, character: 0 },
    end: { line: 2, character: 16 }
  });
  assert.equal(textForPlan(text, plan), 'def add(a, b):\n    value = a + b\n    return value');
});

test('builds changed-lines, file, and wide-change plans', () => {
  const text = 'a = 1\nb = 2\nc = 3\n';
  const lines = buildAnalysisPlan({
    text,
    lineCount: 3,
    languageId: 'python',
    ranges: [{ startLine: 1, endLine: 2 }],
    settings: { analysisScope: 'changedLines', maxChangedLines: 100 }
  });
  assert.equal(lines.kind, 'changedLines');
  assert.equal(lines.selection.start.line, 1);

  const file = buildAnalysisPlan({
    text,
    lineCount: 3,
    languageId: 'python',
    ranges: [{ startLine: 1, endLine: 2 }],
    settings: { analysisScope: 'file', maxChangedLines: 100 }
  });
  assert.equal(file.kind, 'file');
  assert.equal(file.endLine, 3);

  const wide = buildAnalysisPlan({
    text,
    lineCount: 3,
    languageId: 'python',
    ranges: [{ startLine: 0, endLine: 3 }],
    settings: { analysisScope: 'function', maxChangedLines: 2 }
  });
  assert.equal(wide.kind, 'file');
  assert.equal(wide.wideChange, true);
});
