'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { COMMANDS } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const { registerPhase6Commands } = require('../../src/commands/phase6Commands');
const {
  LocalPhase6Error,
  createLocalPhase6Engine,
  readLocalSettings
} = require('../../src/phase6/localEngine');

const FILE = '/workspace/sample.js';
const SESSION = '/workspace/.bugdhor/phase6-session.json';

function createFinding() {
  return {
    id: 'finding-1',
    ruleId: 'JS-TAINT001',
    severity: 'high',
    repairEligible: true,
    documentUri: { toString: () => `file://${FILE}`, fsPath: FILE },
    range: {
      start: { line: 1, character: 20 },
      end: { line: 1, character: 35 }
    }
  };
}

function createFakeVscode(options = {}) {
  const shownDocuments = [];
  const informationMessages = [];
  const warningMessages = [];
  const errorMessages = [];
  const inputPrompts = [];
  const editor = {
    document: {
      uri: {
        scheme: 'file',
        fsPath: FILE,
        toString: () => `file://${FILE}`
      },
      languageId: 'javascript',
      version: 1
    },
    selection: { start: { line: 1, character: 22 } }
  };
  const settings = options.settings ?? {};
  const finding = createFinding();
  const diagnostics = {
    findAt: () => [finding],
    getFindingsForUri: () => [finding]
  };
  const vscode = {
    Uri: {
      file: (fsPath) => ({
        fsPath,
        toString: () => `file://${fsPath}`
      })
    },
    workspace: {
      getConfiguration(section) {
        assert.equal(section, 'bugdhor');
        return {
          get(key, defaultValue) {
            return Object.hasOwn(settings, key) ? settings[key] : defaultValue;
          }
        };
      },
      getWorkspaceFolder() {
        return { uri: { fsPath: '/workspace' } };
      },
      async openTextDocument(documentOptions) {
        return { ...documentOptions, uri: { scheme: 'untitled', fsPath: '/untitled/phase6' } };
      }
    },
    window: {
      get activeTextEditor() {
        return editor;
      },
      async showInformationMessage(message) {
        informationMessages.push(message);
      },
      async showWarningMessage(message, modalOptions, action) {
        warningMessages.push({ message, modalOptions, action });
        return options.warningResult;
      },
      async showInputBox(promptOptions) {
        inputPrompts.push(promptOptions);
        return options.inputResult;
      },
      async showErrorMessage(message) {
        errorMessages.push(message);
      },
      async showTextDocument(document, documentOptions) {
        shownDocuments.push({ document, documentOptions });
        return { document };
      }
    }
  };
  return {
    vscode,
    diagnostics,
    shownDocuments,
    informationMessages,
    warningMessages,
    errorMessages,
    inputPrompts
  };
}

function envelope(action, result) {
  return JSON.stringify({ ok: true, action, result });
}

function createRunner(responses = {}) {
  const calls = [];
  const runner = async (command, args, options) => {
    calls.push({ command, args, options });
    const action = args[2];
    if (action === '__error__') {
      return {
        stdout: JSON.stringify({
          ok: false,
          action,
          error: { type: 'Phase6Error', message: 'deliberate local failure' }
        }),
        stderr: ''
      };
    }
    return { stdout: envelope(action, responses[action] ?? {}), stderr: '' };
  };
  return { runner, calls };
}

const ANALYZE_RESULT = {
  file: FILE,
  language: 'javascript',
  finding_count: 1,
  findings: [
    {
      index: 1,
      rule_id: 'JS-TAINT001',
      location: { start_line: 2, start_column: 21 }
    }
  ]
};

function createEngine(options = {}) {
  const fake = createFakeVscode(options);
  const { runner, calls } = createRunner(options.responses);
  const engine = createLocalPhase6Engine({
    vscode: fake.vscode,
    diagnostics: fake.diagnostics,
    logger: undefined,
    runCommand: runner
  });
  return { ...fake, engine, runner, calls };
}

const ENABLED = Object.freeze({
  'localEngine.enabled': true,
  'localEngine.pythonPath': 'python3',
  'localEngine.requestTimeoutMs': 20000,
  'localEngine.allowSourceWrite': false,
  'localEngine.sessionPath': '.bugdhor/phase6-session.json'
});

test('local engine defaults are opt-in and write-safe', () => {
  const { vscode } = createFakeVscode();
  const settings = readLocalSettings(vscode);
  assert.equal(settings.enabled, false);
  assert.equal(settings.allowSourceWrite, false);
  assert.equal(settings.pythonPath, 'python');
  assert.equal(settings.requestTimeoutMs, 15000);
  assert.equal(settings.sessionPath, '.bugdhor/phase6-session.json');
});

test('disabled local engine refuses every invocation without running a process', async () => {
  const harness = createEngine();
  assert.throws(() => harness.engine.assertEnabled(), /disabled/i);
  await assert.rejects(() => harness.engine.analyze(FILE), LocalPhase6Error);
  assert.equal(harness.calls.length, 0);
});

test('invoke builds an explicit JSON-only CLI command with a bounded timeout', async () => {
  const harness = createEngine({ settings: ENABLED });
  const result = await harness.engine.explain(FILE, 1);
  assert.equal(result, undefined ?? result);
  assert.equal(harness.calls.length, 1);
  const call = harness.calls[0];
  assert.equal(call.command, 'python3');
  assert.deepEqual(call.args.slice(0, 4), [
    '-m',
    'bugdhor_ast.phase6.cli',
    'explain',
    '--file'
  ]);
  assert.ok(call.args.includes(FILE));
  assert.ok(call.args.includes('--index'));
  assert.ok(call.args.includes('1'));
  assert.ok(call.args.includes('--session'));
  assert.ok(call.args.includes(SESSION));
  assert.ok(!call.args.includes('--allow-source-write'));
  assert.equal(call.options.cwd, '/workspace');
  assert.equal(call.options.timeoutMs, 20000);
  assert.ok(call.options.env.PYTHONPATH.split(path.delimiter).includes('/workspace/src'));
});

test('invoke surfaces CLI error envelopes as typed local errors', async () => {
  const harness = createEngine({ settings: ENABLED, responses: {} });
  await assert.rejects(
    () => harness.engine.invoke('__error__'),
    (error) => error instanceof LocalPhase6Error && /deliberate local failure/.test(error.message)
  );
});

test('finding selection maps VS Code zero-based ranges to engine one-based indices', async () => {
  const harness = createEngine({
    settings: ENABLED,
    responses: { analyze: ANALYZE_RESULT }
  });
  const index = await harness.engine.indexForFinding(FILE, createFinding());
  assert.equal(index, 1);
  assert.equal(harness.calls[0].args[2], 'analyze');
});

test('source-write guard is independent from the enabled guard', async () => {
  const harness = createEngine({ settings: ENABLED });
  assert.throws(() => harness.engine.assertWriteAllowed(), /writes are disabled/i);
  await assert.rejects(
    () => harness.engine.apply(FILE, 'patch:abc123', 'patch:abc123'),
    /writes are disabled/i
  );
  await assert.rejects(
    () => harness.engine.revert('history:1', 'patch:abc123'),
    /writes are disabled/i
  );
  assert.equal(harness.calls.length, 0);

  const writeEnabled = createFakeVscode({
    settings: { ...ENABLED, 'localEngine.allowSourceWrite': true }
  });
  const settings = readLocalSettings(writeEnabled.vscode);
  assert.equal(settings.allowSourceWrite, true);
});

function createHandlers(options = {}) {
  const fake = createFakeVscode({ settings: ENABLED, ...options });
  const { runner, calls } = createRunner({
    analyze: ANALYZE_RESULT,
    explain: { finding_id: 'finding-1', explanation: { evidence: {} } },
    suggest: { recommendation: { status: 'ready' } },
    preview: {
      can_apply: true,
      patch: {
        patch_id: 'patch:abc123',
        unified_diff: '--- a/sample.js\n+++ b/sample.js\n@@ -1 +1 @@\n-a\n+b\n'
      }
    },
    apply: { patch_id: 'patch:abc123', entry: { entry_id: 'history:1' } },
    history: {
      entry_count: 1,
      history: {
        entries: [{ entry_id: 'history:1', patch_id: 'patch:abc123', reverted_at: null }]
      }
    },
    verify: { status: 'verified', scope: 'static_reanalysis' },
    revert: { entry_id: 'history:1', restored_sha256: 'abc' }
  });
  const registry = {
    registrations: new Map(),
    register(commandId, handler) {
      this.registrations.set(commandId, handler);
    }
  };
  registerPhase6Commands({
    vscode: fake.vscode,
    logger: { error() {}, debug() {} },
    diagnostics: fake.diagnostics,
    registry,
    phase6Runner: runner
  });
  const expected = COMMAND_DEFINITIONS.filter((item) => item.localEngine).map((item) => item.id);
  assert.deepEqual([...registry.registrations.keys()].sort(), expected.sort());
  return { ...fake, registry, calls };
}

test('Phase 6 read-only commands publish evidence without process writes', async () => {
  const harness = createHandlers();
  await harness.registry.registrations.get(COMMANDS.explainFindingPhase6)();
  await harness.registry.registrations.get(COMMANDS.suggestRepairPhase6)();
  await harness.registry.registrations.get(COMMANDS.previewRepairPhase6)();

  assert.deepEqual(
    harness.calls.map((call) => call.args[2]),
    ['analyze', 'explain', 'suggest', 'analyze', 'suggest', 'analyze', 'preview']
  );
  for (const call of harness.calls) {
    assert.ok(!call.args.includes('--allow-source-write'));
  }
  assert.equal(harness.shownDocuments.length, 3);
  assert.match(harness.shownDocuments[2].document.content, /textContent|\+\+\+ b\/sample\.js/);
  assert.equal(harness.errorMessages.length, 0);
});

test('apply and revert require settings opt-in, modal warning, and exact patch_id', async () => {
  const denied = createHandlers({ warningResult: 'Continue', inputResult: 'patch:abc123' });
  const noSettings = createFakeVscode({
    settings: { ...ENABLED, 'localEngine.allowSourceWrite': false }
  });
  assert.equal(readLocalSettings(noSettings.vscode).allowSourceWrite, false);
  await denied.registry.registrations.get(COMMANDS.applyRepairPhase6)();
  assert.equal(denied.errorMessages.length, 1);
  assert.match(denied.errorMessages[0], /writes are disabled/i);
  assert.equal(
    denied.calls.some((call) => call.args.includes('--allow-source-write')),
    false
  );

  const harness = createHandlers({ warningResult: 'Continue', inputResult: 'patch:abc123' });
  const settings = readLocalSettings(harness.vscode);
  assert.equal(settings.allowSourceWrite, false);
  const writeEnabled = createHandlers({
    settings: { ...ENABLED, 'localEngine.allowSourceWrite': true },
    warningResult: 'Continue',
    inputResult: 'patch:abc123'
  });
  await writeEnabled.registry.registrations.get(COMMANDS.applyRepairPhase6)();

  const applyCall = writeEnabled.calls.find((call) => call.args[2] === 'apply');
  assert.ok(applyCall);
  assert.ok(applyCall.args.includes('--allow-source-write'));
  assert.ok(applyCall.args.includes('patch:abc123'));
  assert.equal(writeEnabled.warningMessages[0].modalOptions.modal, true);
  assert.equal(writeEnabled.inputPrompts[0].placeHolder, 'patch:abc123');

  const wrongConfirmation = createHandlers({
    settings: { ...ENABLED, 'localEngine.allowSourceWrite': true },
    warningResult: 'Continue',
    inputResult: 'wrong'
  });
  await wrongConfirmation.registry.registrations.get(COMMANDS.applyRepairPhase6)();
  assert.equal(wrongConfirmation.errorMessages.length, 0);
  assert.equal(wrongConfirmation.informationMessages.length, 1);
  assert.match(wrongConfirmation.informationMessages[0], /cancelled/i);
  assert.equal(
    wrongConfirmation.calls.some((call) => call.args[2] === 'apply'),
    false
  );
});

test('verify and revert use the latest active history entry and show results', async () => {
  const harness = createHandlers({
    settings: { ...ENABLED, 'localEngine.allowSourceWrite': true },
    warningResult: 'Continue',
    inputResult: 'patch:abc123'
  });
  const verification = await harness.registry.registrations.get(COMMANDS.verifyRepairPhase6)();
  assert.equal(verification.status, 'verified');
  const reverted = await harness.registry.registrations.get(COMMANDS.revertRepairPhase6)();
  assert.equal(reverted.entry_id, 'history:1');

  const verifyCall = harness.calls.find((call) => call.args[2] === 'verify');
  const revertCall = harness.calls.find((call) => call.args[2] === 'revert');
  assert.ok(verifyCall.args.includes('history:1'));
  assert.ok(revertCall.args.includes('--allow-source-write'));
  assert.ok(revertCall.args.includes('patch:abc123'));
  assert.equal(harness.errorMessages.length, 0);
});

test('history command reports the persisted entry count without writing', async () => {
  const harness = createHandlers();
  const result = await harness.registry.registrations.get(COMMANDS.showRepairHistoryPhase6)();
  assert.equal(result.entryCount, 1);
  assert.equal(harness.calls[0].args[2], 'history');
  assert.ok(!harness.calls[0].args.includes('--allow-source-write'));
  assert.equal(harness.errorMessages.length, 0);
});
