'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { FeedbackController, FindingLifecycle, PatchOriginTracker } = require('../../src/feedback');

function createLogger() {
  return {
    entries: [],
    debug(message) {
      this.entries.push(['debug', message]);
    },
    warn(message) {
      this.entries.push(['warn', message]);
    },
    info(message) {
      this.entries.push(['info', message]);
    },
    error(message) {
      this.entries.push(['error', message]);
    }
  };
}

function createController(settings = {}) {
  const notifications = [];
  const controller = new FeedbackController({
    vscode: {
      window: {
        showInformationMessage(message) {
          notifications.push(message);
        }
      }
    },
    logger: createLogger(),
    getSettings: () => settings
  });
  return { controller, notifications };
}

const FINDING = {
  id: 'finding-1',
  documentUri: 'file:///workspace/app.py',
  cwe: 'CWE-89',
  ruleId: 'BD-SQL-001',
  severity: 'high',
  range: { start: { line: 5, character: 11 }, end: { line: 5, character: 49 } }
};

test('a finding resolves only after patch, clean rescan, and passing verification', () => {
  const { controller, notifications } = createController({
    notifyOnPatchApplied: true,
    notifyOnResolution: true
  });
  const scope = [FINDING.documentUri];

  controller.afterScan({ findings: [FINDING], scopeUris: scope });
  assert.equal(controller.getSnapshot().findings[0].state, 'open');

  controller.recordAppliedPatch({
    documentUri: FINDING.documentUri,
    findingId: FINDING.id,
    patchHash: 'patch-hash',
    appliedHash: 'applied-hash',
    source: 'dashboard.explicit-approval'
  });
  assert.equal(controller.getSnapshot().findings[0].state, 'patched');

  // Passing verification before a clean rescan is remembered but cannot resolve.
  controller.recordVerification({
    documentUri: FINDING.documentUri,
    findingId: FINDING.id,
    verdict: 'passed'
  });
  assert.equal(controller.getSnapshot().findings[0].state, 'verification_passed');

  controller.afterScan({ findings: [], scopeUris: scope });
  assert.equal(controller.getSnapshot().findings[0].state, 'resolved');
  assert.equal(controller.stats.resolutions, 1);
  assert.equal(notifications.length, 2);

  // A later scan that reports the finding again reopens it.
  controller.afterScan({ findings: [FINDING], scopeUris: scope });
  assert.equal(controller.getSnapshot().findings[0].state, 'regressed');
  assert.equal(controller.getSnapshot().findings[0].resolvedAt, null);
});

test('a failed verification never resolves a patched finding', () => {
  const { controller } = createController();
  controller.afterScan({ findings: [FINDING], scopeUris: [FINDING.documentUri] });
  controller.recordAppliedPatch({
    documentUri: FINDING.documentUri,
    findingId: FINDING.id,
    appliedHash: 'applied-hash'
  });
  controller.afterScan({ findings: [], scopeUris: [FINDING.documentUri] });
  controller.recordVerification({
    documentUri: FINDING.documentUri,
    findingId: FINDING.id,
    verdict: 'failed'
  });

  const entry = controller.getSnapshot().findings[0];
  assert.equal(entry.state, 'verification_failed');
  assert.equal(controller.stats.resolutions, 0);
});

test('duplicate diagnostics and monitor hooks do not double-count one scan', () => {
  const { controller } = createController();
  const response = { requestId: 'request-1' };
  controller.afterScan({
    documentUri: FINDING.documentUri,
    findings: [FINDING],
    scopeUris: [FINDING.documentUri],
    response
  });
  controller.afterScan({
    documentUri: FINDING.documentUri,
    findings: [FINDING],
    scopeUris: [FINDING.documentUri],
    response
  });

  assert.equal(controller.stats.scans, 1);
  assert.equal(controller.getSnapshot().findings.length, 1);
});

test('patch origin tracker suppresses each applied hash once and schedules one rescan', () => {
  const tracker = new PatchOriginTracker({ logger: createLogger() });
  const hash = 'applied-hash';
  tracker.recordAppliedPatch({
    documentUri: FINDING.documentUri,
    appliedHash: hash,
    patchHash: 'patch-hash',
    findingId: FINDING.id,
    source: 'dashboard.explicit-approval'
  });

  const first = tracker.beforeScan({ documentUri: FINDING.documentUri, hash });
  assert.equal(first.suppress, true);
  assert.equal(first.followUp, true);
  assert.equal(first.reason, 'bugdhor-applied-patch');
  assert.equal(first.patch.source, 'dashboard.explicit-approval');

  const second = tracker.beforeScan({ documentUri: FINDING.documentUri, hash });
  assert.deepEqual(second, { suppress: false, followUp: false });
  assert.equal(tracker.getHistory().length, 1);
  assert.throws(
    () => tracker.recordAppliedPatch({ documentUri: FINDING.documentUri }),
    /applied content hash/
  );
});

test('finding lifecycle ignores unknown findings when recording clean scans', () => {
  const lifecycle = new FindingLifecycle();
  lifecycle.observeScan({ documentUri: FINDING.documentUri, findings: [FINDING] });
  lifecycle.observeScan({ documentUri: 'file:///workspace/other.py', findings: [] });
  assert.equal(lifecycle.getSnapshot()[0].state, 'open');
});
