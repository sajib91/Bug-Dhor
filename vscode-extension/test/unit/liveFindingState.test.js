'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DASHBOARD_SEVERITIES,
  appendLiveScanHistory,
  buildLiveScanDashboardPatch,
  buildLiveScanHistoryEntry,
  mergeLiveFindings,
  toDashboardFinding,
  uriToFilePath
} = require('../../src/webviews/liveFindingState');
const { createFinding } = require('./diagnosticsFake');

test('converts workspace file URIs to dashboard paths without inventing values', () => {
  assert.equal(uriToFilePath('file:///workspace/src/app.js'), '/workspace/src/app.js');
  assert.equal(uriToFilePath('file:///C%3A/workspace/src/app.js'), 'C:/workspace/src/app.js');
  assert.equal(uriToFilePath('untitled:Untitled-1'), undefined);
  assert.equal(uriToFilePath(undefined), undefined);
});

test('maps accepted findings to one-based display locations and keeps zero-based navigation', () => {
  const finding = createFinding({
    category: 'sql_injection',
    filePath: '/workspace/src/app.js',
    startLine: 4,
    startColumn: 2,
    endLine: 4,
    endColumn: 42,
    detectionMethod: 'ast-taint-analysis',
    confidence: 'inference',
    confidenceBasis: 'request reaches a query sink',
    uncertainty: ['A sanitizer may change the sink.'],
    suggestedRemediation: 'Bind the value as a query parameter.',
    verificationStatus: 'potential'
  });

  const mapped = toDashboardFinding(finding);

  assert.equal(mapped.id, 'finding-1');
  assert.equal(mapped.title, 'User input reaches a SQL query.');
  assert.equal(mapped.summary, finding.explanation);
  assert.equal(mapped.severity, 'high');
  assert.equal(mapped.category, 'sql_injection');
  assert.equal(mapped.file, '/workspace/src/app.js');
  assert.equal(mapped.path, '/workspace/src/app.js');
  assert.equal(mapped.line, 5);
  assert.equal(mapped.column, 3);
  assert.equal(mapped.endLine, 5);
  assert.equal(mapped.endColumn, 43);
  assert.equal(mapped.startLine, 4);
  assert.equal(mapped.startColumn, 2);
  assert.equal(mapped.endLineZeroBased, 4);
  assert.equal(mapped.endColumnZeroBased, 42);
  assert.equal(mapped.scanner, 'ast-taint-analysis');
  assert.equal(mapped.detectionMethod, 'ast-taint-analysis');
  assert.equal(mapped.confidence, 'inference');
  assert.deepEqual(mapped.uncertainty, ['A sanitizer may change the sink.']);
  assert.equal(mapped.status, 'potential');
  assert.equal(mapped.repairEligible, true);
});

test('builds severity, category, and status counts from accepted findings only', () => {
  const findings = [
    createFinding({
      id: 'critical-1',
      severity: 'critical',
      category: 'sql_injection',
      verificationStatus: 'confirmed',
      filePath: '/workspace/src/a.js'
    }),
    createFinding({
      id: 'medium-1',
      severity: 'medium',
      category: 'xss',
      filePath: '/workspace/src/b.js',
      explanation: undefined
    }),
    createFinding({
      id: 'medium-2',
      severity: 'medium',
      category: 'sql_injection',
      filePath: '/workspace/src/c.js',
      verificationStatus: 'potential'
    })
  ];

  const patch = buildLiveScanDashboardPatch({
    result: {
      analysisAvailable: true,
      filesScanned: 3,
      workspaceName: '/workspace'
    },
    findings,
    generatedAt: '2026-11-18T12:00:00.000Z'
  });

  assert.deepEqual(DASHBOARD_SEVERITIES, ['critical', 'high', 'medium', 'low']);
  assert.equal(patch.generatedAt, '2026-11-18T12:00:00.000Z');
  assert.equal(patch.vulnerabilities.length, 3);
  assert.equal(patch.summary.totalFindings, 3);
  assert.deepEqual(patch.summary.severity, {
    critical: 1,
    high: 0,
    medium: 2,
    low: 0
  });
  assert.deepEqual(patch.summary.categories, {
    sql_injection: 2,
    xss: 1
  });
  assert.deepEqual(patch.summary.statuses, {
    confirmed: 1,
    'not-reported': 1,
    potential: 1
  });
  assert.equal(patch.summary.analysisAvailable, true);
  assert.equal(patch.summary.filesScanned, 3);
  assert.equal(patch.summary.workspaceName, '/workspace');
  assert.equal(patch.summary.lastScanAt, '2026-11-18T12:00:00.000Z');
});

test('an empty accepted set produces explicit zero counts and no dashboard insects', () => {
  const patch = buildLiveScanDashboardPatch({
    result: { analysisAvailable: true },
    findings: [],
    generatedAt: '2026-11-18T12:00:00.000Z'
  });

  assert.deepEqual(patch.vulnerabilities, []);
  assert.equal(patch.summary.totalFindings, 0);
  assert.deepEqual(patch.summary.categories, {});
  assert.deepEqual(patch.summary.statuses, {});
  assert.deepEqual(patch.summary.severity, {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
});

test('dashboard findings carry a conservative file-extension language label', () => {
  const mapped = toDashboardFinding(
    createFinding({ filePath: '/workspace/src/module.py', languageId: undefined })
  );
  assert.equal(mapped.language, 'python');
  assert.equal(mapped.languageSource, 'file-extension');
});

test('scoped scans replace only their own findings and unscoped scans replace the set', () => {
  const first = createFinding({
    id: 'a-1',
    location: {
      uri: 'file:///workspace/src/a.js',
      range: {
        start: { line: 0, character: 0 },
        end: { line: 0, character: 4 }
      }
    }
  });
  const second = createFinding({
    id: 'b-1',
    location: {
      uri: 'file:///workspace/src/b.js',
      range: {
        start: { line: 1, character: 0 },
        end: { line: 1, character: 4 }
      }
    }
  });

  const scoped = mergeLiveFindings([first, second], [], [first.documentUri]);
  assert.deepEqual(
    scoped.map((finding) => finding.id),
    ['b-1']
  );

  const unscoped = mergeLiveFindings([first, second], [], []);
  assert.deepEqual(unscoped, []);

  const deduplicated = mergeLiveFindings([], [second, second], []);
  assert.equal(deduplicated.length, 1);
});

test('live history entries are honest about scope, status, and missing duration', () => {
  const entry = buildLiveScanHistoryEntry({
    result: { analysisAvailable: true, status: 'partial' },
    findings: [createFinding()],
    scopeUris: ['file:///workspace/src/app.js'],
    generatedAt: '2026-11-18T12:00:00.000Z',
    status: 'partial'
  });

  assert.equal(entry.startedAt, '2026-11-18T12:00:00.000Z');
  assert.equal(entry.scope, 'file:///workspace/src/app.js');
  assert.equal(entry.status, 'partial');
  assert.equal(entry.findings, 1);
  assert.equal('durationMs' in entry, false);

  const history = appendLiveScanHistory([{ id: 'older' }], entry, 2);
  assert.deepEqual(
    history.map((item) => item.id),
    [entry.id, 'older']
  );
  const patch = buildLiveScanDashboardPatch({
    findings: [],
    scanHistory: history
  });
  assert.deepEqual(patch.scanHistory, history);
});
