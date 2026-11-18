'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname, '../../media/dashboard.js'), 'utf8');
const cssSource = fs.readFileSync(path.resolve(__dirname, '../../media/dashboard.css'), 'utf8');

test('dashboard client avoids unsafe rendering and network APIs', () => {
  assert.ok(!/\.innerHTML\s*=/.test(source), 'dynamic innerHTML is forbidden');
  assert.ok(!source.includes('outerHTML'));
  assert.ok(!source.includes('insertAdjacentHTML'));
  assert.ok(!source.includes('document.write'));
  assert.ok(!source.includes('eval('));
  assert.ok(!source.includes('new Function'));
  assert.ok(!source.includes('fetch('));
  assert.ok(!source.includes('XMLHttpRequest'));
  assert.ok(!/https?:\/\//.test(source), 'dashboard client must not reference remote origins');
  assert.ok(!source.includes('.style.'), 'client must not set inline styles');
});

test('dashboard client renders all eleven dashboard sections', () => {
  for (const sectionId of [
    'overview',
    'scan',
    'vulnerabilities',
    'saeFeatures',
    'featureInteractions',
    'securitySteering',
    'explanations',
    'automatedRepair',
    'verification',
    'researchReports',
    'settings'
  ]) {
    assert.ok(source.includes(`'${sectionId}'`), `${sectionId} must be handled`);
  }

  assert.ok(source.includes("sendMessage({ type: 'ready' })"));
  assert.ok(source.includes("type: 'refresh'"));
  assert.ok(source.includes("type: 'setDemoMode'"));
  assert.ok(source.includes("type: 'executeCommand'"));
  assert.ok(source.includes("type: 'openSettings'"));
  assert.ok(source.includes("type: 'showLogs'"));
});

test('dashboard client labels demo and unavailability states honestly', () => {
  assert.match(source, /Demo data/);
  assert.match(source, /not real-world causal claims/i);
  assert.match(source, /Not run is not a pass/i);
  assert.match(source, /No activation values are inferred/i);
  assert.match(source, /The dashboard never applies a patch itself/i);
  assert.match(source, /not probabilities/i);
});

test('dashboard client renders explainability evidence sections and source navigation', () => {
  for (const label of [
    'Vulnerability summary',
    'CWE classification',
    'Vulnerable code location',
    'Evidence sources',
    'AST / CFG / DFG visualization',
    'Taint propagation path',
    'SAE feature activation',
    'Counterfactual feature effects',
    'Feature interaction analysis',
    'Recommended security fixes'
  ]) {
    assert.ok(source.includes(label), `${label} must be rendered`);
  }
  assert.ok(source.includes("type: 'openLocation'"));
  assert.match(source, /hypotheses, not directly observed evidence or causal explanations/i);
  assert.match(source, /Unavailable information/);
});

test('dashboard client renders secure recommendations and feedback lifecycle state', () => {
  for (const label of [
    'Secure recommendations are proposals only',
    'No secure recommendations',
    'What changed',
    'Why it changed',
    'Remaining risks',
    'Original code',
    'Recommended code',
    'Feedback loop activity',
    'Resolution requires three independent signals',
    'Findings resolved'
  ]) {
    assert.ok(source.includes(label), `${label} must be rendered`);
  }
  assert.ok(source.includes('function renderRecommendationCards'));
  assert.ok(source.includes('function renderFeedbackLifecycle'));
  assert.ok(source.includes('function normalizeFeedback'));
  assert.ok(source.includes('recommendations: arrayOfRecords(source.recommendations)'));
  assert.ok(source.includes('feedback: normalizeFeedback(source.feedback)'));
  assert.ok(source.includes('A recommendation never guarantees'));
  assert.ok(source.includes('perfect security and is never applied without explicit approval.'));
});

test('dashboard client validates commands before posting them', () => {
  assert.ok(source.includes('safeCommandPattern'));
  assert.ok(source.includes('/^bugdhor\\.[A-Za-z][A-Za-z0-9]*$/'));
  assert.ok(source.includes('command: action.command'));
});

test('dashboard client renders real findings as clickable, status-aware insects', () => {
  for (const marker of [
    'function renderInsectFindingsCard',
    'function createInsectGlyph',
    'function resolvedFindingIds',
    'function openFindingLocation',
    "type: 'openLocation'",
    'Finding insects',
    'No finding insects',
    'The dashboard never generates insects without backend findings.',
    'Resolved findings stop moving.',
    'vulnerabilities: arrayOfRecords(source.vulnerabilities)',
    'finding.startLine'
  ]) {
    assert.ok(source.includes(marker), `${marker} must be present`);
  }
  assert.ok(!/Math\.random/.test(source), 'insects must not be randomized');
});

test('dashboard client provides finding search, filters, grouping, review, and rescan actions', () => {
  for (const marker of [
    "type: 'setFindingReviewed'",
    "type: 'rescanFinding'",
    'finding-search',
    'category-filter',
    'language-filter',
    'status-filter',
    'review-filter',
    'group-filter',
    'finding-group-row',
    'finding-details',
    'Evidence and fix',
    'Suggested fix',
    'Mark reviewed',
    'Rescan file',
    'normalizeFindingReviews'
  ]) {
    assert.ok(source.includes(marker), `${marker} must be present`);
  }
  assert.ok(
    source.includes('Count categories from the displayed findings only'),
    'category counts must not be double counted'
  );
  assert.ok(
    !source.includes('{ ...state.summary.categories }'),
    'summary categories must not seed counts'
  );
});

test('insect styling is theme-aware, responsive, and animation-safe', () => {
  for (const marker of [
    '.insect-card',
    '.insect-glyph',
    '.insect-count',
    '--vscode-foreground',
    '--vscode-editor-background',
    '@media (max-width: 640px)',
    '.insect-grid',
    '@media (prefers-reduced-motion: no-preference)',
    '@media (forced-colors: active)',
    'CanvasText'
  ]) {
    assert.ok(cssSource.includes(marker), `${marker} must be present in the stylesheet`);
  }

  const motionMatch = cssSource.match(
    /@media \(prefers-reduced-motion: no-preference\) \{([\s\S]*?)\n\}/
  );
  assert.ok(motionMatch, 'animations must be nested in a no-preference media query');
  assert.match(motionMatch[1], /animation: bugdhor-crawl/);
  assert.match(motionMatch[1], /animation: bugdhor-leg-wiggle/);
  assert.ok(
    !/animation:/.test(cssSource.replace(motionMatch[0], '')),
    'animations must not run outside the reduced-motion guard'
  );

  const forcedColors = cssSource.slice(cssSource.indexOf('@media (forced-colors: active)'));
  assert.match(forcedColors, /\.insect-card/);
  assert.match(forcedColors, /\.insect-count/);
  assert.match(forcedColors, /CanvasText/);
});
