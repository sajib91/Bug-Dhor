'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  GATE_DEFINITIONS,
  EXTERNAL_GATES,
  EXTERNAL_BLOCKERS,
  generate,
  validateManifest
} = require('./generateReleaseManifest.js');
const {
  parseArgs,
  writeAuthorizationOutput,
  verifyReleaseManifest
} = require('./verifyReleaseManifest.js');

const COMMIT_SHA = 'a'.repeat(40);
const RUN_ID = '123456';
const REPOSITORY = 'sajib91/Bug-Dhor';
const RUN_URL = `https://github.com/${REPOSITORY}/actions/runs/${RUN_ID}`;

function writeEvidence(evidenceDir, gate, overrides = {}) {
  const payload = {
    schema_version: 1,
    gate,
    status: 'pass',
    commit_sha: COMMIT_SHA,
    run_id: RUN_ID,
    run_url: RUN_URL,
    generated_at: new Date().toISOString(),
    ...overrides
  };
  fs.writeFileSync(path.join(evidenceDir, `${gate}.json`), `${JSON.stringify(payload, null, 2)}\n`);
}

function createWorkspace(t, externalGates = []) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-release-manifest-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidenceDir = path.join(root, 'evidence');
  const outputDir = path.join(root, 'output');
  fs.mkdirSync(evidenceDir);

  for (const { key } of GATE_DEFINITIONS) {
    const overrides = {};
    if (key === 'python-tests') {
      overrides.test_count = 1118;
    }
    if (key === 'python-sca') {
      overrides.lock_sha256 = 'b'.repeat(64);
    }
    writeEvidence(evidenceDir, key, overrides);
  }
  for (const gate of externalGates) {
    writeEvidence(evidenceDir, gate, { detail: `reviewed evidence for ${gate}` });
  }
  return { root, evidenceDir, outputDir };
}

function generateManifest(evidenceDir, outputDir) {
  return generate({
    evidenceDir,
    outputDir,
    commitSha: COMMIT_SHA,
    runId: RUN_ID,
    runUrl: RUN_URL,
    repository: REPOSITORY,
    maxAgeSeconds: 86400,
    generatedAt: new Date().toISOString()
  });
}

async function startFakeGitHub(t, manifest) {
  const server = http.createServer((request, response) => {
    const { pathname } = new URL(request.url, 'http://127.0.0.1');
    response.setHeader('Content-Type', 'application/json');
    if (pathname.endsWith(`/actions/runs/${RUN_ID}`)) {
      response.end(
        JSON.stringify({
          head_sha: COMMIT_SHA,
          status: 'completed',
          conclusion: 'success',
          name: 'Extension compatibility tests'
        })
      );
      return;
    }
    if (pathname.endsWith('/jobs')) {
      response.end(
        JSON.stringify(
          GATE_DEFINITIONS.map(({ key }) => ({
            name: key,
            status: 'completed',
            conclusion: 'success'
          }))
        )
      );
      return;
    }
    if (pathname.endsWith('/artifacts')) {
      response.end(
        JSON.stringify(manifest.external_evidence.map((name) => ({ name, expired: false })))
      );
      return;
    }
    response.statusCode = 404;
    response.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test('missing external evidence produces an explicit NO-GO manifest', (t) => {
  const { evidenceDir, outputDir } = createWorkspace(t);
  const { manifest } = generateManifest(evidenceDir, outputDir);

  assert.equal(manifest.decision, 'NO-GO');
  assert.deepEqual(manifest.external_evidence, []);
  assert.deepEqual(
    manifest.blockers.map(({ gate }) => gate).sort(),
    EXTERNAL_BLOCKERS.map(({ gate }) => gate).sort()
  );
  for (const { gate, status, reason } of EXTERNAL_BLOCKERS) {
    const blocker = manifest.blockers.find((item) => item.gate === gate);
    assert.equal(blocker.status, status);
    assert.equal(blocker.reason, reason);
  }
});

test('passing same-run external evidence clears blockers and is recorded', (t) => {
  const { evidenceDir, outputDir } = createWorkspace(
    t,
    EXTERNAL_GATES.map(({ gate }) => gate)
  );
  const { manifest } = generateManifest(evidenceDir, outputDir);

  assert.equal(manifest.decision, 'GO');
  assert.deepEqual(manifest.blockers, []);
  assert.deepEqual(
    manifest.external_evidence,
    EXTERNAL_GATES.map(({ artifact }) => artifact).sort()
  );
  assert.doesNotThrow(() => validateManifest(manifest));
});

test('malformed external evidence fails closed', (t) => {
  const { evidenceDir, outputDir } = createWorkspace(t);
  writeEvidence(evidenceDir, 'publisher-ownership', {
    commit_sha: 'c'.repeat(40),
    detail: 'wrong-commit evidence'
  });

  assert.throws(
    () => generateManifest(evidenceDir, outputDir),
    /publisher-ownership commit_sha does not match the expected commit/
  );
});

test('a manifest cannot claim evidence and a blocker for the same external gate', (t) => {
  const { evidenceDir, outputDir } = createWorkspace(
    t,
    EXTERNAL_GATES.map(({ gate }) => gate)
  );
  const { manifest } = generateManifest(evidenceDir, outputDir);
  const forged = {
    ...manifest,
    decision: 'NO-GO',
    blockers: [{ gate: 'publisher-ownership', status: 'blocked', reason: 'forged blocker' }]
  };

  assert.throws(
    () => validateManifest(forged),
    /external gate publisher-ownership must have either passing evidence or a blocker/
  );
});

test('authorization output is fail-closed for NO-GO manifests', (t) => {
  const { evidenceDir, outputDir } = createWorkspace(t);
  const { manifest } = generateManifest(evidenceDir, outputDir);
  const outputPath = path.join(outputDir, 'authorization.env');

  writeAuthorizationOutput(outputPath, manifest);
  const text = fs.readFileSync(outputPath, 'utf8');
  assert.match(text, /^decision=NO-GO\n/);
  assert.match(text, /^authorized=false\n/m);
  assert.match(
    text,
    /^blockers=oidc-publish-receipt,publisher-ownership,trusted-publishing-policy\n$/m
  );
});

test('verifier parseArgs accepts report-only mode without weakening the default', () => {
  const defaultOptions = parseArgs([], {});
  assert.equal(defaultOptions.allowNoGo, false);
  assert.equal(defaultOptions.output, '');

  const options = parseArgs(['--allow-no-go', '--output=auth.env'], {});
  assert.equal(options.allowNoGo, true);
  assert.equal(options.output, 'auth.env');
});

test('--allow-no-go verifies integrity but leaves publication blocked', async (t) => {
  const { root, evidenceDir, outputDir } = createWorkspace(t);
  const { manifest, outputPath, sidecarPath } = generateManifest(evidenceDir, outputDir);
  const apiUrl = await startFakeGitHub(t, manifest);
  const options = {
    ...parseArgs([], {}),
    manifest: outputPath,
    sidecar: sidecarPath,
    expectedCommitSha: COMMIT_SHA,
    expectedRepository: REPOSITORY,
    token: 'test-token',
    apiUrl,
    maxAgeSeconds: 86400,
    allowNoGo: true,
    output: path.join(root, 'authorization.env')
  };

  await verifyReleaseManifest(manifest, options);
  writeAuthorizationOutput(options.output, manifest);
  const authorization = fs.readFileSync(options.output, 'utf8');
  assert.match(authorization, /^decision=NO-GO\n/);
  assert.match(authorization, /^authorized=false\n/m);

  await assert.rejects(
    () => verifyReleaseManifest(manifest, { ...options, allowNoGo: false }),
    /publication requires GO/
  );
});
