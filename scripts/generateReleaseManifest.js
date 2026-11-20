'use strict';

// Builds a structured release-gate manifest from CI evidence JSON files.
// Report prose is deliberately never read: only machine-generated evidence
// from the recorded workflow run can contribute to a gate result.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_VERSION = 1;
const DEFAULT_EVIDENCE_TTL_SECONDS = 24 * 60 * 60;
const FUTURE_SKEW_SECONDS = 60;
const MAX_REASON_LENGTH = 500;

const GATE_DEFINITIONS = Object.freeze([
  { key: 'lint-macos-latest', file: 'lint-macos-latest.json' },
  { key: 'lint-windows-latest', file: 'lint-windows-latest.json' },
  { key: 'lint-ubuntu-latest', file: 'lint-ubuntu-latest.json' },
  { key: 'unit-macos-latest', file: 'unit-macos-latest.json' },
  { key: 'unit-windows-latest', file: 'unit-windows-latest.json' },
  { key: 'unit-ubuntu-latest', file: 'unit-ubuntu-latest.json' },
  { key: 'package-macos-latest', file: 'package-macos-latest.json' },
  { key: 'package-windows-latest', file: 'package-windows-latest.json' },
  { key: 'package-ubuntu-latest', file: 'package-ubuntu-latest.json' },
  { key: 'integration-macos-latest', file: 'integration-macos-latest.json' },
  { key: 'integration-windows-latest', file: 'integration-windows-latest.json' },
  { key: 'integration-ubuntu-latest', file: 'integration-ubuntu-latest.json' },
  { key: 'python-tests', file: 'python-tests.json' },
  { key: 'python-sca', file: 'python-sca.json' },
  { key: 'npm-audit', file: 'npm-audit.json' },
  { key: 'untrusted-workspace', file: 'untrusted-workspace.json' }
]);

// These are not inferable from ordinary CI logs. They remain blockers unless a
// separately reviewed process uploads passing evidence for the exact same
// commit and workflow run. Missing or failing evidence stays fail-closed.
const EXTERNAL_GATES = Object.freeze([
  {
    gate: 'oidc-publish-receipt',
    file: 'oidc-publish-receipt.json',
    artifact: 'evidence-oidc-publish-receipt',
    status: 'UNVERIFIED',
    reason: 'No verified OIDC publish receipt exists for this release.'
  },
  {
    gate: 'publisher-ownership',
    file: 'publisher-ownership.json',
    artifact: 'evidence-publisher-ownership',
    status: 'UNVERIFIED',
    reason: 'Marketplace publisher ownership has not been independently verified.'
  },
  {
    gate: 'trusted-publishing-policy',
    file: 'trusted-publishing-policy.json',
    artifact: 'evidence-trusted-publishing-policy',
    status: 'UNVERIFIED',
    reason: 'Marketplace Trusted Publishing policy compliance has not been verified.'
  }
]);
const EXTERNAL_BLOCKERS = Object.freeze(
  EXTERNAL_GATES.map(({ gate, status, reason }) => ({ gate, status, reason }))
);
const EXTERNAL_ARTIFACTS = new Set(EXTERNAL_GATES.map(({ artifact }) => artifact));

// Untrusted workspace behavior is no longer listed here: it is a mandatory CI
// gate (`untrusted-workspace`) with its own evidence artifact. Only facts that
// cannot be established by that run remain external blockers.

const EVIDENCE_FIELDS = new Set([
  'schema_version',
  'gate',
  'status',
  'commit_sha',
  'run_id',
  'run_url',
  'generated_at',
  'test_count',
  'lock_sha256',
  'detail'
]);

const MANIFEST_FIELDS = new Set([
  'schema_version',
  'commit_sha',
  'run_id',
  'run_url',
  'repository',
  'generated_at',
  'gates',
  'blockers',
  'external_evidence',
  'decision'
]);

const GATE_ENTRY_FIELDS = new Set([
  'status',
  'evidence_path',
  'evidence_sha256',
  'generated_at',
  'test_count',
  'lock_sha256',
  'detail'
]);

const BLOCKER_FIELDS = new Set(['gate', 'status', 'reason']);
const GATE_STATUSES = new Set(['pass', 'fail', 'blocked']);
const BLOCKER_STATUSES = new Set(['UNVERIFIED', 'fail', 'blocked']);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function validateCommitSha(value, label) {
  assert(
    typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value),
    `${label} must be a 40-character hex commit SHA`
  );
  return value.toLowerCase();
}

function validateRunId(value, label) {
  assert(
    typeof value === 'string' && /^[1-9][0-9]*$/.test(value),
    `${label} must be a positive decimal run ID string`
  );
  return value;
}

function validateRepository(value, label) {
  assert(
    typeof value === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value),
    `${label} must be in owner/repo form`
  );
  return value;
}

function parseRunUrl(value, label, runId, repository) {
  assert(typeof value === 'string' && value.length > 0, `${label} is required`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }
  assert(parsed.protocol === 'https:', `${label} must use https`);
  assert(!parsed.username && !parsed.password, `${label} must not contain credentials`);
  assert(!parsed.search && !parsed.hash, `${label} must not contain a query or fragment`);
  const segments = parsed.pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  assert(
    segments.length === 5 &&
      segments[2] === 'actions' &&
      segments[3] === 'runs' &&
      segments[4] === runId,
    `${label} must point to /actions/runs/${runId}`
  );
  if (repository) {
    assert(
      `${segments[0]}/${segments[1]}`.toLowerCase() === repository.toLowerCase(),
      `${label} repository does not match ${repository}`
    );
  }
  return parsed;
}

function validateTimestamp(value, label, maxAgeSeconds, now) {
  assert(
    typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value),
    `${label} must be an ISO-8601 timestamp with a timezone`
  );
  const timestamp = Date.parse(value);
  assert(Number.isFinite(timestamp), `${label} is not a valid timestamp`);
  const ageSeconds = (now.getTime() - timestamp) / 1000;
  assert(ageSeconds >= -FUTURE_SKEW_SECONDS, `${label} is in the future`);
  assert(ageSeconds <= maxAgeSeconds, `${label} is older than the ${maxAgeSeconds}s TTL`);
  return value;
}

function validatePositiveIntegerOption(value, label, maximum) {
  assert(
    Number.isInteger(value) && value > 0 && value <= maximum,
    `${label} must be an integer between 1 and ${maximum}`
  );
  return value;
}

function validateEvidence(raw, options) {
  const label =
    isPlainObject(raw) && typeof raw.gate === 'string' ? `evidence ${raw.gate}` : 'evidence';
  assert(isPlainObject(raw), `${label} must be a JSON object`);
  for (const key of Object.keys(raw)) {
    assert(EVIDENCE_FIELDS.has(key), `${label} contains unknown field ${key}`);
  }
  assert(
    raw.schema_version === SCHEMA_VERSION,
    `${label} schema_version must be ${SCHEMA_VERSION}`
  );
  assert(
    typeof raw.gate === 'string' && /^[a-z0-9][a-z0-9._-]{1,63}$/.test(raw.gate),
    `${label} gate must be a lowercase identifier`
  );
  assert(GATE_STATUSES.has(raw.status), `${label} status must be pass, fail, or blocked`);
  const commitSha = validateCommitSha(raw.commit_sha, `${label} commit_sha`);
  assert(
    commitSha === options.commitSha.toLowerCase(),
    `${label} commit_sha does not match the expected commit`
  );
  const runId = validateRunId(raw.run_id, `${label} run_id`);
  assert(runId === options.runId, `${label} run_id does not match the expected run`);
  parseRunUrl(raw.run_url, `${label} run_url`, runId, options.repository);
  if (options.runUrl) {
    const expected = parseRunUrl(options.runUrl, 'expected run_url', runId, options.repository);
    const actual = new URL(raw.run_url);
    assert(
      `${actual.host}${actual.pathname.replace(/\/+$/, '')}` ===
        `${expected.host}${expected.pathname.replace(/\/+$/, '')}`,
      `${label} run_url does not match the expected run URL`
    );
  }
  validateTimestamp(raw.generated_at, `${label} generated_at`, options.maxAgeSeconds, options.now);
  if (raw.test_count !== undefined) {
    assert(
      Number.isInteger(raw.test_count) && raw.test_count >= 0,
      `${label} test_count must be a non-negative integer`
    );
  }
  if (raw.lock_sha256 !== undefined) {
    assert(isSha256(raw.lock_sha256), `${label} lock_sha256 must be a SHA-256 digest`);
  }
  if (raw.detail !== undefined) {
    assert(
      typeof raw.detail === 'string' && raw.detail.length <= MAX_REASON_LENGTH,
      `${label} detail is invalid`
    );
  }
  if (raw.gate === 'python-tests') {
    assert(Number.isInteger(raw.test_count), `${label} requires test_count`);
  }
  if (raw.gate === 'python-sca') {
    assert(isSha256(raw.lock_sha256), `${label} requires lock_sha256`);
  }
  return raw;
}

function validateGateEntry(raw, key) {
  const label = `manifest gate ${key}`;
  assert(isPlainObject(raw), `${label} must be an object`);
  for (const field of Object.keys(raw)) {
    assert(GATE_ENTRY_FIELDS.has(field), `${label} contains unknown field ${field}`);
  }
  assert(GATE_STATUSES.has(raw.status), `${label} status must be pass, fail, or blocked`);
  assert(
    raw.evidence_path === `evidence/${key}.json`,
    `${label} evidence_path must be evidence/${key}.json`
  );
  assert(isSha256(raw.evidence_sha256), `${label} evidence_sha256 must be a SHA-256 digest`);
  assert(typeof raw.generated_at === 'string', `${label} generated_at must be a string`);
  if (raw.test_count !== undefined) {
    assert(
      Number.isInteger(raw.test_count) && raw.test_count >= 0,
      `${label} test_count is invalid`
    );
  }
  if (raw.lock_sha256 !== undefined) {
    assert(isSha256(raw.lock_sha256), `${label} lock_sha256 is invalid`);
  }
  if (raw.detail !== undefined) {
    assert(
      typeof raw.detail === 'string' && raw.detail.length <= MAX_REASON_LENGTH,
      `${label} detail is invalid`
    );
  }
  return raw;
}

function validateBlocker(raw, label) {
  assert(isPlainObject(raw), `${label} must be an object`);
  for (const field of Object.keys(raw)) {
    assert(BLOCKER_FIELDS.has(field), `${label} contains unknown field ${field}`);
  }
  assert(
    typeof raw.gate === 'string' && /^[a-z0-9][a-z0-9._-]{1,63}$/.test(raw.gate),
    `${label} gate is invalid`
  );
  assert(BLOCKER_STATUSES.has(raw.status), `${label} status is invalid`);
  assert(
    typeof raw.reason === 'string' &&
      raw.reason.length > 0 &&
      raw.reason.length <= MAX_REASON_LENGTH,
    `${label} reason is invalid`
  );
  return raw;
}

function validateManifest(raw, options = {}) {
  assert(isPlainObject(raw), 'manifest must be a JSON object');
  for (const key of Object.keys(raw)) {
    assert(MANIFEST_FIELDS.has(key), `manifest contains unknown field ${key}`);
  }
  assert(
    raw.schema_version === SCHEMA_VERSION,
    `manifest schema_version must be ${SCHEMA_VERSION}`
  );
  const commitSha = validateCommitSha(raw.commit_sha, 'manifest commit_sha');
  const runId = validateRunId(raw.run_id, 'manifest run_id');
  const repository = validateRepository(raw.repository, 'manifest repository');
  parseRunUrl(raw.run_url, 'manifest run_url', runId, repository);
  validateTimestamp(
    raw.generated_at,
    'manifest generated_at',
    options.maxAgeSeconds ?? 7 * 24 * 60 * 60,
    options.now ?? new Date()
  );
  assert(isPlainObject(raw.gates), 'manifest gates must be an object');
  const expectedKeys = GATE_DEFINITIONS.map(({ key }) => key).sort();
  const actualKeys = Object.keys(raw.gates).sort();
  assert(
    JSON.stringify(actualKeys) === JSON.stringify(expectedKeys),
    `manifest gates must contain exactly: ${expectedKeys.join(', ')}`
  );
  for (const key of expectedKeys) {
    validateGateEntry(raw.gates[key], key);
  }
  assert(Array.isArray(raw.blockers), 'manifest blockers must be an array');
  const manifestBlockerGates = new Set();
  for (const [index, blocker] of raw.blockers.entries()) {
    validateBlocker(blocker, `manifest blocker ${index}`);
    assert(!manifestBlockerGates.has(blocker.gate), `duplicate blocker ${blocker.gate}`);
    manifestBlockerGates.add(blocker.gate);
  }
  const externalEvidence = raw.external_evidence ?? [];
  assert(Array.isArray(externalEvidence), 'manifest external_evidence must be an array');
  raw.external_evidence = externalEvidence;
  const externalEvidenceSet = new Set();
  for (const name of externalEvidence) {
    assert(
      typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name),
      'manifest external_evidence contains an invalid artifact name'
    );
    assert(
      EXTERNAL_ARTIFACTS.has(name),
      `manifest external_evidence contains unsupported artifact ${name}`
    );
    assert(!externalEvidenceSet.has(name), `duplicate external evidence artifact ${name}`);
    externalEvidenceSet.add(name);
  }
  assert(
    raw.decision === 'GO' || raw.decision === 'NO-GO',
    'manifest decision must be GO or NO-GO'
  );
  const allPass = expectedKeys.every((key) => raw.gates[key].status === 'pass');
  const expectedDecision = allPass && raw.blockers.length === 0 ? 'GO' : 'NO-GO';
  assert(raw.decision === expectedDecision, `manifest decision must be ${expectedDecision}`);
  for (const { gate, artifact } of EXTERNAL_GATES) {
    const cleared = externalEvidenceSet.has(artifact);
    const blocked = manifestBlockerGates.has(gate);
    assert(
      cleared !== blocked,
      `external gate ${gate} must have either passing evidence or a blocker, not both or neither`
    );
  }
  if (options.expectedCommitSha) {
    assert(
      commitSha === options.expectedCommitSha.toLowerCase(),
      'manifest commit_sha does not match the expected commit'
    );
  }
  if (options.expectedRepository) {
    assert(
      repository.toLowerCase() === options.expectedRepository.toLowerCase(),
      `manifest repository does not match ${options.expectedRepository}`
    );
  }
  return raw;
}

function computeSha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function parseArgs(argv, env) {
  const options = {
    evidenceDir: env.RELEASE_EVIDENCE_DIR || '',
    commitSha: env.RELEASE_COMMIT_SHA || env.GITHUB_SHA || '',
    runId: env.RELEASE_RUN_ID || env.GITHUB_RUN_ID || '',
    runUrl:
      env.RELEASE_RUN_URL ||
      (env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
        ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
        : ''),
    outputDir: env.RELEASE_OUTPUT_DIR || '',
    repository: env.RELEASE_REPOSITORY || env.GITHUB_REPOSITORY || '',
    maxAgeSeconds: DEFAULT_EVIDENCE_TTL_SECONDS,
    generatedAt: env.RELEASE_GENERATED_AT || new Date().toISOString()
  };
  const valueOptions = new Set([
    '--evidence-dir',
    '--commit-sha',
    '--run-id',
    '--run-url',
    '--output-dir',
    '--repository',
    '--max-age-seconds',
    '--generated-at'
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    const separator = argument.indexOf('=');
    const name = separator === -1 ? argument : argument.slice(0, separator);
    assert(valueOptions.has(name), `unknown option ${name}`);
    let value;
    if (separator !== -1) {
      value = argument.slice(separator + 1);
    } else {
      index += 1;
      value = argv[index];
    }
    assert(typeof value === 'string' && value.length > 0, `${name} requires a value`);
    if (name === '--max-age-seconds') {
      assert(/^[0-9]+$/.test(value), '--max-age-seconds must be an integer');
      options.maxAgeSeconds = Number(value);
    } else {
      options[name.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    }
  }
  return options;
}

function generate(options, now = new Date()) {
  const commitSha = validateCommitSha(options.commitSha, 'commit_sha');
  const runId = validateRunId(options.runId, 'run_id');
  const repository = validateRepository(options.repository, 'repository');
  const runUrl = options.runUrl;
  parseRunUrl(runUrl, 'run_url', runId, repository);
  validatePositiveIntegerOption(options.maxAgeSeconds, 'max-age-seconds', 30 * 24 * 60 * 60);
  const generatedAt = validateTimestamp(
    options.generatedAt,
    'generated_at',
    options.maxAgeSeconds,
    now
  );
  assert(
    typeof options.evidenceDir === 'string' && options.evidenceDir.length > 0,
    'evidence-dir is required'
  );
  assert(
    typeof options.outputDir === 'string' && options.outputDir.length > 0,
    'output-dir is required'
  );

  let files;
  try {
    files = fs
      .readdirSync(options.evidenceDir)
      .filter((name) => name.endsWith('.json'))
      .sort();
  } catch (error) {
    throw new Error(`cannot read evidence directory ${options.evidenceDir}: ${error.message}`);
  }
  const expectedFiles = new Set(GATE_DEFINITIONS.map(({ file }) => file));
  for (const file of expectedFiles) {
    assert(files.includes(file), `missing required evidence file ${file}`);
  }

  const validationOptions = {
    commitSha,
    runId,
    repository,
    runUrl,
    maxAgeSeconds: options.maxAgeSeconds,
    now
  };
  const rawByFile = new Map();
  for (const file of files) {
    const fullPath = path.join(options.evidenceDir, file);
    let bytes;
    try {
      bytes = fs.readFileSync(fullPath);
    } catch (error) {
      throw new Error(`cannot read ${file}: ${error.message}`);
    }
    let raw;
    try {
      raw = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new Error(`${file} is not valid JSON`);
    }
    validateEvidence(raw, validationOptions);
    rawByFile.set(file, { raw, hash: computeSha256(bytes) });
  }

  const gates = {};
  const blockers = [];
  const trackedGates = new Set();
  const externalEvidence = [];
  for (const { key, file } of GATE_DEFINITIONS) {
    const { raw, hash } = rawByFile.get(file);
    const entry = {
      status: raw.status,
      evidence_path: `evidence/${file}`,
      evidence_sha256: hash,
      generated_at: raw.generated_at
    };
    if (raw.test_count !== undefined) {
      entry.test_count = raw.test_count;
    }
    if (raw.lock_sha256 !== undefined) {
      entry.lock_sha256 = raw.lock_sha256;
    }
    if (raw.detail !== undefined) {
      entry.detail = raw.detail;
    }
    gates[key] = entry;
    if (raw.status !== 'pass') {
      blockers.push({
        gate: key,
        status: raw.status,
        reason: `Gate ${key} evidence status is ${raw.status}.`
      });
      trackedGates.add(key);
    }
  }

  for (const file of files) {
    if (expectedFiles.has(file)) {
      continue;
    }
    const { raw } = rawByFile.get(file);
    const externalGate = EXTERNAL_GATES.find((definition) => definition.file === file);
    if (externalGate) {
      assert(raw.gate === externalGate.gate, `${file} gate must be ${externalGate.gate}`);
      if (raw.status === 'pass') {
        externalEvidence.push(externalGate.artifact);
        trackedGates.add(externalGate.gate);
        continue;
      }
    }
    if (raw.status !== 'pass' && !trackedGates.has(raw.gate)) {
      blockers.push({
        gate: raw.gate,
        status: raw.status,
        reason: `Additional evidence ${file} has status ${raw.status}.`
      });
      trackedGates.add(raw.gate);
    }
  }

  for (const blocker of EXTERNAL_BLOCKERS) {
    if (!trackedGates.has(blocker.gate)) {
      blockers.push({ ...blocker });
      trackedGates.add(blocker.gate);
    }
  }
  externalEvidence.sort();
  blockers.sort((left, right) => left.gate.localeCompare(right.gate));

  const allPass = GATE_DEFINITIONS.every(({ key }) => gates[key].status === 'pass');
  const manifest = {
    schema_version: SCHEMA_VERSION,
    commit_sha: commitSha,
    run_id: runId,
    run_url: runUrl,
    repository,
    generated_at: generatedAt,
    gates,
    blockers,
    external_evidence: externalEvidence,
    decision: allPass && blockers.length === 0 ? 'GO' : 'NO-GO'
  };
  validateManifest(manifest, { maxAgeSeconds: options.maxAgeSeconds, now });

  fs.mkdirSync(options.outputDir, { recursive: true });
  const outputPath = path.join(options.outputDir, 'release-gate-manifest.json');
  const sidecarPath = `${outputPath}.sha256`;
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  fs.writeFileSync(outputPath, bytes);
  fs.writeFileSync(
    sidecarPath,
    Buffer.from(`${computeSha256(bytes)}  ${path.basename(outputPath)}\n`, 'utf8')
  );
  return { manifest, outputPath, sidecarPath };
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2), process.env);
  } catch (error) {
    console.error(`release manifest arguments: ${error.message}`);
    process.exit(1);
  }
  if (options.help) {
    console.log(
      'Usage: node scripts/generateReleaseManifest.js --evidence-dir DIR --commit-sha SHA ' +
        '--run-id ID --run-url URL --repository OWNER/REPO --output-dir DIR ' +
        '[--max-age-seconds N] [--generated-at ISO]'
    );
    return;
  }
  try {
    const { manifest, outputPath, sidecarPath } = generate(options);
    console.log(`Release gate manifest: ${outputPath}`);
    console.log(`Release gate manifest sidecar: ${sidecarPath}`);
    console.log(`Decision: ${manifest.decision}`);
    if (manifest.blockers.length > 0) {
      console.log(`Blockers: ${manifest.blockers.map((blocker) => blocker.gate).join(', ')}`);
    }
  } catch (error) {
    console.error(`release manifest generation: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  SCHEMA_VERSION,
  DEFAULT_EVIDENCE_TTL_SECONDS,
  GATE_DEFINITIONS,
  EXTERNAL_GATES,
  EXTERNAL_BLOCKERS,
  assert,
  isPlainObject,
  isSha256,
  validateCommitSha,
  validateRunId,
  validateRepository,
  parseRunUrl,
  validateTimestamp,
  validatePositiveIntegerOption,
  validateEvidence,
  validateManifest,
  computeSha256,
  parseArgs,
  generate
};
