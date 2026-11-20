'use strict';

// Verifies a release-gate manifest before an actual Marketplace publication.
// The manifest must be fresh, hash-consistent, GO, and backed by a successful
// GitHub Actions run whose referenced gate jobs all succeeded. Any API or
// validation failure is fail-closed. Tokens are sent in headers only and never
// printed.

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

const {
  GATE_DEFINITIONS,
  assert,
  isPlainObject,
  isSha256,
  validateCommitSha,
  validateRepository,
  validatePositiveIntegerOption,
  validateManifest,
  computeSha256
} = require('./generateReleaseManifest.js');

const DEFAULT_MANIFEST_TTL_SECONDS = 7 * 24 * 60 * 60;
const SOURCE_WORKFLOW_NAME = 'Extension compatibility tests';
const MAX_PAGES = 10;
const PAGE_SIZE = 100;

function parseArgs(argv, env) {
  const options = {
    manifest: env.RELEASE_MANIFEST_PATH || '',
    sidecar: env.RELEASE_MANIFEST_SIDECAR || '',
    expectedCommitSha: env.RELEASE_EXPECTED_COMMIT_SHA || env.GITHUB_SHA || '',
    expectedRepository: env.RELEASE_EXPECTED_REPOSITORY || env.GITHUB_REPOSITORY || '',
    token: env.GITHUB_TOKEN || '',
    apiUrl: env.GITHUB_API_URL || 'https://api.github.com',
    maxAgeSeconds: DEFAULT_MANIFEST_TTL_SECONDS
  };
  const valueOptions = new Set([
    '--manifest',
    '--sidecar',
    '--expected-commit-sha',
    '--expected-repository',
    '--token',
    '--api-url',
    '--max-age-seconds'
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
  if (!options.sidecar && options.manifest) {
    options.sidecar = `${options.manifest}.sha256`;
  }
  return options;
}

function readManifest(manifestPath, sidecarPath) {
  assert(manifestPath && sidecarPath, 'manifest and sidecar paths are required');
  let bytes;
  let sidecar;
  try {
    bytes = fs.readFileSync(manifestPath);
    sidecar = fs.readFileSync(sidecarPath, 'utf8').trim();
  } catch (error) {
    throw new Error(`cannot read manifest or sidecar: ${error.message}`);
  }
  const parts = sidecar.split(/\s+/);
  assert(parts.length >= 1 && isSha256(parts[0]), 'sidecar does not contain a SHA-256 digest');
  if (parts.length > 1) {
    assert(parts.length === 2, 'sidecar format is invalid');
    assert(parts[1] === require('node:path').basename(manifestPath), 'sidecar filename does not match the manifest');
  }
  const actual = computeSha256(bytes);
  assert(actual === parts[0].toLowerCase(), 'manifest SHA-256 does not match the sidecar');
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('manifest is not valid JSON');
  }
  return manifest;
}

function extractApiMessage(body) {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed?.message === 'string' && parsed.message.length > 0) {
      return ` (${parsed.message.slice(0, 200)})`;
    }
  } catch {
    // Fall through; the status code is sufficient context.
  }
  return '';
}

function requestJson(url, token) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      reject(new Error('GitHub API URL is invalid'));
      return;
    }
    const loopback = ['127.0.0.1', '::1', 'localhost'].includes(parsed.hostname);
    let transport = null;
    if (parsed.protocol === 'https:') {
      transport = https;
    } else if (parsed.protocol === 'http:' && loopback) {
      transport = http;
    }
    if (!transport) {
      reject(new Error('GitHub API URL must use https (http is allowed only for loopback test servers)'));
      return;
    }
    const request = transport.request(
      parsed,
      {
        method: 'GET',
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'User-Agent': 'bugdhor-release-manifest-verifier',
          'X-GitHub-Api-Version': '2022-11-28'
        }
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const status = response.statusCode ?? 0;
          const body = Buffer.concat(chunks).toString('utf8');
          if (status < 200 || status >= 300) {
            reject(new Error(`GitHub API request failed with HTTP ${status}${extractApiMessage(body)}`));
            return;
          }
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error('GitHub API returned invalid JSON'));
          }
        });
      }
    );
    request.on('error', (error) => reject(new Error(`GitHub API request failed: ${error.message}`)));
    request.end();
  });
}

async function requestAllPages(baseUrl, token) {
  const results = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const url = new URL(baseUrl);
    url.searchParams.set('per_page', String(PAGE_SIZE));
    url.searchParams.set('page', String(page));
    const payload = await requestJson(url.toString(), token);
    let batch;
    if (Array.isArray(payload)) {
      batch = payload;
    } else if (isPlainObject(payload)) {
      const collections = ['jobs', 'artifacts', 'workflow_runs'].filter((key) => Array.isArray(payload[key]));
      assert(collections.length === 1, 'GitHub API returned an unexpected collection');
      batch = payload[collections[0]];
    } else {
      throw new Error('GitHub API returned an unexpected collection');
    }
    results.push(...batch);
    if (batch.length < PAGE_SIZE) {
      return results;
    }
  }
  throw new Error('GitHub API pagination limit exceeded');
}

async function verifyAgainstGitHub(manifest, options) {
  assert(options.token.length > 0, 'GITHUB_TOKEN is required to verify the recorded run');
  const apiUrl = options.apiUrl.replace(/\/+$/, '');
  const base = `${apiUrl}/repos/${manifest.repository}/actions/runs/${manifest.run_id}`;
  const run = await requestJson(base, options.token);
  assert(run.head_sha?.toLowerCase() === manifest.commit_sha, 'recorded run is for a different commit');
  assert(run.status === 'completed', 'recorded run is not completed');
  assert(run.conclusion === 'success', `recorded run conclusion is ${run.conclusion}, not success`);
  assert(run.name === SOURCE_WORKFLOW_NAME, `recorded run workflow is ${run.name}, not ${SOURCE_WORKFLOW_NAME}`);

  const jobs = await requestAllPages(`${base}/jobs`, options.token);
  assert(jobs.length > 0, 'recorded run has no jobs');
  const jobsByName = new Map();
  for (const job of jobs) {
    assert(typeof job?.name === 'string', 'GitHub API returned a job without a name');
    assert(!jobsByName.has(job.name), `duplicate job name in recorded run: ${job.name}`);
    jobsByName.set(job.name, job);
  }
  for (const { key } of GATE_DEFINITIONS) {
    const job = jobsByName.get(key);
    assert(job, `recorded run is missing gate job ${key}`);
    assert(job.status === 'completed', `gate job ${key} is not completed`);
    assert(job.conclusion === 'success', `gate job ${key} conclusion is ${job.conclusion}, not success`);
  }

  if (manifest.external_evidence.length > 0) {
    const artifacts = await requestAllPages(`${base}/artifacts`, options.token);
    const names = new Set(artifacts.filter((artifact) => !artifact.expired).map((artifact) => artifact.name));
    for (const name of manifest.external_evidence) {
      assert(names.has(name), `external evidence artifact ${name} is not present in the recorded run`);
    }
  }
  return { run, jobCount: jobs.length };
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2), process.env);
  } catch (error) {
    console.error(`release manifest verification arguments: ${error.message}`);
    process.exit(1);
  }
  if (options.help) {
    console.log(
      'Usage: node scripts/verifyReleaseManifest.js --manifest FILE --sidecar FILE ' +
        '--expected-commit-sha SHA --expected-repository OWNER/REPO [--api-url URL] ' +
        '[--max-age-seconds N] (GITHUB_TOKEN from environment)'
    );
    return;
  }
  try {
    const expectedCommitSha = validateCommitSha(options.expectedCommitSha, 'expected commit SHA');
    const expectedRepository = validateRepository(options.expectedRepository, 'expected repository');
    validatePositiveIntegerOption(options.maxAgeSeconds, 'max-age-seconds', 30 * 24 * 60 * 60);

    const manifest = readManifest(options.manifest, options.sidecar);
    validateManifest(manifest, {
      expectedCommitSha,
      expectedRepository,
      maxAgeSeconds: options.maxAgeSeconds,
      now: new Date()
    });
    assert(manifest.decision === 'GO', `manifest decision is ${manifest.decision}; publication requires GO`);
    assert(manifest.blockers.length === 0, `manifest has blockers: ${manifest.blockers.map((item) => item.gate).join(', ')}`);
    for (const { key } of GATE_DEFINITIONS) {
      assert(manifest.gates[key].status === 'pass', `mandatory gate ${key} is not pass`);
    }

    const { jobCount } = await verifyAgainstGitHub(manifest, options);
    console.log(
      `Release manifest verified: run ${manifest.run_id}, commit ${manifest.commit_sha}, ` +
        `${GATE_DEFINITIONS.length} mandatory gates, ${jobCount} jobs checked.`
    );
  } catch (error) {
    console.error(`release manifest verification: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_MANIFEST_TTL_SECONDS,
  parseArgs,
  readManifest,
  requestJson,
  requestAllPages,
  verifyAgainstGitHub,
  main
};
