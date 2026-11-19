'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ApiClient, ApiProblemError } = require('../../src/api/apiClient');
const { createLocalPhase6Engine } = require('../../src/phase6/localEngine');
const { gitChangedFilesForRoot } = require('../../src/repository/gitChangedFiles');
const { redactText } = require('../../src/security/redaction');

const SECRET = 'super-secret-value';

function problemResponse(detail) {
  return {
    ok: false,
    status: 422,
    statusText: 'Unprocessable Entity',
    headers: { get: () => null },
    async text() {
      return JSON.stringify({
        type: 'about:blank',
        title: 'Validation failed',
        status: 422,
        code: 'E_VALIDATION',
        detail,
        instance: '/api/v1/scan/file',
        details: { errors: [{ message: `api_key=${SECRET}` }], token: SECRET }
      });
    }
  };
}

test('redactText removes secrets and bounds output', () => {
  const redacted = redactText(`Authorization: Bearer ${SECRET} and password=${SECRET}`);
  assert.equal(redacted.includes(SECRET), false);
  assert.equal(redacted.includes('[REDACTED]'), true);
  assert.equal(redactText('x'.repeat(5000)).endsWith('...[TRUNCATED]'), true);
});

test('API problem errors redact messages and nested details', async () => {
  const client = new ApiClient({
    baseUrl: 'http://127.0.0.1:8765',
    fetchImpl: async () => problemResponse(`Invalid api_key=${SECRET}`)
  });

  await assert.rejects(client.post('/scan/file', {}, undefined), (error) => {
    assert.ok(error instanceof ApiProblemError);
    assert.equal(error.message.includes(SECRET), false);
    assert.equal(JSON.stringify(error.details).includes(SECRET), false);
    assert.equal(JSON.stringify(error.problem).includes(SECRET), false);
    return true;
  });
});

test('git metadata failures redact stderr', async () => {
  await assert.rejects(
    gitChangedFilesForRoot('/workspace', {
      runner: async () => {
        throw { stderr: `fatal: token=${SECRET}` };
      }
    }),
    (error) => {
      assert.equal(error.message.includes(SECRET), false);
      assert.equal(error.code, 'E_GIT_QUERY');
      return true;
    }
  );
});

test('local Phase 6 runner failures redact stdout and stderr', async () => {
  const engine = createLocalPhase6Engine({
    vscode: trustedVscode(),
    runCommand: async () => {
      const error = new Error('command failed');
      error.stdout = `stdout token=${SECRET}`;
      error.stderr = `stderr password=${SECRET}`;
      throw error;
    }
  });

  await assert.rejects(engine.analyze('/workspace/app.py'), (error) => {
    assert.equal(error.message.includes(SECRET), false);
    return true;
  });
});

function trustedVscode() {
  return {
    workspace: {
      getConfiguration() {
        return {
          get(key, fallback) {
            if (key === 'localEngine.enabled') return true;
            return fallback;
          }
        };
      }
    }
  };
}

test('local Phase 6 envelope errors are redacted', async () => {
  const engine = createLocalPhase6Engine({
    vscode: {
      workspace: {
        getConfiguration() {
          return {
            get(key, fallback) {
              if (key === 'localEngine.enabled') return true;
              return fallback;
            }
          };
        }
      }
    },
    runCommand: async () => ({ stdout: '', stderr: `token=${SECRET}` })
  });

  await assert.rejects(engine.analyze('/workspace/app.py'), (error) => {
    assert.equal(error.message.includes(SECRET), false);
    return true;
  });
});
