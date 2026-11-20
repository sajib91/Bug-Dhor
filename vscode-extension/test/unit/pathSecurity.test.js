'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createLocalPhase6Engine } = require('../../src/phase6/localEngine');
const {
  canonicalPath,
  isPathWithinRoot,
  isRealPathWithinRoot
} = require('../../src/security/paths');

test('realpath containment rejects symlinks that escape the workspace', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-path-'));
  try {
    const root = path.join(base, 'workspace');
    const outside = path.join(base, 'outside');
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    const secret = path.join(outside, 'secret.txt');
    fs.writeFileSync(secret, 'secret', 'utf8');
    const link = path.join(root, 'link.txt');
    fs.symlinkSync(secret, link);

    assert.equal(isPathWithinRoot(link, root), true);
    assert.equal(isRealPathWithinRoot(link, root), false);
    assert.equal(isRealPathWithinRoot(path.join(root, 'new-file.py'), root), true);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('canonicalPath normalizes Windows short and long directory names', () => {
  const shortToLong = (target) => String(target).replaceAll('RUNNER~1', 'Runner Long');
  const fileSystem = {
    realpathSync: Object.assign((target) => shortToLong(target), {
      native: shortToLong
    })
  };
  const shortPath = path.resolve('/tmp/RUNNER~1/workspace/saved.py');
  const longPath = path.resolve('/tmp/Runner Long/workspace/saved.py');
  assert.equal(canonicalPath(shortPath, { fileSystem }), longPath);
  assert.equal(canonicalPath(longPath, { fileSystem }), longPath);
});

test('local Phase 6 session path must stay inside the workspace', () => {
  const engine = createLocalPhase6Engine({
    vscode: {
      workspace: {
        getConfiguration() {
          return {
            get(key, fallback) {
              if (key === 'localEngine.sessionPath') return '/tmp/outside-session.json';
              return fallback;
            }
          };
        }
      }
    }
  });
  assert.throws(() => engine.settings(), /must be relative to the workspace root/);
});
