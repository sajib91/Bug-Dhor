'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { prepareStaging } = require('../../scripts/packageVsix');

test('VSIX staging includes the bundled local engine source and requirements', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-vsix-test-'));
  const targetDir = path.join(tempRoot, 'extension');
  try {
    prepareStaging({ targetDir, runtimeClosure: new Map() });

    const engineRoot = path.join(targetDir, 'engine');
    const moduleRoot = path.join(engineRoot, 'src', 'bugdhor');
    assert.ok(fs.existsSync(path.join(moduleRoot, '__main__.py')));
    assert.ok(fs.existsSync(path.join(moduleRoot, 'api', 'app.py')));
    assert.ok(fs.existsSync(path.join(engineRoot, 'requirements.txt')));
    assert.ok(fs.existsSync(path.join(targetDir, 'src', 'extension.js')));

    const ignore = fs.readFileSync(path.join(targetDir, '.vscodeignore'), 'utf8');
    assert.equal(/^engine\//m.test(ignore), false, 'engine assets must not be excluded');
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
