'use strict';

/**
 * Build or inspect the VSIX from a clean staging copy.
 *
 * Running `vsce` directly from vscode-extension/ makes npm traverse the monorepo
 * workspace root and its node_modules/bug-dhor -> ../vscode-extension symlink.
 * That either includes the entire parent repository or duplicates every file.
 * This script copies only the files that VS Code needs, plus the staged
 * production dependency closure, into a temporary directory outside the
 * workspace and runs `vsce` there.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { extensionRoot, stageRuntimeDeps } = require('./stageRuntimeDeps');

const mode = process.argv[2] === 'list' ? 'list' : 'package';
const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.json'), 'utf8'));
const closure = stageRuntimeDeps();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bugdhor-vsix-'));
const stagingDir = path.join(tempRoot, 'extension');

function cleanup() {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function prepareStaging() {
  fs.mkdirSync(stagingDir, { recursive: true });

  for (const file of ['package.json', 'README.md', 'CHANGELOG.md', '.vscodeignore']) {
    fs.copyFileSync(path.join(extensionRoot, file), path.join(stagingDir, file));
  }

  const repositoryRoot = path.resolve(extensionRoot, '..');
  for (const file of ['LICENSE', 'LICENSE.md', 'LICENSE.txt']) {
    const source = [path.join(extensionRoot, file), path.join(repositoryRoot, file)].find(
      (candidate) => fs.existsSync(candidate)
    );
    if (source) {
      fs.copyFileSync(source, path.join(stagingDir, file));
      break;
    }
  }

  for (const directory of ['src', 'media']) {
    fs.cpSync(path.join(extensionRoot, directory), path.join(stagingDir, directory), {
      recursive: true
    });
  }

  const stagingModules = path.join(stagingDir, 'node_modules');
  fs.mkdirSync(stagingModules, { recursive: true });
  for (const name of closure.keys()) {
    const source = path.join(extensionRoot, 'node_modules', ...name.split('/'));
    const destination = path.join(stagingModules, ...name.split('/'));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.cpSync(source, destination, { recursive: true });
  }
}

function resolveVsce() {
  try {
    const packagePath = require.resolve('@vscode/vsce/package.json', { paths: [extensionRoot] });
    const manifest = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    const bin = typeof manifest.bin === 'string' ? manifest.bin : manifest.bin?.vsce;
    if (!bin) {
      throw new Error('@vscode/vsce does not declare a CLI binary.');
    }
    return path.join(path.dirname(packagePath), bin);
  } catch (error) {
    throw new Error('vsce is not installed. Run `npm ci` at the repository root first.', {
      cause: error
    });
  }
}

function runVsce() {
  const executable = resolveVsce();
  if (!fs.existsSync(executable)) {
    throw new Error('vsce is not installed. Run `npm ci` at the repository root first.');
  }
  const args = mode === 'list' ? ['ls', '--tree'] : ['package'];
  return spawnSync(process.execPath, [executable, ...args], {
    cwd: stagingDir,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024
  });
}

try {
  prepareStaging();
  const result = runVsce();
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exitCode = result.status ?? 1;
  } else if (mode === 'package') {
    const vsixName = `${manifest.name}-${manifest.version}.vsix`;
    const stagedVsix = path.join(stagingDir, vsixName);
    const destination = path.join(extensionRoot, vsixName);
    fs.copyFileSync(stagedVsix, destination);
    process.stdout.write(`Wrote ${destination} (${fs.statSync(destination).size} bytes)\n`);
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
} finally {
  cleanup();
}
