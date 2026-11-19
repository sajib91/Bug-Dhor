'use strict';

/**
 * Stage the extension's production dependency closure inside vscode-extension/.
 *
 * The repository is an npm workspace, so `npm install` hoists dependencies to
 * the repository root and creates node_modules/bug-dhor -> ../vscode-extension.
 * Letting `vsce` detect dependencies through that workspace graph walks the
 * parent repository and produces a multi-gigabyte VSIX. This module resolves
 * only declared production dependencies and their production transitive
 * dependencies; packageVsix.js copies that closure into a clean staging area.
 */

const fs = require('node:fs');
const path = require('node:path');

const extensionRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(extensionRoot, '..');
const manifestPath = path.join(extensionRoot, 'package.json');

function packageDirectory(name) {
  const hoisted = path.join(workspaceRoot, 'node_modules', ...name.split('/'));
  if (fs.existsSync(path.join(hoisted, 'package.json'))) {
    return hoisted;
  }
  throw new Error(
    `Cannot resolve production dependency "${name}" from the workspace root. ` +
      'Run `npm install` at the repository root before packaging.'
  );
}

function readPackage(name) {
  const directory = packageDirectory(name);
  const packageJson = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  return { directory, packageJson };
}

function collectProductionClosure() {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const closure = new Map();

  function visit(name) {
    if (closure.has(name)) {
      return;
    }
    const { directory, packageJson } = readPackage(name);
    closure.set(name, { directory, version: packageJson.version });
    for (const dependency of Object.keys(packageJson.dependencies || {})) {
      visit(dependency);
    }
  }

  for (const name of Object.keys(manifest.dependencies || {})) {
    visit(name);
  }
  return closure;
}

function stageRuntimeDeps() {
  const closure = collectProductionClosure();
  const stagingRoot = path.join(extensionRoot, 'node_modules');
  fs.mkdirSync(stagingRoot, { recursive: true });

  for (const [name, { directory }] of closure) {
    const destination = path.join(stagingRoot, ...name.split('/'));
    fs.rmSync(destination, { recursive: true, force: true });
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.cpSync(directory, destination, { recursive: true });
  }
  return closure;
}

module.exports = { collectProductionClosure, extensionRoot, stageRuntimeDeps };

if (require.main === module) {
  const closure = stageRuntimeDeps();
  const summary = [...closure.entries()]
    .map(([name, { version }]) => `${name}@${version}`)
    .sort()
    .join(', ');
  console.log(`Staged ${closure.size} production package(s): ${summary}`);
}
