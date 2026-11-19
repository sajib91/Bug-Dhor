'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { COMMANDS, CONTAINER_ID, VIEW_ID } = require('../../src/constants');
const { COMMAND_DEFINITIONS } = require('../../src/commands/definitions');
const { expectedCommandIds } = require('../../src/commands');
const { UTILITY_COMMANDS } = require('../../src/commands/utilityCommands');

const extensionRoot = path.resolve(__dirname, '..', '..');
const manifestPath = path.join(extensionRoot, 'package.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

test('identity fields match the approved extension identity', () => {
  assert.equal(manifest.name, 'bug-dhor');
  assert.equal(manifest.displayName, 'Bug-Dhor: AI Code Security Analyzer');
  assert.equal(typeof manifest.description, 'string');
  assert.ok(manifest.description.length > 0);
  assert.equal(manifest.publisher, 'sajib91');
  assert.equal(manifest.version, '0.1.0');
});

test('marketplace metadata points at the public repository', () => {
  assert.deepEqual(manifest.repository, {
    type: 'git',
    url: 'https://github.com/sajib91/Bug-Dhor.git'
  });
  assert.equal(manifest.homepage, 'https://github.com/sajib91/Bug-Dhor#readme');
  assert.deepEqual(manifest.bugs, {
    url: 'https://github.com/sajib91/Bug-Dhor/issues'
  });
});

test('marketplace documentation uses HTTPS images and ships a versioned changelog', () => {
  const readme = fs.readFileSync(path.join(extensionRoot, 'README.md'), 'utf8');
  const changelog = fs.readFileSync(path.join(extensionRoot, 'CHANGELOG.md'), 'utf8');
  const imageLinks = [...readme.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)].map((match) => match[1]);
  assert.ok(imageLinks.length > 0, 'README must document the icon');
  for (const link of imageLinks) {
    assert.match(link, /^https:\/\//, `image link must use HTTPS: ${link}`);
  }
  assert.match(readme, /media\/icon\.png/);
  assert.doesNotMatch(readme, /media\/icon\.svg/);
  assert.match(changelog, /## \[0\.1\.0\]/);
});

test('vsce dev dependency supports OIDC trusted publishing', () => {
  const version = manifest.devDependencies['@vscode/vsce'];
  assert.match(version, /^\^?\d+\.\d+\.\d+$/);
  const [major, minor] = version.replace(/^\^/, '').split('.').map(Number);
  assert.ok(major > 4 || (major === 4 && minor >= 0), `@vscode/vsce ${version} is too old`);
});

test('packaging scripts stage runtime dependencies without workspace traversal', () => {
  assert.match(manifest.scripts['package:prepare'], /stageRuntimeDeps/);
  assert.match(manifest.scripts['package:vsix'], /packageVsix\.js package/);
  assert.match(manifest.scripts['package:list'], /packageVsix\.js list/);
  assert.doesNotMatch(manifest.scripts['package:vsix'], /--no-dependencies/);
  assert.doesNotMatch(manifest.scripts['package:list'], /--no-dependencies/);
  assert.doesNotMatch(manifest.scripts['package:vsix'], /--skip-license/);
  assert.doesNotMatch(manifest.scripts['package:list'], /--skip-license/);
});

test('manifest entry point exists and is JavaScript', () => {
  assert.equal(manifest.main, './src/extension.js');
  assert.ok(manifest.main.endsWith('.js'), 'main must be a JavaScript file');
  assert.ok(fs.existsSync(path.join(extensionRoot, manifest.main)));
});

test('manifest targets the selected VS Code API baseline', () => {
  assert.equal(manifest.engines.vscode, '^1.90.0');
  assert.deepEqual(manifest.categories, ['Linters', 'Other']);
  assert.deepEqual(manifest.keywords, [
    'security',
    'vulnerability',
    'static-analysis',
    'ast',
    'diagnostics',
    'repair'
  ]);
});

test('activation events cover startup, commands, and the sidebar view', () => {
  const events = manifest.activationEvents ?? [];
  assert.ok(events.includes('onStartupFinished'));
  assert.ok(events.includes(`onView:${VIEW_ID}`));
  for (const command of Object.values(COMMANDS)) {
    assert.ok(events.includes(`onCommand:${command}`));
  }
});

test('commands are registered with a category and match shared IDs', () => {
  const commands = manifest.contributes?.commands ?? [];
  assert.deepEqual(commands.map((entry) => entry.command).sort(), [...expectedCommandIds()].sort());
  for (const entry of commands) {
    assert.equal(entry.category, 'Bug Dhor');
    assert.equal(typeof entry.title, 'string');
  }
});

test('finding navigation commands are contributed and keyboard accessible', () => {
  const commands = new Map(
    (manifest.contributes?.commands ?? []).map((entry) => [entry.command, entry])
  );
  assert.equal(commands.get(COMMANDS.nextFinding).title, 'Next Finding');
  assert.equal(commands.get(COMMANDS.previousFinding).title, 'Previous Finding');

  const keybindings = manifest.contributes?.keybindings ?? [];
  const byCommand = new Map(keybindings.map((entry) => [entry.command, entry]));
  assert.deepEqual(byCommand.get(COMMANDS.nextFinding), {
    command: COMMANDS.nextFinding,
    key: 'ctrl+alt+n',
    mac: 'cmd+alt+n',
    when: 'editorTextFocus'
  });
  assert.deepEqual(byCommand.get(COMMANDS.previousFinding), {
    command: COMMANDS.previousFinding,
    key: 'ctrl+shift+alt+n',
    mac: 'cmd+shift+alt+n',
    when: 'editorTextFocus'
  });
});

test('severity-specific gutter icons exist as local SVG assets', () => {
  for (const name of [
    'gutter-critical.svg',
    'gutter-high.svg',
    'gutter-medium.svg',
    'gutter-low.svg'
  ]) {
    const iconPath = path.join(extensionRoot, 'media', name);
    assert.ok(fs.existsSync(iconPath), `${name} must exist`);
    const svg = fs.readFileSync(iconPath, 'utf8');
    assert.match(svg, /^<svg /);
    const withoutNamespace = svg.replace('xmlns="http://www.w3.org/2000/svg"', '');
    assert.ok(!/https?:\/\//.test(withoutNamespace), `${name} must not reference remote origins`);
  }
});

test('command definitions are unique and match manifest titles and activation events', () => {
  assert.equal(
    COMMAND_DEFINITIONS.length,
    expectedCommandIds().size - UTILITY_COMMANDS.length,
    'feature command definitions must match the declared registry IDs'
  );

  const definitionIds = COMMAND_DEFINITIONS.map((definition) => definition.id);
  assert.equal(new Set(definitionIds).size, definitionIds.length, 'definition IDs must be unique');

  const contributions = new Map(
    (manifest.contributes?.commands ?? []).map((entry) => [entry.command, entry])
  );
  const activationEvents = manifest.activationEvents ?? [];

  for (const definition of COMMAND_DEFINITIONS) {
    const contribution = contributions.get(definition.id);
    assert.ok(contribution, `${definition.id} must be contributed`);
    assert.equal(contribution.title, definition.title);
    assert.equal(contribution.category, 'Bug Dhor');
    assert.ok(
      activationEvents.includes(`onCommand:${definition.id}`),
      `${definition.id} must activate the extension`
    );
    assert.equal(typeof definition.progressTitle, 'string');
    assert.ok(definition.progressTitle.length > 0);
  }
});

test('every backend feature command declares a service method; local commands declare localEngine', () => {
  for (const definition of COMMAND_DEFINITIONS) {
    if (definition.id === COMMANDS.openSecurityDashboard) {
      assert.equal(definition.serviceMethod, null);
    } else if (definition.localEngine === true) {
      assert.equal(definition.serviceMethod, null);
      assert.equal(typeof definition.key, 'string');
      assert.ok(definition.key.length > 0);
    } else {
      assert.equal(
        typeof definition.serviceMethod,
        'string',
        `${definition.id} must map to a service method`
      );
    }
  }
});

test('activity bar container and sidebar webview are contributed', () => {
  const containers = manifest.contributes?.viewsContainers?.activitybar ?? [];
  const container = containers.find((entry) => entry.id === CONTAINER_ID);
  assert.ok(container, 'activity bar container must exist');
  assert.equal(container.icon, 'media/activitybar.svg');
  assert.ok(fs.existsSync(path.join(extensionRoot, container.icon)));

  const views = manifest.contributes?.views?.[CONTAINER_ID] ?? [];
  const sidebar = views.find((entry) => entry.id === VIEW_ID);
  assert.ok(sidebar, 'sidebar view must exist');
  assert.equal(sidebar.type, 'webview');
});

test('configuration settings are declared', () => {
  const properties = manifest.contributes?.configuration?.properties ?? {};
  for (const key of [
    'bugdhor.backend.url',
    'bugdhor.backend.requestTimeoutMs',
    'bugdhor.backend.healthTimeoutMs',
    'bugdhor.privacy.sendSourceText',
    'bugdhor.backend.pythonPath',
    'bugdhor.backend.autoStart',
    'bugdhor.logging.level',
    'bugdhor.ui.showStatusBarItem',
    'bugdhor.monitoring.enabled',
    'bugdhor.monitoring.allowAutomaticSourceSharing',
    'bugdhor.monitoring.onSaveOnly',
    'bugdhor.monitoring.debounceMs',
    'bugdhor.monitoring.languages',
    'bugdhor.monitoring.analysisScope',
    'bugdhor.monitoring.maxFileBytes',
    'bugdhor.monitoring.maxChangedLines',
    'bugdhor.monitoring.excludeGlobs',
    'bugdhor.monitoring.watchWorkspaceFiles',
    'bugdhor.monitoring.scanNewFiles',
    'bugdhor.monitoring.scanOnOpen',
    'bugdhor.monitoring.fullScanOnWorkspaceChange',
    'bugdhor.monitoring.fullScanDebounceMs',
    'bugdhor.monitoring.maxConcurrentScans',
    'bugdhor.monitoring.maxWorkspaceFiles',
    'bugdhor.monitoring.excludeBinaryFiles',
    'bugdhor.monitoring.excludeGeneratedFiles',
    'bugdhor.monitoring.notifyOnFindings',
    'bugdhor.repository.maxFiles',
    'bugdhor.repository.maxFileBytes',
    'bugdhor.repository.excludeGlobs',
    'bugdhor.repository.includeUntrackedFiles',
    'bugdhor.repository.gitTimeoutMs',
    'bugdhor.repository.notifyOnWorkspaceOpen',
    'bugdhor.repository.autoScanOnWorkspaceOpen',
    'bugdhor.feedback.notifyOnPatchApplied',
    'bugdhor.feedback.notifyOnResolution',
    'bugdhor.recommendations.runFunctionalTests',
    'bugdhor.recommendations.allowSandboxedExecution',
    'bugdhor.recommendations.testCommand',
    'bugdhor.recommendations.testTimeoutSeconds',
    'bugdhor.localEngine.enabled',
    'bugdhor.localEngine.pythonPath',
    'bugdhor.localEngine.requestTimeoutMs',
    'bugdhor.localEngine.allowSourceWrite',
    'bugdhor.localEngine.sessionPath'
  ]) {
    assert.ok(properties[key], `${key} must be declared`);
  }
  assert.deepEqual(properties['bugdhor.logging.level'].enum, [
    'trace',
    'debug',
    'info',
    'warn',
    'error',
    'off'
  ]);
  assert.equal(properties['bugdhor.backend.url'].default, 'http://127.0.0.1:8765');
  assert.equal(properties['bugdhor.backend.requestTimeoutMs'].default, 30000);
  assert.equal(properties['bugdhor.backend.healthTimeoutMs'].default, 3000);
  assert.equal(properties['bugdhor.privacy.sendSourceText'].default, true);
  assert.equal(properties['bugdhor.feedback.notifyOnPatchApplied'].default, true);
  assert.equal(properties['bugdhor.feedback.notifyOnResolution'].default, true);
  assert.equal(properties['bugdhor.recommendations.runFunctionalTests'].default, true);
  assert.equal(properties['bugdhor.recommendations.allowSandboxedExecution'].default, false);
  assert.equal(properties['bugdhor.localEngine.enabled'].default, false);
  assert.equal(properties['bugdhor.localEngine.allowSourceWrite'].default, false);
  assert.equal(properties['bugdhor.localEngine.pythonPath'].default, 'python');
  assert.equal(properties['bugdhor.localEngine.requestTimeoutMs'].default, 15000);
  assert.ok(properties['bugdhor.localEngine.requestTimeoutMs'].minimum >= 1000);
  assert.equal(properties['bugdhor.localEngine.sessionPath'].default, '.bugdhor/phase6-session.json');
});

test('real-time monitoring is off by default and requires explicit source consent', () => {
  const properties = manifest.contributes?.configuration?.properties ?? {};
  assert.equal(properties['bugdhor.monitoring.enabled'].default, false);
  assert.equal(properties['bugdhor.monitoring.allowAutomaticSourceSharing'].default, false);
  assert.equal(properties['bugdhor.monitoring.onSaveOnly'].default, false);
  assert.deepEqual(properties['bugdhor.monitoring.languages'].default, ['python', 'javascript']);
  assert.equal(properties['bugdhor.monitoring.analysisScope'].default, 'function');
  assert.deepEqual(properties['bugdhor.monitoring.analysisScope'].enum, [
    'changedLines',
    'function',
    'file'
  ]);
  assert.ok(properties['bugdhor.monitoring.debounceMs'].minimum >= 100);
  assert.equal(properties['bugdhor.monitoring.watchWorkspaceFiles'].default, true);
  assert.equal(properties['bugdhor.monitoring.scanNewFiles'].default, true);
  assert.equal(properties['bugdhor.monitoring.scanOnOpen'].default, false);
  assert.equal(properties['bugdhor.monitoring.fullScanOnWorkspaceChange'].default, false);
  assert.equal(properties['bugdhor.monitoring.fullScanDebounceMs'].default, 2000);
  assert.equal(properties['bugdhor.monitoring.maxConcurrentScans'].default, 2);
  assert.equal(properties['bugdhor.monitoring.maxWorkspaceFiles'].default, 2000);
  assert.equal(properties['bugdhor.monitoring.excludeBinaryFiles'].default, true);
  assert.equal(properties['bugdhor.monitoring.excludeGeneratedFiles'].default, true);
  assert.ok(
    properties['bugdhor.monitoring.excludeGlobs'].default.some((glob) =>
      glob.includes('node_modules')
    )
  );
});

test('extension icon is a valid 128x128 PNG', () => {
  assert.equal(manifest.icon, 'media/icon.png');
  const iconPath = path.join(extensionRoot, manifest.icon);
  assert.ok(fs.existsSync(iconPath));
  const png = fs.readFileSync(iconPath);
  assert.equal(png.toString('ascii', 1, 4), 'PNG');
  assert.equal(png.readUInt32BE(16), 128);
  assert.equal(png.readUInt32BE(20), 128);
});

test('no TypeScript sources are present', () => {
  const stack = [extensionRoot];
  const ignored = new Set(['node_modules', '.git', '.vscode-test']);

  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (ignored.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else {
        assert.ok(
          !entry.name.endsWith('.ts') && !entry.name.endsWith('.tsx'),
          `TypeScript file found: ${fullPath}`
        );
      }
    }
  }
});
