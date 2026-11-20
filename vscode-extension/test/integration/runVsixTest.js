'use strict';

/**
 * Clean-install VSIX end-to-end harness.
 *
 * This harness deliberately does NOT start a backend. The backend is started by
 * the installed extension's own managed-runtime lifecycle using only assets
 * from the VSIX and a clean Python interpreter. That is the only way to prove
 * the published runtime startup works without a developer checkout, the
 * repository `.venv`, or a `PYTHONPATH` injected by the test.
 */

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {
  downloadAndUnzipVSCode,
  resolveCliArgsFromVSCodeExecutablePath,
  runTests
} = require('@vscode/test-electron');

const { canonicalPath } = require('./pathUtils');
const { resolveCleanPython } = require('./pythonDiscovery');
const { removeTemporaryDirectory } = require('./tempCleanup');

const extensionRoot = path.resolve(__dirname, '..', '..');
const repositoryRoot = path.resolve(extensionRoot, '..');
const extensionTestsPath = path.join(__dirname, 'vsixSmoke.js');
const developmentExtensionPath = path.join(__dirname, 'vsix-host');
const manifest = require('../../package.json');
const extensionId = `${manifest.publisher}.${manifest.name}`;
const DISK_SOURCE = 'value = 1\n';

/** @returns {string | undefined} */
function findLocalVSCode() {
  if (process.env.BUGDHOR_VSCODE_EXECUTABLE) {
    return process.env.BUGDHOR_VSCODE_EXECUTABLE;
  }

  const candidates = [];
  if (process.platform === 'darwin') {
    candidates.push(
      '/Applications/Visual Studio Code.app/Contents/MacOS/Code',
      path.join(
        process.env.HOME ?? '',
        'Applications',
        'Visual Studio Code.app',
        'Contents',
        'MacOS',
        'Code'
      )
    );
  } else if (process.platform === 'win32') {
    if (process.env.LOCALAPPDATA) {
      candidates.push(
        path.join(process.env.LOCALAPPDATA, 'Programs', 'Microsoft VS Code', 'Code.exe')
      );
    }
    if (process.env.ProgramFiles) {
      candidates.push(path.join(process.env.ProgramFiles, 'Microsoft VS Code', 'Code.exe'));
    }
  }

  return candidates.find((candidate) => fs.existsSync(candidate));
}

/** @returns {Promise<number>} */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : undefined;
      server.close((error) => {
        if (error) {
          reject(error);
        } else if (!port) {
          reject(new Error('Could not allocate a loopback port for the backend.'));
        } else {
          resolve(port);
        }
      });
    });
  });
}

/**
 * @param {string} command
 * @param {string[]} args
 * @returns {Promise<string>}
 */
function runCli(command, args) {
  return new Promise((resolve, reject) => {
    const useShell = process.platform === 'win32';
    const spawnTarget = useShell ? `"${command}"` : command;
    // Node does not quote spawned arguments when shell:true, so Windows paths
    // containing spaces must be quoted explicitly.
    const spawnArgs = useShell ? args.map((arg) => (/\s/.test(arg) ? `"${arg}"` : arg)) : args;
    const child = require('node:child_process').spawn(spawnTarget, spawnArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: useShell,
      windowsHide: true
    });
    let output = '';
    child.stdout?.setEncoding('utf8').on('data', (chunk) => {
      output += chunk;
    });
    child.stderr?.setEncoding('utf8').on('data', (chunk) => {
      output += chunk;
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`VS Code CLI exited with ${code}:\n${output}`));
      }
    });
  });
}

/**
 * Resolve a real interpreter path for a command name without using a shell.
 * Windows CI may expose Python as a PATH shim; the extension spawns the
 * interpreter with `shell: false`, so settings must contain a real executable.
 *
 * @param {string} candidate
 * @returns {string | undefined}
 */
function pythonExecutablePath(candidate) {
  try {
    const result = spawnSync(candidate, ['-c', 'import sys; print(sys.executable)'], {
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
      timeout: 10_000
    });
    if (result.status !== 0) {
      return undefined;
    }
    const resolved = result.stdout.trim().split(/\r?\n/).at(-1);
    return resolved && fs.existsSync(resolved) ? resolved : undefined;
  } catch {
    return undefined;
  }
}

/** @returns {string} */
function cleanPython() {
  /** @type {string[]} */
  const candidates = [];
  const override = process.env.BUGDHOR_CLEAN_PYTHON;
  if (override && fs.existsSync(override)) {
    candidates.push(override);
  }
  if (process.platform === 'darwin') {
    candidates.push(
      ...[
        '/opt/homebrew/opt/python@3.11/bin/python3.11',
        '/usr/local/opt/python@3.11/bin/python3.11'
      ].filter((candidate) => fs.existsSync(candidate))
    );
  }
  // Never inject the repository .venv. Use the platform's standard command
  // name: Windows uses `python`, not `python3`, and Node spawns it without a
  // shell so a non-existent `python3` would fail before the engine can start.
  candidates.push(
    resolveCleanPython({ repositoryRoot, platform: process.platform, env: process.env })
  );
  if (process.platform === 'win32') {
    candidates.push('python', 'py');
  }

  for (const candidate of new Set(candidates)) {
    const executable = pythonExecutablePath(candidate);
    if (executable) {
      return executable;
    }
  }
  return candidates[0];
}

async function main() {
  const vsixPath = path.resolve(
    process.env.BUGDHOR_VSIX_PATH ??
      path.join(extensionRoot, `${manifest.name}-${manifest.version}.vsix`)
  );
  assert.ok(fs.existsSync(vsixPath), `VSIX not found: ${vsixPath}`);

  const temporaryRoot = canonicalPath(
    fs.mkdtempSync(path.join(canonicalPath(os.tmpdir()), 'bugdhor-vsix-'))
  );
  const workspacePath = path.join(temporaryRoot, 'workspace with spaces — ünïcøde 🚀');
  const userDataDir = path.join(temporaryRoot, 'user-data');
  const extensionsDir = path.join(temporaryRoot, 'extensions');
  const dataDir = path.join(temporaryRoot, 'data');
  const logDir = path.join(temporaryRoot, 'logs');
  for (const directory of [workspacePath, userDataDir, extensionsDir, dataDir, logDir]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  const sourcePath = path.join(workspacePath, 'installed — café.py');
  fs.writeFileSync(sourcePath, DISK_SOURCE, 'utf8');

  try {
    const port = await findFreePort();
    const backendUrl = `http://127.0.0.1:${port}`;
    const python = cleanPython();
    console.log(`Using clean Python ${python} for the extension-managed runtime.`);

    // Configure a clean VS Code profile. No repository .venv and no PYTHONPATH
    // are injected; the extension must install and start its bundled engine.
    const userDirectory = path.join(userDataDir, 'User');
    fs.mkdirSync(userDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(userDirectory, 'settings.json'),
      `${JSON.stringify(
        {
          'bugdhor.backend.url': backendUrl,
          'bugdhor.engine.autoStart': true,
          'bugdhor.engine.manageRuntime': true,
          'bugdhor.engine.pythonPath': python,
          'bugdhor.engine.startupTimeoutMs': 60_000,
          'bugdhor.privacy.sendSourceText': true,
          'bugdhor.monitoring.enabled': false,
          'bugdhor.repository.notifyOnWorkspaceOpen': false
        },
        null,
        2
      )}\n`,
      'utf8'
    );

    const localExecutable = findLocalVSCode();
    const vscodeExecutablePath =
      localExecutable ??
      (await downloadAndUnzipVSCode({
        version: 'stable',
        cachePath: path.join(extensionRoot, '.vscode-test')
      }));
    console.log(
      localExecutable
        ? `Using local VS Code: ${localExecutable}`
        : `Using downloaded VS Code: ${vscodeExecutablePath}`
    );

    const [cli, ...cliArgs] = resolveCliArgsFromVSCodeExecutablePath(vscodeExecutablePath);
    console.log(`Installing ${vsixPath} into an isolated extensions directory.`);
    const installOutput = await runCli(cli, [
      ...cliArgs,
      '--install-extension',
      vsixPath,
      '--force',
      `--extensions-dir=${extensionsDir}`,
      `--user-data-dir=${userDataDir}`
    ]);
    if (installOutput.trim()) {
      console.log(installOutput.trim());
    }

    // VS Code may append the version to the installed extension directory name.
    const installedDirectory = fs
      .readdirSync(extensionsDir, { withFileTypes: true })
      .filter(
        (entry) =>
          entry.isDirectory() &&
          (entry.name === extensionId || entry.name.startsWith(`${extensionId}-`)) &&
          fs.existsSync(path.join(extensionsDir, entry.name, 'package.json'))
      )
      .map((entry) => entry.name)
      .sort()
      .at(-1);
    assert.ok(installedDirectory, `the VSIX installer must create an ${extensionId} directory`);
    const installedRoot = path.join(extensionsDir, installedDirectory);
    const installedManifest = JSON.parse(
      fs.readFileSync(path.join(installedRoot, 'package.json'), 'utf8')
    );
    assert.equal(installedManifest.name, manifest.name);
    assert.equal(installedManifest.publisher, manifest.publisher);
    assert.equal(installedManifest.version, manifest.version);

    // Verify the engine assets the managed runtime will use are really inside
    // the installed extension and contain no developer editable requirement.
    for (const asset of [
      path.join('engine', 'src', 'bugdhor', '__main__.py'),
      path.join('engine', 'pyproject.toml'),
      path.join('engine', 'requirements-runtime.txt')
    ]) {
      assert.ok(fs.existsSync(path.join(installedRoot, asset)), `${asset} must ship in the VSIX`);
    }
    const installedRequirements = fs.readFileSync(
      path.join(installedRoot, 'engine', 'requirements-runtime.txt'),
      'utf8'
    );
    assert.equal(/^\s*-e\b/im.test(installedRequirements), false);

    const exitCode = await runTests({
      vscodeExecutablePath,
      extensionDevelopmentPath: developmentExtensionPath,
      extensionTestsPath,
      launchArgs: [
        workspacePath,
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        '--new-window'
      ],
      extensionTestsEnv: {
        BUGDHOR_VSIX_ID: extensionId,
        BUGDHOR_VSIX_VERSION: manifest.version,
        BUGDHOR_VSIX_BACKEND_URL: backendUrl,
        BUGDHOR_VSIX_WORKSPACE: workspacePath,
        BUGDHOR_VSIX_FILE: sourcePath,
        BUGDHOR_VSIX_DISK_SHA256: crypto
          .createHash('sha256')
          .update(Buffer.from(DISK_SOURCE, 'utf8'))
          .digest('hex'),
        BUGDHOR_VSIX_INSTALLED_ROOT: installedRoot,
        BUGDHOR_WORKSPACE_ROOTS: workspacePath,
        BUGDHOR_DATA_DIR: dataDir,
        BUGDHOR_LOG_DIR: logDir,
        BUGDHOR_LOG_LEVEL: 'ERROR',
        BUGDHOR_API_TOKEN: '',
        BUGDHOR_ENGINE_TOKEN: ''
      }
    });
    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
  } finally {
    await removeTemporaryDirectory(temporaryRoot);
  }
}

main().catch((error) => {
  console.error('Bug Dhor VSIX clean-install test failed:', error);
  process.exitCode = 1;
});
