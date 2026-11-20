'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  downloadAndUnzipVSCode,
  resolveCliArgsFromVSCodeExecutablePath,
  runTests
} = require('@vscode/test-electron');

const { canonicalPath } = require('./pathUtils');
const { resolvePython } = require('./pythonDiscovery');
const { removeTemporaryDirectory } = require('./tempCleanup');

const extensionRoot = path.resolve(__dirname, '..', '..');
const repositoryRoot = path.resolve(extensionRoot, '..');
const engineRoot = path.join(repositoryRoot, 'security-engine');
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

/** @param {number} ms */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** @param {import('node:child_process').ChildProcess} child @param {number} timeoutMs */
function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve(true);
      return;
    }
    const timer = setTimeout(() => resolve(false), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

/** @param {import('node:child_process').ChildProcess | undefined} child */
async function stopBackend(child) {
  if (!child || child.exitCode !== null) {
    return;
  }
  child.kill('SIGTERM');
  if (!(await waitForExit(child, 5_000))) {
    child.kill('SIGKILL');
    await waitForExit(child, 2_000);
  }
}

/** @param {string} backendUrl @param {import('node:child_process').ChildProcess} child @param {() => string} readLogs */
async function waitForBackend(backendUrl, child, readLogs, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `The Bug Dhor backend exited with code ${child.exitCode} before becoming ready.\n${readLogs()}`
      );
    }
    try {
      const response = await fetch(`${backendUrl}/api/v1/health`, {
        signal: AbortSignal.timeout(1_000)
      });
      if (response.ok) {
        const body = await response.json();
        if (body.status === 'ok') {
          return body;
        }
      }
    } catch (error) {
      lastError = error;
    }
    await delay(150);
  }
  throw new Error(
    `The Bug Dhor backend did not become ready at ${backendUrl} within ${timeoutMs} ms. ` +
      `Last error: ${lastError instanceof Error ? lastError.message : String(lastError)}\n${readLogs()}`
  );
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
    const child = spawn(spawnTarget, spawnArgs, {
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

  /** @type {import('node:child_process').ChildProcess | undefined} */
  let backend;
  const logLines = [];
  const record = (chunk) => {
    for (const line of chunk.toString().split(/\r?\n/)) {
      if (line.length > 0) {
        logLines.push(line);
      }
    }
    while (logLines.length > 200) {
      logLines.shift();
    }
  };
  const readLogs = () =>
    logLines.length > 0 ? `Backend output:\n${logLines.join('\n')}` : 'No backend output captured.';

  try {
    const port = await findFreePort();
    const backendUrl = `http://127.0.0.1:${port}`;
    const python = resolvePython({ repositoryRoot, env: process.env });
    const backendEnvironment = { ...process.env };
    delete backendEnvironment.BUGDHOR_API_TOKEN;
    delete backendEnvironment.BUGDHOR_ENGINE_TOKEN;
    const pythonPath = [path.join(engineRoot, 'src'), backendEnvironment.PYTHONPATH]
      .filter(Boolean)
      .join(path.delimiter);
    backendEnvironment.PYTHONPATH = pythonPath;
    backendEnvironment.BUGDHOR_WORKSPACE_ROOTS = workspacePath;
    backendEnvironment.BUGDHOR_LOG_LEVEL = 'ERROR';
    backendEnvironment.BUGDHOR_DATA_DIR = dataDir;
    backendEnvironment.BUGDHOR_LOG_DIR = logDir;

    console.log(`Starting Bug Dhor backend with ${python} on ${backendUrl}.`);
    backend = spawn(python, ['-m', 'bugdhor', '--host', '127.0.0.1', '--port', String(port)], {
      cwd: engineRoot,
      env: backendEnvironment,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    backend.stdout?.on('data', record);
    backend.stderr?.on('data', record);
    backend.once('error', (error) => record(`spawn error: ${error.message}`));
    const health = await waitForBackend(backendUrl, backend, readLogs);
    console.log(`Bug Dhor backend ready (version ${health.version}, API ${health.apiVersion}).`);

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
    const installedManifestPath = path.join(extensionsDir, installedDirectory, 'package.json');
    const installed = JSON.parse(fs.readFileSync(installedManifestPath, 'utf8'));
    assert.equal(installed.name, manifest.name);
    assert.equal(installed.publisher, manifest.publisher);
    assert.equal(installed.version, manifest.version);

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
        BUGDHOR_API_TOKEN: '',
        BUGDHOR_ENGINE_TOKEN: ''
      }
    });
    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
  } finally {
    await stopBackend(backend);
    await removeTemporaryDirectory(temporaryRoot);
  }
}

main().catch((error) => {
  console.error('Bug Dhor VSIX smoke test failed:', error);
  process.exitCode = 1;
});
