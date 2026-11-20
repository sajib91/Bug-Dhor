'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { downloadAndUnzipVSCode } = require('@vscode/test-electron');
const { CAPABILITY_KEYS } = require('../../src/api/securityResultService');
const { canonicalPath } = require('./pathUtils');

const extensionDevelopmentPath = path.resolve(__dirname, '..', '..');
const extensionTestsPath = path.join(__dirname, 'untrustedWorkspace.js');

const SOURCE_NAME = 'untrusted — source.py';
const SOURCE_MARKER = 'BUGDHOR_UNTRUSTED_SOURCE_MARKER_7c1f9a2e';
const DISK_SOURCE = [
  '# This file lives in an untrusted workspace.',
  `SECRET_MARKER = "${SOURCE_MARKER}"`,
  'def add(a, b):',
  '    return a + b',
  ''
].join('\n');
const MALICIOUS_BACKEND_URL = 'https://attacker.example.test';
const MALICIOUS_ASSISTANT_URL = 'https://attacker.example.test/v1';

/** @param {string} text */
function sha256(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

/**
 * Prefer a locally installed VS Code, then fall back to a downloaded build.
 *
 * @returns {string | undefined}
 */
function findLocalVSCode() {
  if (process.env.BUGDHOR_VSCODE_EXECUTABLE) {
    return process.env.BUGDHOR_VSCODE_EXECUTABLE;
  }

  const candidates = [];
  if (process.platform === 'darwin') {
    candidates.push(
      '/Applications/Visual Studio Code.app/Contents/MacOS/Code',
      '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
      path.join(
        process.env.HOME ?? '',
        'Applications',
        'Visual Studio Code.app',
        'Contents',
        'MacOS',
        'Code'
      ),
      path.join(
        process.env.HOME ?? '',
        'Applications',
        'Visual Studio Code.app',
        'Contents',
        'MacOS',
        'Electron'
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
          reject(new Error('Could not allocate a loopback port for the request recorder.'));
        } else {
          resolve(port);
        }
      });
    });
  });
}

/**
 * A minimal loopback backend. Every request is appended to a JSON file that the
 * Extension Host test reads; only the health endpoint receives a response.
 *
 * @param {string} logPath
 */
function createRequestRecorder(logPath) {
  /** @type {Array<{ method: string, url: string, headers: Record<string, unknown>, body: string }>} */
  const requests = [];

  /** @returns {Record<string, boolean>} */
  function capabilities() {
    /** @type {Record<string, boolean>} */
    const result = {};
    for (const key of CAPABILITY_KEYS) {
      result[key] = false;
    }
    return result;
  }

  const server = http.createServer((request, response) => {
    /** @type {Buffer[]} */
    const chunks = [];
    request.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      /** @type {Record<string, unknown>} */
      const headers = { ...request.headers };
      for (const name of ['authorization', 'proxy-authorization', 'cookie']) {
        if (headers[name] !== undefined) {
          headers[name] = '<redacted>';
        }
      }
      requests.push({
        method: request.method ?? 'GET',
        url: request.url ?? '',
        headers,
        body
      });
      fs.writeFileSync(logPath, JSON.stringify(requests, null, 2), 'utf8');

      if (request.method === 'GET' && request.url === '/api/v1/health') {
        response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        response.end(
          JSON.stringify({
            service: 'bugdhor-untrusted-test-recorder',
            status: 'ok',
            version: '0.0.0-test',
            apiVersion: 'v1',
            timestamp: new Date().toISOString(),
            uptimeSeconds: 0,
            capabilities: capabilities(),
            sandboxBackend: 'mock-loopback-recorder'
          })
        );
        return;
      }

      // Unexpected endpoints are recorded and rejected. They must never be
      // reached by an untrusted workspace in the first place.
      response.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      response.end(
        JSON.stringify({
          status: 404,
          title: 'Unexpected request',
          code: 'E_UNEXPECTED_REQUEST'
        })
      );
    });
  });

  return server;
}

/** @param {http.Server} server @param {number} port */
function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
}

/** @param {http.Server} server */
function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => (error ? reject(error) : resolve()));
    // fetch()/undici may keep loopback connections alive; do not let those
    // prevent the recorder from closing at the end of the run.
    server.closeAllConnections?.();
  });
}

/**
 * Spawn the GUI executable directly. `runTests()` is deliberately not used:
 * it always appends `--disable-workspace-trust`, which would invalidate this
 * test. Windows .cmd launchers need the same quoting as @vscode/test-electron.
 *
 * @param {string} executablePath
 * @param {string[]} args
 * @param {NodeJS.ProcessEnv} env
 */
function spawnVSCode(executablePath, args, env) {
  const useShell = process.platform === 'win32' && /\.cmd$/i.test(executablePath);
  const command = useShell ? `"${executablePath}"` : executablePath;
  const spawnArgs = useShell ? args.map((arg) => `"${arg}"`) : args;
  const child = spawn(command, spawnArgs, {
    env,
    shell: useShell,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  /** @type {string[]} */
  const lines = [];
  const record = (chunk) => {
    for (const line of chunk.toString().split(/\r?\n/)) {
      if (line.length > 0) {
        lines.push(line);
      }
    }
    while (lines.length > 200) {
      lines.shift();
    }
  };
  child.stdout?.on('data', record);
  child.stderr?.on('data', record);
  child.once('error', (error) => record(`spawn error: ${error.message}`));

  return { child, readOutput: () => lines.join('\n') };
}

/** @param {import('node:child_process').ChildProcess} child */
function waitForExit(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
}

async function main() {
  // Keep the root short: macOS limits AF_UNIX socket paths to 103 bytes and
  // VS Code derives its IPC socket name from --user-data-dir. The workspace is
  // canonicalized separately so its URI matches the on-disk real path.
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bd-ut-'));
  const canonicalRoot = canonicalPath(temporaryRoot);
  const workspacePath = path.join(canonicalRoot, 'workspace with spaces — ünïcøde 🚀');
  const userDataDir = path.join(temporaryRoot, 'ud');
  const userSettingsDir = path.join(userDataDir, 'User');
  const extensionsDir = path.join(temporaryRoot, 'ext');
  const sourcePath = path.join(workspacePath, SOURCE_NAME);
  const workspaceSettingsPath = path.join(workspacePath, '.vscode', 'settings.json');
  const userSettingsPath = path.join(userSettingsDir, 'settings.json');
  const requestLogPath = path.join(temporaryRoot, 'request-log.json');
  const executionMarkerPath = path.join(temporaryRoot, 'workspace-command-executed');

  for (const directory of [
    workspacePath,
    path.dirname(workspaceSettingsPath),
    userSettingsDir,
    extensionsDir
  ]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  fs.writeFileSync(sourcePath, DISK_SOURCE, 'utf8');
  fs.writeFileSync(requestLogPath, '[]', 'utf8');

  // A hostile workspace file. Every key below is machine-scoped, so VS Code
  // must ignore it; the trust gate would block the rest even if it were read.
  const maliciousSettings = {
    'bugdhor.backend.url': MALICIOUS_BACKEND_URL,
    'bugdhor.privacy.sendSourceText': true,
    'bugdhor.monitoring.enabled': true,
    'bugdhor.monitoring.allowAutomaticSourceSharing': true,
    'bugdhor.repository.autoScanOnWorkspaceOpen': true,
    'bugdhor.recommendations.allowSandboxedExecution': true,
    'bugdhor.recommendations.testCommand': [
      process.execPath,
      '-e',
      `require('node:fs').writeFileSync(${JSON.stringify(executionMarkerPath)}, 'executed')`
    ],
    'bugdhor.localEngine.enabled': true,
    'bugdhor.localEngine.allowSourceWrite': true,
    'bugdhor.assistant.provider': 'openai-compatible',
    'bugdhor.assistant.openAiCompatible.endpoint': MALICIOUS_ASSISTANT_URL,
    'bugdhor.assistant.sae.enabled': true,
    'bugdhor.assistant.counterfactual.enabled': true
  };
  fs.writeFileSync(
    workspaceSettingsPath,
    `${JSON.stringify(maliciousSettings, null, 2)}\n`,
    'utf8'
  );

  const server = createRequestRecorder(requestLogPath);
  try {
    await listen(server, await findFreePort());
    const port = /** @type {{ port: number }} */ (server.address()).port;
    const backendUrl = `http://127.0.0.1:${port}`;

    // User-scoped settings are machine configuration, not workspace-controlled.
    // The loopback URL lets the health check reach the recorder while the
    // hostile workspace URL must remain ineffective.
    const userSettings = {
      'security.workspace.trust.enabled': true,
      'security.workspace.trust.startupPrompt': 'never',
      'bugdhor.backend.url': backendUrl,
      'bugdhor.privacy.sendSourceText': true
    };
    fs.writeFileSync(userSettingsPath, `${JSON.stringify(userSettings, null, 2)}\n`, 'utf8');

    const localExecutable = findLocalVSCode();
    const vscodeExecutablePath =
      localExecutable ??
      (await downloadAndUnzipVSCode({
        version: 'stable',
        cachePath: path.join(extensionDevelopmentPath, '.vscode-test')
      }));
    console.log(
      localExecutable
        ? `Using local VS Code: ${localExecutable}`
        : `Using downloaded VS Code: ${vscodeExecutablePath}`
    );

    const args = [
      workspacePath,
      '--disable-extensions',
      `--user-data-dir=${userDataDir}`,
      `--extensions-dir=${extensionsDir}`,
      '--new-window',
      '--no-sandbox',
      '--disable-gpu-sandbox',
      '--disable-updates',
      '--skip-welcome',
      '--skip-release-notes',
      '--no-cached-data',
      `--extensionTestsPath=${extensionTestsPath}`,
      `--extensionDevelopmentPath=${extensionDevelopmentPath}`
    ];
    assert.ok(
      !args.some((arg) => arg.includes('disable-workspace-trust')),
      'the untrusted test must never pass --disable-workspace-trust'
    );

    const env = { ...process.env };
    for (const name of ['BUGDHOR_API_TOKEN', 'BUGDHOR_ENGINE_TOKEN', 'BUGDHOR_LLM_API_KEY']) {
      delete env[name];
    }
    Object.assign(env, {
      BUGDHOR_UNTRUSTED_BACKEND_URL: backendUrl,
      BUGDHOR_UNTRUSTED_WORKSPACE: workspacePath,
      BUGDHOR_UNTRUSTED_FILE: sourcePath,
      BUGDHOR_UNTRUSTED_DISK_SHA256: sha256(DISK_SOURCE),
      BUGDHOR_UNTRUSTED_MALICIOUS_BACKEND_URL: MALICIOUS_BACKEND_URL,
      BUGDHOR_UNTRUSTED_MALICIOUS_SETTINGS: workspaceSettingsPath,
      BUGDHOR_UNTRUSTED_EXECUTION_MARKER: executionMarkerPath,
      BUGDHOR_UNTRUSTED_SOURCE_MARKER: SOURCE_MARKER,
      BUGDHOR_UNTRUSTED_REQUEST_LOG: requestLogPath,
      BUGDHOR_API_TOKEN: '',
      BUGDHOR_ENGINE_TOKEN: '',
      BUGDHOR_LLM_API_KEY: ''
    });

    console.log('Launching VS Code with workspace trust ENABLED (no --disable-workspace-trust).');
    const { child, readOutput } = spawnVSCode(vscodeExecutablePath, args, env);
    const { code, signal } = await waitForExit(child);
    if (code !== 0) {
      throw new Error(`VS Code Extension Host exited with ${code ?? signal}.\n${readOutput()}`);
    }
    console.log('Untrusted workspace Extension Host checks passed.');
  } finally {
    await closeServer(server);
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error('Bug Dhor untrusted workspace test failed:', error);
  process.exitCode = 1;
});
