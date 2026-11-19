'use strict';

const { execFile } = require('node:child_process');
const path = require('node:path');

const { selectFinding } = require('../recommendations/secureCodeGeneration');
const { redactProcessDetail, redactText } = require('../security/redaction');

const SETTINGS_SECTION = 'bugdhor';
const DEFAULT_PYTHON_PATH = 'python';
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_SESSION_PATH = '.bugdhor/phase6-session.json';

class LocalPhase6Error extends Error {
  /**
   * @param {string} message
   * @param {{ action?: string, type?: string, exitCode?: number | null }} [details]
   */
  constructor(message, details = {}) {
    super(message);
    this.name = 'LocalPhase6Error';
    this.action = details.action;
    this.type = details.type;
    this.exitCode = details.exitCode ?? null;
  }
}

/**
 * @param {unknown} value
 * @param {number} fallback
 * @returns {number}
 */
function clampTimeout(value, fallback = DEFAULT_TIMEOUT_MS) {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(300000, Math.max(1000, Math.round(parsed)));
}

/**
 * Read the opt-in local engine settings. All defaults are conservative: the
 * engine is off and source writes are forbidden until both are explicit.
 *
 * @param {any} vscode
 */
function readLocalSettings(vscode) {
  const configuration = vscode.workspace.getConfiguration(SETTINGS_SECTION);
  const pythonPath = configuration.get('localEngine.pythonPath', DEFAULT_PYTHON_PATH);
  const sessionPath = configuration.get('localEngine.sessionPath', DEFAULT_SESSION_PATH);
  if (typeof sessionPath === 'string' && path.isAbsolute(sessionPath.trim())) {
    throw new LocalPhase6Error(
      'bugdhor.localEngine.sessionPath must be relative to the workspace root.'
    );
  }
  return Object.freeze({
    enabled: configuration.get('localEngine.enabled', false) === true,
    pythonPath:
      typeof pythonPath === 'string' && pythonPath.trim() ? pythonPath.trim() : DEFAULT_PYTHON_PATH,
    requestTimeoutMs: clampTimeout(
      configuration.get('localEngine.requestTimeoutMs', DEFAULT_TIMEOUT_MS)
    ),
    allowSourceWrite: configuration.get('localEngine.allowSourceWrite', false) === true,
    sessionPath:
      typeof sessionPath === 'string' && sessionPath.trim()
        ? sessionPath.trim()
        : DEFAULT_SESSION_PATH
  });
}

/**
 * Default process runner. execFile is used without a shell, and no generated
 * source is ever executed: the child only runs the explicit Python CLI module.
 *
 * @returns {(command: string, args: string[], options: object) => Promise<{ stdout: string, stderr: string }>}
 */
function createDefaultRunner() {
  return (command, args, options) =>
    new Promise((resolve, reject) => {
      execFile(
        command,
        args,
        {
          cwd: options.cwd,
          env: options.env,
          timeout: options.timeoutMs,
          maxBuffer: 8 * 1024 * 1024,
          windowsHide: true
        },
        (error, stdout, stderr) => {
          if (error) {
            const failure = new Error(`Local Phase 6 command failed: ${redactText(error.message)}`);
            failure.stdout = redactText(stdout);
            failure.stderr = redactText(stderr);
            failure.exitCode = error.code ?? null;
            reject(failure);
            return;
          }
          resolve({ stdout, stderr });
        }
      );
    });
}

/**
 * @param {any} vscode
 * @param {string} file
 * @returns {string}
 */
function workspaceRootFor(vscode, file) {
  const uri = vscode.Uri?.file?.(file);
  const folder = uri ? vscode.workspace.getWorkspaceFolder?.(uri) : undefined;
  return folder?.uri?.fsPath ?? path.dirname(file);
}

/**
 * Create a local, opt-in Phase 6 engine adapter.
 *
 * @param {{
 *   vscode: any,
 *   logger?: any,
 *   diagnostics?: any,
 *   runCommand?: (command: string, args: string[], options: object) => Promise<{ stdout: string, stderr: string }>
 * }} dependencies
 */
function createLocalPhase6Engine({ vscode, logger, diagnostics, runCommand }) {
  if (!vscode) {
    throw new TypeError('createLocalPhase6Engine requires a vscode API object.');
  }
  const runner = runCommand ?? createDefaultRunner();

  /** @returns {ReturnType<typeof readLocalSettings>} */
  function settings() {
    return readLocalSettings(vscode);
  }

  function assertEnabled() {
    const current = settings();
    if (!current.enabled) {
      throw new LocalPhase6Error(
        'The local Phase 6 engine is disabled. Enable bugdhor.localEngine.enabled to use Phase 6 commands.'
      );
    }
    return current;
  }

  function assertWriteAllowed(current = settings()) {
    if (!current.allowSourceWrite) {
      throw new LocalPhase6Error(
        'Source writes are disabled. Enable bugdhor.localEngine.allowSourceWrite only after reviewing the patch.'
      );
    }
  }

  /**
   * @param {string} action
   * @param {{ file?: string, index?: number, findingId?: string, patchId?: string, confirmation?: string, entryId?: string, allowSourceWrite?: boolean }} [options]
   */
  async function invoke(action, options = {}) {
    const current = assertEnabled();
    const args = ['-m', 'bugdhor_ast.phase6.cli', action];
    if (options.file) args.push('--file', options.file);
    if (options.findingId) args.push('--finding-id', options.findingId);
    if (typeof options.index === 'number') args.push('--index', String(options.index));
    if (options.patchId) args.push('--patch-id', options.patchId);
    if (options.confirmation) args.push('--confirmation', options.confirmation);
    if (options.entryId) args.push('--entry-id', options.entryId);
    if (options.allowSourceWrite) args.push('--allow-source-write');

    const root = options.file ? workspaceRootFor(vscode, options.file) : process.cwd();
    const configuredSession = current.sessionPath;
    const sessionPath = path.isAbsolute(configuredSession)
      ? configuredSession
      : path.join(root, configuredSession);
    args.push('--session', sessionPath);

    const pythonPath = [path.join(root, 'src'), process.env.PYTHONPATH]
      .filter(Boolean)
      .join(path.delimiter);
    const environment = { ...process.env, PYTHONPATH: pythonPath };

    let stdout;
    let stderr = '';
    let exitCode = 0;
    try {
      const output = await runner(current.pythonPath, args, {
        cwd: root,
        env: environment,
        timeoutMs: current.requestTimeoutMs
      });
      stdout = output.stdout;
      stderr = output.stderr ?? '';
    } catch (error) {
      stdout = error?.stdout ?? '';
      stderr = error?.stderr ?? '';
      exitCode = error?.exitCode ?? 1;
      if (!stdout) {
        const detail = redactProcessDetail(error) ?? redactText(error?.message ?? error);
        throw new LocalPhase6Error(`Local Phase 6 ${action} failed: ${detail}`, {
          action,
          exitCode
        });
      }
    }

    let envelope;
    try {
      envelope = JSON.parse(stdout);
    } catch {
      const detail = redactText(stderr || stdout.slice(0, 200));
      throw new LocalPhase6Error(`Local Phase 6 ${action} returned non-JSON output: ${detail}`, {
        action,
        exitCode
      });
    }
    if (!envelope || typeof envelope !== 'object' || typeof envelope.ok !== 'boolean') {
      throw new LocalPhase6Error(`Local Phase 6 ${action} returned an invalid envelope.`, {
        action,
        exitCode
      });
    }
    if (!envelope.ok) {
      throw new LocalPhase6Error(
        redactText(envelope.error?.message ?? `Local Phase 6 ${action} failed.`),
        {
          action,
          type: envelope.error?.type,
          exitCode
        }
      );
    }
    logger?.debug?.(`Local Phase 6 ${action} completed.`);
    return envelope.result;
  }

  /**
   * Map a normalized VS Code finding to a one-based local engine finding index.
   * VS Code ranges are zero-based; engine locations are one-based.
   */
  async function indexForFinding(file, finding) {
    const analysis = await invoke('analyze', { file });
    const findings = analysis.findings ?? [];
    const zeroBasedLine = Number(finding?.range?.start?.line);
    const zeroBasedColumn = Number(finding?.range?.start?.character);
    const hasLocation = Number.isInteger(zeroBasedLine) && Number.isInteger(zeroBasedColumn);

    const matches = findings.filter((item) => {
      if (finding.ruleId && item.rule_id !== finding.ruleId) return false;
      if (!hasLocation) return true;
      return (
        item.location?.start_line === zeroBasedLine + 1 &&
        item.location?.start_column === zeroBasedColumn + 1
      );
    });
    if (matches.length === 0) {
      throw new LocalPhase6Error(
        'No local Phase 6 finding matches the selected diagnostic. Run a backend scan to publish compatible findings.'
      );
    }
    return matches[0].index;
  }

  /**
   * @param {{ uri: any, languageId?: string }} document
   * @param {any} [editor]
   */
  function currentFinding(document, editor) {
    return selectFinding(
      diagnostics,
      document.uri.toString(),
      editor ?? vscode.window.activeTextEditor
    );
  }

  return {
    settings,
    assertEnabled,
    assertWriteAllowed,
    invoke,
    indexForFinding,
    currentFinding,
    analyze: (file) => invoke('analyze', { file }),
    explain: (file, index) => invoke('explain', { file, index }),
    suggest: (file, index) => invoke('suggest', { file, index }),
    preview: (file, index) => invoke('preview', { file, index }),
    apply: async (file, patchId, confirmation) => {
      assertWriteAllowed();
      return invoke('apply', {
        file,
        patchId,
        confirmation,
        allowSourceWrite: true
      });
    },
    verify: (entryId) => invoke('verify', { entryId }),
    revert: async (entryId, confirmation) => {
      assertWriteAllowed();
      return invoke('revert', { entryId, confirmation, allowSourceWrite: true });
    },
    history: () => invoke('history')
  };
}

module.exports = {
  DEFAULT_PYTHON_PATH,
  DEFAULT_SESSION_PATH,
  DEFAULT_TIMEOUT_MS,
  LocalPhase6Error,
  clampTimeout,
  createDefaultRunner,
  createLocalPhase6Engine,
  readLocalSettings
};
