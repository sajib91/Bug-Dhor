'use strict';

const path = require('node:path');

const { COMMANDS } = require('../constants');
const { getCommandDefinition } = require('./definitions');
const { registerEngineCommand } = require('./registerEngineCommand');
const { reportScanAvailability } = require('./scanCommands');
const { CommandValidationError, createWorkspaceRequest } = require('../workspace/workspaceService');
const { isLoopbackBackendUrl } = require('../api/configurationService');
const { discoverRepositoryInventory } = require('../repository');
const { collectGitChangedFiles, GitChangedFilesError } = require('../repository/gitChangedFiles');
const { isRealPathWithinRoot } = require('../security/paths');

const WORKSPACE_PROMPT_KEY = 'bugdhor.repository.workspacePrompt';

/** @param {unknown} token */
function assertNotCancelled(token) {
  if (
    token &&
    ((typeof token === 'object' && token.isCancellationRequested === true) ||
      (typeof token?.isCancellationRequested === 'function' && token.isCancellationRequested()))
  ) {
    const error = new Error('Repository scan cancelled.');
    error.name = 'CanceledError';
    throw error;
  }
}

/** @param {unknown} settings */
function normalizeSettings(settings) {
  const source = settings && typeof settings === 'object' ? settings : {};
  const number = (value, fallback, minimum, maximum) => {
    const parsed = typeof value === 'string' && value.trim() ? Number(value) : value;
    if (!Number.isFinite(parsed)) {
      return fallback;
    }
    return Math.min(maximum, Math.max(minimum, Math.round(parsed)));
  };
  return {
    maxFiles: number(source.repositoryMaxFiles, 2000, 1, 50_000),
    maxFileBytes: number(source.repositoryMaxFileBytes, 1_048_576, 1024, 10 * 1024 * 1024),
    excludeGlobs: Array.isArray(source.repositoryExcludeGlobs)
      ? source.repositoryExcludeGlobs.filter(
          (entry) => typeof entry === 'string' && entry.trim().length > 0
        )
      : [],
    includeUntrackedFiles: source.repositoryIncludeUntrackedFiles !== false,
    gitTimeoutMs: number(source.repositoryGitTimeoutMs, 10_000, 1000, 60_000),
    notifyOnWorkspaceOpen: source.repositoryNotifyOnWorkspaceOpen !== false,
    autoScanOnWorkspaceOpen: source.repositoryAutoScanOnWorkspaceOpen === true,
    allowAutomaticSourceSharing: source.monitoringAllowAutomaticSourceSharing === true,
    sendSourceText: source.sendSourceText !== false,
    backendUrl: typeof source.backendUrl === 'string' ? source.backendUrl : ''
  };
}

/**
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   getRepositorySettings: () => object
 * }} context
 * @param {readonly import('vscode').WorkspaceFolder[] | undefined} folders
 * @param {{ token?: unknown, progress?: { report: (value: object) => void } }} engineContext
 */
async function discoverInventory(context, folders, engineContext) {
  const { vscode, logger, getRepositorySettings } = context;
  const settings = normalizeSettings(getRepositorySettings());
  assertNotCancelled(engineContext?.token);
  if (!isLoopbackBackendUrl(settings.backendUrl)) {
    throw new CommandValidationError(
      'Repository scans require a loopback backend; source files are read from the local disk by the backend.',
      'E_REMOTE_BACKEND'
    );
  }
  engineContext?.progress?.report({ message: 'Discovering eligible source files.' });

  const scopedVscode = folders
    ? {
        ...vscode,
        workspace: { ...vscode.workspace, workspaceFolders: [...folders] }
      }
    : vscode;
  const inventory = await discoverRepositoryInventory(scopedVscode, {
    maxFiles: settings.maxFiles,
    maxFileBytes: settings.maxFileBytes,
    excludeGlobs: settings.excludeGlobs,
    token: engineContext?.token
  });
  assertNotCancelled(engineContext?.token);
  if (inventory.stats.truncated) {
    logger.warn(
      `Repository inventory reached the ${settings.maxFiles}-file limit; ` +
        'the scan covers only the first discovered files.'
    );
  }
  engineContext?.progress?.report({
    message: `Discovered ${inventory.files.length} eligible source file(s).`
  });
  return { inventory, settings };
}

/**
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   getRepositorySettings: () => object
 * }} context
 * @param {{ filePaths: string[], folders?: readonly import('vscode').WorkspaceFolder[] }} input
 * @param {object} settings
 */
function buildRequest(context, { filePaths, folders }, settings) {
  if (!Array.isArray(filePaths) || filePaths.length === 0) {
    throw new CommandValidationError(
      'No eligible source files were found for this repository scope.',
      'E_NO_SOURCE_FILES'
    );
  }
  return createWorkspaceRequest(context.vscode, {
    filePaths,
    folders,
    maxFilePaths: settings.maxFiles
  });
}

/**
 * @param {unknown} uri
 * @param {import('vscode')} vscode
 * @returns {import('vscode').Uri}
 */
function normalizeFolderUri(uri, vscode) {
  if (uri && typeof uri === 'object' && uri.scheme === 'file' && typeof uri.fsPath === 'string') {
    return /** @type {import('vscode').Uri} */ (uri);
  }
  if (typeof uri === 'string' && vscode.Uri && typeof vscode.Uri.file === 'function') {
    return vscode.Uri.file(uri);
  }
  throw new CommandValidationError(
    'Select a local folder inside the workspace before running this command.',
    'E_INVALID_FOLDER'
  );
}

/**
 * @param {import('vscode')} vscode
 * @param {import('vscode').Uri} uri
 */
function findContainingWorkspaceFolder(vscode, uri) {
  const folders = vscode.workspace?.workspaceFolders ?? [];
  const candidates = folders.filter((folder) => {
    return (
      folder?.uri?.scheme === 'file' &&
      typeof folder.uri.fsPath === 'string' &&
      isRealPathWithinRoot(uri.fsPath, folder.uri.fsPath)
    );
  });
  candidates.sort((left, right) => right.uri.fsPath.length - left.uri.fsPath.length);
  return candidates[0];
}

/**
 * Register explicit repository scan commands. Every command sends only folder
 * metadata and absolute file paths; the local backend reads source files.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   logger: import('../logging/output').Logger,
 *   registry: import('./registry').CommandRegistry,
 *   diagnostics?: { getPublishedUris?: () => string[] },
 *   getRepositorySettings: () => object,
 *   gitRunner?: (cwd: string, args: string[], timeoutMs: number) => Promise<string>
 * }} context
 * @returns {import('vscode').Disposable[]}
 */
function registerRepositoryCommands(context) {
  const { vscode, logger, diagnostics } = context;
  const disposables = [];

  const prepareFull = async (engineContext) => {
    const { inventory, settings } = await discoverInventory(context, undefined, engineContext);
    return buildRequest(
      context,
      { filePaths: inventory.files.map((file) => file.fsPath) },
      settings
    );
  };

  const onResult = (result) =>
    reportScanAvailability({ vscode, logger }, 'Repository scan', result);

  for (const id of [COMMANDS.scanRepository, COMMANDS.rescanAll]) {
    disposables.push(
      registerEngineCommand(context, getCommandDefinition(id), prepareFull, {
        onResult,
        passContextToPrepare: true
      })
    );
  }

  const prepareChanged = async (engineContext) => {
    const settings = normalizeSettings(context.getRepositorySettings());
    assertNotCancelled(engineContext?.token);
    if (!isLoopbackBackendUrl(settings.backendUrl)) {
      throw new CommandValidationError(
        'Repository scans require a loopback backend.',
        'E_REMOTE_BACKEND'
      );
    }
    engineContext?.progress?.report({ message: 'Reading Git changed-file metadata.' });
    const roots = (vscode.workspace?.workspaceFolders ?? [])
      .filter((folder) => folder?.uri?.scheme === 'file' && typeof folder.uri.fsPath === 'string')
      .map((folder) => folder.uri.fsPath);
    let changed;
    try {
      changed = await collectGitChangedFiles(roots, {
        runner: context.gitRunner,
        includeUntracked: settings.includeUntrackedFiles,
        timeoutMs: settings.gitTimeoutMs,
        maxPaths: settings.maxFiles,
        cancellationToken: engineContext?.token
      });
    } catch (error) {
      if (error instanceof GitChangedFilesError) {
        throw new CommandValidationError(error.message, error.code);
      }
      throw error;
    }
    assertNotCancelled(engineContext?.token);
    if (changed.cancelled) {
      const error = new Error('Repository scan cancelled.');
      error.name = 'CanceledError';
      throw error;
    }
    const { inventory } = await discoverInventory(context, undefined, engineContext);
    const eligible = new Set(inventory.files.map((file) => file.fsPath));
    const filePaths = changed.paths.filter((filePath) => eligible.has(filePath));
    if (filePaths.length === 0) {
      throw new CommandValidationError(
        'No changed source files are eligible for scanning. Ignored, excluded, binary, and deleted files are skipped.',
        'E_NO_CHANGED_FILES'
      );
    }
    return buildRequest(context, { filePaths }, settings);
  };
  disposables.push(
    registerEngineCommand(
      context,
      getCommandDefinition(COMMANDS.scanChangedFiles),
      prepareChanged,
      { onResult, passContextToPrepare: true }
    )
  );

  const prepareSelected = async (uri, engineContext) => {
    const folderUri = normalizeFolderUri(uri, vscode);
    const workspaceFolder = findContainingWorkspaceFolder(vscode, folderUri);
    if (!workspaceFolder) {
      throw new CommandValidationError(
        'The selected folder is outside every open workspace folder.',
        'E_FOLDER_OUTSIDE_WORKSPACE'
      );
    }
    if (typeof vscode.workspace?.fs?.stat === 'function' && vscode.FileType?.Directory) {
      try {
        const stat = await vscode.workspace.fs.stat(folderUri);
        if ((stat.type & vscode.FileType.Directory) === 0) {
          throw new CommandValidationError(
            'Only folders can be scanned with this command.',
            'E_INVALID_FOLDER'
          );
        }
      } catch (error) {
        if (error instanceof CommandValidationError) {
          throw error;
        }
        throw new CommandValidationError(
          'The selected folder could not be inspected.',
          'E_INVALID_FOLDER'
        );
      }
    }
    const folders = [
      {
        name: path.basename(folderUri.fsPath) || workspaceFolder.name,
        index: workspaceFolder.index,
        uri: folderUri
      }
    ];
    const { inventory, settings } = await discoverInventory(context, folders, engineContext);
    return buildRequest(
      context,
      {
        filePaths: inventory.files.map((file) => file.fsPath),
        folders
      },
      settings
    );
  };
  disposables.push(
    registerEngineCommand(
      context,
      getCommandDefinition(COMMANDS.scanSelectedFolder),
      prepareSelected,
      { onResult, passContextToPrepare: true }
    )
  );

  const prepareIncremental = async (engineContext) => {
    const settings = normalizeSettings(context.getRepositorySettings());
    assertNotCancelled(engineContext?.token);
    if (!isLoopbackBackendUrl(settings.backendUrl)) {
      throw new CommandValidationError(
        'Repository scans require a loopback backend.',
        'E_REMOTE_BACKEND'
      );
    }
    const { inventory } = await discoverInventory(context, undefined, engineContext);
    const eligible = new Map(inventory.files.map((file) => [file.uriText, file.fsPath]));
    /** @type {Set<string>} */
    const targets = new Set();
    for (const uri of diagnostics?.getPublishedUris?.() ?? []) {
      const fsPath = eligible.get(uri);
      if (fsPath) {
        targets.add(fsPath);
      }
    }
    for (const document of vscode.workspace?.textDocuments ?? []) {
      if (document?.uri?.scheme === 'file' && document.isDirty === true) {
        const fsPath = eligible.get(document.uri.toString());
        if (fsPath) {
          targets.add(fsPath);
        }
      }
    }
    const filePaths = [...targets];
    if (filePaths.length === 0) {
      throw new CommandValidationError(
        'No incremental targets are available. Open or modify a source file, or scan the repository first.',
        'E_NO_INCREMENTAL_TARGETS'
      );
    }
    return buildRequest(context, { filePaths }, settings);
  };
  disposables.push(
    registerEngineCommand(
      context,
      getCommandDefinition(COMMANDS.scanIncremental),
      prepareIncremental,
      { onResult, passContextToPrepare: true }
    )
  );

  return disposables;
}

/** @param {string[]} roots */
function workspacePromptKey(roots) {
  let hash = 2166136261;
  for (const root of [...roots].sort()) {
    for (let i = 0; i < root.length; i += 1) {
      hash ^= root.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    hash ^= 0x7c;
    hash = Math.imul(hash, 16777619);
  }
  return `${WORKSPACE_PROMPT_KEY}.${(hash >>> 0).toString(16)}`;
}

/**
 * Detect a workspace and either run an explicitly configured automatic scan or
 * offer a one-time manual scan. Automatic scans require loopback plus both
 * consent flags; no source text is sent by this notice itself.
 *
 * @param {{
 *   vscode: import('vscode'),
 *   logger: import('../logging/output').Logger,
 *   memento?: { get: (key: string, fallback: unknown) => unknown, update: (key: string, value: unknown) => unknown },
 *   settings: object,
 *   backendReachable: boolean
 * }} options
 */
async function offerWorkspaceScan(options) {
  const { vscode, logger, memento, backendReachable } = options;
  const settings = normalizeSettings(options.settings);
  const folders = (vscode.workspace?.workspaceFolders ?? []).filter(
    (folder) => folder?.uri?.scheme === 'file' && typeof folder.uri.fsPath === 'string'
  );
  if (folders.length === 0) {
    return;
  }
  const roots = folders.map((folder) => path.resolve(folder.uri.fsPath));
  const key = workspacePromptKey(roots);
  try {
    if (memento && typeof memento.get === 'function' && memento.get(key, false) === true) {
      return;
    }
  } catch {
    // A broken memento must not block the notice.
  }

  const canAutoScan =
    settings.autoScanOnWorkspaceOpen &&
    settings.allowAutomaticSourceSharing &&
    settings.sendSourceText &&
    isLoopbackBackendUrl(settings.backendUrl) &&
    backendReachable;

  try {
    if (canAutoScan) {
      logger.info('Auto-scanning the detected workspace after all consent checks passed.');
      await vscode.commands.executeCommand(COMMANDS.scanRepository);
    } else if (settings.notifyOnWorkspaceOpen) {
      const action = await vscode.window.showInformationMessage(
        `Bug Dhor detected ${roots.length} workspace folder${roots.length === 1 ? '' : 's'}. ` +
          'A repository scan reads local source files through the local backend.',
        'Scan Repository'
      );
      if (action === 'Scan Repository') {
        await vscode.commands.executeCommand(COMMANDS.scanRepository);
      } else {
        logger.info('Workspace detection notice was dismissed without a scan.');
      }
    }
    if (memento && typeof memento.update === 'function') {
      await memento.update(key, true);
    }
  } catch (error) {
    logger.warn(
      `Workspace detection follow-up failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

module.exports = {
  registerRepositoryCommands,
  offerWorkspaceScan,
  discoverInventory,
  buildRequest,
  normalizeSettings,
  workspacePromptKey
};
