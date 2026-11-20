'use strict';

/**
 * Official-API workspace monitor for Bug Dhor.
 *
 * This is the single owner of VS Code document and workspace event
 * registration. It treats every edit as an ordinary document event, so code
 * from Copilot, Cursor, Claude, ChatGPT, OpenCode, other assistants, or a human
 * is handled identically. No private extension API is used and no author or
 * model attribution is inferred.
 */

const { RealtimeMonitor } = require('./realtimeMonitor');
const { ScanScheduler } = require('./scanScheduler');
const { evaluateFileEligibility } = require('./fileFilter');
const { DEFAULT_MONITORING_SETTINGS, normalizeMonitoringSettings } = require('./settings');
const { canonicalPath } = require('../security/paths');
const { createWorkspaceRequest } = require('../workspace/workspaceService');

/**
 * @param {unknown} uri
 * @returns {{ scheme?: string, fsPath?: string, path?: string }}
 */
function normalizeUri(uri) {
  if (!uri || typeof uri !== 'object') {
    return {};
  }
  return {
    scheme: typeof uri.scheme === 'string' ? uri.scheme : undefined,
    fsPath: typeof uri.fsPath === 'string' ? uri.fsPath : undefined,
    path: typeof uri.path === 'string' ? uri.path : undefined
  };
}

/** @param {unknown} uri @returns {string} */
function uriKey(uri) {
  const normalized = normalizeUri(uri);
  if (typeof uri?.toString === 'function') {
    return uri.toString();
  }
  return `${normalized.scheme ?? 'file'}:${normalized.fsPath ?? normalized.path ?? ''}`;
}

/** @param {unknown} uri @returns {string | undefined} */
function fsPathOf(uri) {
  const normalized = normalizeUri(uri);
  return normalized.fsPath ?? normalized.path;
}

/**
 * Dedupe key for real files. Windows can report the same saved file through an
 * 8.3 short path and a long path; canonicalizing prevents an editor save and
 * the external watcher from cancelling each other's scan. URI identity is
 * preserved elsewhere by `uriKey`.
 *
 * @param {unknown} uri @returns {string}
 */
function pathKey(uri) {
  const normalized = normalizeUri(uri);
  if (normalized.scheme === 'file' && normalized.fsPath) {
    return `file:${canonicalPath(normalized.fsPath)}`;
  }
  return uriKey(uri);
}

/**
 * @param {{
 *   vscode: import('vscode'),
 *   service: import('../api/securityEngineService').SecurityEngineService,
 *   diagnostics: import('../diagnostics/diagnosticController').DiagnosticController,
 *   logger: import('../logging/output').Logger,
 *   getSettings?: () => object,
 *   hooks?: import('../integrations/securityHooks').SecurityHooks,
 *   feedback?: import('../feedback/feedbackController').FeedbackController
 * }} dependencies
 */
class WorkspaceMonitor {
  constructor({ vscode, service, diagnostics, logger, getSettings, hooks, feedback } = {}) {
    if (!vscode?.workspace || !service || !diagnostics || !logger) {
      throw new TypeError('WorkspaceMonitor requires vscode, service, diagnostics, and logger.');
    }

    this.vscode = vscode;
    this.service = service;
    this.diagnostics = diagnostics;
    this.logger = logger;
    this.feedback = feedback ?? null;
    this.getSettings = typeof getSettings === 'function' ? getSettings : () => ({});
    this.settings = normalizeMonitoringSettings(this.getSettings());

    this.executor = new RealtimeMonitor({
      vscode,
      service,
      diagnostics,
      logger,
      getSettings: this.getSettings,
      hooks,
      feedback,
      registerDocumentListeners: false
    });
    this.scheduler = new ScanScheduler({
      debounceMs: this.settings.fullScanDebounceMs,
      maxConcurrentScans: this.settings.maxConcurrentScans
    });

    /** @type {Set<string>} */
    this.createdUris = new Set();
    /** @type {Map<string, number>} */
    this.recentEditorSaves = new Map();
    /** @type {{ dispose: () => void } | undefined} */
    this.externalWatcher = undefined;
    /** @type {Array<{ dispose: () => void }>} */
    this.subscriptions = [];
    this.stats = {
      openEvents: 0,
      createdFiles: 0,
      deletedFiles: 0,
      ignoredCreations: 0,
      renames: 0,
      externalChanges: 0,
      fullScans: 0,
      workspaceFolderEvents: 0
    };
    this.disposed = false;
  }

  /**
   * Register every supported official VS Code event. Repeated calls are safe.
   */
  start() {
    if (this.subscriptions.length > 0 || this.disposed) {
      return this;
    }
    const workspace = this.vscode.workspace;
    const required = [
      'onDidOpenTextDocument',
      'onDidChangeTextDocument',
      'onDidSaveTextDocument',
      'onDidCreateFiles',
      'onDidDeleteFiles',
      'onDidChangeWorkspaceFolders'
    ];
    for (const method of required) {
      if (typeof workspace[method] !== 'function') {
        throw new TypeError(`The VS Code workspace API must provide ${method}.`);
      }
    }

    this.subscriptions.push(
      workspace.onDidOpenTextDocument((document) => this.handleOpen(document)),
      workspace.onDidChangeTextDocument((event) => this.handleChange(event)),
      workspace.onDidSaveTextDocument((document) => this.handleSave(document)),
      workspace.onDidCreateFiles((event) => void this.handleCreate(event)),
      workspace.onDidDeleteFiles((event) => this.handleDelete(event)),
      workspace.onDidChangeWorkspaceFolders((event) => this.handleWorkspaceFoldersChanged(event))
    );
    if (typeof workspace.onDidCloseTextDocument === 'function') {
      this.subscriptions.push(
        workspace.onDidCloseTextDocument((document) => this.handleClose(document))
      );
    }
    if (typeof workspace.onDidRenameFiles === 'function') {
      this.subscriptions.push(workspace.onDidRenameFiles((event) => void this.handleRename(event)));
    }
    if (typeof workspace.createFileSystemWatcher === 'function') {
      this.externalWatcher = workspace.createFileSystemWatcher('**/*');
      this.subscriptions.push(
        this.externalWatcher,
        this.externalWatcher.onDidCreate((uri) => void this.handleExternalCreate(uri)),
        this.externalWatcher.onDidChange((uri) => void this.handleExternalChange(uri)),
        this.externalWatcher.onDidDelete((uri) => this.handleDelete({ files: [uri] }))
      );
    }

    this.logger.debug(
      'Bug Dhor workspace monitoring registered all official document and folder events. ' +
        'Automatic source sharing remains subject to explicit consent.'
    );
    return this;
  }

  /** @param {any} document */
  handleOpen(document) {
    if (this.disposed || !this.settings.enabled) {
      return { scheduled: false, reason: 'disabled' };
    }
    this.stats.openEvents += 1;
    return this.executor.handleOpen(document);
  }

  /** @param {{ document?: any, contentChanges?: unknown[] }} event */
  handleChange(event) {
    if (!this.disposed) {
      this.executor.handleChange(event);
    }
  }

  /** @param {any} document */
  handleSave(document) {
    if (!this.disposed) {
      if (document?.uri) {
        this.recentEditorSaves.set(pathKey(document.uri), Date.now());
      }
      this.executor.handleSave(document);
    }
  }

  /** @param {any} document */
  handleClose(document) {
    if (this.disposed || !document?.uri) {
      return;
    }
    this.createdUris.delete(pathKey(document.uri));
    this.executor.handleClose(document);
  }

  /**
   * New files are opened through the documented API so the same language and
   * version rules apply. Repeated create events for one URI are ignored.
   *
   * @param {{ files?: unknown[] }} event
   */
  async handleCreate(event) {
    if (
      this.disposed ||
      !this.settings.enabled ||
      !this.settings.watchWorkspaceFiles ||
      !this.settings.scanNewFiles
    ) {
      return;
    }

    const files = Array.isArray(event?.files) ? event.files : [];
    const limit = Math.max(0, this.settings.maxWorkspaceFiles);
    for (const file of files.slice(0, limit)) {
      const key = pathKey(file);
      if (this.createdUris.has(key) || key.length === 0) {
        this.stats.ignoredCreations += 1;
        continue;
      }
      const fsPath = fsPathOf(file);
      const eligibility = evaluateFileEligibility({
        fsPath,
        settings: this.settings,
        workspaceFolders: this.vscode.workspace?.workspaceFolders ?? []
      });
      if (!eligibility.eligible) {
        this.stats.ignoredCreations += 1;
        continue;
      }

      // Mark before awaiting so a duplicate event cannot start a second open.
      this.createdUris.add(key);
      try {
        const document = await this.resolveDocument(file);
        if (!document || this.disposed) {
          continue;
        }
        if (this.executor.handleCreate(document)) {
          this.stats.createdFiles += 1;
        } else {
          this.stats.ignoredCreations += 1;
        }
      } catch (error) {
        this.createdUris.delete(key);
        this.stats.ignoredCreations += 1;
        this.logger.debug(
          `Bug Dhor could not open a newly created file for monitoring: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
    if (files.length > limit) {
      this.stats.ignoredCreations += files.length - limit;
    }
  }

  /** @param {{ files?: unknown[] }} event */
  handleDelete(event) {
    if (this.disposed || !this.settings.enabled || !this.settings.watchWorkspaceFiles) {
      return;
    }
    const files = Array.isArray(event?.files) ? event.files : [];
    for (const file of files) {
      this.createdUris.delete(pathKey(file));
      this.executor.handleDeleteUri(uriKey(file));
      this.stats.deletedFiles += 1;
    }
  }

  /**
   * Official rename events are handled as a delete plus a creation so tracked
   * findings, diagnostics, and debounce state follow the new path.
   *
   * @param {{ files?: Array<{ oldUri?: unknown, newUri?: unknown }> }} event
   */
  handleRename(event) {
    if (this.disposed || !this.settings.enabled || !this.settings.watchRenames) {
      return;
    }
    const files = Array.isArray(event?.files) ? event.files : [];
    for (const file of files) {
      this.stats.renames += 1;
      if (file?.oldUri) {
        this.handleDelete({ files: [file.oldUri] });
      }
      if (file?.newUri) {
        void this.handleCreate({ files: [file.newUri] });
      }
    }
  }

  /** @param {unknown} uri */
  async handleExternalCreate(uri) {
    if (!this.settings.watchExternalFiles) {
      return;
    }
    await this.handleCreate({ files: [uri] });
  }

  /** @param {string} dedupeKey @returns {boolean} */
  consumeRecentSave(dedupeKey) {
    const savedAt = this.recentEditorSaves.get(dedupeKey);
    if (typeof savedAt !== 'number' || Date.now() - savedAt >= 2000) {
      return false;
    }
    this.recentEditorSaves.delete(dedupeKey);
    return true;
  }

  /**
   * External writes are scanned from disk only. A recent editor save is skipped
   * because the document listener already handled that exact event.
   *
   * @param {unknown} uri
   */
  async handleExternalChange(uri) {
    if (
      this.disposed ||
      !this.settings.enabled ||
      !this.settings.watchWorkspaceFiles ||
      !this.settings.watchExternalFiles
    ) {
      return;
    }
    const key = uriKey(uri);
    const dedupeKey = pathKey(uri);
    if (this.consumeRecentSave(dedupeKey)) {
      return;
    }
    const eligibility = evaluateFileEligibility({
      fsPath: fsPathOf(uri),
      settings: this.settings,
      workspaceFolders: this.vscode.workspace?.workspaceFolders ?? []
    });
    if (!eligibility.eligible) {
      return;
    }
    try {
      const document = await this.resolveDocument(uri);
      if (!document || this.disposed) {
        return;
      }
      // A slow Windows watcher callback can start before the editor save event
      // and resume after it. Recheck here so the newly scheduled save scan is
      // never cancelled by the duplicate watcher scan.
      if (this.consumeRecentSave(dedupeKey) || this.executor.isActiveScan(key, 'save')) {
        return;
      }
      const fsPath = fsPathOf(uri);
      this.stats.externalChanges += 1;
      this.executor.schedule(document, key, 'external-change', { immediate: true });
      this.logger.debug(`Bug Dhor observed an external file change: ${fsPath ?? key}`);
    } catch (error) {
      this.logger.debug(
        `Bug Dhor could not open an externally changed file: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Folder changes always prune stale state. A full workspace rescan is a
   * separate opt-in because it can be expensive.
   *
   * @param {{ added?: unknown[], removed?: unknown[] }} event
   */
  handleWorkspaceFoldersChanged(event) {
    if (this.disposed || !this.settings.enabled || !this.settings.watchWorkspaceFiles) {
      return;
    }
    this.stats.workspaceFolderEvents += 1;
    this.createdUris.clear();
    this.executor.pruneOutOfWorkspace();

    const added = Array.isArray(event?.added) ? event.added : [];
    const removed = Array.isArray(event?.removed) ? event.removed : [];
    if (added.length === 0 && removed.length === 0) {
      return;
    }
    if (!this.settings.fullScanOnWorkspaceChange) {
      return;
    }
    this.scheduleWorkspaceScan('workspace-folders-changed');
  }

  /**
   * Schedule a bounded, metadata-only workspace scan. Source text is read by
   * the backend from allowlisted files; the client sends folder metadata only.
   *
   * @param {string} reason
   */
  scheduleWorkspaceScan(reason = 'manual') {
    if (this.disposed || !this.settings.enabled) {
      return false;
    }
    this.stats.fullScans += 1;
    return this.scheduler.schedule(
      'workspace',
      async ({ token }) => {
        if (token?.isCancellationRequested) {
          return { cancelled: true };
        }
        const request = createWorkspaceRequest(this.vscode);
        const response = await this.service.scanWorkspace(request, { token });
        const publication = this.diagnostics.publishScanResult(response, { scopeUris: [] });
        const findings = Array.isArray(publication?.findings)
          ? publication.findings
          : Array.isArray(response?.findings)
            ? response.findings
            : [];
        this.feedback?.afterScan?.({
          documentUri: null,
          findings,
          scopeUris: [],
          response
        });
        return { published: publication?.published ?? findings.length };
      },
      { debounceMs: this.settings.fullScanDebounceMs, reason }
    );
  }

  /** @param {unknown} uri */
  async resolveDocument(uri) {
    const key = pathKey(uri);
    const openDocuments = this.vscode.workspace.textDocuments;
    if (Array.isArray(openDocuments)) {
      const existing = openDocuments.find((document) => pathKey(document?.uri) === key);
      if (existing) {
        return existing;
      }
    }
    return this.vscode.workspace.openTextDocument(uri);
  }

  /** @param {object} settings */
  updateSettings(settings) {
    if (this.disposed) {
      return;
    }
    this.settings = normalizeMonitoringSettings(settings ?? this.getSettings());
    this.executor.updateSettings(this.settings);
    this.scheduler.updateLimits({
      debounceMs: this.settings.fullScanDebounceMs,
      maxConcurrentScans: this.settings.maxConcurrentScans
    });
    this.executor.pruneOutOfWorkspace();
    if (!this.settings.enabled) {
      this.scheduler.cancelAll('monitoring disabled');
      this.createdUris.clear();
      this.recentEditorSaves.clear();
    }
    this.logger.debug('Bug Dhor workspace monitoring settings updated.');
  }

  /** Metadata-only observability; never includes source text. */
  getStats() {
    return {
      ...this.executor.getStats(),
      workspace: {
        ...this.scheduler.getStats(),
        ...this.stats,
        openEvents: this.stats.openEvents,
        createdFiles: this.stats.createdFiles,
        deletedFiles: this.stats.deletedFiles,
        ignoredCreations: this.stats.ignoredCreations,
        renames: this.stats.renames,
        externalChanges: this.stats.externalChanges,
        fullScans: this.stats.fullScans,
        workspaceFolderEvents: this.stats.workspaceFolderEvents,
        trackedCreations: this.createdUris.size
      },
      registeredEvents: this.subscriptions.length > 0
    };
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.scheduler.dispose();
    for (const subscription of this.subscriptions) {
      try {
        subscription.dispose();
      } catch {
        // Ignore duplicate disposal.
      }
    }
    this.subscriptions = [];
    this.externalWatcher = undefined;
    this.createdUris.clear();
    this.recentEditorSaves.clear();
    this.executor.dispose();
    this.disposed = true;
  }
}

module.exports = {
  WorkspaceMonitor,
  DEFAULT_MONITORING_SETTINGS,
  uriKey,
  fsPathOf
};
