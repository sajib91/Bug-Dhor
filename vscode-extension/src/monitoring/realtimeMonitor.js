'use strict';

/**
 * Background, non-blocking document monitoring for the Bug Dhor extension.
 *
 * Editor events are treated as ordinary document changes: the monitor never
 * assumes an edit came from an AI assistant and never claims to identify the
 * author or model responsible. It tracks document versions, identifies changed
 * lines, scopes work to the enclosing function (or the whole file), debounces
 * bursts, cancels superseded requests, and refreshes native diagnostics from
 * validated backend results only.
 *
 * Source text leaves the extension only when BOTH the general source-sharing
 * setting and the explicit automatic-sharing consent are enabled. Monitoring
 * is disabled by default.
 */

const crypto = require('node:crypto');
const path = require('node:path');

const { MAX_ABSOLUTE_LINES, buildAnalysisPlan, textForPlan } = require('./changeAnalyzer');
const { DocumentVersionTracker } = require('./documentVersionTracker');
const { evaluateFileEligibility } = require('./fileFilter');
const { DEFAULT_MONITORING_SETTINGS, normalizeMonitoringSettings } = require('./settings');
const { isRealPathWithinRoot } = require('../security/paths');

// Backward-compatible aliases for existing callers and tests. The shared
// settings module is the single source of truth for all monitoring defaults.
const DEFAULT_SETTINGS = DEFAULT_MONITORING_SETTINGS;
const normalizeSettings = normalizeMonitoringSettings;

const MAX_RECORDED_ANALYSES = 25;
const MAX_LINES_FOR_SCAN = MAX_ABSOLUTE_LINES;

/**
 * A minimal cancellation token source. The API client only needs
 * `isCancellationRequested` and `onCancellationRequested`, so the monitor can
 * stay independent of VS Code's implementation and be unit tested in Node.
 */
function createCancellationTokenSource() {
  let cancelled = false;
  /** @type {Set<() => void>} */
  const listeners = new Set();
  const token = {
    get isCancellationRequested() {
      return cancelled;
    },
    /** @param {() => void} listener */
    onCancellationRequested(listener) {
      if (typeof listener !== 'function') {
        return { dispose() {} };
      }
      if (cancelled) {
        listener();
        return { dispose() {} };
      }
      listeners.add(listener);
      return {
        dispose() {
          listeners.delete(listener);
        }
      };
    }
  };
  return {
    token,
    cancel() {
      if (cancelled) {
        return;
      }
      cancelled = true;
      for (const listener of [...listeners]) {
        try {
          listener();
        } catch {
          // A failed listener must not stop other cancellations.
        }
      }
      listeners.clear();
    },
    dispose() {
      listeners.clear();
    }
  };
}

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isCancellation(error) {
  if (!error || typeof error !== 'object') {
    return false;
  }
  return (
    error.name === 'AbortError' ||
    error.name === 'Canceled' ||
    error.name === 'CanceledError' ||
    error.code === 'E_CANCELLED' ||
    error.code === 'ERR_CANCELED'
  );
}

/**
 * @param {import('vscode')} vscode
 * @param {import('vscode').Uri} uri
 * @returns {import('vscode').WorkspaceFolder | undefined}
 */
function resolveWorkspaceFolder(vscode, uri) {
  const direct = vscode.workspace?.getWorkspaceFolder?.(uri);
  if (direct?.uri?.fsPath) {
    return direct;
  }
  return (vscode.workspace?.workspaceFolders ?? []).find(
    (folder) =>
      folder?.uri?.scheme === 'file' &&
      typeof folder.uri.fsPath === 'string' &&
      typeof uri?.fsPath === 'string' &&
      isRealPathWithinRoot(uri.fsPath, folder.uri.fsPath)
  );
}

/**
 * @param {string} text
 * @returns {string}
 */
function hashText(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

class RealtimeMonitor {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   service: import('../api/securityEngineService').SecurityEngineService,
   *   diagnostics: import('../diagnostics/diagnosticController').DiagnosticController,
   *   logger: import('../logging/output').Logger,
   *   getSettings?: () => object,
   *   hooks?: import('../integrations/securityHooks').SecurityHooks,
   *   feedback?: import('../feedback/feedbackController').FeedbackController,
   *   registerDocumentListeners?: boolean
   * }} dependencies
   */
  constructor({
    vscode,
    service,
    diagnostics,
    logger,
    getSettings,
    hooks,
    feedback,
    registerDocumentListeners = true
  } = {}) {
    if (!vscode?.workspace || !service || !diagnostics || !logger) {
      throw new TypeError('RealtimeMonitor requires vscode, service, diagnostics, and logger.');
    }
    this.vscode = vscode;
    this.service = service;
    this.diagnostics = diagnostics;
    this.logger = logger;
    this.hooks = hooks ?? null;
    this.feedback = feedback ?? null;
    this.registerDocumentListeners = registerDocumentListeners !== false;
    this.getSettings = typeof getSettings === 'function' ? getSettings : () => ({});
    this.settings = normalizeSettings(this.getSettings());

    this.tracker = new DocumentVersionTracker();
    /** @type {Map<string, { timer: NodeJS.Timeout, generation: number }>} */
    this.timers = new Map();
    /** @type {Map<string, { generation: number, source: ReturnType<typeof createCancellationTokenSource> }>} */
    this.inFlight = new Map();
    /** @type {Map<string, number>} */
    this.generations = new Map();
    /** @type {Map<string, string>} */
    this.analyzedHashes = new Map();

    this.stats = {
      scheduled: 0,
      completed: 0,
      cancelled: 0,
      skipped: 0,
      failed: 0,
      duplicates: 0,
      suppressed: 0,
      notifications: 0,
      /** @type {Array<object>} */
      analyses: []
    };

    /** @type {Array<{ dispose: () => void }>} */
    this.subscriptions = [];
    this.consentWarningShown = false;
    this.disposed = false;
  }

  /**
   * Register document listeners. A workspace orchestrator can set
   * `registerDocumentListeners: false` and drive the same public handlers so
   * there is exactly one owner of VS Code event registration.
   */
  start() {
    if (!this.registerDocumentListeners) {
      this.logger.debug(
        'Bug Dhor incremental monitor is using an external workspace event coordinator.'
      );
      return this;
    }
    const workspace = this.vscode.workspace;
    if (
      typeof workspace.onDidChangeTextDocument !== 'function' ||
      typeof workspace.onDidSaveTextDocument !== 'function'
    ) {
      throw new TypeError(
        'The VS Code workspace API must provide onDidChangeTextDocument and onDidSaveTextDocument.'
      );
    }
    this.subscriptions.push(
      workspace.onDidChangeTextDocument((event) => this.handleChange(event)),
      workspace.onDidSaveTextDocument((document) => this.handleSave(document))
    );
    if (typeof workspace.onDidCloseTextDocument === 'function') {
      this.subscriptions.push(
        workspace.onDidCloseTextDocument((document) => this.handleClose(document))
      );
    }
    this.logger.debug(
      'Bug Dhor real-time monitoring registered (disabled by default; automatic source ' +
        'sharing requires explicit consent).'
    );
    return this;
  }

  /** @param {object} settings */
  updateSettings(settings) {
    this.settings = normalizeSettings(settings ?? this.getSettings());
    if (!this.settings.enabled) {
      this.cancelAll('monitoring disabled');
    }
    this.logger.debug('Bug Dhor real-time monitoring settings updated.');
  }

  /** @param {{ document?: any, contentChanges?: unknown[] }} event */
  handleChange(event) {
    if (this.disposed || !this.settings.enabled) {
      return;
    }
    const document = event?.document;
    if (!this.isEligibleDocument(document)) {
      return;
    }
    const uri = document.uri.toString();
    const observed = this.tracker.observeChange({
      uri,
      version: document.version,
      lineCount: document.lineCount,
      fsPath: document.uri.fsPath,
      contentChanges: event.contentChanges
    });
    if (observed.ignored) {
      this.stats.duplicates += 1;
      return;
    }
    if (this.settings.onSaveOnly) {
      return;
    }
    this.schedule(document, uri, 'change');
  }

  /** @param {any} document */
  handleSave(document) {
    if (this.disposed || !this.settings.enabled) {
      return;
    }
    if (!this.isEligibleDocument(document)) {
      return;
    }
    const uri = document.uri.toString();
    this.tracker.observeSave({ uri, version: document.version, fsPath: document.uri.fsPath });
    this.schedule(document, uri, 'save', { immediate: true });
  }

  /**
   * Observe an opened document. Opening is recorded once per version; scanning
   * on open is opt-in because it would otherwise create a scan for every tab a
   * user visits.
   *
   * @param {any} document
   * @returns {{ scheduled: boolean, reason?: string }}
   */
  handleOpen(document) {
    if (this.disposed || !this.settings.enabled) {
      return { scheduled: false, reason: 'disabled' };
    }
    if (!this.isEligibleDocument(document)) {
      return { scheduled: false, reason: 'ineligible' };
    }
    const uri = document.uri.toString();
    const observed = this.tracker.observeOpen({
      uri,
      version: document.version,
      lineCount: document.lineCount,
      fsPath: document.uri.fsPath
    });
    if (observed.ignored) {
      return { scheduled: false, reason: observed.reason };
    }
    if (!this.settings.scanOnOpen) {
      return { scheduled: false, reason: 'scan-on-open-disabled' };
    }
    this.schedule(document, uri, 'open');
    return { scheduled: true };
  }

  /**
   * Schedule a file-level scan for a newly created source file.
   *
   * @param {any} document
   * @returns {boolean}
   */
  handleCreate(document) {
    if (this.disposed || !this.settings.enabled || !this.settings.scanNewFiles) {
      return false;
    }
    if (!this.isEligibleDocument(document)) {
      return false;
    }
    const uri = document.uri.toString();
    const observed = this.tracker.observeOpen({
      uri,
      version: document.version,
      lineCount: document.lineCount,
      fsPath: document.uri.fsPath
    });
    if (observed.ignored) {
      return false;
    }
    this.schedule(document, uri, 'create');
    return true;
  }

  /**
   * Cancel and forget all monitoring state for a deleted URI. No scan is
   * scheduled for the deletion itself.
   *
   * @param {string} uri
   */
  handleDeleteUri(uri) {
    if (typeof uri !== 'string' || uri.length === 0) {
      return;
    }
    this.cancelAnalysis(uri, 'file deleted');
    this.tracker.forget(uri);
    this.analyzedHashes.delete(uri);
    try {
      this.diagnostics.clearUri?.(uri);
    } catch {
      // Diagnostic cleanup is best effort; never fail a delete event.
    }
  }

  /**
   * Drop tracking for documents that are no longer inside the workspace.
   *
   * @param {ReadonlyArray<{ uri?: { scheme?: string, fsPath?: string } }>} [folders]
   */
  pruneOutOfWorkspace(folders = this.vscode.workspace?.workspaceFolders ?? []) {
    for (const [uri, state] of [...this.tracker.documents]) {
      const fsPath = /** @type {any} */ (state)?.fsPath;
      const inside =
        typeof fsPath === 'string' &&
        folders.some(
          (folder) =>
            folder?.uri?.scheme === 'file' &&
            typeof folder.uri.fsPath === 'string' &&
            isRealPathWithinRoot(fsPath, folder.uri.fsPath)
        );
      if (!inside) {
        this.handleDeleteUri(uri);
      }
    }
  }

  /** @param {any} document */
  handleClose(document) {
    if (this.disposed || !document?.uri) {
      return;
    }
    const uri = document.uri.toString();
    this.cancelPending(uri, 'document closed');
    this.cancelInFlight(uri, 'document closed');
    this.tracker.forget(uri);
    this.analyzedHashes.delete(uri);
    try {
      this.diagnostics.clearUri?.(uri);
    } catch {
      // Diagnostic cleanup is best effort; never fail a close event.
    }
  }

  /**
   * @param {any} document
   * @param {string} uri
   * @param {'change' | 'save' | 'rescan' | 'open' | 'create'} reason
   * @param {{ immediate?: boolean }} [options]
   */
  schedule(document, uri, reason, options = {}) {
    this.cancelPending(uri, 'newer change');
    this.cancelInFlight(uri, 'newer change');

    const generation = (this.generations.get(uri) ?? 0) + 1;
    this.generations.set(uri, generation);
    this.stats.scheduled += 1;
    this.recordAnalysis({ uri, version: document.version, reason, status: 'scheduled' });

    const run = () => {
      this.timers.delete(uri);
      void this.runAnalysis({ document, uri, generation, reason });
    };

    if (options.immediate) {
      run();
      return;
    }
    this.timers.set(uri, {
      generation,
      timer: setTimeout(run, this.settings.debounceMs)
    });
  }

  /**
   * @param {{
   *   document: any,
   *   uri: string,
   *   generation: number,
   *   reason: 'change' | 'save' | 'rescan' | 'open' | 'create'
   * }} task
   */
  async runAnalysis({ document, uri, generation, reason }) {
    if (this.disposed || generation !== this.generations.get(uri) || !this.settings.enabled) {
      return;
    }

    if (!this.hasSourceConsent()) {
      this.stats.skipped += 1;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'skipped',
        detail: 'consent-required'
      });
      if (!this.consentWarningShown) {
        this.consentWarningShown = true;
        this.logger.info(
          'Bug Dhor skipped background analysis: real-time monitoring requires both ' +
            'bugdhor.monitoring.allowAutomaticSourceSharing and bugdhor.privacy.sendSourceText.'
        );
      }
      return;
    }

    if (!this.isEligibleDocument(document)) {
      this.stats.skipped += 1;
      return;
    }

    let text;
    try {
      text = document.getText();
    } catch (error) {
      this.stats.failed += 1;
      this.logger.warn(
        `Bug Dhor could not read the monitored document: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      return;
    }
    if (typeof text !== 'string') {
      this.stats.skipped += 1;
      return;
    }

    const byteLength = Buffer.byteLength(text, 'utf8');
    const lines = text.split('\n');
    if (byteLength > this.settings.maxFileBytes || lines.length > MAX_LINES_FOR_SCAN) {
      this.stats.skipped += 1;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'skipped',
        detail: 'document-too-large'
      });
      this.logger.debug('Bug Dhor skipped background analysis for an oversized document.');
      return;
    }

    const textHash = hashText(text);

    // Only patches explicitly applied by this extension are recorded by the
    // feedback controller. Suppress the immediate self-induced scan once, then
    // schedule exactly one bounded rescan instead of looping on the same edit.
    const suppression = this.feedback?.beforeScan?.({
      documentUri: uri,
      hash: textHash,
      documentVersion: document.version
    });
    if (suppression?.suppress) {
      this.stats.suppressed += 1;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'suppressed',
        detail: suppression.reason ?? 'own-patch'
      });
      if (suppression.followUp) {
        this.schedule(document, uri, 'rescan');
      }
      return;
    }

    if (this.analyzedHashes.get(uri) === textHash) {
      this.stats.skipped += 1;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'deduplicated'
      });
      return;
    }

    const folder = resolveWorkspaceFolder(this.vscode, document.uri);
    if (!folder?.uri?.fsPath) {
      this.stats.skipped += 1;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'skipped',
        detail: 'outside-workspace'
      });
      return;
    }

    const changeState = /** @type {any} */ (this.tracker.get(uri));
    const plan = buildAnalysisPlan({
      text,
      lineCount: document.lineCount,
      languageId: document.languageId,
      ranges: changeState?.ranges ?? [],
      settings: {
        analysisScope:
          reason === 'save' || reason === 'rescan' || reason === 'create' || reason === 'open'
            ? 'file'
            : this.settings.analysisScope,
        maxChangedLines: this.settings.maxChangedLines
      },
      reason
    });
    if (!plan) {
      this.stats.skipped += 1;
      return;
    }

    // Editor monitoring is the universal fallback. The hook records provenance
    // only; it never attributes an edit to an assistant or model.
    const provenance = this.hooks?.observeChange({
      uri,
      version: document.version,
      ranges: changeState?.ranges ?? [],
      reason
    });

    /** @type {Record<string, unknown>} */
    const request = {
      workspaceFolder: folder.uri.fsPath,
      workspaceFolderName: folder.name,
      filePath: document.uri.fsPath,
      documentUri: uri,
      languageId: document.languageId,
      documentVersion: document.version,
      // Explicit automatic consent was verified above; no other path sends text.
      sourceText: text
    };
    if (plan.kind !== 'file') {
      request.selection = plan.selection;
      request.selectedText = textForPlan(text, plan);
    }

    const source = createCancellationTokenSource();
    this.inFlight.set(uri, { generation, source });
    this.analyzedHashes.set(uri, textHash);

    try {
      const response =
        plan.kind === 'file'
          ? await this.service.scanFile(request, { token: source.token })
          : await this.service.scanSelection(request, { token: source.token });

      if (this.disposed || generation !== this.generations.get(uri)) {
        this.stats.cancelled += 1;
        return;
      }

      const publication = this.diagnostics.publishScanResult(response, { scopeUris: [uri] });
      const findings = Array.isArray(publication?.findings)
        ? publication.findings
        : Array.isArray(response?.findings)
          ? response.findings
          : [];
      this.feedback?.afterScan?.({
        documentUri: uri,
        findings,
        scopeUris: [uri],
        snapshotHash: textHash,
        response
      });
      this.stats.completed += 1;

      const published = publication?.published ?? findings.length;
      this.recordAnalysis({
        uri,
        version: document.version,
        reason,
        status: 'completed',
        kind: plan.kind,
        changedLines: plan.changedLines,
        published,
        provenance
      });

      if (published > 0 && this.settings.notifyOnFindings) {
        this.notify(document, published);
      }
    } catch (error) {
      if (isCancellation(error) || generation !== this.generations.get(uri) || this.disposed) {
        // Proactive cancellation already incremented the counter.
        if (!source.token.isCancellationRequested) {
          this.stats.cancelled += 1;
        }
      } else {
        this.stats.failed += 1;
        this.logger.warn(
          `Bug Dhor background analysis failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        this.recordAnalysis({
          uri,
          version: document.version,
          reason,
          status: 'failed'
        });
      }
    } finally {
      if (this.inFlight.get(uri)?.generation === generation) {
        this.inFlight.delete(uri);
      }
      source.dispose();
    }
  }

  /** @param {any} document */
  isEligibleDocument(document) {
    if (!document?.uri || document.uri.scheme !== 'file') {
      return false;
    }
    if (!Number.isInteger(document.version) || document.version < 0) {
      return false;
    }
    const eligibility = evaluateFileEligibility({
      fsPath: document.uri.fsPath,
      languageId: document.languageId,
      settings: this.settings,
      workspaceFolders: this.vscode.workspace?.workspaceFolders ?? []
    });
    if (!eligibility.eligible) {
      return false;
    }
    return !Number.isInteger(document.lineCount) || document.lineCount <= MAX_LINES_FOR_SCAN;
  }

  hasSourceConsent() {
    return (
      this.settings.allowAutomaticSourceSharing === true && this.settings.sendSourceText === true
    );
  }

  /**
   * @param {any} document
   * @param {number} count
   */
  notify(document, count) {
    if (typeof this.vscode.window?.showWarningMessage !== 'function') {
      return;
    }
    this.stats.notifications += 1;
    const fileName = path.basename(document.uri.fsPath ?? 'document');
    const noun = count === 1 ? 'finding' : 'findings';
    void Promise.resolve(
      this.vscode.window.showWarningMessage(
        `Bug Dhor found ${count} potential security ${noun} in ${fileName}.`,
        'Show Problems'
      )
    ).then((action) => {
      if (action === 'Show Problems') {
        void this.vscode.commands?.executeCommand?.('workbench.action.problems.focus');
      }
    });
  }

  /**
   * Cancel a pending or in-flight analysis for one document. Findings already
   * published are intentionally left untouched; cancellation is not evidence
   * that a vulnerability was resolved.
   *
   * @param {string} uri
   * @param {string} [cause]
   */
  cancelAnalysis(uri, cause = 'user cancellation') {
    const hadPending = this.timers.has(uri);
    const hadInFlight = this.inFlight.has(uri);
    this.cancelPending(uri, cause);
    this.cancelInFlight(uri, cause);
    if (hadPending || hadInFlight) {
      this.recordAnalysis({ uri, reason: 'cancellation', status: 'cancelled', detail: cause });
    }
  }

  /** @param {string} uri @param {string} cause */
  cancelPending(uri, cause) {
    const pending = this.timers.get(uri);
    if (!pending) {
      return;
    }
    clearTimeout(pending.timer);
    this.timers.delete(uri);
    this.stats.cancelled += 1;
    this.logger.debug(`Bug Dhor cancelled a pending analysis for ${uri} (${cause}).`);
  }

  /** @param {string} uri @param {string} cause */
  cancelInFlight(uri, cause) {
    const active = this.inFlight.get(uri);
    if (!active) {
      return;
    }
    active.source.cancel();
    this.inFlight.delete(uri);
    this.stats.cancelled += 1;
    this.logger.debug(`Bug Dhor cancelled an outdated analysis request for ${uri} (${cause}).`);
  }

  /** @param {string} cause */
  cancelAll(cause) {
    for (const uri of [...this.timers.keys()]) {
      this.cancelPending(uri, cause);
    }
    for (const uri of [...this.inFlight.keys()]) {
      this.cancelInFlight(uri, cause);
    }
  }

  /** @param {object} entry */
  recordAnalysis(entry) {
    this.stats.analyses.push({ ...entry, at: Date.now() });
    if (this.stats.analyses.length > MAX_RECORDED_ANALYSES) {
      this.stats.analyses.shift();
    }
  }

  /**
   * Observability for tests and the extension API. Contains metadata only;
   * source text, selected text, and code identifiers are never exposed here.
   */
  getStats() {
    return {
      scheduled: this.stats.scheduled,
      completed: this.stats.completed,
      cancelled: this.stats.cancelled,
      skipped: this.stats.skipped,
      failed: this.stats.failed,
      duplicates: this.stats.duplicates,
      suppressed: this.stats.suppressed,
      notifications: this.stats.notifications,
      pending: this.timers.size,
      inFlight: this.inFlight.size,
      enabled: this.settings.enabled,
      analyses: this.stats.analyses.map((entry) => ({ ...entry }))
    };
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.cancelAll('disposed');
    for (const subscription of this.subscriptions) {
      try {
        subscription.dispose();
      } catch {
        // Ignore duplicate disposal.
      }
    }
    this.subscriptions = [];
    this.tracker.clear();
    this.analyzedHashes.clear();
    this.disposed = true;
  }
}

module.exports = {
  RealtimeMonitor,
  normalizeSettings,
  createCancellationTokenSource,
  isCancellation,
  DEFAULT_SETTINGS
};
