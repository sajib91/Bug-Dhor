'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { COMMAND_DEFINITIONS } = require('../commands/definitions');
const { isFileUriWithinFolders } = require('../security/paths');
const { applyUnifiedPatch, patchFiles } = require('../repair/patchApplication');
const { createNonce } = require('./csp');
const { createDashboardHtml } = require('./dashboardHtml');
const { createEmptyDashboardState } = require('./dashboardModel');

const DASHBOARD_VIEW_TYPE = 'bugdhor.dashboard';
const DASHBOARD_TITLE = 'Bug Dhor Security Dashboard';
const SETTINGS_QUERY = 'bugdhor';

function hashText(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Only engine-backed commands may be triggered from the dashboard. The panel
 * never accepts arbitrary command IDs or command arguments from the webview.
 */
const EXECUTABLE_COMMANDS = Object.freeze(
  new Set(
    COMMAND_DEFINITIONS.filter((definition) => definition.serviceMethod).map(
      (definition) => definition.id
    )
  )
);

class DashboardPanelController {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   extensionUri: import('vscode').Uri,
   *   logger: import('../logging/output').Logger,
   *   getState?: (dataMode: 'empty' | 'demo') => object,
   *   feedback?: import('../feedback/feedbackController').FeedbackController
   * }} options
   */
  constructor({ vscode, extensionUri, logger, getState, feedback }) {
    if (!vscode) {
      throw new TypeError('DashboardPanelController requires a vscode API object.');
    }
    if (!extensionUri) {
      throw new TypeError('DashboardPanelController requires an extension URI.');
    }
    if (!logger) {
      throw new TypeError('DashboardPanelController requires a logger.');
    }

    this.vscode = vscode;
    this.extensionUri = extensionUri;
    this.logger = logger;
    this.getState = getState ?? (() => createEmptyDashboardState());
    this.dataMode = 'empty';
    this.liveData = {};
    this.repairRecords = new Map();
    this.repairHistory = [];
    this.feedback = feedback ?? null;
    this.recommendationHistory = [];
    /** @type {import('vscode').WebviewPanel | undefined} */
    this.panel = undefined;
    /** @type {object | undefined} */
    this.state = undefined;
    /** @type {import('vscode').Disposable[]} */
    this.disposables = [];
  }

  /**
   * Open the dashboard, or reveal the existing panel.
   *
   * @returns {import('vscode').WebviewPanel}
   */
  open() {
    if (this.panel) {
      this.panel.reveal(this.panel.viewColumn ?? this.vscode.ViewColumn.One);
      return this.panel;
    }

    const mediaRoot = this.vscode.Uri.joinPath(this.extensionUri, 'media');
    const panel = this.vscode.window.createWebviewPanel(
      DASHBOARD_VIEW_TYPE,
      DASHBOARD_TITLE,
      this.vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [mediaRoot]
      }
    );

    this.panel = panel;
    panel.iconPath = this.vscode.Uri.joinPath(this.extensionUri, 'media', 'icon.png');

    this.state = this.buildCurrentState();
    panel.webview.html = this.buildHtml(panel.webview, mediaRoot, this.state);

    this.disposables = [
      panel.webview.onDidReceiveMessage((message) => this.handleMessage(message)),
      panel.onDidDispose(() => this.handleDispose(panel))
    ];

    this.logger.info('Opened the Bug Dhor security dashboard.');
    return panel;
  }

  /**
   * @param {import('vscode').Webview} webview
   * @param {import('vscode').Uri} mediaRoot
   * @param {object} state
   * @returns {string}
   */
  buildHtml(webview, mediaRoot, state) {
    const nonce = createNonce();
    const styleUri = webview.asWebviewUri(this.vscode.Uri.joinPath(mediaRoot, 'dashboard.css'));
    const scriptUri = webview.asWebviewUri(this.vscode.Uri.joinPath(mediaRoot, 'dashboard.js'));

    return createDashboardHtml({
      cspSource: webview.cspSource,
      styleUri: styleUri.toString(),
      scriptUri: scriptUri.toString(),
      nonce,
      state
    });
  }

  /**
   * @param {unknown} message
   */
  async handleMessage(message) {
    if (!message || typeof message !== 'object') {
      return;
    }

    switch (message.type) {
      case 'ready':
        this.postState();
        break;
      case 'refresh':
        this.refresh();
        break;
      case 'setDemoMode':
        if (typeof message.enabled !== 'boolean') {
          this.logger.warn('Ignored a malformed dashboard data-mode request.');
          return;
        }
        this.setDataMode(message.enabled ? 'demo' : 'empty');
        break;
      case 'executeCommand':
        await this.executeDashboardCommand(message.command);
        break;
      case 'openSettings':
        await this.openSettings();
        break;
      case 'showLogs':
        this.logger.show();
        break;
      case 'openLocation':
        await this.openLocation(message);
        break;
      case 'viewRepairDiff':
        await this.viewRepairDiff(message);
        break;
      case 'acceptRepair':
        await this.acceptRepair(message);
        break;
      case 'rejectRepair':
        this.updateRepairStatus(message.repairId, 'rejected');
        break;
      case 'restoreRepair':
        await this.restoreRepair(message);
        break;
      case 'viewRepairHistory':
        this.postNotice(
          'info',
          `${this.repairHistory.length} repair history record(s) are available below.`
        );
        break;
      default:
        this.logger.debug('Ignored an unknown dashboard message.');
    }

  }

  /**
   * Open a backend-supplied source location only when it is inside a workspace.
   *
   * @param {{ path?: unknown, line?: unknown, column?: unknown }} message
   */
  async openLocation(message) {
    if (
      typeof message.path !== 'string' ||
      !Number.isInteger(message.line) ||
      message.line < 0 ||
      (message.column !== undefined &&
        (!Number.isInteger(message.column) || message.column < 0))
    ) {
      this.logger.warn('Ignored a malformed dashboard source-location request.');
      return;
    }

    const uri = this.vscode.Uri.file(message.path);
    if (!isFileUriWithinFolders(uri, this.vscode.workspace.workspaceFolders ?? [])) {
      this.logger.warn(`Ignored a dashboard location outside the workspace: ${message.path}`);
      this.postNotice('warning', 'The requested source location is outside the workspace.');
      return;
    }

    try {
      const document = await this.vscode.workspace.openTextDocument(uri);
      const position = new this.vscode.Position(message.line, message.column ?? 0);
      await this.vscode.window.showTextDocument(document, {
        selection: new this.vscode.Range(position, position),
        preserveFocus: false,
        preview: false
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      this.logger.error(`Unable to open dashboard source location: ${detail}`, error);
      this.postNotice('error', 'Unable to open the requested source location. See Bug Dhor logs.');
    }
  }

  /**
   * @param {'empty' | 'demo'} dataMode
   */
  setDataMode(dataMode) {
    this.dataMode = dataMode === 'demo' ? 'demo' : 'empty';
    if (!this.panel) {
      return;
    }
    this.state = this.buildCurrentState();
    this.postState();
    this.logger.debug(`Dashboard data mode: ${this.dataMode}.`);
  }

  refresh() {
    if (!this.panel) {
      return;
    }
    this.state = this.buildCurrentState();
    this.postState();
    this.logger.debug('Refreshed the Bug Dhor security dashboard.');
  }

  postState() {
    if (!this.panel || !this.state) {
      return;
    }
    this.panel.webview.postMessage({ type: 'state', state: this.state });
  }

  /**
   * Merge validated backend data into the live dashboard state.
   *
   * @param {Record<string, unknown>} patch
   */
  updateLiveState(patch) {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      this.logger.warn('Ignored malformed live dashboard data.');
      return;
    }
    this.liveData = { ...this.liveData, ...patch, dataMode: 'live' };
    if (this.panel) {
      this.state = this.buildCurrentState();
      this.postState();
    }
  }

    /**
     * Capture the exact document baseline associated with a backend proposal.
     *
     * @param {Record<string, any>} response
     * @param {Record<string, any>} request
     */
    async recordRepairResult(response, request) {
      const result = response?.result;
      if (!result || result.analysisAvailable !== true || typeof result.patch !== 'string') {
        this.updateLiveState({
          repairs: [
            {
              id: `repair-${Date.now()}`,
              title: 'Repair proposal unavailable',
              status: 'unavailable',
              summary: 'The backend did not produce a reviewable patch.',
              verificationStatus: 'not-run'
            }
          ]
        });
        return;
      }

      const uri = this.vscode.Uri.parse(request.documentUri);
      const document = await this.vscode.workspace.openTextDocument(uri);
      const originalText = document.getText();
      const repairId = result.metadata?.repairId ?? `repair-${Date.now()}`;
      const candidates = Array.isArray(result.metadata?.candidates)
        ? result.metadata.candidates
        : [{ candidateId: 'selected', patch: result.patch }];
      const record = {
        id: repairId,
        uri: request.documentUri,
        filePath: request.filePath,
        targetPatchPath: path
          .relative(request.workspaceFolder, request.filePath)
          .split(path.sep)
          .join('/'),
        languageId: request.languageId,
        baseVersion: document.version,
        baseHash: hashText(originalText),
        originalText,
        patch: result.patch,
        candidates,
        status: 'proposed',
        verificationStatus: result.metadata?.verificationStatus ?? 'not-run',
        metadata: result.metadata ?? {},
        findingId: request.finding?.findingId ?? result.metadata?.findingId ?? null
      };
      this.repairRecords.set(repairId, record);
      this.repairHistory.unshift({
        id: repairId,
        status: 'proposed',
        verificationStatus: record.verificationStatus,
        timestamp: new Date().toISOString()
      });
      this.updateRepairState(record);
    }

    /**
     * Capture a secure recommendation proposal. The baseline is the exact
     * source returned by the backend, not the current editor buffer, so a later
     * approval must revalidate the document before any patch can be applied.
     *
     * @param {Record<string, any>} response
     * @param {Record<string, any>} request
     */
    async recordRecommendationResult(response, request) {
      const result = response?.result;
      if (
        !result ||
        result.analysisAvailable !== true ||
        result.requiresApproval !== true ||
        typeof result.originalCode !== 'string'
      ) {
        this.updateRecommendationState({
          id: `recommendation-${Date.now()}`,
          kind: 'recommendation',
          title: 'Secure recommendation unavailable',
          status: 'unavailable',
          verificationStatus: 'not-run',
          state: result?.state ?? 'unavailable',
          requiresApproval: true,
          explanation: result?.explanation ?? {
            summary: 'The backend did not produce a reviewable secure recommendation.',
            changes: [],
            why: [],
            remainingRisks: []
          }
        });
        return;
      }

      const uri = this.vscode.Uri.parse(request.documentUri);
      const document = await this.vscode.workspace.openTextDocument(uri);
      const originalCode = result.originalCode;
      const repairedCode =
        typeof result.repairedCode === 'string' && result.repairedCode.length > 0
          ? result.repairedCode
          : null;
      const id = result.metadata?.recommendationId ?? `recommendation-${Date.now()}`;
      const selected = result.selected && typeof result.selected === 'object' ? result.selected : null;
      const candidates = (Array.isArray(result.candidates) ? result.candidates : [])
        .filter((item) => item && typeof item === 'object')
        .map((candidate) => ({
          candidateId: candidate.candidateId ?? 'candidate',
          patch: typeof candidate.patch === 'string' ? candidate.patch : '',
          verification: candidate.verification ?? null,
          functional: candidate.functional ?? null,
          accepted: candidate.accepted === true,
          rejectionReason: candidate.rejectionReason ?? null
        }));
      if (selected && !candidates.some((item) => item.candidateId === selected.candidateId)) {
        candidates.unshift({
          candidateId: selected.candidateId ?? 'selected',
          patch: typeof selected.patch === 'string' ? selected.patch : '',
          verification: selected.verification ?? null,
          functional: selected.functional ?? null,
          accepted: selected.accepted === true,
          rejectionReason: selected.rejectionReason ?? null
        });
      }

      const record = {
        id,
        kind: 'recommendation',
        uri: request.documentUri,
        filePath: request.filePath,
        targetPatchPath: path
          .relative(request.workspaceFolder, request.filePath)
          .split(path.sep)
          .join('/'),
        languageId: request.languageId,
        baseVersion: document.version,
        baseHash: hashText(originalCode),
        originalText: originalCode,
        repairedText: repairedCode,
        originalCode,
        repairedCode,
        patch: selected?.patch ?? '',
        candidates,
        status: result.verified === true && repairedCode ? 'proposed' : 'unavailable',
        verificationStatus:
          result.verified === true
            ? 'passed'
            : result.state === 'rejected'
              ? 'failed'
              : 'not-run',
        state: result.state,
        requiresApproval: result.requiresApproval,
        explanation: result.explanation ?? null,
        verification: selected?.verification ?? null,
        functional: selected?.functional ?? null,
        stages: Array.isArray(result.stages) ? result.stages : [],
        prompt: result.prompt ?? null,
        metadata: result.metadata ?? {},
        findingId: request.finding?.findingId ?? result.findingId ?? null,
        cwe: result.cwe ?? null
      };
      this.repairRecords.set(id, record);
      this.recommendationHistory.unshift({
        id,
        status: record.status,
        verificationStatus: record.verificationStatus,
        state: record.state,
        timestamp: new Date().toISOString()
      });
      this.updateRepairState(record);
    }

    async viewRepairDiff(message) {
      const record = this.repairRecords.get(message?.repairId);
      if (!record) {
        this.postNotice('warning', 'The requested repair proposal is no longer available.');
        return;
      }
      const candidate = record.candidates.find(
        (item) => item.candidateId === message.candidateId
      ) ?? record.candidates[0];
      const hasFullText = typeof record.repairedText === 'string' && record.repairedText.length > 0;
      if (!hasFullText && (!candidate || typeof candidate.patch !== 'string' || !candidate.patch)) {
        this.postNotice('warning', 'The selected repair candidate has no patch.');
        return;
      }
      try {
        const document = await this.vscode.workspace.openTextDocument(
          this.vscode.Uri.parse(record.uri)
        );
        const patchedText = hasFullText
          ? record.repairedText
          : applyUnifiedPatch(document.getText(), candidate.patch);
        const preview = await this.vscode.workspace.openTextDocument({
          content: patchedText,
          language: record.languageId
        });
        await this.vscode.commands.executeCommand(
          'vscode.diff',
          this.vscode.Uri.parse(record.uri),
          preview.uri,
          `Bug Dhor Repair Preview: ${record.id}`
        );
      } catch (error) {
        this.postNotice(
          'warning',
          `The inline diff is unavailable: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    async acceptRepair(message) {
      const record = this.repairRecords.get(message?.repairId);
      if (!record) {
        this.postNotice('warning', 'The requested repair proposal is no longer available.');
        return;
      }
      const candidate = record.candidates.find(
        (item) => item.candidateId === message.candidateId
      ) ?? record.candidates[0];
      const hasFullText = typeof record.repairedText === 'string' && record.repairedText.length > 0;
      if (!hasFullText && (!candidate || typeof candidate.patch !== 'string' || !candidate.patch)) {
        this.postNotice('warning', 'The selected repair candidate has no patch.');
        return;
      }
      const approval = await this.vscode.window.showWarningMessage(
        'Apply this Bug Dhor repair patch to the source file?',
        { modal: true },
        'Apply Patch'
      );
      if (approval !== 'Apply Patch') {
        return;
      }
      const document = await this.vscode.workspace.openTextDocument(
        this.vscode.Uri.parse(record.uri)
      );
      if (
        document.version !== record.baseVersion ||
        hashText(document.getText()) !== record.baseHash
      ) {
        this.postNotice(
          'warning',
          'The source changed after repair generation. The patch was not applied.'
        );
        this.updateRepairStatus(record.id, 'stale');
        return;
      }
      let patchedText;
      if (hasFullText) {
        // Secure recommendations carry the verified full-file result. The base
        // hash check above still guarantees the document matches that result.
        patchedText = record.repairedText;
      } else {
        const files = patchFiles(candidate.patch);
        if (files.length !== 1 || files[0] !== record.targetPatchPath) {
          this.postNotice('warning', 'Only single-file repair patches can be applied safely.');
          return;
        }
        try {
          patchedText = applyUnifiedPatch(document.getText(), candidate.patch);
        } catch (error) {
          this.postNotice('error', `Repair patch could not be applied: ${error.message}`);
          return;
        }
      }
      const edit = new this.vscode.WorkspaceEdit();
      const end = document.positionAt(document.getText().length);
      edit.replace(document.uri, new this.vscode.Range(new this.vscode.Position(0, 0), end), patchedText);
      if (!(await this.vscode.workspace.applyEdit(edit))) {
        this.postNotice('error', 'VS Code rejected the repair edit.');
        return;
      }
      record.appliedHash = hashText(patchedText);
      record.appliedVersion = document.version + 1;
      record.appliedText = patchedText;
      record.status = 'accepted';
      record.selectedCandidateId = candidate?.candidateId ?? 'selected';
      // Only this explicit, approved application path is recorded as an
      // extension-authored patch. Editor events are never treated as evidence.
      this.feedback?.recordAppliedPatch?.({
        documentUri: record.uri,
        findingId: record.findingId,
        patchHash: hashText(candidate?.patch ?? patchedText),
        appliedHash: record.appliedHash,
        source: 'dashboard.explicit-approval'
      });
      this.updateRepairState(record);
      this.postNotice(
        'info',
        'Patch applied with approval. Verification status remains separate and unchanged.'
      );
    }

    async restoreRepair(message) {
      const record = this.repairRecords.get(message?.repairId);
      if (!record || !record.appliedText) {
        this.postNotice('warning', 'There is no approved patch to restore.');
        return;
      }
      const approval = await this.vscode.window.showWarningMessage(
        'Restore the original source content captured before this repair?',
        { modal: true },
        'Restore Original'
      );
      if (approval !== 'Restore Original') {
        return;
      }
      const document = await this.vscode.workspace.openTextDocument(
        this.vscode.Uri.parse(record.uri)
      );
      if (hashText(document.getText()) !== record.appliedHash) {
        this.postNotice('warning', 'The file changed after the repair. Original content was preserved but not restored.');
        return;
      }
      const edit = new this.vscode.WorkspaceEdit();
      edit.replace(
        document.uri,
        new this.vscode.Range(new this.vscode.Position(0, 0), document.positionAt(document.getText().length)),
        record.originalText
      );
      if (await this.vscode.workspace.applyEdit(edit)) {
        record.status = 'restored';
        this.updateRepairState(record);
        this.postNotice('info', 'Original content restored.');
      }
    }

    updateRepairStatus(repairId, status) {
      const record = this.repairRecords.get(repairId);
      if (!record) {
        return;
      }
      record.status = status;
      this.updateRepairState(record);
    }

    updateRepairState(record) {
      if (record.kind === 'recommendation') {
        this.updateRecommendationState(record);
        return;
      }
      const visible = {
        id: record.id,
        title: `Repair proposal ${record.id}`,
        findingId: record.findingId,
        status: record.status,
        verificationStatus: record.verificationStatus,
        baseSnapshotId: record.baseHash,
        generator: record.metadata.modelId ?? 'Bug Dhor backend',
        patch: record.patch,
        candidates: record.candidates,
        riskNotes: record.metadata.riskNotes ?? [],
        rationale: record.metadata.rationale ?? '',
        filePath: record.filePath
      };
      this.updateLiveState({
        repairs: [visible, ...(this.liveData.repairs ?? []).filter((item) => item.id !== record.id)],
        repairHistory: this.repairHistory
      });
    }

    updateRecommendationState(record) {
      const explanation = record.explanation ?? {};
      const visible = {
        id: record.id,
        kind: 'recommendation',
        title: `Secure recommendation ${record.id}`,
        findingId: record.findingId,
        cwe: record.cwe,
        state: record.state,
        status: record.status,
        verificationStatus: record.verificationStatus,
        requiresApproval: record.requiresApproval,
        baseSnapshotId: record.baseHash,
        originalCode: record.originalCode,
        repairedCode: record.repairedCode,
        generator: record.metadata?.modelId ?? record.prompt?.modelId ?? 'Bug Dhor backend',
        patch: record.patch,
        candidates: record.candidates,
        explanation: {
          summary: explanation.summary ?? '',
          changes: Array.isArray(explanation.changes) ? explanation.changes : [],
          why: Array.isArray(explanation.why) ? explanation.why : [],
          remainingRisks: Array.isArray(explanation.remainingRisks) ? explanation.remainingRisks : [],
          functionalAssurance: explanation.functionalAssurance ?? ''
        },
        verification: record.verification,
        functional: record.functional,
        filePath: record.filePath,
        stages: record.stages,
        prompt: record.prompt
          ? {
              promptHash: record.prompt.promptHash,
              steeringApplied: record.prompt.steeringApplied,
              steeringReason: record.prompt.steeringReason,
              providerId: record.prompt.providerId,
              modelId: record.prompt.modelId
            }
          : null
      };
      const recommendationHistory = this.recommendationHistory.map((entry) =>
        entry.id === record.id
          ? {
              ...entry,
              status: record.status,
              verificationStatus: record.verificationStatus,
              state: record.state
            }
          : entry
      );
      this.updateLiveState({
        recommendations: [
          visible,
          ...(this.liveData.recommendations ?? []).filter((item) => item.id !== record.id)
        ],
        recommendationHistory
      });
    }

  buildCurrentState() {
    const base = this.getState(this.dataMode);
    if (this.dataMode !== 'empty' || Object.keys(this.liveData).length === 0) {
      return base;
    }
    return { ...base, ...this.liveData, dataMode: 'live' };
  }

  /**
   * @param {unknown} command
   */
  async executeDashboardCommand(command) {
    if (typeof command !== 'string' || !EXECUTABLE_COMMANDS.has(command)) {
      this.logger.warn(`Ignored a dashboard request for a disallowed command: ${String(command)}`);
      return;
    }

    try {
      await this.vscode.commands.executeCommand(command);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to start dashboard command ${command}: ${message}`, error);
      this.postNotice('error', `Unable to run the requested command. See Bug Dhor logs.`);
    }
  }

  async openSettings() {
    try {
      await this.vscode.commands.executeCommand('workbench.action.openSettings', SETTINGS_QUERY);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Unable to open Bug Dhor settings: ${message}`, error);
      this.postNotice('error', 'Unable to open VS Code settings. See Bug Dhor logs.');
    }
  }

  /**
   * @param {'info' | 'warning' | 'error'} level
   * @param {string} message
   */
  postNotice(level, message) {
    if (!this.panel) {
      return;
    }
    this.panel.webview.postMessage({ type: 'notice', level, message });
  }

  /**
   * @param {import('vscode').WebviewPanel} panel
   */
  handleDispose(panel) {
    if (this.panel !== panel) {
      return;
    }
    this.panel = undefined;
    this.state = undefined;
    this.liveData = {};
    this.repairRecords.clear();
    this.repairHistory = [];
    this.recommendationHistory = [];
    this.disposeListeners();
    this.logger.debug('Closed the Bug Dhor security dashboard.');
  }

  disposeListeners() {
    const disposables = this.disposables;
    this.disposables = [];
    for (const disposable of disposables) {
      try {
        disposable.dispose();
      } catch (error) {
        this.logger.error('Failed to dispose a dashboard listener.', error);
      }
    }
  }

  dispose() {
    const panel = this.panel;
    this.panel = undefined;
    this.state = undefined;
    this.liveData = {};
    this.repairRecords.clear();
    this.repairHistory = [];
    this.recommendationHistory = [];
    this.disposeListeners();
    if (panel) {
      panel.dispose();
    }
  }
}

module.exports = {
  DashboardPanelController,
  DASHBOARD_VIEW_TYPE,
  DASHBOARD_TITLE,
  EXECUTABLE_COMMANDS,
  SETTINGS_QUERY
};
