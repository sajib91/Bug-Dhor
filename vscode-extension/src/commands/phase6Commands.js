'use strict';

const { COMMAND_DEFINITIONS } = require('./definitions');
const { LocalPhase6Error, createLocalPhase6Engine } = require('../phase6/localEngine');

/**
 * Phase 6 commands use the opt-in local engine only. They never replace the
 * backend commands and never write source without a separate settings opt-in
 * plus an exact, explicit developer confirmation.
 *
 * @param {{
 *   vscode: any,
 *   logger: any,
 *   diagnostics: any,
 *   registry: import('./registry').CommandRegistry,
 *   trustGate?: { assertCapability: (operation?: string) => void },
 *   phase6Runner?: (command: string, args: string[], options: object) => Promise<{ stdout: string, stderr: string }>
 * }} context
 */
function registerPhase6Commands(context) {
  const { vscode, logger, diagnostics, registry, trustGate, phase6Runner } = context;
  const engine = createLocalPhase6Engine({
    vscode,
    logger,
    diagnostics,
    runCommand: phase6Runner
  });

  /** @param {string} title @param {string} content @param {string} [language] */
  async function showDocument(title, content, language = 'json') {
    const document = await vscode.workspace.openTextDocument({
      content: `${title}\n\n${content}\n`,
      language
    });
    await vscode.window.showTextDocument(document, { preview: true });
  }

  /** @param {unknown} error */
  function reportFailure(error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error('Local Phase 6 command failed.', error);
    Promise.resolve(vscode.window.showErrorMessage(`Bug Dhor Phase 6: ${message}`)).catch(() => {
      // A dismissed or failed notification must not surface a second error.
    });
    return undefined;
  }

  /** @param {string} message */
  async function notify(message) {
    await vscode.window.showInformationMessage(`Bug Dhor Phase 6: ${message}`);
  }

  /**
   * @returns {Promise<{ file: string, index: number } | undefined>}
   */
  async function selectedLocation() {
    engine.assertEnabled();
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.scheme !== 'file') {
      throw new LocalPhase6Error('Open and save a workspace source file first.');
    }
    const finding = engine.currentFinding(editor.document, editor);
    if (!finding) {
      throw new LocalPhase6Error(
        'No finding is selected. Scan the file and place the cursor on a finding.'
      );
    }
    const file = editor.document.uri.fsPath;
    const index = await engine.indexForFinding(file, finding);
    return { file, index };
  }

  /**
   * @param {string} patchId
   * @param {string} purpose
   * @returns {Promise<boolean>}
   */
  async function confirmWrite(patchId, purpose) {
    engine.assertWriteAllowed();
    const action = await vscode.window.showWarningMessage(
      `Bug Dhor Phase 6: ${purpose}. This writes the source file after exact confirmation.`,
      { modal: true },
      'Continue'
    );
    if (action !== 'Continue') return false;
    const confirmation = await vscode.window.showInputBox({
      prompt: `Type the patch_id to confirm ${purpose.toLowerCase()}:`,
      placeHolder: patchId,
      ignoreFocusOut: true
    });
    return confirmation === patchId;
  }

  /** @returns {object} */
  function latestActiveEntry(history) {
    const entries = history?.history?.entries ?? [];
    const active = entries.filter((entry) => !entry.reverted_at);
    if (active.length === 0) {
      throw new LocalPhase6Error('No active applied patch is available in the local session.');
    }
    return active[active.length - 1];
  }

  /** @param {(...args: any[]) => Promise<unknown>} task */
  async function guarded(task) {
    try {
      trustGate?.assertCapability?.('localEngine');
      return await task();
    } catch (error) {
      return reportFailure(error);
    }
  }

  const handlers = {
    explainFindingPhase6: async () =>
      guarded(async () => {
        const location = await selectedLocation();
        if (!location) return undefined;
        const explanation = await engine.explain(location.file, location.index);
        const suggestion = await engine.suggest(location.file, location.index);
        await showDocument(
          'Bug Dhor Phase 6 explanation',
          JSON.stringify({ explanation, suggestion }, null, 2)
        );
        return { findingId: explanation.finding_id };
      }),

    suggestRepairPhase6: async () =>
      guarded(async () => {
        const location = await selectedLocation();
        if (!location) return undefined;
        const suggestion = await engine.suggest(location.file, location.index);
        await showDocument(
          'Bug Dhor Phase 6 repair suggestion',
          JSON.stringify(suggestion, null, 2)
        );
        return { status: suggestion.recommendation?.status };
      }),

    previewRepairPhase6: async () =>
      guarded(async () => {
        const location = await selectedLocation();
        if (!location) return undefined;
        const preview = await engine.preview(location.file, location.index);
        if (preview.patch?.unified_diff) {
          await showDocument('Bug Dhor Phase 6 patch preview', preview.patch.unified_diff, 'diff');
          await notify(
            `Patch ${preview.patch.patch_id} is ready for review. No source was changed.`
          );
        } else {
          await showDocument('Bug Dhor Phase 6 patch preview', JSON.stringify(preview, null, 2));
          await notify('No reviewable deterministic patch is available for this finding.');
        }
        return { patchId: preview.patch?.patch_id ?? null, canApply: preview.can_apply };
      }),

    applyRepairPhase6: async () =>
      guarded(async () => {
        const location = await selectedLocation();
        if (!location) return undefined;
        const preview = await engine.preview(location.file, location.index);
        if (!preview.patch || !preview.can_apply) {
          throw new LocalPhase6Error('No reviewable patch is available for this finding.');
        }
        const patchId = preview.patch.patch_id;
        const approved = await confirmWrite(patchId, 'apply the reviewed patch');
        if (!approved) {
          await notify('Apply cancelled; no source was changed.');
          return { applied: false };
        }
        const applied = await engine.apply(location.file, patchId, patchId);
        await notify(`Patch applied. Verify with Phase 6 before treating the finding as resolved.`);
        return applied;
      }),

    verifyRepairPhase6: async () =>
      guarded(async () => {
        engine.assertEnabled();
        const history = await engine.history();
        const entry = latestActiveEntry(history);
        const verification = await engine.verify(entry.entry_id);
        await showDocument(
          `Bug Dhor Phase 6 verification ${entry.entry_id}`,
          JSON.stringify(verification, null, 2)
        );
        return { entryId: entry.entry_id, status: verification.status };
      }),

    revertRepairPhase6: async () =>
      guarded(async () => {
        engine.assertEnabled();
        const history = await engine.history();
        const entry = latestActiveEntry(history);
        const approved = await confirmWrite(entry.patch_id, 'revert the applied patch');
        if (!approved) {
          await notify('Revert cancelled; no source was changed.');
          return { reverted: false };
        }
        const reverted = await engine.revert(entry.entry_id, entry.patch_id);
        await notify(`Patch reverted for ${entry.file}.`);
        return reverted;
      }),

    showRepairHistoryPhase6: async () =>
      guarded(async () => {
        engine.assertEnabled();
        const history = await engine.history();
        await showDocument('Bug Dhor Phase 6 repair history', JSON.stringify(history, null, 2));
        return { entryCount: history.entry_count };
      })
  };

  for (const definition of COMMAND_DEFINITIONS.filter((item) => item.localEngine)) {
    const handler = handlers[definition.key];
    if (typeof handler !== 'function') {
      throw new Error(`No Phase 6 handler for ${definition.id}`);
    }
    registry.register(definition.id, handler);
  }
}

module.exports = { registerPhase6Commands };
