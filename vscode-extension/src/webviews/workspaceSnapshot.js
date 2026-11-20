'use strict';

/**
 * Build dashboard workspace/inventory state from the folders actually open in
 * VS Code. Discovery is metadata-only: file contents are never read here and
 * no value is estimated when VS Code has not supplied one.
 */

const path = require('node:path');

const { discoverRepositoryInventory } = require('../repository');

/** @param {unknown} value */
function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** @param {unknown} value */
function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * @param {{
 *   vscode: import('vscode'),
 *   logger?: import('../logging/output').Logger,
 *   getSettings?: () => object
 * }} dependencies
 */
function createWorkspaceSnapshotProvider({ vscode, logger, getSettings } = {}) {
  if (!vscode?.workspace) {
    throw new TypeError('Workspace snapshot provider requires a vscode API object.');
  }

  let snapshot = emptySnapshot();
  let lastError = null;

  function emptySnapshot() {
    return {
      workspace: {
        available: false,
        name: null,
        path: null,
        folders: []
      },
      inventory: {
        available: false,
        totalFiles: null,
        languages: {},
        truncated: null
      },
      discoveredPaths: []
    };
  }

  function currentFolders() {
    const folders = Array.isArray(vscode.workspace.workspaceFolders)
      ? vscode.workspace.workspaceFolders
      : [];
    return folders.filter((folder) => {
      return (
        folder?.uri?.scheme === 'file' &&
        typeof folder.uri.fsPath === 'string' &&
        path.isAbsolute(folder.uri.fsPath)
      );
    });
  }

  function workspaceMetadata(folders) {
    if (folders.length === 0) {
      return {
        available: false,
        name: null,
        path: null,
        folders: []
      };
    }
    const workspaceName = stringOrNull(vscode.workspace.name);
    return {
      available: true,
      name: workspaceName ?? (folders.length === 1 ? stringOrNull(folders[0].name) : null),
      path: folders.length === 1 ? folders[0].uri.fsPath : null,
      folders: folders.map((folder, index) => ({
        name:
          stringOrNull(folder.name) ?? path.basename(folder.uri.fsPath) ?? `Folder ${index + 1}`,
        path: folder.uri.fsPath
      }))
    };
  }

  async function refresh() {
    const folders = currentFolders();
    const workspace = workspaceMetadata(folders);
    if (folders.length === 0) {
      snapshot = { ...emptySnapshot(), workspace };
      lastError = null;
      return dashboardPatch();
    }

    const requestedSettings = getSettings?.();
    const settings = isRecord(requestedSettings) ? requestedSettings : {};
    try {
      const inventory = await discoverRepositoryInventory(vscode, {
        maxFiles: settings.repositoryMaxFiles,
        maxFileBytes: settings.repositoryMaxFileBytes,
        excludeGlobs: settings.repositoryExcludeGlobs
      });
      const files = Array.isArray(inventory.files) ? inventory.files : [];
      lastError = null;
      snapshot = {
        workspace,
        inventory: {
          available: true,
          totalFiles: files.length,
          languages: isRecord(inventory.languages) ? { ...inventory.languages } : {},
          truncated: inventory.stats?.truncated === true
        },
        discoveredPaths: files.map((file) => file.fsPath)
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      lastError = message;
      logger?.warn?.(`Repository discovery unavailable: ${message}`);
      snapshot = { ...emptySnapshot(), workspace };
    }
    return dashboardPatch();
  }

  function dashboardPatch() {
    return {
      workspace: {
        ...snapshot.workspace,
        folders: snapshot.workspace.folders.map((entry) => ({ ...entry }))
      },
      inventory: {
        ...snapshot.inventory,
        languages: { ...snapshot.inventory.languages }
      }
    };
  }

  return {
    refresh,
    getSnapshot: () => ({
      workspace: {
        ...snapshot.workspace,
        folders: snapshot.workspace.folders.map((entry) => ({ ...entry }))
      },
      inventory: {
        ...snapshot.inventory,
        languages: { ...snapshot.inventory.languages }
      }
    }),
    getDiscoveredPaths: () => [...snapshot.discoveredPaths],
    hasDiscoveredPath: (fsPath) =>
      typeof fsPath === 'string' && snapshot.discoveredPaths.includes(fsPath),
    getLastError: () => lastError
  };
}

module.exports = { createWorkspaceSnapshotProvider };
