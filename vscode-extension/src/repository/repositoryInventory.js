'use strict';

/**
 * Bounded, metadata-only repository discovery for Bug Dhor.
 *
 * The module is pure with respect to the editor: every editor API is injected
 * through `vscode`; there is no direct `require('vscode')`. Traversal uses only
 * `vscode.workspace.fs.readDirectory`, `vscode.workspace.fs.stat`, and
 * `vscode.FileType`. Symlinks are never followed, paths outside a workspace
 * root are never traversed, and non-`file:` folder URIs are rejected.
 *
 * Cancellation policy: cancellation is *non-throwing*. If the injected token
 * reports `isCancellationRequested` (a boolean property or a function), the
 * scan stops promptly and returns a partial inventory with
 * `stats.cancelled === true`. Invalid input and filesystem failures throw
 * {@link RepositoryInventoryError} instead.
 */

const path = require('node:path');

const { isPathExcluded } = require('../monitoring/changeAnalyzer');
const { isBinaryPath, isGeneratedPath, languageForPath } = require('../monitoring/fileFilter');
const { isPathWithinRoot } = require('../security/paths');
const { GitIgnoreRules, parseGitIgnore } = require('./gitignore');

const DEFAULT_MAX_FILES = 2000;
const MIN_MAX_FILES = 1;
const MAX_MAX_FILES = 50_000;
const DEFAULT_MAX_FILE_BYTES = 1_048_576;

/** Directory names that are never traversed, regardless of gitignore rules. */
const DEFAULT_EXCLUDED_DIRECTORY_NAMES = Object.freeze(
  new Set([
    '.git',
    'node_modules',
    'vendor',
    '.venv',
    'venv',
    'dist',
    'build',
    'coverage',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    '.cache',
    '.tox',
    '.vscode-test',
    '.bugdhor-data'
  ])
);

/** Stable machine-readable values used in `ignored[].reason`. */
const IGNORE_REASONS = Object.freeze({
  defaultExcludedDirectory: 'default-excluded-directory',
  userGlob: 'user-glob',
  gitignore: 'gitignore',
  infoExclude: 'info-exclude',
  outsideWorkspace: 'outside-workspace',
  symbolicLink: 'symbolic-link',
  invalidEntryName: 'invalid-entry-name',
  unsupportedFileType: 'unsupported-file-type',
  binaryFile: 'binary-file',
  generatedFile: 'generated-file',
  fileTooLarge: 'file-too-large',
  unknownLanguage: 'unknown-language',
  duplicateFile: 'duplicate-file'
});

/** Typed errors for invalid input and filesystem failures. */
class RepositoryInventoryError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {{ path?: string, cause?: unknown }} [options]
   */
  constructor(message, code, options = {}) {
    super(message);
    this.name = 'RepositoryInventoryError';
    this.code = code;
    if (typeof options.path === 'string') {
      this.path = options.path;
    }
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }

  /** @returns {Record<string, unknown>} */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      path: this.path ?? null
    };
  }
}

/** Internal control-flow signal used to stop a recursive traversal. */
class InventoryStop extends Error {
  /** @param {'cancelled' | 'truncated'} kind */
  constructor(kind) {
    super(`inventory stopped: ${kind}`);
    this.kind = kind;
  }
}

/**
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} minimum
 * @param {number} maximum
 * @returns {number}
 */
function integerSetting(value, fallback, minimum, maximum) {
  const number = typeof value === 'string' && value.trim().length > 0 ? Number(value) : value;
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(maximum, Math.max(minimum, Math.round(number)));
}

/**
 * @param {unknown} options
 * @returns {{
 *   maxFiles: number,
 *   maxFileBytes: number,
 *   excludeGlobs: string[],
 *   cancellationToken: object | undefined
 * }}
 */
function normalizeOptions(options) {
  const source = options && typeof options === 'object' ? options : {};
  const excludeGlobs = Array.isArray(source.excludeGlobs)
    ? source.excludeGlobs.filter((entry) => typeof entry === 'string' && entry.trim().length > 0)
    : [];
  return {
    maxFiles: integerSetting(source.maxFiles, DEFAULT_MAX_FILES, MIN_MAX_FILES, MAX_MAX_FILES),
    maxFileBytes: integerSetting(
      source.maxFileBytes,
      DEFAULT_MAX_FILE_BYTES,
      1,
      Number.MAX_SAFE_INTEGER
    ),
    excludeGlobs,
    cancellationToken: source.cancellationToken ?? source.token
  };
}

/** @param {unknown} vscode @returns {{ fsApi: object, FileType: object }} */
function requireVscode(vscode) {
  const fsApi = vscode?.workspace?.fs;
  const FileType = vscode?.FileType;
  if (
    !fsApi ||
    typeof fsApi.readDirectory !== 'function' ||
    typeof fsApi.stat !== 'function' ||
    typeof fsApi.readFile !== 'function' ||
    !FileType ||
    typeof FileType !== 'object'
  ) {
    throw new RepositoryInventoryError(
      'discoverRepositoryInventory requires an injected vscode API with workspace.fs and FileType.',
      'E_INVALID_VSCODE'
    );
  }
  return { fsApi, FileType };
}

/** @param {{ scheme?: string, fsPath?: string } | undefined} uri @returns {string} */
function uriTextOf(uri) {
  if (uri && typeof uri.toString === 'function') {
    return uri.toString();
  }
  return `file://${uri?.fsPath ?? ''}`;
}

/**
 * Validate workspace folders and keep internal URIs for traversal. Duplicate
 * folder paths collapse to the first occurrence so files are not counted twice.
 *
 * @param {unknown} vscode
 * @returns {Array<{ name: string, path: string, uriText: string, uri: object }>}
 */
function collectWorkspaceFolders(vscode) {
  const folders = vscode?.workspace?.workspaceFolders;
  if (!Array.isArray(folders) || folders.length === 0) {
    return [];
  }
  /** @type {Array<{ name: string, path: string, uriText: string, uri: object }>} */
  const result = [];
  const seen = new Set();
  for (const folder of folders) {
    const uri = folder?.uri;
    if (
      !uri ||
      uri.scheme !== 'file' ||
      typeof uri.fsPath !== 'string' ||
      uri.fsPath.length === 0
    ) {
      throw new RepositoryInventoryError(
        'Repository inventory requires file-scheme workspace folders.',
        'E_UNSUPPORTED_WORKSPACE'
      );
    }
    const fsPath = path.resolve(uri.fsPath);
    if (seen.has(fsPath)) {
      continue;
    }
    seen.add(fsPath);
    result.push({
      name: typeof folder.name === 'string' && folder.name ? folder.name : path.basename(fsPath),
      path: fsPath,
      uriText: uriTextOf(uri),
      uri
    });
  }
  return result;
}

/**
 * Build the plain workspace-folder metadata included in an inventory.
 *
 * @param {unknown} vscode
 * @returns {Array<{ name: string, path: string, uriText: string }>}
 */
function buildWorkspaceFolderMetadata(vscode) {
  return collectWorkspaceFolders(vscode).map(({ name, path: fsPath, uriText }) => ({
    name,
    path: fsPath,
    uriText
  }));
}

/** @param {unknown} type @param {unknown} flag @returns {boolean} */
function hasFlag(type, flag) {
  return typeof type === 'number' && typeof flag === 'number' && (type & flag) === flag;
}

/**
 * @param {object} vscode
 * @param {object} parentUri
 * @param {string} name
 * @returns {object}
 */
function childUri(vscode, parentUri, name) {
  const Uri = vscode.Uri;
  if (Uri && typeof Uri.joinPath === 'function') {
    return Uri.joinPath(parentUri, name);
  }
  if (Uri && typeof Uri.file === 'function') {
    return Uri.file(path.join(parentUri.fsPath, name));
  }
  throw new RepositoryInventoryError(
    'vscode.Uri.joinPath or vscode.Uri.file is required to build child URIs.',
    'E_INVALID_VSCODE'
  );
}

/** @param {string} base @param {string} name @returns {string} */
function joinRelative(base, name) {
  return base.length === 0 ? name : `${base}/${name}`;
}

/**
 * @param {object} fsApi
 * @param {object} uri
 * @returns {Promise<{ type: number, size?: number } | undefined>}
 */
async function statOrUndefined(fsApi, uri) {
  try {
    return await fsApi.stat(uri);
  } catch {
    return undefined;
  }
}

/**
 * @param {object} fsApi
 * @param {object} uri
 * @param {string} fsPath
 * @returns {Promise<{ type: number, size?: number }>}
 */
async function statOrThrow(fsApi, uri, fsPath) {
  try {
    return await fsApi.stat(uri);
  } catch (error) {
    throw new RepositoryInventoryError(`Unable to stat ${fsPath}.`, 'E_FILESYSTEM', {
      path: fsPath,
      cause: error
    });
  }
}

/** @param {object} fsApi @param {object} uri @returns {Promise<string>} */
async function readText(fsApi, uri) {
  try {
    const bytes = await fsApi.readFile(uri);
    if (!bytes) {
      return '';
    }
    return Buffer.from(bytes)
      .toString('utf8')
      .replace(/^\uFEFF/, '');
  } catch {
    return '';
  }
}

/** @param {string} name @returns {boolean} */
function isInvalidEntryName(name) {
  return (
    typeof name !== 'string' ||
    name.length === 0 ||
    name === '.' ||
    name === '..' ||
    name.includes('/') ||
    name.includes('\\') ||
    name.includes('\u0000')
  );
}

/** @param {string} left @param {string} right @returns {number} */
function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * Discover a bounded repository inventory from injected workspace folders.
 *
 * @param {{
 *   workspace: { workspaceFolders?: unknown, fs: object },
 *   FileType: object,
 *   Uri?: object
 * }} vscode
 * @param {{
 *   maxFiles?: unknown,
 *   maxFileBytes?: unknown,
 *   excludeGlobs?: unknown,
 *   cancellationToken?: { isCancellationRequested?: boolean | (() => boolean) }
 * }} [options]
 * @returns {Promise<{
 *   folders: Array<{ name: string, path: string, uriText: string }>,
 *   files: Array<{
 *     uriText: string,
 *     fsPath: string,
 *     relativePath: string,
 *     language: string,
 *     sizeBytes: number,
 *     rootIndex: number
 *   }>,
 *   ignored: Array<{ fsPath: string, reason: string }>,
 *   languages: Record<string, number>,
 *   stats: {
 *     directoriesVisited: number,
 *     filesVisited: number,
 *     filesIncluded: number,
 *     filesExcluded: number,
 *     symlinksSkipped: number,
 *     truncated: boolean,
 *     cancelled: boolean
 *   }
 * }>}
 */
async function discoverRepositoryInventory(vscode, options = {}) {
  const { fsApi, FileType } = requireVscode(vscode);
  const settings = normalizeOptions(options);
  const internalFolders = collectWorkspaceFolders(vscode);
  if (internalFolders.length === 0) {
    throw new RepositoryInventoryError(
      'Repository inventory requires at least one file-scheme workspace folder.',
      'E_NO_WORKSPACE'
    );
  }

  const state = {
    settings,
    files: [],
    ignored: [],
    seenFiles: new Set(),
    seenIgnored: new Set(),
    languages: new Map(),
    stats: {
      directoriesVisited: 0,
      filesVisited: 0,
      filesIncluded: 0,
      filesExcluded: 0,
      symlinksSkipped: 0,
      truncated: false,
      cancelled: false
    }
  };

  /** @param {string} fsPath @param {string} reason */
  function recordIgnored(fsPath, reason) {
    const key = `${fsPath}\u0000${reason}`;
    if (state.seenIgnored.has(key)) {
      return;
    }
    state.seenIgnored.add(key);
    state.ignored.push({ fsPath, reason });
  }

  /** @param {string} fsPath @param {string} reason */
  function excludeFile(fsPath, reason) {
    state.stats.filesExcluded += 1;
    recordIgnored(fsPath, reason);
  }

  function checkCancellation() {
    if (state.stats.cancelled) {
      throw new InventoryStop('cancelled');
    }
    const token = settings.cancellationToken;
    if (!token) {
      return;
    }
    const raw = token.isCancellationRequested;
    const requested = typeof raw === 'function' ? Boolean(raw.call(token)) : raw === true;
    if (requested) {
      state.stats.cancelled = true;
      throw new InventoryStop('cancelled');
    }
  }

  function checkCapacity() {
    if (state.files.length >= settings.maxFiles) {
      state.stats.truncated = true;
      throw new InventoryStop('truncated');
    }
  }

  /**
   * @param {{
   *   rootIndex: number,
   *   rootPath: string,
   *   dirFsPath: string,
   *   dirUri: object,
   *   relDir: string,
   *   rules: GitIgnoreRules
   * }} context
   */
  async function walkDirectory(context) {
    checkCancellation();
    state.stats.directoriesVisited += 1;

    /** @type {Array<[string, number]>} */
    let entries;
    try {
      entries = await fsApi.readDirectory(context.dirUri);
    } catch (error) {
      throw new RepositoryInventoryError(
        `Unable to read directory ${context.dirFsPath}.`,
        'E_FILESYSTEM',
        { path: context.dirFsPath, cause: error }
      );
    }

    const sorted = entries
      .filter((entry) => Array.isArray(entry) && typeof entry[0] === 'string')
      .map((entry) => /** @type {[string, number]} */ [entry[0], entry[1]])
      .sort((left, right) => compareStrings(left[0], right[0]));
    const entryTypes = new Map(sorted);

    let effectiveRules = context.rules;

    // `.git/info/exclude` has lower precedence than `.gitignore` and is never
    // traversed as part of the excluded `.git` directory.
    if (context.relDir.length === 0) {
      const gitType = entryTypes.get('.git');
      if (
        typeof gitType === 'number' &&
        hasFlag(gitType, FileType.Directory) &&
        !hasFlag(gitType, FileType.SymbolicLink)
      ) {
        const infoUri = childUri(vscode, childUri(vscode, context.dirUri, '.git'), 'info');
        const excludeUri = childUri(vscode, infoUri, 'exclude');
        const excludeStat = await statOrUndefined(fsApi, excludeUri);
        if (excludeStat && hasFlag(excludeStat.type, FileType.File)) {
          const text = await readText(fsApi, excludeUri);
          effectiveRules = effectiveRules.merge(parseGitIgnore(text, { source: 'info-exclude' }));
        }
      }
    }

    const gitignoreType = entryTypes.get('.gitignore');
    if (
      typeof gitignoreType === 'number' &&
      hasFlag(gitignoreType, FileType.File) &&
      !hasFlag(gitignoreType, FileType.SymbolicLink)
    ) {
      const text = await readText(fsApi, childUri(vscode, context.dirUri, '.gitignore'));
      effectiveRules = effectiveRules.merge(
        parseGitIgnore(text, { baseDir: context.relDir, source: 'gitignore' })
      );
    }

    for (const [name, type] of sorted) {
      checkCancellation();
      if (isInvalidEntryName(name)) {
        recordIgnored(path.join(context.dirFsPath, name), IGNORE_REASONS.invalidEntryName);
        continue;
      }

      const fsPath = path.join(context.dirFsPath, name);
      if (!isPathWithinRoot(fsPath, context.rootPath)) {
        recordIgnored(fsPath, IGNORE_REASONS.outsideWorkspace);
        continue;
      }
      if (hasFlag(type, FileType.SymbolicLink)) {
        state.stats.symlinksSkipped += 1;
        recordIgnored(fsPath, IGNORE_REASONS.symbolicLink);
        continue;
      }

      const isDirectory = hasFlag(type, FileType.Directory);
      const isFile = hasFlag(type, FileType.File);
      if (!isDirectory && !isFile) {
        recordIgnored(fsPath, IGNORE_REASONS.unsupportedFileType);
        continue;
      }

      const relativePath = joinRelative(context.relDir, name);
      if (isDirectory && DEFAULT_EXCLUDED_DIRECTORY_NAMES.has(name)) {
        recordIgnored(fsPath, IGNORE_REASONS.defaultExcludedDirectory);
        continue;
      }
      if (
        isPathExcluded(relativePath, settings.excludeGlobs) ||
        (isDirectory && isPathExcluded(`${relativePath}/`, settings.excludeGlobs))
      ) {
        recordIgnored(fsPath, IGNORE_REASONS.userGlob);
        continue;
      }
      const decision = effectiveRules.decide(relativePath, isDirectory);
      if (decision?.ignored) {
        recordIgnored(
          fsPath,
          decision.source === 'info-exclude' ? IGNORE_REASONS.infoExclude : IGNORE_REASONS.gitignore
        );
        continue;
      }

      const entryUri = childUri(vscode, context.dirUri, name);
      if (isDirectory) {
        await walkDirectory({
          ...context,
          dirFsPath: fsPath,
          dirUri: entryUri,
          relDir: relativePath,
          rules: effectiveRules
        });
        continue;
      }

      state.stats.filesVisited += 1;
      checkCapacity();
      if (isBinaryPath(fsPath)) {
        excludeFile(fsPath, IGNORE_REASONS.binaryFile);
        continue;
      }
      if (isGeneratedPath(fsPath)) {
        excludeFile(fsPath, IGNORE_REASONS.generatedFile);
        continue;
      }
      const fileStat = await statOrUndefined(fsApi, entryUri);
      const sizeBytes = fileStat && Number.isFinite(fileStat.size) ? fileStat.size : 0;
      if (sizeBytes > settings.maxFileBytes) {
        excludeFile(fsPath, IGNORE_REASONS.fileTooLarge);
        continue;
      }
      const language = languageForPath(fsPath);
      if (!language) {
        excludeFile(fsPath, IGNORE_REASONS.unknownLanguage);
        continue;
      }
      if (state.seenFiles.has(fsPath)) {
        excludeFile(fsPath, IGNORE_REASONS.duplicateFile);
        continue;
      }

      state.files.push({
        uriText: uriTextOf(entryUri),
        fsPath,
        relativePath,
        language,
        sizeBytes,
        rootIndex: context.rootIndex
      });
      state.seenFiles.add(fsPath);
      state.languages.set(language, (state.languages.get(language) ?? 0) + 1);
      state.stats.filesIncluded += 1;
    }
  }

  try {
    for (let rootIndex = 0; rootIndex < internalFolders.length; rootIndex += 1) {
      checkCancellation();
      const folder = internalFolders[rootIndex];
      const rootStat = await statOrThrow(fsApi, folder.uri, folder.path);
      if (hasFlag(rootStat.type, FileType.SymbolicLink)) {
        throw new RepositoryInventoryError(
          `Workspace root ${folder.path} is a symbolic link and is not followed.`,
          'E_UNSUPPORTED_ROOT',
          { path: folder.path }
        );
      }
      if (!hasFlag(rootStat.type, FileType.Directory)) {
        throw new RepositoryInventoryError(
          `Workspace root ${folder.path} is not a directory.`,
          'E_UNSUPPORTED_ROOT',
          { path: folder.path }
        );
      }
      await walkDirectory({
        rootIndex,
        rootPath: folder.path,
        dirFsPath: folder.path,
        dirUri: folder.uri,
        relDir: '',
        rules: new GitIgnoreRules()
      });
    }
  } catch (error) {
    if (!(error instanceof InventoryStop)) {
      throw error;
    }
  }

  state.files.sort(
    (left, right) =>
      left.rootIndex - right.rootIndex || compareStrings(left.relativePath, right.relativePath)
  );
  state.ignored.sort(
    (left, right) =>
      compareStrings(left.fsPath, right.fsPath) || compareStrings(left.reason, right.reason)
  );

  /** @type {Record<string, number>} */
  const languages = {};
  for (const language of [...state.languages.keys()].sort(compareStrings)) {
    languages[language] = state.languages.get(language);
  }

  return {
    folders: internalFolders.map(({ name, path: fsPath, uriText }) => ({
      name,
      path: fsPath,
      uriText
    })),
    files: state.files,
    ignored: state.ignored,
    languages,
    stats: { ...state.stats }
  };
}

module.exports = {
  DEFAULT_EXCLUDED_DIRECTORY_NAMES,
  DEFAULT_MAX_FILES,
  IGNORE_REASONS,
  RepositoryInventoryError,
  buildWorkspaceFolderMetadata,
  discoverRepositoryInventory
};
