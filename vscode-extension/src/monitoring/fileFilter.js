'use strict';

/**
 * Pure eligibility rules for workspace monitoring.
 *
 * This module never imports `vscode` and never reads a file. It exists so the
 * rules that keep monitoring bounded and safe can be tested with plain Node.
 * Nothing here inspects or records who wrote a file.
 */

const path = require('node:path');

const {
  isPathExcluded,
  isSupportedLanguage,
  normalizeLanguage,
  normalizeLanguageList
} = require('./changeAnalyzer');
const { isRealPathWithinRoot } = require('../security/paths');

/** Extensions treated as non-source by default. */
const BINARY_EXTENSIONS = Object.freeze(
  new Set([
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.bmp',
    '.ico',
    '.webp',
    '.avif',
    '.pdf',
    '.zip',
    '.gz',
    '.tgz',
    '.bz2',
    '.xz',
    '.7z',
    '.rar',
    '.tar',
    '.mp3',
    '.mp4',
    '.avi',
    '.mov',
    '.wav',
    '.ogg',
    '.woff',
    '.woff2',
    '.ttf',
    '.eot',
    '.wasm',
    '.exe',
    '.dll',
    '.so',
    '.dylib',
    '.class',
    '.jar',
    '.pyc',
    '.pyo',
    '.pyd',
    '.node',
    '.o',
    '.a',
    '.db',
    '.sqlite',
    '.sqlite3'
  ])
);

/** Generated or vendored artifacts that should not be re-analyzed on change. */
const GENERATED_FILE_PATTERNS = Object.freeze([
  /\.min\.(?:js|css)$/i,
  /\.bundle\.(?:js|css)$/i,
  /\.generated\.[A-Za-z0-9]+$/i,
  /\.g\.[cm]?[jt]s$/i,
  /\.map$/i,
  /(?:^|[.-])lock(?:\.json|\.yaml|\.yml)?$/i,
  /^package-lock\.json$/i,
  /^yarn\.lock$/i,
  /^pnpm-lock\.yaml$/i,
  /^poetry\.lock$/i,
  /^Pipfile\.lock$/i,
  /^Gemfile\.lock$/i,
  /^composer\.lock$/i,
  /^Cargo\.lock$/i
]);

/** Conservative extension-to-language mapping used when no languageId is known. */
const EXTENSION_LANGUAGES = Object.freeze({
  '.py': 'python',
  '.pyw': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.java': 'java',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.php': 'php',
  '.c': 'c',
  '.cc': 'cpp',
  '.cpp': 'cpp',
  '.cxx': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.scala': 'scala',
  '.sh': 'shellscript',
  '.bash': 'shellscript',
  '.zsh': 'shellscript',
  '.ps1': 'powershell',
  '.sql': 'sql',
  '.html': 'html',
  '.htm': 'html',
  '.css': 'css',
  '.scss': 'scss',
  '.vue': 'vue',
  '.svelte': 'svelte',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.toml': 'toml',
  '.json': 'json'
});

/** @param {unknown} fsPath @returns {string} */
function extensionOf(fsPath) {
  if (typeof fsPath !== 'string') {
    return '';
  }
  const base = path.basename(fsPath).toLowerCase();
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot) : '';
}

/** @param {unknown} fsPath @returns {boolean} */
function isBinaryPath(fsPath) {
  if (typeof fsPath !== 'string' || fsPath.length === 0) {
    return false;
  }
  return BINARY_EXTENSIONS.has(extensionOf(fsPath));
}

/** @param {unknown} fsPath @returns {boolean} */
function isGeneratedPath(fsPath) {
  if (typeof fsPath !== 'string' || fsPath.length === 0) {
    return false;
  }
  const base = path.basename(fsPath);
  return GENERATED_FILE_PATTERNS.some((pattern) => pattern.test(base));
}

/**
 * Infer a language id from a path. Returns undefined for unknown extensions.
 *
 * @param {unknown} fsPath
 * @returns {string | undefined}
 */
function languageForPath(fsPath) {
  return EXTENSION_LANGUAGES[extensionOf(fsPath)];
}

/**
 * @param {unknown} fsPath
 * @param {ReadonlyArray<{ uri?: { scheme?: string, fsPath?: string } }>} folders
 * @returns {boolean}
 */
function isWithinWorkspace(fsPath, folders) {
  if (typeof fsPath !== 'string' || fsPath.length === 0 || !Array.isArray(folders)) {
    return false;
  }
  return folders.some(
    (folder) =>
      folder?.uri?.scheme === 'file' &&
      typeof folder.uri.fsPath === 'string' &&
      isRealPathWithinRoot(fsPath, folder.uri.fsPath)
  );
}

/**
 * Decide whether a path may be monitored. The result never depends on an AI
 * provider identity and never attributes an edit to a model or a person.
 *
 * @param {{
 *   fsPath: unknown,
 *   languageId?: unknown,
 *   sizeBytes?: unknown,
 *   settings: object,
 *   workspaceFolders?: ReadonlyArray<{ uri?: { scheme?: string, fsPath?: string } }>,
 *   requireWorkspace?: boolean
 * }} input
 * @returns {{ eligible: boolean, reason?: string }}
 */
function evaluateFileEligibility(input) {
  const settings = input?.settings ?? {};
  const fsPath = input?.fsPath;
  if (typeof fsPath !== 'string' || fsPath.length === 0) {
    return { eligible: false, reason: 'invalid-path' };
  }
  if (input.requireWorkspace !== false) {
    if (!isWithinWorkspace(fsPath, input.workspaceFolders ?? [])) {
      return { eligible: false, reason: 'outside-workspace' };
    }
  }
  if (isPathExcluded(fsPath, settings.excludeGlobs)) {
    return { eligible: false, reason: 'excluded-path' };
  }
  if (settings.excludeBinaryFiles !== false && isBinaryPath(fsPath)) {
    return { eligible: false, reason: 'binary-file' };
  }
  if (settings.excludeGeneratedFiles !== false && isGeneratedPath(fsPath)) {
    return { eligible: false, reason: 'generated-file' };
  }
  if (Number.isFinite(input.sizeBytes) && input.sizeBytes > settings.maxFileBytes) {
    return { eligible: false, reason: 'file-too-large' };
  }

  const language =
    typeof input.languageId === 'string' && input.languageId.length > 0
      ? normalizeLanguage(input.languageId)
      : languageForPath(fsPath);
  if (!language || !isSupportedLanguage(language, normalizeLanguageList(settings.languages))) {
    return { eligible: false, reason: 'unsupported-language' };
  }
  return { eligible: true };
}

module.exports = {
  BINARY_EXTENSIONS,
  GENERATED_FILE_PATTERNS,
  EXTENSION_LANGUAGES,
  extensionOf,
  isBinaryPath,
  isGeneratedPath,
  languageForPath,
  isWithinWorkspace,
  evaluateFileEligibility
};
