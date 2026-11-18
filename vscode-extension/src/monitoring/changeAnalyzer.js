'use strict';

/**
 * Pure helpers for real-time change analysis.
 *
 * This module has no `vscode` import so its range, language, and scoping rules
 * can be unit tested with plain Node. It performs lexical, bounded work only:
 * it never decides whether code is vulnerable and never infers who or what
 * produced an edit. Editor events are treated as ordinary document changes
 * regardless of their origin.
 */

const DEFAULT_SUPPORTED_LANGUAGES = Object.freeze(['python', 'javascript']);
const DEFAULT_EXCLUDE_GLOBS = Object.freeze([
  '**/node_modules/**',
  '**/.git/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/dist/**',
  '**/out/**',
  '**/build/**',
  '**/.bugdhor-data/**'
]);

const LANGUAGE_ALIASES = Object.freeze({
  py: 'python',
  python: 'python',
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  javascript: 'javascript',
  javascriptreact: 'javascript'
});

const ANALYSIS_SCOPES = Object.freeze(['changedLines', 'function', 'file']);
const MAX_FUNCTION_LINES = 400;
const MAX_FUNCTIONS = 20;
const MAX_ABSOLUTE_LINES = 20_000;

/**
 * @param {unknown} value
 * @returns {string | undefined}
 */
function normalizeLanguage(value) {
  if (typeof value !== 'string') {
    return undefined;
  }
  const key = value.trim().toLowerCase();
  return LANGUAGE_ALIASES[key] ?? (key.length > 0 ? key : undefined);
}

/**
 * @param {unknown} configuredLanguages
 * @returns {string[]}
 */
function normalizeLanguageList(configuredLanguages) {
  const values = Array.isArray(configuredLanguages)
    ? configuredLanguages
    : DEFAULT_SUPPORTED_LANGUAGES;
  /** @type {string[]} */
  const result = [];
  for (const value of values) {
    const language = normalizeLanguage(value);
    if (language && !result.includes(language)) {
      result.push(language);
    }
  }
  return result.length > 0 ? result : [...DEFAULT_SUPPORTED_LANGUAGES];
}

/**
 * @param {unknown} languageId
 * @param {unknown} configuredLanguages
 * @returns {boolean}
 */
function isSupportedLanguage(languageId, configuredLanguages) {
  const language = normalizeLanguage(languageId);
  if (!language) {
    return false;
  }
  return normalizeLanguageList(configuredLanguages).includes(language);
}

/**
 * Translate a small, explicit glob syntax into a regular expression. This is
 * intentionally dependency-free; only `*`, `**`, and `?` are special.
 *
 * @param {string} glob
 * @returns {RegExp}
 */
function globToRegExp(glob) {
  let source = '';
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === '*') {
      if (glob[index + 1] === '*') {
        source += '.*';
        index += 1;
        if (glob[index + 1] === '/') {
          index += 1;
        }
      } else {
        source += '[^/]*';
      }
    } else if (character === '?') {
      source += '[^/]';
    } else if (character === '/') {
      source += '/';
    } else {
      source += character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${source}$`, 'i');
}

/**
 * @param {unknown} fsPath
 * @param {unknown} globs
 * @returns {boolean}
 */
function isPathExcluded(fsPath, globs) {
  if (typeof fsPath !== 'string' || fsPath.length === 0) {
    return false;
  }
  const normalized = fsPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const patterns = Array.isArray(globs) ? globs : DEFAULT_EXCLUDE_GLOBS;
  return patterns.some((pattern) => {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      return false;
    }
    const normalizedPattern = pattern.replace(/\\/g, '/').replace(/^\/+/, '');
    try {
      return globToRegExp(normalizedPattern).test(normalized);
    } catch {
      return false;
    }
  });
}

/**
 * Convert one editor content change into a half-open, zero-based line range.
 * `endLine` counts lines replaced by the edit plus lines introduced by the new
 * text, so both single-line edits and multi-line insertions are covered.
 *
 * @param {{ text?: unknown, range?: { start?: { line?: unknown }, end?: { line?: unknown } } }} change
 * @param {number} fallbackLineCount
 * @returns {{ startLine: number, endLine: number }}
 */
function rangeFromContentChange(change, fallbackLineCount) {
  const text = typeof change?.text === 'string' ? change.text : '';
  const newLineCount = (text.match(/\n/g) ?? []).length;
  const startLineValue = change?.range?.start?.line;
  const endLineValue = change?.range?.end?.line;
  const startLine = Number.isInteger(startLineValue) ? Math.max(0, startLineValue) : 0;
  const replacedEnd = Number.isInteger(endLineValue)
    ? Math.max(startLine, endLineValue)
    : startLine;
  const maximum = Math.max(1, Number.isInteger(fallbackLineCount) ? fallbackLineCount : 1);
  const endLine = Math.min(maximum, Math.max(startLine + 1, replacedEnd + newLineCount + 1));
  return { startLine, endLine: Math.max(startLine + 1, endLine) };
}

/**
 * Return true when an edit is a multi-line or large insertion. This is a
 * description of the edit shape only. It does not identify an AI model, an AI
 * assistant, or any other author of the change.
 *
 * @param {unknown} change
 * @returns {boolean}
 */
function isBulkInsert(change) {
  if (!change || typeof change !== 'object') {
    return false;
  }
  const text = typeof change.text === 'string' ? change.text : '';
  const newLineCount = (text.match(/\n/g) ?? []).length;
  return newLineCount >= 2 || text.length >= 64;
}

/**
 * Merge overlapping and adjacent half-open line ranges.
 *
 * @param {Array<{ startLine: number, endLine: number }>} ranges
 * @returns {Array<{ startLine: number, endLine: number }>}
 */
function mergeRanges(ranges) {
  const sorted = ranges
    .filter(
      (range) =>
        Number.isInteger(range?.startLine) &&
        Number.isInteger(range?.endLine) &&
        range.endLine > range.startLine
    )
    .map((range) => ({ startLine: range.startLine, endLine: range.endLine }))
    .sort((left, right) => left.startLine - right.startLine || left.endLine - right.endLine);

  /** @type {Array<{ startLine: number, endLine: number }>} */
  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.startLine <= last.endLine) {
      last.endLine = Math.max(last.endLine, range.endLine);
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

/**
 * @param {string} line
 * @returns {number}
 */
function indentationOf(line) {
  const match = /^[\t ]*/.exec(line);
  if (!match) {
    return 0;
  }
  return match[0].replace(/\t/g, '    ').length;
}

/**
 * Find Python function spans using indentation and `def` markers.
 *
 * @param {string[]} lines
 * @returns {Array<{ startLine: number, endLine: number, name: string }>}
 */
function findPythonFunctions(lines) {
  /** @type {Array<{ startLine: number, endLine: number, name: string }>} */
  const functions = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(lines[index]);
    if (!match) {
      continue;
    }
    const indent = indentationOf(lines[index]);
    let startLine = index;
    while (startLine > 0 && /^\s*@/.test(lines[startLine - 1])) {
      startLine -= 1;
    }

    let endLine = index + 1;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor];
      if (line.trim().length === 0) {
        endLine = cursor + 1;
        continue;
      }
      if (indentationOf(line) <= indent) {
        break;
      }
      endLine = cursor + 1;
      if (endLine - startLine >= MAX_FUNCTION_LINES) {
        break;
      }
    }
    while (endLine > index + 1 && lines[endLine - 1].trim().length === 0) {
      endLine -= 1;
    }
    functions.push({ startLine, endLine, name: match[2] });
  }
  return functions;
}

/**
 * @param {string[]} lines
 * @param {number} startLine
 * @returns {{ line: number, character: number } | undefined}
 */
function findOpeningBrace(lines, startLine) {
  for (let line = startLine; line < Math.min(lines.length, startLine + 4); line += 1) {
    const index = lines[line].indexOf('{');
    if (index >= 0) {
      return { line, character: index };
    }
    if (lines[line].trim().length > 0 && !lines[line].trim().endsWith(';')) {
      continue;
    }
  }
  return undefined;
}

/**
 * Walk braces from an opening position, skipping simple strings/comments.
 *
 * @param {string[]} lines
 * @param {{ line: number, character: number }} opening
 * @returns {number}
 */
function findClosingBraceLine(lines, opening) {
  let depth = 0;
  let quote;
  let lineComment = false;
  let blockComment = false;

  for (let lineIndex = opening.line; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    lineComment = false;
    for (
      let index = opening.line === lineIndex ? opening.character : 0;
      index < line.length;
      index += 1
    ) {
      const character = line[index];
      const next = line[index + 1];

      if (lineComment) {
        if (character === '\n') {
          lineComment = false;
        }
        continue;
      }
      if (blockComment) {
        if (character === '*' && next === '/') {
          blockComment = false;
          index += 1;
        }
        continue;
      }
      if (quote) {
        if (character === '\\') {
          index += 1;
          continue;
        }
        if (character === quote) {
          quote = undefined;
        }
        continue;
      }
      if (character === '/' && next === '/') {
        lineComment = true;
        index += 1;
        continue;
      }
      if (character === '/' && next === '*') {
        blockComment = true;
        index += 1;
        continue;
      }
      if (character === '"' || character === "'" || character === '`') {
        quote = character;
        continue;
      }
      if (character === '{') {
        depth += 1;
      } else if (character === '}') {
        depth -= 1;
        if (depth === 0) {
          return lineIndex + 1;
        }
      }
    }
    if (lineIndex - opening.line >= MAX_FUNCTION_LINES) {
      return Math.min(lines.length, opening.line + MAX_FUNCTION_LINES);
    }
  }
  return lines.length;
}

/**
 * Find JavaScript function-like spans using a bounded lexical scan.
 *
 * @param {string[]} lines
 * @returns {Array<{ startLine: number, endLine: number, name: string }>}
 */
function findJavaScriptFunctions(lines) {
  /** @type {Array<{ startLine: number, endLine: number, name: string }>} */
  const functions = [];
  const patterns = [
    /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/,
    /\b([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/,
    /^\s*(?:async\s+)?(?:get\s+|set\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/
  ];

  for (let index = 0; index < lines.length; index += 1) {
    let name;
    for (const pattern of patterns) {
      const match = pattern.exec(lines[index]);
      if (match) {
        name = match[1];
        break;
      }
    }
    if (!name) {
      continue;
    }
    const opening = findOpeningBrace(lines, index);
    if (!opening) {
      continue;
    }
    const endLine = findClosingBraceLine(lines, opening);
    functions.push({ startLine: index, endLine, name });
    index = Math.max(index, endLine - 1);
  }
  return functions;
}

/**
 * Select the function spans that contain the changed lines. Uncovered changed
 * lines are returned as plain ranges so top-level edits are still analyzed.
 *
 * @param {string} text
 * @param {unknown} languageId
 * @param {Array<{ startLine: number, endLine: number }>} changedRanges
 * @param {{ maxFunctions?: number }} [options]
 * @returns {Array<{ startLine: number, endLine: number, name?: string }>}
 */
function findFunctionRanges(text, languageId, changedRanges, options = {}) {
  const lines = text.split('\n');
  const language = normalizeLanguage(languageId);
  const functions =
    language === 'python'
      ? findPythonFunctions(lines)
      : language === 'javascript'
        ? findJavaScriptFunctions(lines)
        : [];
  const maxFunctions = Number.isInteger(options.maxFunctions)
    ? options.maxFunctions
    : MAX_FUNCTIONS;

  /** @type {Array<{ startLine: number, endLine: number, name?: string }>} */
  const selected = [];
  /** @type {Array<{ startLine: number, endLine: number }>} */
  const uncovered = [];

  for (const changed of changedRanges) {
    const covering = functions.filter(
      (fn) => fn.startLine <= changed.startLine && fn.endLine >= changed.endLine - 1
    );
    if (covering.length === 0) {
      uncovered.push(changed);
      continue;
    }
    for (const fn of covering) {
      if (
        !selected.some((entry) => entry.startLine === fn.startLine && entry.endLine === fn.endLine)
      ) {
        selected.push({ startLine: fn.startLine, endLine: fn.endLine, name: fn.name });
      }
    }
  }

  const combined = [...selected, ...mergeRanges(uncovered)];
  combined.sort((left, right) => left.startLine - right.startLine);
  return combined.slice(0, Math.max(1, maxFunctions));
}

/**
 * Build one bounded analysis target for a batch of document changes.
 *
 * @param {{
 *   text: string,
 *   lineCount?: number,
 *   languageId?: unknown,
 *   ranges: Array<{ startLine: number, endLine: number }>,
 *   settings: { analysisScope?: unknown, maxChangedLines?: number, maxFileBytes?: number },
 *   reason?: string
 * }} input
 * @returns {{
 *   kind: 'changedLines' | 'function' | 'file',
 *   selection: { start: { line: number, character: number }, end: { line: number, character: number } },
 *   startLine: number,
 *   endLine: number,
 *   changedLines: number,
 *   wideChange: boolean,
 *   reason: string | undefined
 * } | undefined}
 */
function buildAnalysisPlan(input) {
  const text = typeof input?.text === 'string' ? input.text : '';
  const lines = text.split('\n');
  const totalLines = Math.max(
    1,
    Number.isInteger(input.lineCount) ? input.lineCount : lines.length
  );
  const changedRanges = mergeRanges(Array.isArray(input.ranges) ? input.ranges : []);
  const ranges = changedRanges.length > 0 ? changedRanges : [{ startLine: 0, endLine: totalLines }];
  const changedLines = ranges.reduce((sum, range) => sum + (range.endLine - range.startLine), 0);
  const maxChangedLines =
    Number.isInteger(input.settings?.maxChangedLines) && input.settings.maxChangedLines > 0
      ? input.settings.maxChangedLines
      : 500;
  const wideChange = changedLines > maxChangedLines;
  const scope = ANALYSIS_SCOPES.includes(input.settings?.analysisScope)
    ? input.settings.analysisScope
    : 'function';

  /** @type {Array<{ startLine: number, endLine: number }>} */
  let targets;
  let kind;
  if (scope === 'file' || wideChange) {
    targets = [{ startLine: 0, endLine: totalLines }];
    kind = 'file';
  } else if (scope === 'function') {
    const functions = findFunctionRanges(text, input.languageId, ranges);
    targets = functions;
    kind = functions.length > 0 ? 'function' : 'changedLines';
  } else {
    targets = ranges;
    kind = 'changedLines';
  }

  let startLine = Math.max(
    0,
    Math.min(totalLines - 1, Math.min(...targets.map((r) => r.startLine)))
  );
  let endLine = Math.max(startLine + 1, Math.max(...targets.map((r) => r.endLine)));
  endLine = Math.min(totalLines, endLine);
  if (endLine <= startLine) {
    endLine = Math.min(totalLines, startLine + 1);
  }

  return {
    kind,
    selection: {
      start: { line: startLine, character: 0 },
      end: { line: endLine - 1, character: lines[endLine - 1]?.length ?? 0 }
    },
    startLine,
    endLine,
    changedLines,
    wideChange,
    reason: input.reason
  };
}

/**
 * Extract the exact text covered by a plan's selection.
 *
 * @param {string} text
 * @param {{ startLine: number, endLine: number }} plan
 * @returns {string}
 */
function textForPlan(text, plan) {
  return text.split('\n').slice(plan.startLine, plan.endLine).join('\n');
}

module.exports = {
  DEFAULT_SUPPORTED_LANGUAGES,
  DEFAULT_EXCLUDE_GLOBS,
  ANALYSIS_SCOPES,
  MAX_ABSOLUTE_LINES,
  LANGUAGE_ALIASES,
  normalizeLanguage,
  normalizeLanguageList,
  isSupportedLanguage,
  globToRegExp,
  isPathExcluded,
  rangeFromContentChange,
  isBulkInsert,
  mergeRanges,
  findFunctionRanges,
  findPythonFunctions,
  findJavaScriptFunctions,
  buildAnalysisPlan,
  textForPlan
};
