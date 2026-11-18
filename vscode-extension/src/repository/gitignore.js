'use strict';

/**
 * Pure `.gitignore` parsing and matching for repository inventory.
 *
 * No `vscode` import and no filesystem access happen here. The module consumes
 * text that the caller has already read and evaluates paths relative to a
 * workspace root. It supports comments, escaped `#`/`!`, negation, anchored
 * leading `/`, directory-only trailing `/`, and `**`, `*`, and `?` wildcards.
 */

const { globToRegExp } = require('../monitoring/changeAnalyzer');

/** Escaped `*` and `?` are protected from `globToRegExp` with private tokens. */
const ESCAPED_STAR = '\u0001';
const ESCAPED_QUESTION = '\u0002';

/** @param {unknown} value @returns {string} */
function toPosix(value) {
  return typeof value === 'string' ? value.replace(/\\/g, '/') : '';
}

/**
 * Remove trailing whitespace unless it is escaped by an odd number of slashes.
 *
 * @param {string} line
 * @returns {string}
 */
function trimUnescapedTrailing(line) {
  let end = line.length;
  while (end > 0 && (line[end - 1] === ' ' || line[end - 1] === '\t')) {
    let slashes = 0;
    for (let index = end - 2; index >= 0 && line[index] === '\\'; index -= 1) {
      slashes += 1;
    }
    if (slashes % 2 === 1) {
      break;
    }
    end -= 1;
  }
  return line.slice(0, end);
}

/** @param {string} pattern @returns {string} */
function protectEscapes(pattern) {
  return pattern.replace(/\\(.)/g, (_, character) => {
    if (character === '*') {
      return ESCAPED_STAR;
    }
    if (character === '?') {
      return ESCAPED_QUESTION;
    }
    return character;
  });
}

/** @param {string} value @returns {string} */
function protectValue(value) {
  return value.replace(/[*?]/g, (character) =>
    character === '*' ? ESCAPED_STAR : ESCAPED_QUESTION
  );
}

/**
 * Match one gitignore path segment with the shared glob helper.
 *
 * @param {string} patternSegment
 * @param {string} valueSegment
 * @returns {boolean}
 */
function segmentMatches(patternSegment, valueSegment) {
  return globToRegExp(protectEscapes(patternSegment)).test(protectValue(valueSegment));
}

/**
 * Match a sequence of path segments. `**` consumes zero or more whole segments.
 *
 * @param {string[]} patternSegments
 * @param {string[]} pathSegments
 * @returns {boolean}
 */
function matchPathSegments(patternSegments, pathSegments) {
  /** @type {Set<string>} */
  const seen = new Set();

  /** @param {number} patternIndex @param {number} pathIndex @returns {boolean} */
  function visit(patternIndex, pathIndex) {
    const key = `${patternIndex}:${pathIndex}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);

    if (patternIndex === patternSegments.length) {
      return pathIndex === pathSegments.length;
    }
    const patternSegment = patternSegments[patternIndex];
    if (patternSegment === '**') {
      if (visit(patternIndex + 1, pathIndex)) {
        return true;
      }
      return pathIndex < pathSegments.length && visit(patternIndex, pathIndex + 1);
    }
    if (pathIndex >= pathSegments.length) {
      return false;
    }
    if (!segmentMatches(patternSegment, pathSegments[pathIndex])) {
      return false;
    }
    return visit(patternIndex + 1, pathIndex + 1);
  }

  return visit(0, 0);
}

/**
 * @param {string} line
 * @param {string} baseDir
 * @param {'gitignore' | 'info-exclude'} source
 * @returns {object | undefined}
 */
function parseRule(line, baseDir, source) {
  let text = trimUnescapedTrailing(line);
  if (text.length === 0 || text.startsWith('#')) {
    return undefined;
  }

  let negated = false;
  if (text.startsWith('!')) {
    negated = true;
    text = text.slice(1);
  } else if (text.startsWith('\\!')) {
    text = text.slice(1);
  }
  if (text.startsWith('\\#')) {
    text = text.slice(1);
  }

  let dirOnly = false;
  if (text.endsWith('/')) {
    dirOnly = true;
    text = text.slice(0, -1);
  }
  let anchored = false;
  if (text.startsWith('/')) {
    anchored = true;
    text = text.slice(1);
  }

  // Non-glob escapes are literal characters.
  text = text.replace(/\\([!# ])/g, '$1');
  const normalized = toPosix(text).replace(/^\/+|\/+$/g, '');
  if (normalized.length === 0) {
    return undefined;
  }

  const baseSegments = toPosix(baseDir).split('/').filter(Boolean);
  const patternSegments = normalized.split('/').filter(Boolean);
  const basenameOnly = !anchored && patternSegments.length === 1;

  return {
    source,
    negated,
    dirOnly,
    basenameOnly,
    baseSegments,
    patternSegments,
    matchSegments: basenameOnly ? patternSegments : [...baseSegments, ...patternSegments]
  };
}

/**
 * @param {object} rule
 * @param {string[]} pathSegments
 * @param {boolean} isDirectory
 * @returns {boolean}
 */
function ruleMatches(rule, pathSegments, isDirectory) {
  if (rule.dirOnly && !isDirectory) {
    return false;
  }
  if (rule.basenameOnly) {
    if (pathSegments.length <= rule.baseSegments.length) {
      return false;
    }
    for (let index = 0; index < rule.baseSegments.length; index += 1) {
      if (pathSegments[index] !== rule.baseSegments[index]) {
        return false;
      }
    }
    return segmentMatches(rule.patternSegments[0], pathSegments[pathSegments.length - 1]);
  }
  return matchPathSegments(rule.matchSegments, pathSegments);
}

/** Ordered gitignore rules. Later rules, including negations, win. */
class GitIgnoreRules {
  /** @param {object[]} [rules] */
  constructor(rules = []) {
    this.rules = Array.isArray(rules) ? rules.map((rule) => ({ ...rule })) : [];
  }

  /**
   * @param {string} text
   * @param {{ baseDir?: string, source?: 'gitignore' | 'info-exclude' } | string} [options]
   * @returns {GitIgnoreRules}
   */
  static fromText(text, options = {}) {
    const baseDir = typeof options === 'string' ? options : (options.baseDir ?? '');
    const source = typeof options === 'string' ? 'gitignore' : (options.source ?? 'gitignore');
    /** @type {object[]} */
    const rules = [];
    const lines = String(text ?? '')
      .replace(/^\uFEFF/, '')
      .split(/\r?\n/);
    for (const line of lines) {
      const rule = parseRule(line, toPosix(baseDir), source);
      if (rule) {
        rules.push(rule);
      }
    }
    return new GitIgnoreRules(rules);
  }

  /** @param {GitIgnoreRules} other @returns {GitIgnoreRules} */
  merge(other) {
    return new GitIgnoreRules([...this.rules, ...(other?.rules ?? [])]);
  }

  /**
   * Evaluate a workspace-relative path. When the path is a file, ancestor
   * directories are also tested so directory patterns still apply. Negation
   * cannot re-include a descendant of a directory that the caller skipped; the
   * caller enforces that by not traversing excluded directories.
   *
   * @param {string} relativePath
   * @param {boolean} [isDirectory]
   * @returns {{ ignored: boolean, source: 'gitignore' | 'info-exclude' } | undefined}
   */
  decide(relativePath, isDirectory = false) {
    const normalized = toPosix(relativePath).replace(/^\/+/, '').replace(/\/+$/, '');
    if (normalized.length === 0) {
      return undefined;
    }
    const segments = normalized.split('/');
    /** @type {{ ignored: boolean, source: 'gitignore' | 'info-exclude' } | undefined} */
    let result;

    for (const rule of this.rules) {
      if (ruleMatches(rule, segments, isDirectory)) {
        result = { ignored: !rule.negated, source: rule.source };
        continue;
      }
      if (!isDirectory && segments.length > 1) {
        for (let index = 1; index < segments.length; index += 1) {
          if (ruleMatches(rule, segments.slice(0, index), true)) {
            result = { ignored: !rule.negated, source: rule.source };
            break;
          }
        }
      }
    }
    return result;
  }

  /** @param {string} relativePath @param {boolean} [isDirectory] @returns {boolean} */
  isIgnored(relativePath, isDirectory = false) {
    return this.decide(relativePath, isDirectory)?.ignored === true;
  }
}

/**
 * Parse one gitignore file into an ordered rule set.
 *
 * @param {string} text
 * @param {{ baseDir?: string, source?: 'gitignore' | 'info-exclude' } | string} [options]
 * @returns {GitIgnoreRules}
 */
function parseGitIgnore(text, options = {}) {
  return GitIgnoreRules.fromText(text, options);
}

module.exports = { GitIgnoreRules, parseGitIgnore };
