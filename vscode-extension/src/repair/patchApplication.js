'use strict';

const path = require('node:path');

const HUNK_PATTERN = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

function normalizePatchPath(rawPath) {
  const value = String(rawPath || '').trim();
  if (!value || value === '/dev/null') {
    return value || '/dev/null';
  }
  if (value.includes('\0')) {
    throw new Error('The repair contains an invalid path.');
  }
  const normalized = path.posix.normalize(value.replace(/\\/g, '/'));
  if (
    normalized === '..' ||
    normalized.startsWith('../') ||
    normalized.startsWith('/') ||
    /^[A-Za-z]:\//.test(normalized)
  ) {
    throw new Error('The repair path escapes the target file scope.');
  }
  return normalized;
}

/**
 * Apply a single-file unified diff without invoking a shell or mutating the
 * source document. The caller performs the final WorkspaceEdit.
 *
 * @param {string} source
 * @param {string} patch
 * @returns {string}
 */
function applyUnifiedPatch(source, patch) {
  const normalizedPatch = String(patch).replace(/\r\n/g, '\n').trimEnd();
  if (normalizedPatch.length === 0) {
    throw new Error('The repair patch is empty.');
  }
  const lines = normalizedPatch.split('\n');
  const header = lines.findIndex((line) => line.startsWith('+++ '));
  if (header < 1 || !lines[header - 1].startsWith('--- ')) {
    throw new Error('The repair is not a valid unified diff.');
  }
  // Validate paths early to reject traversal/device-like or multi-scope surprises.
  patchFiles(normalizedPatch);

  const original = source.split('\n');
  const output = [];
  let cursor = 0;
  let index = header + 1;
  let sawHunk = false;
  while (index < lines.length) {
    if (!lines[index].startsWith('@@ ')) {
      index += 1;
      continue;
    }
    sawHunk = true;
    const match = HUNK_PATTERN.exec(lines[index]);
    if (!match) {
      throw new Error('The repair contains a malformed diff hunk.');
    }
    const start = Number(match[1]) - 1;
    if (start < cursor || start > original.length) {
      throw new Error('The repair hunk is outside the current document.');
    }
    output.push(...original.slice(cursor, start));
    cursor = start;
    index += 1;
    while (index < lines.length && !lines[index].startsWith('@@ ')) {
      const line = lines[index];
      if (line.startsWith(' ')) {
        if (original[cursor] !== line.slice(1)) {
          throw new Error('The repair context does not match the current document.');
        }
        output.push(original[cursor]);
        cursor += 1;
      } else if (line.startsWith('-')) {
        if (original[cursor] !== line.slice(1)) {
          throw new Error('The repair deletion does not match the current document.');
        }
        cursor += 1;
      } else if (line.startsWith('+')) {
        output.push(line.slice(1));
      } else if (line === '\\ No newline at end of file') {
        // informational marker
      } else if (
        line.startsWith('--- ') ||
        line.startsWith('+++ ') ||
        line.startsWith('diff ') ||
        line.startsWith('index ') ||
        line.startsWith('@@ ')
      ) {
        break;
      } else {
        throw new Error('The repair contains an invalid diff line.');
      }
      index += 1;
    }
  }
  if (!sawHunk) {
    throw new Error('The repair contains no applicable diff hunks.');
  }
  output.push(...original.slice(cursor));
  return output.join('\n');
}

/**
 * @param {string} patch
 * @returns {string[]}
 */
function patchFiles(patch) {
  return [
    ...new Set(
      patch
        .split(/\r?\n/)
        .filter((line) => line.startsWith('+++ '))
        .map((line) =>
          normalizePatchPath(line.slice(4).split(/\s+/)[0].replace(/^b\//, '').replace(/^a\//, ''))
        )
        .filter((file) => file !== '/dev/null')
    )
  ];
}

module.exports = { applyUnifiedPatch, patchFiles };
