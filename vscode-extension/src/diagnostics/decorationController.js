'use strict';

const { buildHoverMarkdown } = require('./hoverProvider');

const STYLE_DEFINITIONS = Object.freeze({
  error: Object.freeze({
    gutter: 'gutter-critical.svg',
    themeColor: 'charts.red',
    fallbackColor: '#f14c4c',
    label: 'Bug Dhor error finding'
  }),
  warning: Object.freeze({
    gutter: 'gutter-medium.svg',
    themeColor: 'charts.yellow',
    fallbackColor: '#cca700',
    label: 'Bug Dhor warning finding'
  }),
  information: Object.freeze({
    gutter: 'gutter-low.svg',
    themeColor: 'charts.blue',
    fallbackColor: '#3794ff',
    label: 'Bug Dhor informational finding'
  })
});

const KIND_TO_STYLE = Object.freeze({
  error: 'error',
  warning: 'warning',
  information: 'information',
  hint: 'information'
});

/**
 * @param {import('vscode')} vscode
 * @param {string} kind
 */
function decorationColor(vscode, kind) {
  const definition = STYLE_DEFINITIONS[kind];
  if (typeof vscode.ThemeColor === 'function') {
    return new vscode.ThemeColor(definition.themeColor);
  }
  return definition.fallbackColor;
}

/**
 * Own static, native editor decorations for published findings.
 *
 * Decorations are intentionally static: colored underlines, gutter icons, and
 * overview-ruler marks. Animation belongs only in the dashboard Webview and
 * never blocks or moves the editor.
 */
class DecorationController {
  /**
   * @param {{
   *   vscode: import('vscode'),
   *   extensionUri: import('vscode').Uri,
   *   logger?: import('../logging/output').Logger
   * }} dependencies
   */
  constructor({ vscode, extensionUri, logger }) {
    if (
      !vscode ||
      typeof vscode.window?.createTextEditorDecorationType !== 'function' ||
      !Array.isArray(vscode.window.visibleTextEditors) ||
      typeof vscode.window.onDidChangeVisibleTextEditors !== 'function' ||
      typeof vscode.Range !== 'function' ||
      typeof vscode.MarkdownString !== 'function'
    ) {
      throw new TypeError('DecorationController requires the VS Code decoration APIs.');
    }
    if (!extensionUri || typeof vscode.Uri?.joinPath !== 'function') {
      throw new TypeError('DecorationController requires an extension URI for gutter icons.');
    }

    this.vscode = vscode;
    this.logger = logger;
    this.disposed = false;
    /** @type {Map<string, object[]>} */
    this.findingsByUri = new Map();
    /** @type {Record<string, import('vscode').TextEditorDecorationType>} */
    this.types = Object.create(null);

    const overviewLane = vscode.OverviewRulerLane?.Full ?? 7;
    for (const [kind, definition] of Object.entries(STYLE_DEFINITIONS)) {
      const color = decorationColor(vscode, kind);
      this.types[kind] = vscode.window.createTextEditorDecorationType({
        textDecoration: 'underline',
        borderWidth: '0 0 2px 0',
        borderStyle: 'solid',
        borderColor: color,
        overviewRulerColor: color,
        overviewRulerLane: overviewLane,
        gutterIconPath: vscode.Uri.joinPath(extensionUri, 'media', definition.gutter),
        gutterIconSize: 'contain'
      });
    }

    this.visibleSubscription = vscode.window.onDidChangeVisibleTextEditors(() => this.refresh());
  }

  /** @param {string | import('vscode').Uri} value */
  toKey(value) {
    return typeof value === 'string' ? value : value?.toString?.();
  }

  /**
   * Replace decorations for one document. Findings must already be normalized.
   *
   * @param {import('vscode').Uri} uri
   * @param {object[]} findings
   */
  setFindings(uri, findings) {
    this.assertActive();
    const key = this.toKey(uri);
    if (!key) {
      return;
    }
    const accepted = Array.isArray(findings) ? findings : [];
    if (accepted.length === 0) {
      this.findingsByUri.delete(key);
    } else {
      this.findingsByUri.set(
        key,
        accepted.map((finding) => ({ ...finding }))
      );
    }
    this.applyToVisibleEditors(key);
  }

  /** Reapply stored findings when the visible editor set changes. */
  refresh() {
    if (this.disposed) {
      return;
    }
    for (const key of this.findingsByUri.keys()) {
      this.applyToVisibleEditors(key);
    }
  }

  /** @param {string | import('vscode').Uri} value */
  clearUri(value) {
    if (this.disposed) {
      return;
    }
    const key = this.toKey(value);
    if (!key) {
      return;
    }
    this.findingsByUri.delete(key);
    this.applyToVisibleEditors(key);
  }

  clearAll() {
    if (this.disposed) {
      return;
    }
    const keys = [...this.findingsByUri.keys()];
    this.findingsByUri.clear();
    for (const key of keys) {
      this.applyToVisibleEditors(key);
    }
  }

  /** @param {string} key */
  applyToVisibleEditors(key) {
    const editors = this.vscode.window.visibleTextEditors.filter(
      (editor) => this.toKey(editor?.document?.uri) === key
    );
    if (editors.length === 0) {
      return;
    }

    /** @type {Record<string, object[]>} */
    const optionsByStyle = { error: [], warning: [], information: [] };
    for (const finding of this.findingsByUri.get(key) ?? []) {
      const style = KIND_TO_STYLE[finding.severityKind] ?? 'information';
      const markdown = new this.vscode.MarkdownString(buildHoverMarkdown([finding]));
      markdown.isTrusted = false;
      const range = finding.range ?? {
        start: { line: 0, character: 0 },
        end: { line: 0, character: 0 }
      };
      optionsByStyle[style].push({
        range: new this.vscode.Range(
          range.start.line,
          range.start.character,
          range.end.line,
          range.end.character
        ),
        hoverMessage: markdown
      });
    }

    for (const editor of editors) {
      if (typeof editor.setDecorations !== 'function') {
        continue;
      }
      for (const [style, type] of Object.entries(this.types)) {
        editor.setDecorations(type, optionsByStyle[style] ?? []);
      }
    }
  }

  assertActive() {
    if (this.disposed) {
      throw new Error('The Bug Dhor decoration controller has been disposed.');
    }
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    try {
      this.visibleSubscription?.dispose();
      for (const type of Object.values(this.types)) {
        type.dispose();
      }
    } finally {
      this.findingsByUri.clear();
    }
  }
}

module.exports = {
  DecorationController,
  STYLE_DEFINITIONS,
  KIND_TO_STYLE,
  decorationColor
};
