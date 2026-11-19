# Static Bug Detection Engine (`bugdhor_ast`)

This document describes the rule-based static detection layer built on the
existing lightweight `bugdhor_ast` tree-sitter wrapper. It is separate from
the `security-engine` detection stack and does not change the original AST
JSON output.

## What is implemented

- Ten detection categories, with one rule ID per language:
  `PY001`–`PY010`, `JS001`–`JS010`, and `JAVA001`–`JAVA010`.
- A syntax-error rule `AST001` used when a source file has parse errors.
- Structured diagnostics with rule ID, rule name, severity, language, file,
  start/end line and column, message, explanation, and suggested fix.
- Rule metadata with descriptions, severities, suggestions, and explicit
  limitations; available programmatically through `list_rules()`.
- A CLI `--detect` mode with JSON/text output, severity filtering, rule
  filtering, file-level diagnostics, and JSON file export.
- Dedup and deterministic sorting of diagnostics by location and rule ID.

Parsing, traversal, and line/column extraction reuse `BugDhorASTEngine` and
`tree-sitter`; no AST output schema was changed.

## Architecture

| File | Responsibility |
| --- | --- |
| `src/bugdhor_ast/detection/models.py` | `RuleMetadata`, `Diagnostic`, `DetectionResult`, severity constants |
| `src/bugdhor_ast/detection/context.py` | `AnalysisContext`: parse-tree traversal, fields, text, positions, diagnostic construction |
| `src/bugdhor_ast/detection/rules/base.py` | `BaseRule` contract (`check(context)` and `report(...)`) |
| `src/bugdhor_ast/detection/rules/common.py` | Shared identifier, call, argument, block, and literal helpers |
| `src/bugdhor_ast/detection/rules/python_rules.py` | Python rules `PY001`–`PY010` |
| `src/bugdhor_ast/detection/rules/javascript_rules.py` | JavaScript rules `JS001`–`JS010` |
| `src/bugdhor_ast/detection/rules/java_rules.py` | Java rules `JAVA001`–`JAVA010` |
| `src/bugdhor_ast/detection/registry.py` | `RuleRegistry`, `DEFAULT_REGISTRY`, rule selection by language/ID/severity |
| `src/bugdhor_ast/detection/engine.py` | `BugDhorDetectionEngine`: parse, run rules, handle syntax errors, filter, dedup |
| `src/bugdhor_ast/detection/reporting.py` | `render_text()` human-readable output |
| `src/bugdhor_ast/detection/__init__.py` | Public detection exports |
| `src/bugdhor_ast/cli.py` | Original AST mode plus opt-in `--detect` mode |

Rule IDs are language-specific. The same numeric ID does not mean identical
semantics: each language implementation has its own scope model, allowlist, and
limitations documented below.

## Rule catalog

All three languages implement the ten requested categories, but the checks are
deliberately conservative and are not equivalent across languages.

| Category | Python | JavaScript | Java |
| --- | --- | --- | --- |
| Undefined variables | `PY001` | `JS001` | `JAVA001` (conservative, no type inference) |
| Unused variables | `PY002` | `JS002` | `JAVA002` |
| Unreachable code | `PY003` | `JS003` | `JAVA003` |
| Duplicate declarations | `PY004` | `JS004` | `JAVA004` |
| Unused imports | `PY005` | `JS005` | `JAVA005` |
| Unused parameters | `PY006` | `JS006` | `JAVA006` |
| Potential null/None access | `PY007` | `JS007` | `JAVA007` |
| Empty exception handlers | `PY008` | `JS008` | `JAVA008` |
| Suspicious calls | `PY009` | `JS009` | `JAVA009` |
| Dangerous calls | `PY010` | `JS010` | `JAVA010` |

### Python

| ID | Severity | Detects | Main limitation |
| --- | --- | --- | --- |
| `PY001` | error | Bare identifier uses with no visible file-wide definition or builtin | No control-flow or cross-file resolution |
| `PY002` | warning | Function-local assignments that are never read | Module-level assignments are not reported |
| `PY003` | warning | First statement after `return`/`raise`/`break`/`continue` in a block | Only the first unreachable statement is reported |
| `PY004` | error | Repeated annotated declarations in one scope | Plain reassignment is not a declaration |
| `PY005` | warning | Unused imported bindings, including aliases | Wildcard imports are skipped |
| `PY006` | warning | Unused function/lambda parameters | `self`, `cls`, and `_`-prefixed names are ignored |
| `PY007` | warning | Dereference of a name assigned `None` without a visible guard | Intra-scope, approximate flow, no call-chain tracking |
| `PY008` | warning | `except` clauses whose body is only `pass`/comments | No analysis of logging through indirect calls |
| `PY009` | warning | `input`, `compile`, `breakpoint` calls | `eval`/`exec` are reported by `PY010` instead |
| `PY010` | error | `eval`, `exec`, `os.system`, `subprocess` with `shell=True`, unsafe `yaml.load`, pickle/marshal loads | No taint analysis; aliases are not resolved |

### JavaScript

| ID | Severity | Detects | Main limitation |
| --- | --- | --- | --- |
| `JS001` | error | Bare identifier uses with no visible definition or known global | Fixed global allowlist; file-wide resolution only |
| `JS002` | warning | Unused `let`/`const`/`var` declarators | Exported bindings are ignored; destructuring is handled only for identifier names |
| `JS003` | warning | First statement after `return`/`throw`/`break`/`continue` | Only the first unreachable statement is reported |
| `JS004` | error | Repeated declarations in the same lexical scope | Plain assignment is not a declaration |
| `JS005` | warning | Unused ES import bindings | Side-effect imports are not bindings |
| `JS006` | warning | Unused formal parameters | Nested-function uses count as uses |
| `JS007` | warning | Dereference of a name assigned `null` without a guard | Recognizes `!== null`, `!= null`, and optional chaining; approximate flow |
| `JS008` | warning | Empty or comment-only `catch` blocks | No analysis of indirect logging |
| `JS009` | warning | `document.write` and string-literal timer calls | Dangerous names such as `eval` are handled by `JS010` |
| `JS010` | error | `eval`, `Function`, `exec`/`execSync`, `child_process.exec`, shell-enabled spawn | No taint analysis; `require` aliases such as `cp.exec` are not resolved |

### Java

| ID | Severity | Detects | Main limitation |
| --- | --- | --- | --- |
| `JAVA001` | error | Undefined lower-camel bare identifiers | No type inference; `type_identifier`, fields, imports, methods, types, and JDK names are treated as known |
| `JAVA002` | warning | Unused local declarators inside methods/constructors | Fields and `_`-prefixed names are skipped |
| `JAVA003` | warning | First statement after a terminator in a block | Only the first unreachable statement is reported |
| `JAVA004` | error | Repeated local declarations in one method/block scope | Fields are skipped; invalid Java with `ERROR` nodes is not interpreted |
| `JAVA005` | warning | Unused non-wildcard, non-static imports | Usage is matched by simple name only |
| `JAVA006` | warning | Unused method/constructor parameters | Only method/constructor bodies with parameters are checked |
| `JAVA007` | warning | Dereference of a local assigned `null` without a guard | Intra-method; recognizes only simple null checks and `Objects.requireNonNull` |
| `JAVA008` | warning | Empty or comment-only `catch` blocks | No analysis of indirect logging |
| `JAVA009` | warning | `System.exit`, `printStackTrace`, thread `stop` | Fixed call names without receiver-type analysis |
| `JAVA010` | error | `Runtime.exec`, `ProcessBuilder` creation, `ObjectInputStream.readObject`, `Class.forName`, `ScriptEngine.eval` | Fixed names and a few local receiver types; no taint analysis |

`AST001` (error) is emitted instead of category rules when the parse tree has
errors or missing nodes.

## Diagnostic schema

`--detect --format json` and `DetectionResult.to_dict()` produce:

```json
{
  "file": "examples/sample.py",
  "language": "python",
  "has_syntax_errors": false,
  "summary": {"total": 1, "error": 0, "warning": 1, "info": 0},
  "rules_executed": ["PY001", "PY002", "PY003", "PY004", "PY005",
                     "PY006", "PY007", "PY008", "PY009", "PY010"],
  "diagnostics": [
    {
      "rule_id": "PY005",
      "rule_name": "Unused Import",
      "severity": "warning",
      "message": "Imported binding 'os' is not used.",
      "file": "examples/sample.py",
      "line": 2,
      "column": 8,
      "end_line": 2,
      "end_column": 10,
      "explanation": "An imported binding is not used in the file.",
      "suggestion": "Remove the import or use the imported binding.",
      "language": "python"
    }
  ]
}
```

Lines and columns are one-based. `summary.total` counts all diagnostics after
filtering and deduplication.

## CLI usage

```bash
# Original AST output (unchanged behavior)
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.py

# Detection, JSON on stdout (default)
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.py --detect

# Human-readable terminal output
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.js --detect --format text

# Only errors, and only selected rules
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.java \
  --detect --severity error --rule JAVA010

# Save JSON while showing text in the terminal
PYTHONPATH=src ./.venv/bin/python -m bugdhor_ast.cli examples/sample.py \
  --detect --format text --output reports/diagnostics.json
```

Flags:

- `--detect` opts into detection; without it the original AST JSON is printed.
- `--format {json,text}` only affects detection terminal output.
- `--severity` may be repeated; accepted values: `error`, `warning`, `info`.
- `--rule` may be repeated; rule IDs are matched case-insensitively.
- `--output/-o` writes the JSON result even when the terminal format is `text`.

Errors: unknown rule IDs, missing files, unsupported extensions, and output
write failures exit with status `1`. Argparse errors exit with status `2`.

## Python API

```python
from bugdhor_ast.detection import BugDhorDetectionEngine

engine = BugDhorDetectionEngine()

result = engine.analyze_file("examples/sample.py")
print(result.summary)
for diagnostic in result.diagnostics:
    print(diagnostic.rule_id, diagnostic.line, diagnostic.message)

# Rule catalog, including descriptions and limitations
rules = engine.list_rules("python")

# Filters
result = engine.analyze_source(
    source_code,
    "python",
    rule_ids=["PY005"],
    severities=["warning"],
)
```

## Verification record

Commands actually run in this repository with Python 3.11.14:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -v
# 137 passed in 0.09s

PYTHONPATH=src ./.venv/bin/python -m pytest tests/ --cov=bugdhor_ast --cov-report=term-missing
# 137 passed in 0.34s
# TOTAL: 1643 statements, 95 missed, 94% coverage
```

Notable per-module coverage: `engine.py` (detection) 100%, `models.py` 100%,
`registry.py` 100%, `cli.py` 100%, `context.py` 100%, shared helpers 100%,
Python rules 97%, JavaScript rules 91%, Java rules 90%. The pre-existing AST
`engine.py` remains at 94% and its schema is unchanged.

CLI runs against the provided samples produced:

- `examples/sample.py`: one `PY005` warning for unused `os`.
- `examples/sample.js`: one `JS005` warning for unused `fs`.
- `examples/sample.java`: `JAVA005` for unused `Scanner` and `JAVA006` for
  unused `args`.
- Filtered run with `--rule JAVA005 --severity warning` returned only the
  `JAVA005` diagnostic.

## Known issues and limitations

- This is an **intra-file, syntax-level** analyzer. It does not resolve
  imports across files, infer types, or perform taint/data-flow analysis.
- Name resolution is file-wide and flow-insensitive; shadowing and complex
  control flow can produce false negatives or, rarely, false positives.
- Java undefined-variable checking is intentionally narrow; it will miss
  undefined names in typed positions or inherited/field-heavy code.
- JavaScript dangerous-call detection does not follow `require` aliases
  (for example `const cp = require("child_process"); cp.exec(...)`).
- Only the first statement after a terminator is reported as unreachable.
- The VS Code extension still talks to the FastAPI backend and does not call
  this CLI or the detection engine directly; integration is a separate task.
- Some defensive branches inside the language rule modules are not exercised,
  which is why the Java and JavaScript rule modules are around 90% coverage.
