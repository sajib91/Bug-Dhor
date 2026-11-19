# Phase 6 Initial Audit — Bug-Dhor

**Date:** 2026-11-19  
**Repository:** `/Users/md.khayrulislamsajib/Downloads/Bug-Dhor`  
**Audit scope:** Step 1 of Phase 6 only. Read-only inspection of `src/bugdhor_ast/`, `security-engine/`, `vscode-extension/`, `tests/`, `reports/`, `docs/`, manifests, scripts, and repository state.  
**Implementation status:** No Phase 6 implementation was performed. No tests were run during this audit. The only file created by this step is this report.

---

## 1. Executive summary

1. **Phase 5 is not complete in the repository.** There are no `reports/PHASE_5_*` artifacts, no Phase 5 implementation commit, and no code path that invokes the local `bugdhor_ast` CLI from the VS Code extension. The latest completed and evidenced phase is Phase 4.
2. **The VS Code extension invokes only the FastAPI backend.** All analysis, explanation, repair, and verification commands go through `HttpSecurityEngineService` and `/api/v1/*`. The local `src/bugdhor_ast/` package is not referenced by extension source, tests, manifest, or README.
3. **Backend and local engine are separate systems.** They use different schemas, coordinate conventions, severity vocabularies, and taint models. There is no adapter between `bugdhor.program_analysis.TaintAnalysis` and `bugdhor_ast.flow`.
4. **Current extension behavior is partially Phase 5-complete.** Backend scanning, Python/JavaScript diagnostics, metadata preservation, cancellation, and some stale-clearing work. Java diagnostics are not available from the backend, workspace stale-clearing depends on backend scope metadata, repository commands publish no diagnostics, and there is no local/interpreter-based engine path.
5. **`bugdhor_ast` provides a strong analysis substrate but no Phase 6 feature implementation.** It has AST, detection, symbols/scopes, CFG, data flow, def-use, bounded interprocedural taint, and stable JSON sections. It has no CWE layer, root-cause explanation engine, repair engine, patch model, patch applier, repair history, or independent verification engine.
6. **The backend contains older explanation/repair/verification modules, but they must not be conflated with `bugdhor_ast`.** They are useful references and may be reusable through adapters, but they currently consume backend-specific schemas and are not wired to the local AST engine.
7. **No experimental claims may be made.** There is no evidence in this repository for SAE-based feature extraction, activation steering, model-internal counterfactual analysis, calibrated model probabilities, exploitability proofs, guaranteed-secure repair, sandboxing, or functional-correctness proofs.
8. **User-owned changes are intact and must be preserved.** The Phase 4 work and the three pre-existing extension modifications remain uncommitted/untracked as found.

---

## 2. Repository state and preservation boundary

### 2.1 Current state

`git status --short` at audit time showed:

- Modified: `benchmarks/README.md`, `docs/README.md`, `vscode-extension/package.json`, `vscode-extension/src/commands/runEngineCommand.js`, `vscode-extension/test/integration/index.js`.
- Untracked: `benchmarks/harness/run_phase4_performance.py`, `docs/scope-data-flow-analysis.md`, `docs/static-bug-detection.md`, `examples/`, `outputs/`, `reports/`, `requirements-ast.txt`, `src/`, `tests/`.

`HEAD` is `710ff24` (`Testing`). No Phase 5 or Phase 6 commit, branch artifact, or report was found.

### 2.2 User-owned modifications to preserve verbatim

| Path | User-owned content |
|---|---|
| `vscode-extension/package.json:3` | `"displayName": "Bug Dhor Security Framewor"` |
| `vscode-extension/package.json:6` | `"publisher": "sajib91"` |
| `vscode-extension/src/commands/runEngineCommand.js:27-45,103` | Synchronous `reportFailure`, non-blocking `Promise.resolve(showErrorMessage(...)).then(...).catch(...)`, and call without `await` |
| `vscode-extension/test/integration/index.js:570-595` | Async `run()`, 5-minute `Promise.race` watchdog, `console.error(stack)`, and `clearTimeout(watchdog)` in `finally` |
| `docs/README.md` | Phase 4 documentation links |
| `benchmarks/README.md` | Phase 4 benchmark harness/results note and `not_run` coding benchmark statement |

All untracked Phase 3/4 artifacts (`src/`, `tests/`, `reports/`, docs, examples, outputs, benchmark harness) are prior work and must not be reverted, deleted, or overwritten.

### 2.3 Known pre-existing test conflict

`vscode-extension/test/unit/manifest.test.js:15-22` still expects the original `displayName` and placeholder publisher, while the user-owned `package.json` now contains the shortened display name and `sajib91`. This is a pre-existing conflict, not a Phase 5/6 regression. Do **not** change the user-owned manifest identity to satisfy the test. Any later test update must preserve the manifest values.

---

## 3. Phase 3/4 reports and exact baselines

### 3.1 Report inventory

Present:

- `reports/PHASE_3_FINAL_REPORT.md`
- `reports/PHASE_3_TEST_REPORT.txt`
- `reports/PHASE_3_COVERAGE_REPORT.txt`
- `reports/PHASE_4_FINAL_REPORT.md`
- `reports/PHASE_4_TEST_REPORT.txt`
- `reports/PHASE_4_COVERAGE_REPORT.txt`
- `reports/PHASE_4_BENCHMARK_REPORT.md`

Absent:

- `reports/PHASE_5_FINAL_REPORT.md`
- `reports/PHASE_5_TEST_REPORT.txt`
- `reports/PHASE_5_COVERAGE_REPORT.txt`
- `reports/PHASE_5_MANUAL_VERIFICATION.md`
- Any other Phase 5 or Phase 6 report before this audit.

A repository-wide search found no `Phase 5`/`PHASE_5` or `Phase 6`/`PHASE_6` text before this report.

### 3.2 Recorded baselines

| Metric | Exact recorded value | Authority |
|---|---:|---|
| Phase 3 full suite | `collected 163 items`; `163 passed in 0.25s` | `reports/PHASE_3_TEST_REPORT.txt:6,172` |
| Phase 3 final-report timing quote | `163 passed in 0.16s` | `reports/PHASE_3_FINAL_REPORT.md:394` |
| Phase 3 coverage run | `collected 163 items`; `TOTAL 3452 276 92%`; `163 passed in 0.60s` | `reports/PHASE_3_COVERAGE_REPORT.txt:5,54,55` |
| Phase 3 final-report coverage timing quote | `163 passed in 0.52s` | `reports/PHASE_3_FINAL_REPORT.md:458` |
| Phase 4 full suite | `collected 205 items`; `205 passed in 0.24s` | `reports/PHASE_4_TEST_REPORT.txt:6,214` |
| Phase 4 coverage run | `collected 205 items`; `TOTAL 3811 186 95%`; `205 passed in 0.89s` | `reports/PHASE_4_COVERAGE_REPORT.txt:5,59,60` |
| Phase 4 focused flow suite | 10 modules, 68 tests | `reports/PHASE_4_FINAL_REPORT.md:266-269` |
| Phase 4 benchmark | medians `0.004550 s`–`0.433720 s`; peak `0.211 MiB`–`12.208 MiB`; coding benchmark `not_run` | `reports/PHASE_4_BENCHMARK_REPORT.md:108-118,149-157,175-176` |

The raw saved test/coverage outputs are authoritative for timings because the final reports quote different point-in-time durations. These numbers are historical baselines only; they were not re-measured in this audit.

### 3.3 Phase 4 capability baseline

Phase 4 added Python, JavaScript, and Java taint profiles, JSON taint configuration, bounded interprocedural argument/return propagation, conservative Python object/container flow, and taint diagnostics `PY-TAINT001`, `JS-TAINT001`, and `JAVA-TAINT001`. The Phase 4 benchmark measures performance only and is not security-effectiveness evidence.

---

## 4. Phase 5 integration audit

### 4.1 Direct answers

| Audit question | Verified answer |
|---|---|
| Does the extension invoke the actual `bugdhor_ast` engine? | **No.** It invokes only the FastAPI backend over HTTP. There is no CLI, subprocess, or in-process Python integration for `bugdhor_ast`. |
| Does workspace scanning work? | **Partially.** The extension builds a bounded local repository inventory and POSTs file paths to the backend. Inventory supports exclusions, `.gitignore`, dedupe, limits, and cancellation. The analysis itself is backend-only. |
| Are Python, JavaScript, and Java diagnostics displayed? | **Python and JavaScript: yes via backend. Java: no via backend.** `security-engine/src/bugdhor/parsing/languages.py:168-179` has no Java grammar/program-analysis factory. `bugdhor_ast` has Java rules, but the extension never calls them. |
| Are source locations accurate? | **For backend findings: yes.** Backend ranges are zero-based and validated before `new vscode.Range(...)`. For any future local `bugdhor_ast` findings: **no direct reuse**, because engine locations are one-based and must be converted. |
| Is diagnostic metadata preserved? | **Yes for backend findings.** `findingModel.js`, `DiagnosticController`, hover, decorations, code actions, and dashboard state retain rule ID, severity, message, location, language, category, confidence, source/sink, explanation, limitations, and related information. |
| Does scan cancellation work? | **Yes for backend scans.** Tokens flow to `AbortController`, `RequestCancelledError`, scheduler cancellation, inventory checks, and stale-version guards. No local process cancellation exists because no local process is started. |
| Are stale diagnostics cleared correctly? | **Partially.** Current-file/selection scans clear their URI scope; delete/close clears that URI. Workspace scans rely on backend `response.scope.uris`; an empty scope can leave stale diagnostics. Repository commands publish no diagnostics and therefore do not clear them. |

### 4.2 Evidence

- Extension activation explicitly states it starts no Python process: `vscode-extension/src/extension.js:139-145`.
- Only service implementation is `HttpSecurityEngineService` in `vscode-extension/src/api/securityEngineService.js`; it calls `/api/v1/scan/file`, `/api/v1/detection/analyze`, `/api/v1/scan/workspace`, and other backend routes via `ApiClient.request()`.
- No reference to `bugdhor_ast` exists under `vscode-extension/src/`, `vscode-extension/test/`, `vscode-extension/package.json`, or `vscode-extension/README.md`.
- The only runtime `execFile` is `git` discovery in `vscode-extension/src/repository/gitChangedFiles.js:51`. The only `spawn` in the extension tree is backend startup in `test/integration/runTest.js:240`.
- `bugdhor.backend.pythonPath` and `bugdhor.backend.autoStart` are reserved but unused; `extension.js:329-334` explicitly warns that auto-start is not implemented.
- `DiagnosticController.publishScanResult()` clears declared scope or response scope; `WorkspaceMonitor.scheduleWorkspaceScan()` passes `scopeUris: []`.
- `vscode-extension/src/commands/repositoryCommands.js` (`scanRepository`, `rescanAll`, `scanChangedFiles`, `scanSelectedFolder`, `scanIncremental`) calls `reportScanAvailability()` but never publishes diagnostics.

### 4.3 Phase 5 unresolved issues relevant to Phase 6

The following must be documented and, if Phase 6 needs them, fixed additively:

1. **No local engine execution layer.** Needed if Phase 6 must use `bugdhor_ast` evidence directly or work without the backend.
2. **No `bugdhor_ast` result adapter.** One-based line/column, `error|warning|info`, and `low|medium|high` confidence are incompatible with the extension’s zero-based ranges, `critical|high|medium|low|info`, and `observation|inference|hypothesis`.
3. **No true multi-file “Scan Selected Files” command.** The existing `bugdhor.scanSelection` means editor text selection, not selected files.
4. **No Clear Diagnostics command.**
5. **No Show Analysis Report command** with a canonical local-engine report.
6. **No local-engine settings** for interpreter path, include/exclude globs, enabled languages, flow/taint toggles, custom taint config, max file size, or scan timeout.
7. **Workspace/repository stale-clearing is incomplete.**
8. **Java analysis is unavailable through the backend path.**

**Do not silently redesign the extension.** The recommended fix is an opt-in local-engine command family and adapter layered beside the existing backend service, leaving all current command IDs, backend behavior, JSON keys, and integration tests intact.

---

## 5. Backend versus local engine

| Aspect | FastAPI backend (`security-engine/`) | Local engine (`src/bugdhor_ast/`) |
|---|---|---|
| Used by extension | **Yes, exclusively** | **No** |
| Invocation | HTTP via `ApiClient.request()` | Standalone CLI: `python -m bugdhor_ast.cli <file> --detect --flow --taint-diagnostics` |
| Locations | Zero-based | One-based (`row + 1`, `column + 1`) |
| Severities | `critical`, `high`, `medium`, `low`, `info` | `error`, `warning`, `info` |
| Confidence | `observation`, `inference`, `hypothesis` | `low`, `medium`, `high` on taint rules/findings |
| Java | Detected but no grammar/program-analysis factory | AST, detection, flow profiles, and Java taint pack exist |
| Explanation/repair/verification | Older modules exist in `bugdhor.explain`, `bugdhor.repair`, `bugdhor.verification` | None exist |
| Taint model | `bugdhor.program_analysis.TaintAnalysis` | `bugdhor_ast.flow` models |
| Bridge between models | N/A | **None** |

The two packages must remain separate unless an explicit adapter is implemented. Do not change existing backend or `bugdhor_ast` schemas in place.

---

## 6. `bugdhor_ast` substrate available for Phase 6

### 6.1 Exact interfaces

- `BugDhorASTEngine.analyze_source()` / `analyze_file()` produce AST JSON with `language`, `has_syntax_errors`, `summary`, and item arrays. Items use one-based `start_line`, `end_line`, `start_column`, `end_column`.
- `DetectionResult.to_dict()` produces exactly: `file`, `language`, `has_syntax_errors`, `summary`, `rules_executed`, `diagnostics`.
- `Diagnostic.to_dict()` produces exactly: `rule_id`, `rule_name`, `severity`, `message`, `file`, `line`, `column`, `end_line`, `end_column`, `explanation`, `suggestion`, `language`.
- `FlowAnalysisResult.to_dict(sections=None)` always includes `file`, `language`, `has_syntax_errors`, `summary`, `limitations`, `unresolved_references`, plus requested sections from `symbols`, `scopes`, `control_flow_graph`, `data_flow`, `taint_analysis`.
- `SourceLocation` uses `{file, line, column, end_line, end_column}` with one-based coordinates.
- `TaintFinding` includes source/sink rule IDs, names, locations, ordered `path`, `confidence`, `sanitizers`, and `limitations`.

Tests in `tests/test_detection_core.py` assert exact detection key sets, so additive Phase 6 data must live in new wrapper/adapter modules, not in these dictionaries.

### 6.2 Detection rules

| Language | Rule IDs | Semantics summary |
|---|---|---|
| Python | `PY001`–`PY010` | Undefined variable, unused variable/import/parameter, unreachable code, duplicate declaration, potential None access, empty handler, suspicious/dangerous call. No taint requirement. |
| JavaScript | `JS001`–`JS010` | Equivalent conservative checks for JS. No taint requirement. |
| Java | `JAVA001`–`JAVA010` | Equivalent conservative checks for Java. No taint requirement. |
| Syntax | `AST001` | Syntax-error short-circuit. |
| Taint | `PY-TAINT001`, `JS-TAINT001`, `JAVA-TAINT001` | Converted taint diagnostics with source/sink path information in raw `taint_analysis`. |

Rule packs contain 7 Python sources / 4 sanitizers / 7 sinks, 14 JavaScript sources / 6 sanitizers / 12 sinks, and 11 Java sources / 6 sanitizers / 8 sinks.

### 6.3 Available evidence

- **AST evidence:** functions, classes, variables, calls, imports, syntax errors, one-based spans, source text snippets, stable byte-based node keys.
- **Scope/symbol evidence:** scope kinds and IDs, declarations, declaration locations, references, assignments, symbol types, unresolved references.
- **CFG evidence:** nodes with statement IDs, scope IDs, kind, text, location, successors/predecessors; typed edges; `consistent` flag. CFGs are emitted for module/function/class scopes.
- **Data-flow evidence:** definitions, uses, reaching definitions, live variables, def-use/use-def chains, dependencies, assignment propagation, function summaries, call edges.
- **Taint evidence:** source rule/name/location, sink rule/name/location, ordered propagation path with kinds `source`, `assignment`, `slot_write`, `slot_read`, `argument`, `parameter`, `call`, `sink`, confidence, limitations.
- **Call evidence:** AST calls, scope call records, `CallEdge`, function summaries with call sites, bounded interprocedural argument/return mapping.

### 6.4 Missing in `bugdhor_ast`

There is no:

- CWE field, CWE table, or CWE rationale;
- root-cause analysis or causal explanation engine;
- explanation schema beyond static rule descriptions and taint path strings;
- deterministic repair engine;
- patch/diff generator, patch applier, stale-patch guard, or rollback;
- repair history;
- independent verification engine;
- dynamic execution, sandbox, fuzzing, or LLM integration;
- full heap/alias/type analysis, reflection/dynamic-dispatch reasoning, or library-aware sanitizer semantics.

### 6.5 Latent defect observed

`src/bugdhor_ast/flow/scopes.py:470-472` references `current_scope_id` without defining it in `_register_declaration()`. Global directives work because `directive` is truthy, but an unresolved `nonlocal` directive could raise `NameError`. No test covers that case. This is out of scope for Step 1 and was not changed.

---

## 7. Backend explanation/repair/verification inventory

The backend contains earlier committed feature work that Phase 6 can study or adapt:

- `security-engine/src/bugdhor/explain/engine.py`: `ExplainableVulnerabilityEngine.explain()` and `VulnerabilityExplanation`; consumes backend taint model.
- `security-engine/src/bugdhor/repair/context.py`: `RepositoryContextBuilder.build()`, bounded repository context without source text.
- `security-engine/src/bugdhor/repair/engine.py`: `RepairEngine.propose()`, `RepairProposal`, `CandidatePatch`, provider-backed generation.
- `security-engine/src/bugdhor/repair/ranking.py`: candidate ranking and mandatory constraints.
- `security-engine/src/bugdhor/repair/workflow.py`: multi-step repair workflow record.
- `security-engine/src/bugdhor/verification/engine.py`: `IndependentVerificationEngine.verify()`.
- `security-engine/src/bugdhor/verification/functional.py`: scripted functional verification with explicit `executed` status.

Important constraints:

1. These are not part of `bugdhor_ast` and are not wired to its flow schema.
2. Backend repair is provider-backed; deterministic repair without an AI provider remains a Phase 6 requirement.
3. Existing docs explicitly caution that repair proposals are not proof of security and that verification is limited to checks actually run.
4. Do not reuse backend claims as evidence for `bugdhor_ast` capabilities.

---

## 8. Test and toolchain baseline

### 8.1 Exact commands

| Scope | Command |
|---|---|
| Canonical Python + extension units | `npm test` from repository root |
| Backend pytest only | `cd security-engine && ../.venv/bin/python -m pytest` |
| Root AST suite | `PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -v` |
| Root AST coverage | `PYTHONPATH=src ./.venv/bin/python -m pytest tests/ --cov=bugdhor_ast --cov-report=term-missing` |
| Extension units | `npm run extension:test` or `cd vscode-extension && npm test` |
| Extension integration | `npm run extension:test:integration` or `cd vscode-extension && npm run test:integration` |
| Full check gate | `npm run check` |

`npm test` runs backend pytest and extension units. It does **not** run root `tests/`, mathematical regressions, or VS Code integration tests.

### 8.2 Current coverage relevant to Phase 6

- 34 extension unit test files exist.
- 65 backend Python test files exist.
- 19 root AST/detection/flow test files exist.
- No `phase6`-labeled tests exist. Existing backend tests cover explanation API, repair engine, verification engine, and scripted functional verification.
- Existing extension tests cover repair generation, patch extraction/application, explanation/verification commands, hover/quick fix, and real backend integration.
- Integration tests require a live FastAPI backend started by `test/integration/runTest.js`, a real VS Code host, and no API tokens.

No tests were executed during this audit. Current pass counts are therefore not asserted here.

---

## 9. Documentation constraints and inconsistencies

Claims that must not be treated as implemented:

- SAE feature extraction, activation steering, counterfactual model analysis, calibrated probabilities, or model-internal causal explanations.
- Exploitability inferred from severity/category alone.
- Autonomous or guaranteed-secure repair.
- Generic sanitizer names as proof of safety.
- Universal verification pass, sandbox success, or functional-correctness proof.
- Full heap/alias/type analysis, cross-file program analysis, complete interprocedural analysis, or library-aware sanitizer semantics.

Known inconsistencies:

1. `docs/current-feature-status.md` and `docs/program-analysis.md` describe an older backend package with Python/JavaScript-only flow; `docs/scope-data-flow-analysis.md` describes the newer `bugdhor_ast` package with Python/JavaScript/Java flow. They are separate packages and must not be conflated.
2. Two taint schemas exist: backend `TaintAnalysis` and `bugdhor_ast.flow`. No adapter exists.
3. Stale status counters/dates in `docs/current-feature-status.md`, `research-implementation-status.md`, and some root reports do not match the current Phase 3/4 suite counts.
4. `docs/README.md:39-44` says no empirical results are reported, but `reports/PHASE_4_BENCHMARK_REPORT.md` contains measured performance results. This is a wording inconsistency; benchmark results are performance-only.
5. Endpoint registration in `docs/api.md` is not proof of end-to-end capability; `docs/current-feature-status.md` and `end-to-end-test-report.md` are more cautious.

---

## 10. Proposed Phase 6 architecture

The following is a proposal only. No implementation starts until approved.

### 10.1 Design principles

1. **Additive only.** Preserve all Phase 1–5 APIs, JSON keys, CLI behavior, commands, and user-owned changes.
2. **Evidence-first.** Every explanation field must cite observed, derived, or heuristic evidence, or explicitly state `unavailable` / `unknown`.
3. **No fabricated causality.** Root cause is emitted only when AST/symbol/data-flow/taint evidence supports it.
4. **Context-specific repair.** No generic sanitizer recommendations. A repair for HTML, SQL, shell, or process APIs must match the destination context.
5. **Explicit approval.** No source file is modified unless the developer approves the exact previewed patch.
6. **Independent verification.** A finding disappearing is necessary but not sufficient; report only checks that actually ran.
7. **Local and backend modes coexist.** Keep backend commands unchanged; add local-engine capabilities behind an opt-in mode.

### 10.2 Suggested module layout

```text
src/bugdhor_ast/explain/
  __init__.py
  schema.py              # stable explanation schema and status enums
  evidence.py            # adapters from AST/detection/flow JSON to evidence records
  root_cause.py          # deterministic localization from evidence
  cwe.py                 # evidence-based rule -> CWE mapping with rationale/confidence
  explainer.py           # unified orchestration API
  repair/
    __init__.py
    strategies.py         # deterministic, language/context-aware repair rules
    recommendation.py     # repair recommendation model
    patch.py              # minimal patch, line spans, diff, hash/stale/overlap checks
    history.py            # apply/revert history model
  verification/
    __init__.py
    pipeline.py           # reparse, redetect, re-taint, compare, status computation
    tests_runner.py       # optional configured safe tests; never arbitrary default execution
  providers/
    __init__.py
    base.py               # provider-independent AI repair interface
    registry.py           # explicit opt-in registry; disabled by default
```

No existing `DetectionResult`, `Diagnostic`, `FlowAnalysisResult`, `CLI`, or backend response schema is changed. New data is returned from new adapters/wrappers.

### 10.3 Explanation schema

Stable additive schema:

```json
{
  "schema_version": "1.0",
  "finding_id": "string",
  "rule_id": "string",
  "severity": "string",
  "language": "python|javascript|java|all",
  "category": "string|null",
  "cwe": [
    {
      "id": "CWE-89",
      "confidence": "high|medium|low",
      "rationale": "string",
      "evidence_refs": ["string"]
    }
  ],
  "location": { "file": "string", "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 1 },
  "root_cause": {
    "status": "determined|heuristic|unknown",
    "location": "object|null",
    "rationale": "string",
    "evidence_refs": ["string"]
  },
  "trigger": "object|null",
  "evidence": {
    "observed": [],
    "derived": [],
    "heuristic": [],
    "unavailable": []
  },
  "source_to_sink_path": [],
  "confidence": {
    "value": "high|medium|low",
    "basis": "string"
  },
  "limitations": ["string"],
  "suggested_remediation": "string|null",
  "verification_requirements": ["string"]
}
```

Evidence status vocabulary maps directly to the required distinction:

- `observed` — directly present in source/AST/detection output.
- `derived` — computed from scope, CFG, data-flow, or taint analysis.
- `heuristic` — conservative inference; never presented as causation.
- `unavailable` — required evidence is absent.

### 10.4 CWE mapping policy

- Start with defensible mappings only, keyed by concrete sink/rule semantics, not broad finding IDs.
- Multiple CWEs are allowed only when semantics genuinely overlap.
- Every mapping carries `rationale`, `confidence`, and `evidence_refs`.
- Unmapped rules return an empty `cwe` array; no placeholder IDs.
- Candidate examples to validate against actual rule semantics: CWE-78 (OS command injection), CWE-79 (XSS), CWE-89 (SQL injection), CWE-94 (code injection), CWE-22 (path traversal).

### 10.5 Deterministic repair subset

Implement a documented subset first:

| Language | Scenario | Conservative strategy |
|---|---|---|
| Python | SQL string concatenation/formatting into `cursor.execute` | Parameterized query when the statement structure is confidently recognizable |
| Python | `os.system`/shell string construction | Prefer argument-list process API when semantics are preserved; otherwise unsupported |
| JavaScript | `innerHTML` with plain text | `textContent` when no markup is required |
| Java | `Statement.executeQuery` with concatenated SQL | `PreparedStatement` with bound parameters when structure is recognizable |

All other cases return `unsupported` with a reason. Never apply a patch automatically.

### 10.6 Patch safety

- Verify file path, byte size, SHA-256, and exact original span before preview/apply.
- Generate minimal line-based patches and unified diffs.
- Reject stale patches and overlapping patches.
- Preserve original source content and encoding/newline style where possible.
- Show diff and require explicit developer confirmation.
- Store history in extension state and revert exact prior content.
- Revert must never overwrite a file that changed since apply without explicit handling.

### 10.7 Verification states

Use only the required statuses:

- `VERIFIED` — every configured required check passed.
- `PARTIALLY_VERIFIED` — some checks passed, unavailable checks remain.
- `FAILED` — a required check failed.
- `NOT_VERIFIED` — verification could not be completed.

Checks: syntax validity, AST parse, original finding status, related security findings, new findings, patch integrity, unrelated changes, and optional regression tests. Test execution is disabled by default and must use an explicitly configured safe command; no sandbox claim is made.

### 10.8 VS Code workflow

Preserve existing command IDs. Add new additive command IDs:

- `bugdhor.explainFinding`
- `bugdhor.suggestFix`
- `bugdhor.previewRepair`
- `bugdhor.applyRepair`
- `bugdhor.verifyRepair` — reuse existing command ID with backward-compatible target handling
- `bugdhor.revertRepair`

Keep `bugdhor.explainVulnerability`, `bugdhor.repairVulnerability`, and existing backend behavior unchanged. The new workflow uses diagnostics as input, renders explanation/recommendation/diff in a webview or quick pick, and applies edits only after confirmation.

### 10.9 Incremental implementation order

A. Explanation schema and evidence adapter; tests.  
B. Root-cause localization; tests for determinable, heuristic, and unknown cases.  
C. CWE mapping layer; tests for mapped/unmapped rules.  
D. Deterministic repair recommendations; tests for the four subset scenarios and unsupported/context-specific cases.  
E. Patch model, diff, stale/overlap detection, apply/revert; tests.  
F. VS Code commands, preview, approval, history; tests.  
G. Independent verification pipeline; tests for all statuses.  
H. Optional provider abstraction, disabled by default; tests.  
I. Only the Phase 5 fixes required by Phase 6, through additive local-engine adapter/settings/commands.  
J. Full tests, coverage, benchmarks, documentation, and reports.

After each step: run relevant tests, inspect the diff, report actual results, and preserve unrelated modifications.

---

## 11. Decision gates before implementation

1. **Local-engine policy:** Should the local `bugdhor_ast` engine remain opt-in for Phase 6, or become the default for existing scan commands? Recommendation: **opt-in first**, because backend integration tests and user-owned changes must remain intact.
2. **Repair subset:** Approve the conservative subset in Section 10.5, or specify a different subset.
3. **Command naming:** Approve additive command IDs in Section 10.8 while preserving existing IDs.
4. **Test execution policy:** Approve that no repaired code is executed by default; optional regression commands are explicitly configured and documented as non-sandboxed.

No Phase 6 code will be written until the first gate is resolved and the remaining decisions are confirmed.

---

## 12. Audit integrity statement

- All inspection was read-only.
- No Phase 3/4/extension file was modified, reverted, deleted, or regenerated.
- No test, coverage, benchmark, or manual-verification result was produced during this audit.
- Historical numbers in this report are quoted from existing reports and labeled as such.
- This report was created as the sole Step 1 artifact.
