# Phase 6 Final Report — Bug-Dhor

**Project:** Bug-Dhor  
**Phase:** Phase 6 — evidence-based explanations, root-cause localization, CWE mapping, deterministic repair, safe patch workflow, independent verification, optional AI abstraction, local CLI, and VS Code opt-in integration  
**Date:** 2026-11-19  
**Repository:** `/Users/md.khayrulislamsajib/Downloads/Bug-Dhor`  
**Status:** Implemented and validated within the stated boundaries. Known limitations and one pre-existing extension identity test failure are preserved and reported below.

---

## 1. Executive summary

Phase 6 was implemented additively on top of the existing `bugdhor_ast` AST,
detection, CFG, data-flow, and taint engines. Existing detection schemas,
Phase 3/4 flow keys, CLI behavior, backend API behavior, commands, and tests
were not changed.

The approved policy decision was **opt-in first**: FastAPI backend scans remain
the VS Code default, and the local `bugdhor_ast` engine is used only when
`bugdhor.localEngine.enabled` is true. Source writes require a second opt-in,
`bugdhor.localEngine.allowSourceWrite`, plus a modal warning and an exact
`patch_id` confirmation.

Measured results:

- AST/Phase 6 Python suite: `275 passed in 1.51s`.
- Backend suite: `726 passed in 10.27s`.
- Coverage run: `275 passed in 2.46s`; `TOTAL 6526 719 89%`.
- Focused Phase 6 local workflow: `9 passed in 0.73s`.
- Focused Phase 6 extension adapter: `10/10 pass`.
- Full extension unit suite: `400 pass / 1 fail`; the failure is the pre-existing
  user-owned manifest identity assertion.
- Phase 6 core workflow medians: `0.005509 s`–`0.065821 s`; peak traced memory
  `0.197 MiB`–`1.914 MiB`.
- Coding benchmark remains `not_run`; no security-effectiveness claim is made.

Supporting reports:

- `reports/PHASE_6_INITIAL_AUDIT.md`
- `reports/PHASE_6_TEST_REPORT.txt`
- `reports/PHASE_6_COVERAGE_REPORT.txt`
- `reports/PHASE_6_REPAIR_VALIDATION_REPORT.md`
- `reports/PHASE_6_BENCHMARK_REPORT.md`

---

## 2. Architecture and additive boundaries

### 2.1 Python packages

New Phase 6 code is additive under:

```text
src/bugdhor_ast/explain/
src/bugdhor_ast/phase6/
```

Key modules:

| Area | Files |
|---|---|
| Explanation schema and evidence adapter | `schema.py`, `evidence.py`, `explainer.py` |
| Root-cause localization | `root_cause.py` |
| CWE mapping | `cwe.py` |
| Deterministic repair | `repair/recommendation.py`, `repair/strategies.py` |
| Patch model and safety | `repair/patch.py`, `repair/history.py` |
| Optional AI abstraction | `repair/ai.py` |
| Independent verification | `verification.py` |
| Local workflow service | `phase6/service.py` |
| Local session persistence | `phase6/session.py` |
| JSON-only CLI | `phase6/cli.py` |

The local workflow assembles a payload from the existing AST engine, detection
engine, flow sections, taint diagnostics, unresolved references, and
limitations. `unresolved_references` and `limitations` are included in in-process
payloads because they are not part of the existing CLI `FLOW_SECTIONS`.

### 2.2 Preserved contracts

- No fields were added to `DetectionResult.to_dict()` or `Diagnostic.to_dict()`.
- Existing Phase 3/4 flow JSON keys were preserved.
- The existing CLI contract remains
  `python -m bugdhor_ast.cli <file> --detect --flow --taint-diagnostics`.
- Backend routes, envelopes, and schemas were unchanged.
- Existing VS Code backend commands and settings were not replaced.
- Coordinates remain one-based in the engine; VS Code adapters convert to/from
  zero-based ranges when matching diagnostics.

---

## 3. Explanation, evidence, root cause, and CWE mapping

Explanations distinguish four evidence categories:

```text
observed, derived, heuristic, unavailable
```

and three confidence levels:

```text
high, medium, low
```

Root-cause localization reports one of:

```text
determined, heuristic, unknown
```

It uses actual AST/CFG/data-flow/taint evidence and does not invent a cause when
evidence is insufficient.

CWE mapping uses a 33-entry rule table. Mappings are emitted only when concrete
evidence exists:

- matched taint sink rules support a mapping; or
- direct null-access rule semantics support a mapping.

Dangerous calls without taint evidence remain unmapped. The implementation does
not claim exploitability, CVE identity, or a universal vulnerability taxonomy.

---

## 4. Deterministic repair and optional AI abstraction

Repair recommendations use:

```text
ready, needs_review, unsupported
```

Deterministic strategies are always attempted first for the supported syntactic
patterns:

- Python parameterized SQL query;
- Python process argument-list conversion;
- JavaScript HTML property to `textContent`;
- Java SQL string concatenation to `PreparedStatement`.

No generic sanitizer is inserted. Unsupported contexts remain `unsupported`;
uncertain contexts remain `needs_review`.

The AI layer is provider-independent and disabled by default:

- no provider is registered in the default registry;
- no SDK or network client is included;
- `AiRepairConfig` must explicitly enable it;
- provider output is treated as an untrusted `UntrustedPatchCandidate`;
- candidate `requires_approval` is always true;
- secret values can be supplied for redaction from provider error messages;
- AI candidates are never automatically applied or promoted to trusted
  recommendations.

Measured default provider registry: empty tuple `()`.

---

## 5. Patch workflow and source-write safety

A preview produces:

- deterministic explanation;
- repair recommendation;
- exact one-based source span;
- original and proposed code;
- unified diff;
- deterministic `patch_id`;
- `can_apply` and `requires_approval`.

Apply and revert safeguards:

- exact patch hash, size, and span are checked;
- target file identity is resolved and compared;
- freshness and overlap checks are performed;
- `PatchApproval(approved=True, confirmation=patch_id)` is required;
- a wrong confirmation refuses the operation before any write;
- exact backup and applied snapshots are stored in patch history;
- revert restores exact pre-apply bytes;
- revert refuses to overwrite a source file changed externally after apply;
- verification refuses reverted history entries.

The local session persists patches, findings, recommendations, and history. It
is local-only, never sent to the backend, and written atomically with mode
`0600`.

No source write occurs from `analyze`, `explain`, `suggest`, `preview`, `verify`,
or `history`.

---

## 6. Independent verification

`verify_repair()` reruns the AST, detection, flow, and taint analyzers from
current source bytes. It does not trust the explanation, recommendation, patch,
or prior analysis result.

Verification states:

```text
verified, partially_verified, failed, not_verified
```

Defined checks:

- target finding reproduced before repair;
- modified source reparses;
- target finding resolved;
- no new finding signatures;
- modified source exactly matches the reviewed patch.

Measured repair matrix:

| Language | Scenario | Recommendation | Verification |
|---|---|---|---|
| Python | SQL query | `ready` | `failed`, target unresolved |
| Python | Process execution | `ready` | `failed`, one new taint finding |
| JavaScript | HTML injection | `ready` | `verified` |
| Java | SQL query | `ready` | `verified` |

The Python failures are caused by current syntax-only taint rules: parameterized
query arguments and subprocess argument lists are still modeled as tainted
sink arguments. They are reported as failures, not hidden. Details are in
`reports/PHASE_6_REPAIR_VALIDATION_REPORT.md`.

Verification does not run compilers, functional tests, dynamic analysis, or a
sandbox. A `verified` status means only that the five defined static checks
passed.

---

## 7. Local Phase 6 CLI

The CLI is JSON-only:

```bash
python -m bugdhor_ast.phase6.cli <action> [options]
```

Actions:

```text
analyze, explain, suggest, preview, apply, verify, revert, history
```

Envelopes:

```json
{"ok": true, "action": "...", "result": {}}
{"ok": false, "action": "...", "error": {"type": "...", "message": "..."}}
```

Exit codes observed:

- `0` for success;
- `1` for workflow errors;
- `2` for CLI argument errors.

`apply` and `revert` additionally require `--allow-source-write` and an exact
`--confirmation` equal to the reviewed `patch_id`.

The end-to-end subprocess test covers:

```text
analyze → explain → suggest → preview → apply denied → apply approved
        → history → verify → revert
```

It also verifies that stdout contains exactly one JSON object and no extra text.

---

## 8. VS Code opt-in integration

Seven new command IDs were added:

| Command ID | Purpose |
|---|---|
| `bugdhor.explainFindingPhase6` | Show evidence-based explanation and suggestion |
| `bugdhor.suggestRepairPhase6` | Show deterministic repair recommendation |
| `bugdhor.previewRepairPhase6` | Show the unified diff without writing |
| `bugdhor.applyRepairPhase6` | Apply a reviewed patch after explicit approval |
| `bugdhor.verifyRepairPhase6` | Verify the latest active applied patch |
| `bugdhor.revertRepairPhase6` | Revert after explicit approval |
| `bugdhor.showRepairHistoryPhase6` | Show persisted local history |

There are 22 canonical command definitions in total, including these seven
local-engine commands. Package manifest contributions and activation events were
extended additively.

New settings:

| Setting | Default |
|---|---|
| `bugdhor.localEngine.enabled` | `false` |
| `bugdhor.localEngine.pythonPath` | `"python"` |
| `bugdhor.localEngine.requestTimeoutMs` | `15000` |
| `bugdhor.localEngine.allowSourceWrite` | `false` |
| `bugdhor.localEngine.sessionPath` | `".bugdhor/phase6-session.json"` |

The adapter runs the explicit CLI module through `execFile` without a shell. It
never executes generated source. Read-only commands do not pass the write flag.
The write helpers independently recheck `allowSourceWrite`; command handlers
also show a modal warning and require the exact `patch_id` through an input box.
Wrong confirmation cancels with no write.

VS Code zero-based diagnostic ranges are matched to one-based engine findings
by rule ID and converted start position. A mismatch produces an explicit error
rather than guessing a finding.

---

## 9. Tests and verification record

### 9.1 Python

| Command | Measured result |
|---|---|
| `PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -q` | `275 passed in 1.51s` |
| Coverage run | `275 passed in 2.46s`; `TOTAL 6526 719 89%` |
| `pytest tests/test_phase6_local.py -v` | `9 passed in 0.73s` |
| Focused explanation/repair modules | `36 passed in 0.13s` |
| Backend `pytest -q` from `security-engine/` | `726 passed in 10.27s` |

### 9.2 JavaScript

| Command | Measured result |
|---|---|
| `npm test` in `vscode-extension/` | 401 tests, 400 pass, 1 fail |
| `node --test test/unit/phase6LocalEngine.test.js` | 10 tests, 10 pass |
| `npm run lint` in `vscode-extension/` | clean |
| Root `npm test` | fails through the same extension identity assertion |

The only failing test is pre-existing and user-owned:

```text
identity fields match the approved extension identity
expected: 'Bug Dhor Security Framework'
actual:   'Bug Dhor Security Framewor'
```

The assertion and package identity were not changed.

### 9.3 Lint

Scoped Ruff check over `src/bugdhor_ast/explain`, `src/bugdhor_ast/phase6`,
`tests/test_phase6_local.py`, and the Phase 6 benchmark harness reports:

```text
All checks passed!
```

A broader Ruff run that includes older test files still reports 17 pre-existing
errors. Those files were not changed for Phase 6.

### 9.4 Coverage interpretation

Phase 6 service coverage is 86% and session coverage is 88%. The Phase 6 CLI
shows 0% because coverage.py traces the in-process pytest run, while CLI tests
execute it as a subprocess. CLI behavior is covered end to end by subprocess
assertions; no CLI line-coverage claim is made.

---

## 10. Benchmarks

The new harness `benchmarks/harness/run_phase6_performance.py` measures the
complete read-only core workflow on deterministic Python, JavaScript, and Java
sources at three sizes. Raw data is in
`benchmarks/results/phase6-performance/results.json`.

Measured range across nine workloads:

- median total time: `0.005509 s`–`0.065821 s`;
- peak `tracemalloc`: `0.197 MiB`–`1.914 MiB`;
- verification dominated total time;
- explanation, recommendation, and patch construction were sub-millisecond.

This is a performance measurement, not a security benchmark. The coding
benchmark remains `not_run`, with `claimKind: null` and null metrics in its
readiness bundle.

---

## 11. Documentation updates

Updated:

- `docs/README.md` — Phase 6 report link and opt-in summary.
- `docs/scope-data-flow-analysis.md` — Phase 6 evidence/repair/verification
  extension and command/settings reference.
- `vscode-extension/README.md` — local-engine status, commands, settings,
  approval workflow, limitations, layout, and test status.
- `benchmarks/README.md` was left unchanged in this step because it contains
  user-owned Phase 4 edits; Phase 6 results are referenced from the new
  benchmark report.

---

## 12. Preserved user-owned changes

The following user-owned modifications were inspected and left intact:

- `vscode-extension/package.json`
  - `"displayName": "Bug Dhor Security Framewor"`
  - `"publisher": "sajib91"`
- `vscode-extension/src/commands/runEngineCommand.js` non-blocking
  `reportFailure` behavior.
- `vscode-extension/test/integration/index.js` watchdog/error echo changes.
- Existing user edits in `docs/README.md` and `benchmarks/README.md`.
- Manifest identity assertions were not changed to make the pre-existing test
  pass.

---

## 13. Limitations and non-claims

Phase 6 does **not** provide:

- SAE feature extraction, activation steering, or counterfactual model analysis;
- exploitability proofs;
- functional-correctness proofs;
- guaranteed-secure repairs;
- repository-wide call-site completeness;
- dynamic analysis or sandboxing;
- execution-based coding-benchmark results;
- JavaScript coverage measurements;
- a clean full extension test suite while the user-owned identity mismatch
  remains.

Python SQL and subprocess repairs require manual review because the current
static taint engine cannot verify them cleanly. AI repair is optional,
provider-neutral, disabled by default, and returns untrusted candidates only.

---

## 14. Repository state

All Phase 3–6 work remains uncommitted or untracked at the time of this report.
No push, pull request, review, merge, or release was performed. This report is a
local verification record only.

---

## 15. Reproduction commands

From the repository root:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ -q
PYTHONPATH=src ./.venv/bin/python -m pytest tests/ \
  --cov=bugdhor_ast --cov-report=term-missing -q
../.venv/bin/python -m pytest -q   # from security-engine/
./.venv/bin/python -m ruff check \
  src/bugdhor_ast/explain \
  src/bugdhor_ast/phase6 \
  tests/test_phase6_local.py \
  benchmarks/harness/run_phase6_performance.py
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase6_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase6-performance/results.json
```

From `vscode-extension/`:

```bash
npm test
node --test test/unit/phase6LocalEngine.test.js
npm run lint
```

---

## 16. Conclusion

Phase 6 is implemented as an additive, opt-in local workflow. Explanations are
grounded in existing static-analysis evidence; root causes, CWE mappings,
repairs, and verification results preserve explicit uncertainty. Patch writing
is guarded by exact identity checks, approval, history, and revert. The local
CLI and VS Code integration were exercised end to end.

The implementation is complete within the measured boundaries, with the
documented Python static-verification limitations, the `not_run` coding
benchmark, and the pre-existing user-owned extension identity assertion noted
above.
