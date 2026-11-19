# Phase 6 Repair Validation Report — Bug-Dhor

**Date:** 2026-11-19  
**Repository:** `/Users/md.khayrulislamsajib/Downloads/Bug-Dhor`  
**Scope:** Deterministic repair recommendations, exact patch previews, and independent static verification.  
**Raw test evidence:** `tests/test_phase6_local.py`, `reports/PHASE_6_TEST_REPORT.txt`

---

## 1. Purpose and claim boundary

This report records the measured behavior of the Phase 6 repair workflow. It
does **not** claim that a repair is exploit-proof, functionally correct, or
universally safe. Verification means one specific thing here: the modified
source is reparsed and reanalyzed with the same local static engines, then
checked against the original finding, patch identity, new finding signatures,
and exact reviewed bytes.

No repaired or generated source was executed. No sandbox is implemented or
claimed. No functional test suite was run for the generated repairs.

---

## 2. Validation method

For each case below, the workflow was:

1. Build an analysis payload from the original source using the existing AST,
   detection, CFG/data-flow, and taint engines.
2. Select the deterministic `*-TAINT001` finding.
3. Build an evidence-based explanation and deterministic repair recommendation.
4. Build an exact patch when the recommendation status was `ready`.
5. Apply patch edits **in memory only** with the same span-replacement helper
   used by the patch layer. No repository source file was modified.
6. Call `verify_repair()` with the original source, reviewed patch, and modified
   source. Verification runs independent static reanalysis; it does not trust
   the recommendation.

The five measured verification checks are:

- `baseline` — the target finding reproduced before repair;
- `reparse` — modified source reparsed without syntax errors;
- `target_resolution` — target finding count decreased after repair;
- `new_findings` — no new finding signatures after repair;
- `patch_identity` — modified source exactly matches the reviewed patch.

---

## 3. Measured repair matrix

| Language | Scenario | Recommendation | Strategy | Patch | Verification | `target_resolved` | New findings |
|---|---|---|---|---|---|---:|---:|
| Python | SQL query | `ready` | `python_sql_parameterization` | yes | `failed` | `false` | 0 |
| Python | Process execution | `ready` | `python_process_argument_list` | yes | `failed` | `true` | 1 |
| JavaScript | HTML injection | `ready` | `javascript_html_property_to_text_content` | yes | `verified` | `true` | 0 |
| Java | SQL query | `ready` | `java_prepared_statement` | yes | `verified` | `true` | 0 |

The matrix was measured directly from the current implementation. The Python
results are reported as failures, not hidden or relabeled as successes.

---

## 4. Detailed Python failures

### 4.1 Python SQL — `failed`

Original finding: `PY-TAINT001`, untrusted data from `request.args.get` reaching
a database query.

Patch applied in memory:

```python
q = request.args.get('q')
cursor.execute('SELECT * FROM users WHERE name = ?', (q,))
```

Measured summary:

```json
{
  "before_findings": 3,
  "after_findings": 3,
  "target_before": 1,
  "target_after": 1,
  "target_resolved": false,
  "new_finding_count": 0,
  "new_findings": []
}
```

Check details:

- `baseline`: pass — target reproduced once before repair.
- `reparse`: pass — modified source reparsed.
- `target_resolution`: fail — target remained at 1.
- `new_findings`: pass — no new signatures.
- `patch_identity`: pass — source exactly matched the patch.

Observed after-reanalysis finding: the current syntax-only taint engine still
reports `PY-TAINT001` because tainted `q` remains an argument to the database
query sink. The engine does not model parameterized-query semantics well enough
to clear this case. This is a verification limitation of the current static
analyzer; it is not proof that the patch is insecure or secure.

### 4.2 Python process execution — `failed`

Original finding: `PY-TAINT001`, untrusted data from `os.getenv` reaching
`os.system`.

Patch applied in memory:

```python
import subprocess
token = os.getenv('T')
subprocess.call(['echo', token])
```

Measured summary:

```json
{
  "before_findings": 4,
  "after_findings": 2,
  "target_before": 1,
  "target_after": 0,
  "target_resolved": true,
  "new_finding_count": 1,
  "new_findings": [
    {
      "rule_id": "PY-TAINT001",
      "message": "Untrusted data from os.getenv reaches Subprocess execution.",
      "language": "python",
      "count": 1
    }
  ]
}
```

Check details:

- `baseline`: pass.
- `reparse`: pass.
- `target_resolution`: pass — the original `os.system` target was resolved.
- `new_findings`: fail — one new `PY-TAINT001` signature remains for the
  subprocess argument list.
- `patch_identity`: pass.

The current taint rule pack treats taint reaching any subprocess argument as a
finding and does not model the shell=no-argument-list distinction. The repair
must therefore remain `needs manual review` in verification terms.

---

## 5. Verified cases

### 5.1 JavaScript HTML injection

The deterministic strategy changes assignment to an HTML property into a
`textContent` assignment. Static reanalysis returned:

- status: `verified`;
- `target_resolved: true`;
- `new_finding_count: 0`;
- all five checks pass.

This is static verification only. It does not prove browser-level behavioral
equivalence for every application.

### 5.2 Java SQL injection

The deterministic strategy converts string-concatenated SQL into a
`PreparedStatement` form with a placeholder and bound parameter. Static
reanalysis returned:

- status: `verified`;
- `target_resolved: true`;
- `new_finding_count: 0`;
- all five checks pass.

This is static verification only. It does not execute Java or prove that all
JDBC call sites in a repository were repaired.

---

## 6. Patch workflow safety validation

The following safety behaviors were verified in `tests/test_phase6_local.py`:

- Preview is read-only: source bytes are unchanged and the patch includes a
  unified diff.
- Apply requires an exact `patch_id` confirmation; a wrong confirmation is
  refused before writing.
- Apply stores exact backup and applied snapshots and a history entry.
- Verify reruns analyzers from current source bytes and refuses reverted
  entries.
- Revert restores exact pre-apply bytes.
- Revert refuses to overwrite a file changed externally after apply.
- Session files are persisted with mode `0600`.
- The CLI requires `--allow-source-write` for apply/revert.
- The VS Code adapter independently rechecks
  `bugdhor.localEngine.allowSourceWrite`, shows a modal warning, and requires
  the developer to type the exact `patch_id`.

No automatic source modification occurs after a suggestion or preview.

---

## 7. Evidence and status vocabulary

- Explanation evidence: `observed`, `derived`, `heuristic`, `unavailable`.
- Root cause status: `determined`, `heuristic`, `unknown`.
- Repair recommendation status: `ready`, `needs_review`, `unsupported`.
- Verification status: `verified`, `partially_verified`, `failed`,
  `not_verified`.

CWE mappings are emitted only when concrete taint sink rules or direct null
access rule semantics support them. Dangerous calls without taint evidence
remain unmapped.

---

## 8. Limitations

- The current taint engine is syntax-driven and conservative; Python SQL
  parameterization and subprocess argument-list patterns can remain findings.
- Verification does not run language compilers, unit tests, functional tests,
  or dynamic analysis.
- A `verified` status means only that the defined static checks passed.
- AI-generated candidates, when explicitly enabled, are untrusted and are
  never automatically promoted to a trusted recommendation or applied.
- No repository-wide call-site proof, exploitability proof, sandbox, or
  security guarantee is provided.

---

## 9. Reproduction

From the repository root:

```bash
PYTHONPATH=src ./.venv/bin/python -m pytest tests/test_phase6_local.py -v
PYTHONPATH=src ./.venv/bin/python -m pytest \
  tests/test_explain_schema.py \
  tests/test_explain_evidence.py \
  tests/test_explain_repair.py \
  tests/test_explain_repair_patch.py \
  tests/test_explain_repair_ai.py -q
```

The benchmark harness also records verification status per workload:

```bash
PYTHONPATH=src ./.venv/bin/python \
  benchmarks/harness/run_phase6_performance.py \
  --repeats 5 \
  --output benchmarks/results/phase6-performance/results.json
```
