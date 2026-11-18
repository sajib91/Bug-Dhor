# Secure code recommendations and the continuous feedback loop

This document describes the proposal-only secure recommendation workflow and the
bounded feedback loop in the VS Code extension. It complements the
[HTTP API](api.md), [repository-aware repair](repair.md), and
[AI assistant integration](ai-assistant-integration.md) documents.

## 1. Non-claims and safety boundary

Bug Dhor does **not** guarantee secure, correct, or functionally perfect code. A
recommendation is a reviewable proposal, not a merged change.

- The backend never writes to the workspace and never applies a patch.
- `requiresApproval` is always `true` in a recommendation response.
- A candidate is recommended only when every mandatory gate passes. Missing,
  denied, unavailable, or failing evidence is reported as such; it is never
  converted into a pass.
- The extension records an applied patch in the feedback loop only after the
  user explicitly approves the change, the document base hash is revalidated,
  and the `WorkspaceEdit` succeeds. Editor events and hook metadata are never
  authorship evidence.
- API-driven activation steering is always `None`/not applied. Only a direct
  local engine caller with genuine D/E/F access and a real steering pipeline
  may request steering, and SAE/counterfactual evidence remains a hypothesis
  rather than observed causal proof.

## 2. Secure recommendation workflow

The backend executes these stages in order and reports each one honestly:

1. `receive_findings`
2. `source_context`
3. `cwe_requirements`
4. `repository_context`
5. `security_evidence`
6. `secure_prompt`
7. `generate_candidates`
8. `syntax`
9. `static_analysis`
10. `functional_tests`
11. `rank_candidates`
12. `display_recommendation`

The secure prompt is injection-hardened: content inside `<untrusted_*>` tags is
data only, CWE-specific requirements are explicit, and provider provenance is
recorded without credentials. The prompt text is returned in
`result.prompt.text` so the extension can drive a configured provider from the
backend-built prompt. Stage reports retain prompt metadata only.

### Mandatory gates

A patch can be selected only if it satisfies all of these constraints:

| Gate | Requirement |
|---|---|
| Syntax | The patched source must parse. |
| Patch scope | Only the inspected target file may be touched, within the file-count limit. |
| Independent verification | The security verifier must report a passing classification with no regression. |
| Functional tests | Tests must run and pass; the minimum pass rate is `1.0` and regressions are rejected. |
| Regression checks | Required regression checks must pass. |
| CWE requirements | The CWE-specific remediation requirements must be met. |
| Ranking | The ranker must accept the candidate after applying mandatory constraints. |

Consequently, no consent, no sandbox, no test command, a denied test run, or an
unavailable verifier means **no recommended candidate**. The result state is
`rejected`, `verified` is `false`, `repairedCode` is `null`, and a warning
explains that no candidate passed the mandatory gates.

Functional tests are required by design. The
`bugdhor.recommendations.runFunctionalTests` and
`bugdhor.recommendations.allowSandboxedExecution` settings cannot weaken the
gate; they only decide whether a test run is possible. Network, privileged, and
destructive test operations remain forbidden.

## 3. Backend endpoint

`POST /api/v1/recommendations/generate` is the proposal-only entry point.

Required and commonly supplied request fields:

| Field | Purpose |
|---|---|
| `workspaceRoot`, `filePath` | Common file context; containment rules apply. |
| `sourceText`, `documentUri`, `documentVersion` | Optional editor snapshot and location metadata. |
| `finding` | Validated finding with `findingId`, `cwe`, `ruleId`, and range. A mismatched `documentUri` is rejected. |
| `candidates` | Zero or more unified diffs (at most eight). An empty list asks only for the secure prompt. |
| `provider` | Non-secret provenance: `providerId`, `modelId`, `capabilities`, `hosted`, `steeringRequested`, `steeringValidated`. No keys are accepted or returned. |
| `securityEvidence` | Claim-kinded observations/explanations supplied by validated analysis. |
| `executionConsent` | Explicit, non-network, non-privileged, non-destructive consent metadata. |
| `runFunctionalTests`, `projectTestCommand`, `testTimeoutSeconds` | Functional verification inputs. |
| `snapshotHash` | SHA-256 of the source snapshot used to build the candidates. |

The result includes `findingId`, `cwe`, `state`, `originalCode`, `repairedCode`,
`selected`, `candidates`, `prompt` (including `text`), `stages`, `explanation`,
`requiresApproval`, `verified`, and `metadata`. Metadata records
`appliedByEngine: false`, `securityGuarantee: "none"`, and steering provenance.
No API key, bearer token, or other credential is echoed back.

See [api.md](api.md#secure-recommendations) for the transport contract.

## 4. Provider-backed generation in VS Code

**Bug Dhor: Generate Secure Code** is a custom, provider-backed command rather
than a plain engine command. With a valid finding in the active saved editor, it:

1. Requires a diagnostic finding that the diagnostics controller published from
   a validated backend scan. A command-palette invocation without such a
   finding generates nothing.
2. Requires the active editor URI to match the request document URI.
3. Requires an available configured provider exposing capabilities **B** and
   **C** (generation request and response access). The `editor-monitor`
   provider exposes only A and is rejected with a clear error before any
   request is made.
4. Calls `POST /api/v1/recommendations/generate` with no candidates to obtain
   the backend-built secure prompt.
5. Calls the configured provider with that prompt. Hosted assistants expose
   A/B/C only and never report validated steering.
6. Extracts fenced unified diffs for the target file, validates them with the
   patch application code, and submits at most three candidates back to the
   backend for verification.
7. Returns the backend recommendation to the dashboard. The extension does not
   apply it.

If the prompt is unavailable, cancellation is requested, the provider returns
no applicable diff, or verification fails, the command reports the failure and
no patch is stored as recommended.

## 5. Dashboard review and explicit approval

The dashboard's **Automated Repair** section shows each secure recommendation
with:

- the exact original source from the backend snapshot and the verified
  repaired source;
- what changed, why it changed, and remaining risks;
- verification and functional-test results, workflow state, and prompt
  provenance;
- bandwidth-limited visibility of unavailable candidates rather than an
  invented patch;
- **View inline diff**, **Accept patch**, and **Reject patch** controls where
  applicable.

Acceptance follows the same safety path as other repair proposals: an explicit
warning confirmation, base-hash revalidation against the current document,
target-path filtering, and a successful `WorkspaceEdit`. A verified secure
recommendation applies the backend's full repaired source; other proposals use
a single-file unified diff. Stale snapshots cannot be applied. Only after a
successful edit does the dashboard call
`feedback.recordAppliedPatch()` with source `dashboard.explicit-approval`.

## 6. Bounded continuous feedback loop

The feedback loop observes, analyzes, explains, recommends only on request,
verifies, updates diagnostics, rescans, and tracks resolution. It is bounded so
an applied patch cannot cause endless analysis.

### Recording and deduplication

- The diagnostics controller publishes only validated backend findings through
  `publishScanResult()`. Hooks record metadata only; they never synthesize or
  resolve findings and never infer authorship.
- `FeedbackController.afterScan()` deduplicates a hook/monitor pair reporting
  the same `requestId` and scope URIs so one scan is recorded once.
- `PatchOriginTracker` records only patches that the extension applied after
  explicit approval.

### Suppression and rescanning

- After an applied patch, `RealtimeMonitor` consults feedback before analyzing a
  changed document. One immediate self-induced scan is suppressed.
- Exactly one bounded follow-up rescan is scheduled for that document and
  hash. A second scan with the same applied hash is not suppressed again.
- `RealtimeMonitor.cancelAnalysis(uri, cause?)` cancels pending and in-flight
  analysis for a document without publishing findings.

A finding is not resolved by a hook event, an editor change, a passing
verification alone, or a clean rescan alone. All three signals are required:

1. an explicitly applied Bug Dhor patch,
2. a clean rescan that no longer reports the finding in scope, and
3. a passing verification result.

If the order is verification-then-rescan or rescan-then-verification, the
controller counts the transition into `resolved` exactly once and sends a
notification when enabled. If the finding appears again later, it reopens as
`regressed` and can be resolved again only after the same three signals.

### Settings

| Setting | Default | Effect |
|---|---|---|
| `bugdhor.feedback.notifyOnPatchApplied` | `true` | Notify when an explicitly applied patch is recorded. |
| `bugdhor.feedback.notifyOnResolution` | `true` | Notify when a finding reaches `resolved`. |
| `bugdhor.recommendations.runFunctionalTests` | `true` | Request functional tests; disabling them prevents recommendation rather than bypassing them. |
| `bugdhor.recommendations.allowSandboxedExecution` | `false` | Permit sandboxed test execution; network/privileged/destructive operations stay forbidden. |
| `bugdhor.recommendations.testCommand` | `[]` | Optional argv list for the project's functional tests. |
| `bugdhor.recommendations.testTimeoutSeconds` | `120` | Per-run functional-test timeout (1–3600 seconds). |

API keys remain in environment variables and are never stored in settings,
request payloads, responses, or logs. Extension-specific providers still
require an official manifest with `documentationUrl`, `apiVersion`, and declared
methods.

## 7. Verification

- Extension: `npm test` and `npm run lint` in `vscode-extension/`.
- Backend: `PYTHONPATH=src ./.venv/bin/python -m pytest
  tests/api/test_recommendation.py tests/api/test_openapi.py
  tests/unit/test_pipeline.py tests/integration/test_secure_recommendation.py -q`
- Lint: `./.venv/bin/ruff check src/bugdhor/recommendation
  src/bugdhor/api/schemas/recommendation.py
  src/bugdhor/api/routes/recommendation.py
  tests/integration/test_secure_recommendation.py tests/api/test_recommendation.py`

The suite covers proposal-only contracts, prompt isolation, SQL/command
injection cases, scripted verifiers, syntax/regression rejection, steering
gating, provider B/C enforcement, candidate extraction, cancellation, deduped
feedback, one-shot suppression/bounded rescan, resolution ordering, and dashboard
display/approval.
