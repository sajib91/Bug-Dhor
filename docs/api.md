# Bug Dhor HTTP API

**Status:** Versioned FastAPI transport implemented and tested. File inspection and
workspace discovery are real. A proposal-only secure recommendation endpoint is
implemented with mandatory verification gates; it never applies code. Detection,
explanation, SAE features, counterfactuals, steering, repair, and verification
operations are declared; where a stage is not implemented or unconfigured it
returns `unavailable` and its result payload contains no fabricated data.

- Base URL: `http://127.0.0.1:8765`
- API prefix: `/api/v1`
- OpenAPI schema: `GET /openapi.json`
- Interactive docs: `GET /docs` and `GET /redoc`
- Media type for success: `application/json`
- Media type for errors: `application/problem+json` (RFC 9457)

The full target API in [architecture.md](architecture.md#72-endpoint-surface-initial-contract)
is broader than the surface implemented in this phase. The endpoints below are the
complete set exposed by the current server.

## Running the server

From `security-engine/`:

```bash
../.venv/bin/python -m bugdhor
# or, when the package is installed:
../.venv/bin/bugdhor
```

Host and port are configurable:

```bash
../.venv/bin/python -m bugdhor --host 127.0.0.1 --port 8765
# or
BUGDHOR_HOST=127.0.0.1 BUGDHOR_PORT=8765 ../.venv/bin/python -m bugdhor
```

The server is local-first. The default bind address is loopback, CORS is disabled
unless explicit origins are configured, and there is no hardcoded secret.

| Variable | Default | Purpose |
|---|---|---|
| `BUGDHOR_HOST` | `127.0.0.1` | Bind address |
| `BUGDHOR_PORT` | `8765` | Bind port (`0` selects an ephemeral port) |
| `BUGDHOR_CORS_ORIGINS` | empty | Comma-separated or JSON-array origin allowlist; `*` is rejected |
| `BUGDHOR_WORKSPACE_ROOTS` | process working directory | Comma-separated or JSON-array roots allowed for scans |
| `BUGDHOR_MAX_REQUEST_BYTES` | `2097152` (2 MB) | Maximum JSON request body |
| `BUGDHOR_MAX_FILE_BYTES` | `1048576` (1 MB) | Maximum inspected file size |
| `BUGDHOR_MAX_WORKSPACE_FILES` | `50000` | Maximum files discovered in one workspace scan |
| `BUGDHOR_API_TOKEN` | unset | Optional bearer token for `/api/*` requests |
| `BUGDHOR_SANDBOX_BACKEND` | `docker` | Reported sandbox backend |

All settings may also be supplied in a local `.env` file. See
[`.env.example`](../.env.example).

## Request context

File-oriented endpoints accept this common context, using camelCase JSON:

| Field | Required | Description |
|---|---|---|
| `workspaceRoot` | yes | Workspace root; must resolve inside `BUGDHOR_WORKSPACE_ROOTS` |
| `filePath` | yes | Absolute path or path relative to `workspaceRoot` |
| `documentUri` | no | Editor document URI; validated findings must match the inspected file |
| `languageId` | no | Editor language identifier; otherwise inferred from the extension |
| `documentVersion` | no | Editor document version |
| `selection` | no | Zero-based `{ start: { line, character }, end: { line, character } }` |
| `selectedText` | no | Optional editor selection text |
| `sourceText` | no | Current editor buffer text. When present, it is hashed and inspected instead of re-reading the saved file |

Paths are fully resolved. `..` traversal and symlinks that escape the workspace
root are rejected. Binary and non-UTF-8 files are rejected.

`sourceText` lets an editor scan unsaved changes. The path must still exist and
resolve inside the allowed workspace root; the configured
`BUGDHOR_MAX_FILE_BYTES` limit applies to the supplied UTF-8 text, and NUL bytes
are rejected. The response `file.sha256` and `file.size` describe the supplied
text, not the disk copy. Clients should send `sourceText` and `selectedText`
only after explicit user action and only when source sharing is enabled.

## Operation envelope

Every successful analysis or scan response uses one envelope:

```json
{
  "operation": "scan_file",
  "status": "partial",
  "apiVersion": "v1",
  "requestId": "9f33c6d4f8c84a2ab4ef5e6f0d1c2b3a",
  "stages": [
    {
      "stage": "file_snapshot",
      "status": "ok",
      "reasonCode": null,
      "detail": null,
      "warnings": [],
      "data": { "size": 6, "sha256": "…", "languageId": "python" }
    },
    {
      "stage": "static_evidence",
      "status": "unavailable",
      "reasonCode": "E_ANALYZER_UNAVAILABLE",
      "detail": "No static analyzer adapter is implemented or enabled.",
      "warnings": [],
      "data": {}
    }
  ],
  "warnings": [],
  "result": null
}
```

### Aggregate statuses

| Status | Meaning |
|---|---|
| `completed` | Every stage completed successfully. |
| `partial` | At least one stage completed, but another stage was unavailable, partial, or skipped. |
| `unavailable` | No stage provided an analysis result. |
| `failed` | A stage failed. The HTTP response is a sanitized problem detail. |

### Stage statuses

| Status | Meaning |
|---|---|
| `ok` | The stage ran and produced its declared output. |
| `partial` | The stage ran with explicit limitations. |
| `skipped` | The stage was intentionally not run. |
| `unavailable` | The capability is absent or unconfigured. No output is invented. |
| `failed` | The stage failed. |

**`unavailable` is never a clean scan.** Clients must not convert an unavailable
stage into an empty successful result, a zero risk score, or a pass verdict.

## Endpoints

| Method | Path | Required request fields | Current result |
|---|---|---|---|
| GET | `/api/v1/health` | — | Service metadata, uptime, and capability flags |
| POST | `/api/v1/scan/file` | `workspaceRoot`, `filePath` | File hash/size/language and scope; empty findings |
| POST | `/api/v1/scan/workspace` | `workspaceFolders[]` with `name`, `path` | Discovered source-file scope; empty findings |
| POST | `/api/v1/detection/analyze` | common context | Empty findings; detector and analyzer unavailable |
| POST | `/api/v1/explanation/analyze` | common context plus `finding` or `findingId` | No explanation graph |
| POST | `/api/v1/features/extract` | common context | No SAE features |
| POST | `/api/v1/counterfactual/analyze` | common context, `findingId`, one or more `interventions` | No effects or validity estimate |
| POST | `/api/v1/prevention/steer` | common context, `featureIndices`, `targetMetric`, `explicitOptIn=true` | No steering plan or evaluation |
| POST | `/api/v1/repair/generate` | common context plus `finding` | No patch |
| POST | `/api/v1/recommendations/generate` | common context plus `finding` | Proposal only; verified candidate when all mandatory gates pass |
| POST | `/api/v1/verification/run` | common context plus `repairId` or `patch` | `verdict: "not_run"` |

### Health

`GET /api/v1/health` returns `200` when the process is alive. Capability flags are
derived from the registered operation stages, not from optimistic configuration.
`recommendation_generate: true` means the proposal workflow is registered; it
does not promise that a given candidate will pass verification.

```json
{
  "service": "bugdhor-engine",
  "status": "ok",
  "version": "0.1.0",
  "apiVersion": "v1",
  "timestamp": "2026-11-12T00:00:00Z",
  "uptimeSeconds": 12.4,
  "capabilities": {
    "scan_file": true,
    "scan_workspace": true,
    "detection_analyze": true,
    "explanation_analyze": true,
    "features_extract": false,
    "counterfactual_analyze": false,
    "prevention_steer": false,
    "repair_generate": true,
    "recommendation_generate": true,
    "verification_run": true
  },
  "sandboxBackend": "docker"
}
```

### Scans

`scan/file` inspects the requested file, computes its SHA-256, records size and
language, and runs the scan pipeline. When `sourceText` is supplied, its hash and
size replace the on-disk values while the file path remains the containment
anchor. `scan/workspace` walks each allowed root without following symlinks,
ignores generated directories such as `.git`, `node_modules`, `dist`, and
`__pycache__`, and returns file URIs.

Both scans currently return:

- `status: "partial"` because the snapshot stage succeeds while evidence and
  detection are unavailable;
- `findings: []`;
- `analysisAvailable: false`;
- explicit unavailable stages with reason codes.

An empty `findings` array does **not** mean the file is secure. It means no
detector produced findings.

### Analysis endpoints

The analysis endpoints currently return `200` with a `partial` envelope and a
typed result whose `analysisAvailable` is `false`. Result-specific guarantees:

| Endpoint | Never fabricated in this phase |
|---|---|
| `detection/analyze` | findings, evidence sources, score kind |
| `explanation/analyze` | graph, claims, feature evidence |
| `features/extract` | feature IDs, activations, coverage |
| `counterfactual/analyze` | effects, validity, confidence |
| `prevention/steer` | steering plan, guardrails, evaluation |
| `repair/generate` | patch, touched files, rationale |
| `verification/run` | checks, verdict; verdict is `not_run` |

Requests are schema-validated before file inspection. Examples of enforced
constraints:

- explanation requires `finding` or `findingId`;
- activation steering requires `explicitOptIn: true`;
- execution verification requires `profile: "sandbox"`;
- intervention feature indices are non-negative;
- ranges are ordered and selections must fit the inspected file.

### Secure recommendations

`POST /api/v1/recommendations/generate` runs the 12-stage secure recommendation
workflow and returns a **proposal only**. The endpoint never writes to the
workspace, and `requiresApproval` is always `true`.

The request extends the common file context with:

| Field | Required | Description |
|---|---|---|
| `finding` | yes | Validated finding (`findingId`, `cwe`, `ruleId`, ordered `range`); a mismatched `documentUri` is rejected |
| `candidates` | no | Up to eight unified diffs; an empty list returns the secure prompt without generating candidates |
| `provider` | no | Non-secret provenance only: `providerId`, `modelId`, `capabilities`, `hosted`, `steeringRequested`, `steeringValidated` |
| `securityEvidence` | no | Up to 100 claim-kinded observations/explanations supplied by validated analysis |
| `snapshotHash` | no | SHA-256 of the source snapshot used to create candidates |
| `executionConsent` | no | Explicit, non-network, non-privileged, non-destructive consent metadata |
| `runFunctionalTests` | no | Defaults to `true`; disabling it prevents recommendation rather than bypassing the gate |
| `projectTestCommand` | no | Optional argv list for functional tests |
| `testTimeoutSeconds` | no | 1–3600 seconds; defaults to 120 |

The result carries `findingId`, `cwe`, `state`, `originalCode`, `repairedCode`,
`selected`, `candidates`, `prompt`, `stages`, `explanation`, `requiresApproval`,
`verified`, and `metadata`. `result.prompt.text` is the backend-built,
injection-hardened prompt; stage reports keep only prompt metadata. Metadata
records `appliedByEngine: false`, `securityGuarantee: "none"`, and steering
provenance. No credential is accepted or echoed back.

For HTTP requests, `metadata.steering.pipeline` is always `null` and steering is
never marked applied. Genuine activation steering exists only for validated
local D/E/F callers with a real pipeline; SAE/counterfactual claims remain
hypotheses.

A candidate is recommended only after syntax, patch-scope, independent security
verification, functional tests, regression checks, CWE requirements, and
ranking all pass. If any gate is missing or fails, `state` is `rejected`,
`verified` is `false`, `repairedCode` is `null`, and a warning states that no
candidate passed the mandatory gates. An empty findings list or unavailable
stage is never a clean result.

See [secure recommendations and feedback](secure-recommendation-and-feedback.md)
for the full workflow, verification gates, and extension approval flow.

## Errors

Errors use RFC 9457 problem details with `application/problem+json`:

```json
{
  "type": "https://bugdhor.local/errors/E_VALIDATION",
  "title": "Request validation failed",
  "status": 422,
  "code": "E_VALIDATION",
  "detail": "One or more request fields are invalid.",
  "instance": "/api/v1/scan/file",
  "retryable": false,
  "requestId": "9f33c6d4f8c84a2ab4ef5e6f0d1c2b3a",
  "details": {
    "errors": [
      {
        "location": ["body", "filePath"],
        "message": "Field required",
        "type": "missing"
      }
    ]
  }
}
```

| HTTP | Code | Meaning |
|---|---|---|
| 401 | `E_UNAUTHORIZED` | Bearer token missing, malformed, or invalid |
| 403 | `E_ROOT_NOT_ALLOWED` | Workspace root outside the configured allowlist |
| 403 | `E_PATH_OUTSIDE_WORKSPACE` | File or symlink target outside the workspace |
| 404 | `E_NOT_FOUND` | Route, workspace root, or file not found |
| 405 | `E_METHOD_NOT_ALLOWED` | Method not supported by the route |
| 413 | `E_REQUEST_TOO_LARGE` | JSON body exceeds the request limit |
| 413 | `E_FILE_TOO_LARGE` | File exceeds the analysis limit |
| 413 | `E_WORKSPACE_TOO_LARGE` | Workspace exceeds the file-count limit |
| 415 | `E_UNSUPPORTED_FILE` | Binary or non-UTF-8 content |
| 422 | `E_VALIDATION` | Pydantic or domain validation failure |
| 500 | `E_INTERNAL` | Sanitized internal error; details are logged, not returned |

Every response carries `X-Request-ID`. A valid client-supplied value is echoed;
otherwise the server generates one. Internal exception text and secrets are never
returned in problem details.

## Authentication

When `BUGDHOR_API_TOKEN` is set, all `/api/*` requests require:

```http
Authorization: Bearer <token>
```

Comparison is constant-time. Tokens are supplied at process launch and are never
returned by health, logs, or settings output. Preflight `OPTIONS` requests are not
blocked. `/`, `/docs`, `/redoc`, and `/openapi.json` are not token-protected in this
phase; expose the server only on loopback or a trusted network.

## CORS, limits, and logging

- CORS is off by default. When configured, only exact origins are allowed;
  wildcards and credentialed origins are rejected. Credentials are disabled.
- Request bodies are limited while streaming; declared and actual sizes are
  enforced.
- Scans enforce file-size and workspace-file-count limits.
- Logs are one JSON object per line with request ID, method, path, status, and
  duration. Request bodies and source text are not logged.
- All configuration is environment-backed. No secret is hardcoded.

## Shared JSON contracts

The versioned endpoints in this document return interim operation envelopes. The
shared contracts in [`shared/schemas/`](../shared/schemas/README.md) define the
target payloads for `ScanRequest`, `ScanResult`, `VulnerabilityFinding`,
`FeatureExtractionResult`, `CounterfactualResult`, `SteeringResult`,
`ExplanationResult`, `RepairCandidate`, `VerificationResult`, and
`ExperimentMetadata`. `shared/schemas/manifest.json` maps each contract to its
schema and fixtures; the same schemas and fixtures are validated by the Python and
JavaScript test suites.

Downstream implementations must follow these rules:

- **Score semantics.** Every `riskScore` carries `kind` and `interpretation`.
  `heuristic` maps to `heuristic_risk` in `[0, 1]`; `model_logit` maps to
  `model_score_not_calibrated` and is unbounded; `calibrated` maps to
  `calibrated_probability` in `[0, 1]` and requires a calibrator artifact,
  dataset identity, split hash, Brier score, and expected calibration error.
  Only `calibrated` may be rendered or described as a probability.
- **Availability.** `analysisAvailable: false` means the analysis stage produced
  no result. Results must then carry empty findings, features, effects, claims,
  or checks; verification must report `not_run`, and a steering plan must be
  `null`. An empty findings list is not a clean scan result.
- **Approval.** Repair candidates and secure recommendations always carry
  `requiresApproval: true`; the backend does not apply patches.
- **Unknown fields.** Payload schemas reject unknown fields so a client cannot
  silently depend on undocumented data.

## Related documentation

- [Architecture and target contract](architecture.md)
- [Repository-aware repair](repair.md)
- [Secure recommendations and feedback](secure-recommendation-and-feedback.md)
- [Shared JSON Schemas](../shared/schemas/README.md)
- [Research integrity contract](research-alignment.md)
- [Engine limitations](../security-engine/LIMITATIONS.md)
- [Development setup](development-setup.md)
