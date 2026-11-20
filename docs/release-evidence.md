# Release evidence contract

The release-gate manifest treats three facts as external because ordinary CI
logs cannot establish them:

| Gate                        | Required evidence artifact           |
| --------------------------- | ------------------------------------ |
| `oidc-publish-receipt`      | `evidence-oidc-publish-receipt`      |
| `publisher-ownership`       | `evidence-publisher-ownership`       |
| `trusted-publishing-policy` | `evidence-trusted-publishing-policy` |

Each artifact must contain exactly one JSON object using the same strict schema
as the mandatory CI evidence files:

```json
{
  "schema_version": 1,
  "gate": "publisher-ownership",
  "status": "pass",
  "commit_sha": "<40 hex characters, exact GITHUB_SHA>",
  "run_id": "<exact GITHUB_RUN_ID>",
  "run_url": "https://github.com/sajib91/Bug-Dhor/actions/runs/<run_id>",
  "generated_at": "<ISO-8601 timestamp with timezone>",
  "detail": "<short, reviewed evidence reference>"
}
```

Supported optional fields are `test_count`, `lock_sha256`, and `detail`. Unknown
fields are rejected. `detail` must be a string of at most 500 characters; it
must not contain secrets or long-lived credentials.

A blocker is cleared only when all of the following hold:

1. A passing evidence file is named exactly `<gate>.json`.
2. Its `commit_sha`, `run_id`, `run_url`, and TTL match the compatibility run
   that produced the manifest.
3. The corresponding `evidence-<gate>` artifact is present and unexpired in
   that same run.
4. The manifest records the artifact in `external_evidence` and does **not**
   record a blocker for the same gate.

Missing, stale, malformed, or non-passing evidence keeps the gate as a blocker.
Default generation and publication therefore remain NO-GO. A manifest may not
pair an external evidence artifact with a blocker for the same gate.

The publish workflow uses `verifyReleaseManifest.js --allow-no-go` only to
report authorization state. The verifier still checks the manifest SHA-256
sidecar, freshness, expected commit and repository, all 16 mandatory gates, and
the recorded GitHub Actions run and jobs. With no genuine external evidence,
validation succeeds but prints a `NO-GO` warning and the `Publish with OIDC` job
is skipped. Without `--allow-no-go`, the verifier continues to fail closed on
NO-GO.
