# Repository-aware repair context

`RepositoryContextBuilder` supplies an opt-in repair stage with a bounded
`RepositoryContext` object. It starts at the requested target file, follows
resolvable imports, and then adds narrowly related tests, configuration files,
and security utilities. Workspace discovery reuses the containment and
exclusion rules from `craftsec.core.paths`; symlinks, ignored directories, and
files outside the configured workspace are not followed.

Each context file contains relative path, language, size, SHA-256, role,
imports, symbols, function dependencies, interfaces, and compact AST/CFG/DFG
summaries where supported. Source text is never included. Sanitization and
validation candidates are reported as candidates based on names only; they are
not treated as proof that a value is safe.

The context is passed to the repair pipeline as `payload["repositoryContext"]`.

`RepairEngine` constructs a CWE/evidence-aware prompt for a validated local
model adapter, accepts multiple unified-diff candidates, normalizes and applies
each candidate only inside a temporary directory, validates syntax, and ranks
security-aware candidates. It supports CWE-89 SQL injection, CWE-78 command
injection, CWE-79 XSS, CWE-22 path traversal, and CWE-502 unsafe
deserialization. Candidate metadata records model/version, source and patch
hashes, and verification state.

Independent verification is required before a candidate can be selected as
verified. Without a passing verifier the result remains
`pending_verification`; no claim of security is made. Proposals always require
explicit user approval and the original workspace is never modified.

## Ranking and constraints

`PatchRanker` separates mandatory constraints from preferences. Mandatory
checks can require syntax validity, independent security improvement evidence,
functional-test pass rate, regression-test success, CWE requirement
compliance, and touched-file limits. A failed mandatory check records a
candidate-specific rejection reason.

Surviving candidates receive a documented weighted normalized score. The
default terms are measured security improvement, functional and regression
results, syntax validity, CWE compliance, repository consistency, inverse
changed-line complexity (`1 / (1 + additions + deletions)`), and inverse
unnecessary-change ratio. Weights are configurable through `RankingPolicy`;
missing evidence contributes no preference and is recorded as unavailable,
not fabricated.
