"""Integrated repair workflow with independent security and functional verification."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from bugdhor.repair.engine import RepairConstraints, RepairEngine, normalize_patch, patch_paths
from bugdhor.sandbox.executor import ExecutionConsent
from bugdhor.verification.engine import IndependentVerificationEngine
from bugdhor.verification.functional import FunctionalVerifier

# Explicit workflow states
PENDING = "PENDING"
SECURITY_PASSED = "SECURITY_PASSED"
FUNCTIONAL_PASSED = "FUNCTIONAL_PASSED"
FULLY_VERIFIED = "FULLY_VERIFIED"
FAILED = "FAILED"
INCONCLUSIVE = "INCONCLUSIVE"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


@dataclass(slots=True)
class WorkflowRecord:
    workflow_id: str
    state: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    candidate: dict[str, Any] | None = None
    security: dict[str, Any] | None = None
    functional: dict[str, Any] | None = None
    comparison: dict[str, Any] | None = None
    report: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflowId": self.workflow_id,
            "state": self.state,
            "steps": self.steps,
            "candidate": self.candidate,
            "security": self.security,
            "functional": self.functional,
            "comparison": self.comparison,
            "report": self.report,
            "metadata": self.metadata,
        }


class RepairWorkflow:
    """Run the integrated 12-step repair verification workflow."""

    def __init__(self, *, sandbox_backend: str = "docker") -> None:
        self.sandbox_backend = sandbox_backend
        self.security_engine = IndependentVerificationEngine(sandbox_backend=sandbox_backend)
        self.functional_verifier = FunctionalVerifier(sandbox_backend=sandbox_backend)

    def run(
        self,
        *,
        workspace_root: str | Path,
        file_path: str,
        original_source: str,
        language_id: str | None = None,
        cwe: str | None = None,
        finding_id: str | None = None,
        patch: str | None = None,
        generate: bool = False,
        generator: Callable[[str, str], str] | None = None,
        adapter: Any = None,
        repository_context: Any = None,
        finding: Mapping[str, Any] | None = None,
        execution_consent: ExecutionConsent | None = None,
        functional_enabled: bool = True,
        test_timeout_seconds: float = 120.0,
        project_test_command: Sequence[str] | None = None,
    ) -> WorkflowRecord:
        consent = execution_consent or ExecutionConsent()
        root = Path(workspace_root)
        workflow_id = hashlib.sha256(f"{file_path}:{_sha256(original_source)}:{_now()}".encode()).hexdigest()[:16]
        record = WorkflowRecord(workflow_id=workflow_id, state=PENDING)
        steps = record.steps

        def step(num: int, name: str, status: str, detail: str = "", data: Any = None) -> None:
            entry: dict[str, Any] = {"step": num, "name": name, "status": status}
            if detail:
                entry["detail"] = detail
            if data is not None:
                entry["data"] = data
            steps.append(entry)

        # 1. Record original source state.
        original_state = {
            "filePath": file_path,
            "sha256": _sha256(original_source),
            "size": len(original_source.encode("utf-8")),
            "languageId": language_id,
            "recordedAt": _now(),
        }
        record.metadata["originalState"] = original_state
        step(1, "Record original source state", "completed", "Original source state recorded.", original_state)

        # 2. Generate repair candidate.
        candidate_patch = patch
        candidate_meta: dict[str, Any] = {"generated": False}
        if generate and candidate_patch is None:
            try:
                if adapter is not None and repository_context is not None and finding is not None:
                    engine = RepairEngine()
                    proposal = engine.propose(
                        source_text=original_source,
                        file_path=file_path,
                        finding=dict(finding),
                        repository_context=repository_context,
                        adapter=adapter,
                    )
                    if proposal.selected:
                        candidate_patch = proposal.selected.patch
                        candidate_meta = {"generated": True, "proposal": proposal.to_dict()}
                    else:
                        candidate_meta = {"generated": True, "proposal": proposal.to_dict(), "error": "no_candidate_selected"}
                elif generator is not None:
                    candidate_patch = generator(original_source, file_path)
                    candidate_meta = {"generated": True, "generator": "callback"}
                else:
                    candidate_meta = {"generated": False, "error": "no_generator_or_adapter_available"}
            except Exception as exc:  # noqa: BLE001
                candidate_meta = {"generated": False, "error": f"generation_failed: {type(exc).__name__}: {exc}"}
        if not candidate_patch:
            step(2, "Generate repair candidate", "failed" if generate else "skipped", candidate_meta.get("error", "No patch provided."), candidate_meta)
            record.state = FAILED if generate else INCONCLUSIVE
            step(3, "Validate patch format", "skipped", "No patch to validate.")
            step(4, "Validate syntax", "skipped", "No patch to validate.")
            step(5, "Run independent security checks", "skipped", "No candidate available.")
            step(6, "Run functional tests", "skipped", "No candidate available.")
            step(7, "Run regression tests", "skipped", "No candidate available.")
            step(8, "Compare before-and-after findings", "skipped", "No candidate available.")
            step(9, "Generate final verification report", "completed", f"state={record.state}", {"state": record.state})
            step(10, "Request user approval", "skipped", "No candidate available for approval.", {"required": True})
            step(11, "Apply accepted patch", "blocked", "No applicable patch; engine never modifies user source.", {"applied": False})
            record.metadata.update({"state": record.state, "terminalReason": "missing_repair_candidate", "workflowId": workflow_id, "approval": {"required": True, "granted": False, "applied": False}, "reproducible": True, "traceable": True})
            step(12, "Record final patch metadata", "completed", "Final metadata recorded; no patch applied.", record.metadata)
            record.report = self._final_report(record)
            return record
        step(2, "Generate repair candidate", "completed", "Repair candidate available.", {"generated": candidate_meta.get("generated", False), "patchSha256": _sha256(candidate_patch)})

        # 3. Validate patch format.
        normalized = normalize_patch(candidate_patch)
        if normalized is None:
            step(3, "Validate patch format", "failed", "Patch is not a valid unified diff.")
            record.state = FAILED
            step(4, "Validate syntax", "skipped", "Invalid patch format.")
            step(5, "Run independent security checks", "skipped", "Invalid patch format.")
            step(6, "Run functional tests", "skipped", "Invalid patch format.")
            step(7, "Run regression tests", "skipped", "Invalid patch format.")
            step(8, "Compare before-and-after findings", "skipped", "Invalid patch format.")
            step(9, "Generate final verification report", "completed", f"state={record.state}", {"state": record.state})
            step(10, "Request user approval", "skipped", "Invalid patch cannot be approved.", {"required": True})
            step(11, "Apply accepted patch", "blocked", "Invalid patch; engine never modifies user source.", {"applied": False})
            record.metadata.update({"state": record.state, "terminalReason": "invalid_patch_format", "workflowId": workflow_id, "approval": {"required": True, "granted": False, "applied": False}, "reproducible": True, "traceable": True})
            step(12, "Record final patch metadata", "completed", "Final metadata recorded; no patch applied.", record.metadata)
            record.report = self._final_report(record)
            return record
        touched = list(patch_paths(normalized))
        step(3, "Validate patch format", "completed", f"Unified diff validated; touched_files={len(touched)}", {"touchedFiles": touched, "patchSha256": _sha256(normalized)})

        # Apply to get patched source for validation/tests (isolated, in-memory/temp only)
        try:
            patched_source = self._apply_patch_to_source(original_source, file_path, normalized)
        except Exception as exc:  # noqa: BLE001
            step(4, "Validate syntax", "failed", f"Patch could not be applied: {exc}")
            record.state = FAILED
            step(5, "Run independent security checks", "skipped", "Patch could not be applied.")
            step(6, "Run functional tests", "skipped", "Patch could not be applied.")
            step(7, "Run regression tests", "skipped", "Patch could not be applied.")
            step(8, "Compare before-and-after findings", "skipped", "Patch could not be applied.")
            step(9, "Generate final verification report", "completed", f"state={record.state}", {"state": record.state})
            step(10, "Request user approval", "skipped", "Unapplicable patch cannot be approved.", {"required": True})
            step(11, "Apply accepted patch", "blocked", "Unapplicable patch; engine never modifies user source.", {"applied": False})
            record.metadata.update({"state": record.state, "terminalReason": "patch_apply_failed", "workflowId": workflow_id, "approval": {"required": True, "granted": False, "applied": False}, "reproducible": True, "traceable": True})
            step(12, "Record final patch metadata", "completed", "Final metadata recorded; no patch applied.", record.metadata)
            record.report = self._final_report(record)
            return record

        # 4. Validate syntax.
        syntax_ok, syntax_detail = self._validate_syntax(patched_source, file_path, language_id)
        step(4, "Validate syntax", "completed" if syntax_ok else "failed", syntax_detail, {"syntaxValid": syntax_ok})
        record.candidate = {
            "patch": normalized,
            "patchSha256": _sha256(normalized),
            "touchedFiles": touched,
            "patchedSourceSha256": _sha256(patched_source),
            "syntaxValid": syntax_ok,
            "metadata": candidate_meta,
        }
        if not syntax_ok:
            record.state = FAILED
            step(5, "Run independent security checks", "skipped", "Syntax-invalid patch.")
            step(6, "Run functional tests", "skipped", "Syntax-invalid patch.")
            step(7, "Run regression tests", "skipped", "Syntax-invalid patch.")
            step(8, "Compare before-and-after findings", "skipped", "Syntax-invalid patch.")
            step(9, "Generate final verification report", "completed", f"state={record.state}", {"state": record.state})
            step(10, "Request user approval", "skipped", "Syntax-invalid patch cannot be approved.", {"required": True})
            step(11, "Apply accepted patch", "blocked", "Syntax-invalid patch; engine never modifies user source.", {"applied": False})
            record.metadata.update({"state": record.state, "terminalReason": "syntax_invalid", "workflowId": workflow_id, "approval": {"required": True, "granted": False, "applied": False}, "reproducible": True, "traceable": True})
            step(12, "Record final patch metadata", "completed", "Final metadata recorded; no patch applied.", record.metadata)
            record.report = self._final_report(record)
            return record

        # 5. Run independent security checks.
        security = self.security_engine.verify(
            original_source=original_source,
            file_path=file_path,
            language_id=language_id,
            patch=normalized,
            cwe=cwe,
            finding_id=finding_id,
            profile="static_only",
        ).to_result(repair_id=None)
        record.security = security
        sec_class = security.get("classification")
        sec_verdict = security.get("verdict")
        sec_ok = sec_class == "verified_security_improvement" and sec_verdict == "passed"
        sec_failed = sec_class == "verification_failure" or sec_verdict == "failed" and sec_class != "partial_improvement"
        sec_inconclusive = sec_class in {"inconclusive_verification", "partial_improvement"} or sec_verdict == "inconclusive"
        sec_step_status = "completed" if sec_ok else ("failed" if sec_class == "verification_failure" else "completed")
        step(5, "Run independent security checks", sec_step_status, f"classification={sec_class} verdict={sec_verdict}", {"classification": sec_class, "verdict": sec_verdict})

        # 6. Run functional tests.
        functional_report = None
        func_ok = False
        func_inconclusive = False
        func_failed = False
        if functional_enabled:
            functional_report = self.functional_verifier.verify_patch(
                workspace_root=root,
                file_path=file_path,
                original_source=original_source,
                patched_source=patched_source,
                language_id=language_id,
                consent=consent,
                test_timeout_seconds=test_timeout_seconds,
                project_test_command=project_test_command,
            ).to_dict()
            record.functional = functional_report
            fstatus = functional_report.get("status")
            func_ok = fstatus == "passed"
            func_failed = fstatus == "failed"
            func_inconclusive = fstatus in {"inconclusive", "not_run"}
            step(6, "Run functional tests", "completed" if func_ok else ("failed" if func_failed else "completed"), f"status={fstatus} passRate={functional_report.get('passRate')}", {"status": fstatus, "executed": functional_report.get("executed")})
        else:
            func_inconclusive = True
            record.functional = {"status": "not_run", "detail": "Functional verification disabled."}
            step(6, "Run functional tests", "skipped", "Functional verification disabled.")

        # 7. Run regression tests (before/after comparison included in functional verifier).
        regressions = (functional_report or {}).get("regressions", [])
        reg_failed = bool(regressions)
        step(7, "Run regression tests", "failed" if reg_failed else "completed", f"regressions={len(regressions)}", {"regressions": regressions, "comparison": (functional_report or {}).get("comparison")})

        # 8. Compare before-and-after findings.
        comparison = {
            "security": (security.get("report") or {}).get("staticAnalysisComparison"),
            "taint": (security.get("report") or {}).get("taintFlowComparison"),
            "functional": (functional_report or {}).get("comparison"),
            "newVulnerabilities": (security.get("report") or {}).get("newVulnerabilityDetection", []),
            "regressions": regressions,
        }
        record.comparison = comparison
        step(8, "Compare before-and-after findings", "completed", "Security and functional before/after comparison recorded.", {"hasSecurityComparison": comparison["security"] is not None, "hasFunctionalComparison": comparison["functional"] is not None})

        # 9. Generate final verification report.
        record.state = self._derive_state(
            syntax_ok=syntax_ok,
            security_ok=sec_ok,
            security_failed=(sec_class == "verification_failure" or (sec_verdict == "failed" and sec_class == "verification_failure")),
            security_inconclusive=sec_inconclusive and not sec_ok,
            security_partial=(sec_class == "partial_improvement"),
            functional_ok=func_ok,
            functional_failed=func_failed or reg_failed,
            functional_inconclusive=func_inconclusive,
        )
        # Mandatory requirements: syntax, security not failed, and for FULLY_VERIFIED both security and functional must fully pass.
        if record.state == FULLY_VERIFIED and not (syntax_ok and sec_ok and func_ok and not reg_failed):
            record.state = SECURITY_PASSED if sec_ok else (FUNCTIONAL_PASSED if func_ok else INCONCLUSIVE)
        record.report = self._final_report(record)
        step(9, "Generate final verification report", "completed", f"state={record.state}", {"state": record.state})

        # 10. Request user approval.
        approval_required = True
        step(10, "Request user approval", "pending", "Explicit user approval is required before applying any patch.", {"required": approval_required, "state": record.state})

        # 11. Apply accepted patch. (never performed by engine)
        step(11, "Apply accepted patch", "blocked", "Patch application is blocked until explicit user approval is recorded by the client; engine never modifies user source.", {"applied": False})

        # 12. Record final patch metadata.
        record.metadata.update({
            "state": record.state,
            "workflowId": workflow_id,
            "patchSha256": _sha256(normalized),
            "patchedSourceSha256": _sha256(patched_source),
            "touchedFiles": touched,
            "securityClassification": sec_class,
            "functionalStatus": (functional_report or {}).get("status"),
            "approval": {"required": True, "granted": False, "applied": False},
            "reproducible": True,
            "traceable": True,
            "sandboxBackend": self.sandbox_backend,
        })
        step(12, "Record final patch metadata", "completed", "Final metadata recorded; patch not applied.", record.metadata)

        return record

    def _apply_patch_to_source(self, original: str, file_path: str, patch: str) -> str:
        # reuse verification logic-like application in temp dir
        import tempfile
        tmp = tempfile.TemporaryDirectory(prefix="bugdhor-wf-apply-")
        try:
            root = Path(tmp.name)
            target = root / Path(file_path).name
            target.write_text(original, encoding="utf-8")
            # simple unified diff apply
            lines = patch.splitlines()
            original_lines = original.splitlines()
            output: list[str] = []
            cursor = 0
            i = 0
            while i < len(lines) and not lines[i].startswith("@@ "):
                i += 1
            if i >= len(lines):
                raise ValueError("no hunks")
            while i < len(lines):
                if not lines[i].startswith("@@ "):
                    i += 1
                    continue
                header = lines[i]
                # parse @@ -l,s +l,s @@
                m = __import__("re").match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", header)
                if not m:
                    raise ValueError("bad hunk")
                start = int(m.group(1)) - 1
                if start < 0:
                    start = 0
                output.extend(original_lines[cursor:start])
                cursor = start
                i += 1
                while i < len(lines) and not lines[i].startswith("@@ "):
                    line = lines[i]
                    if line.startswith(" "):
                        if cursor >= len(original_lines) or original_lines[cursor] != line[1:]:
                            raise ValueError("context mismatch")
                        output.append(original_lines[cursor]); cursor += 1
                    elif line.startswith("-"):
                        if cursor >= len(original_lines) or original_lines[cursor] != line[1:]:
                            raise ValueError("delete mismatch")
                        cursor += 1
                    elif line.startswith("+"):
                        output.append(line[1:])
                    elif line.startswith("\\"):
                        pass
                    elif line.startswith("---") or line.startswith("+++"):
                        pass
                    else:
                        raise ValueError("bad patch line")
                    i += 1
            output.extend(original_lines[cursor:])
            return "\n".join(output) + ("\n" if original.endswith("\n") or output else "")
        finally:
            tmp.cleanup()

    def _validate_syntax(self, source: str, file_path: str, language_id: str | None) -> tuple[bool, str]:
        suffix = Path(file_path).suffix.lower()
        if suffix == ".py" or language_id == "python":
            try:
                __import__("ast").parse(source)
                return True, "Python syntax valid."
            except SyntaxError as exc:
                return False, f"Python syntax error: {exc}"
        if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                from bugdhor.program_analysis.analysis import analyze_source
                parsed = analyze_source(source, path=file_path)
                if getattr(parsed.parsed, "has_syntax_errors", False):
                    return False, "JavaScript/TypeScript parse reported syntax errors."
                return True, "JavaScript/TypeScript syntax valid."
            except Exception as exc:
                return False, f"Parse error: {exc}"
        return True, "Syntax validation not applicable for this language."

    def _derive_state(self, *, syntax_ok, security_ok, security_failed, security_inconclusive, security_partial, functional_ok, functional_failed, functional_inconclusive) -> str:
        if not syntax_ok or security_failed or functional_failed:
            return FAILED
        if security_ok and functional_ok:
            return FULLY_VERIFIED
        if security_ok and functional_inconclusive:
            return SECURITY_PASSED
        if functional_ok and (security_inconclusive or security_partial):
            return FUNCTIONAL_PASSED
        return INCONCLUSIVE

    def _final_report(self, record: WorkflowRecord) -> dict[str, Any]:
        sec = record.security or {}
        func = record.functional or {}
        return {
            "workflowId": record.workflow_id,
            "state": record.state,
            "fullyVerified": record.state == FULLY_VERIFIED,
            "definition": {
                "FULLY_VERIFIED": "All mandatory verification requirements pass: valid patch/syntax, independent security verification passes, and functional/regression tests pass without regressions in isolated execution.",
            },
            "states": [PENDING, SECURITY_PASSED, FUNCTIONAL_PASSED, FULLY_VERIFIED, FAILED, INCONCLUSIVE],
            "originalState": record.metadata.get("originalState"),
            "candidate": record.candidate,
            "securityVerification": sec,
            "functionalVerification": func,
            "beforeAfterComparison": record.comparison,
            "functionalPassRate": func.get("passRate"),
            "missingTestCoverage": func.get("missingTestCoverage"),
            "steps": record.steps,
            "approval": {"required": True, "granted": False, "applied": False, "note": "Explicit user approval is required before applying the patch."},
            "reproducible": True,
            "traceable": True,
            "metadata": record.metadata,
        }


__all__ = [
    "FAILED",
    "FULLY_VERIFIED",
    "FUNCTIONAL_PASSED",
    "INCONCLUSIVE",
    "PENDING",
    "RepairWorkflow",
    "SECURITY_PASSED",
    "WorkflowRecord",
]
