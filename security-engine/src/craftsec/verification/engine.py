"""Independent security verification engine.

This module compares a patched source state against its original state using
independent program-analysis tools where available. It never treats the repair
generator as authority over its own patch.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from craftsec.parsing.languages import detect_language
from craftsec.parsing.models import SupportedLanguage
from craftsec.program_analysis.analysis import analyze_source
from craftsec.program_analysis.taint import analyze_taint_source
from craftsec.repair.engine import normalize_patch, patch_paths
from craftsec.static import BanditAdapter, SemgrepAdapter, StaticAnalysisRunner
from craftsec.static.models import ScanStatus, StaticFinding

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_PATCH_HEADER_FILE_RE = re.compile(r"^(---|\+\+\+) ")

# Verdict classification required by the research contract.
VERIFIED_SECURITY_IMPROVEMENT = "verified_security_improvement"
PARTIAL_IMPROVEMENT = "partial_improvement"
VERIFICATION_FAILURE = "verification_failure"
INCONCLUSIVE_VERIFICATION = "inconclusive_verification"

# Shared schema verdict mapping. No unverified patch may be marked secure.
_CLASSIFICATION_TO_SCHEMA_VERDICT = {
    VERIFIED_SECURITY_IMPROVEMENT: "passed",
    PARTIAL_IMPROVEMENT: "failed",
    VERIFICATION_FAILURE: "failed",
    INCONCLUSIVE_VERIFICATION: "inconclusive",
}

_CWE_TAINT_KIND = {
    "CWE-89": "sql_injection",
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-22": "path_traversal",
    "CWE-502": "unsafe_deserialization",
}


@dataclass(slots=True)
class VerificationCheck:
    check_id: str
    kind: str
    name: str
    status: str
    details: str | None = None
    evidence_sources: list[dict[str, str]] = field(default_factory=list)
    classification: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "checkId": self.check_id,
            "kind": self.kind,
            "name": self.name,
            "status": self.status,
        }
        if self.details is not None:
            payload["details"] = self.details
        if self.evidence_sources:
            payload["evidenceSources"] = self.evidence_sources
        return payload


@dataclass(slots=True)
class VerificationOutcome:
    analysis_available: bool
    verdict: str
    classification: str
    checks: list[VerificationCheck]
    limitations: list[str]
    sandbox_backend: str
    profile: str
    report: dict[str, Any]

    def to_result(self, repair_id: str | None) -> dict[str, Any]:
        return {
            "analysisAvailable": self.analysis_available,
            "repairId": repair_id,
            "verdict": self.verdict,
            "classification": self.classification,
            "profile": self.profile,
            "sandboxBackend": self.sandbox_backend,
            "checks": [check.to_dict() for check in self.checks],
            "limitations": list(dict.fromkeys(self.limitations)),
            "report": self.report,
        }


class IndependentVerificationEngine:
    """Run before/after verification using independent analysis tools."""

    def __init__(self, *, sandbox_backend: str = "none") -> None:
        self.sandbox_backend = sandbox_backend

    def verify(
        self,
        *,
        original_source: str,
        file_path: str,
        language_id: str | None = None,
        patch: str | None = None,
        patched_source: str | None = None,
        repair_id: str | None = None,
        cwe: str | None = None,
        finding_id: str | None = None,
        profile: str = "static_only",
        run_execution: bool = False,
    ) -> VerificationOutcome:
        del repair_id, finding_id
        checks: list[VerificationCheck] = []
        limitations: list[str] = []
        counter = 0

        def next_id(prefix: str = "check") -> str:
            nonlocal counter
            counter += 1
            return f"{prefix}-{counter:02d}"

        if patch is None and patched_source is None:
            return self._inconclusive(
                next_id,
                profile,
                checks,
                ["Provide a patch or patched source for independent verification."],
                reason="missing_patch",
            )

        try:
            normalized_patch = normalize_patch(patch) if patch is not None else None
        except Exception:
            normalized_patch = None
        if patch is not None and normalized_patch is None:
            return self._inconclusive(
                next_id,
                profile,
                checks,
                ["The supplied patch is not a parseable unified diff."],
                reason="invalid_patch",
            )

        try:
            before_source = original_source
            if patched_source is not None:
                after_source = patched_source
                touched_files = (file_path,)
            else:
                assert normalized_patch is not None
                touched_files = patch_paths(normalized_patch)
                after_source = self._apply_to_source(before_source, file_path, normalized_patch)
        except Exception as exc:
            checks.append(
                VerificationCheck(
                    next_id(),
                    "security",
                    "Patch application",
                    "error",
                    f"Could not apply patch for independent verification: {type(exc).__name__}: {exc}",
                )
            )
            return self._inconclusive(
                next_id,
                profile,
                checks,
                [
                    "After-patch analysis could not run because the patch did not apply cleanly.",
                ],
                reason="patch_apply_failed",
                report_extra={"touchedFiles": list(touched_files) if 'touched_files' in locals() else []},
            )

        lang = self._resolve_language(file_path, language_id, before_source)
        before_hash = _sha256(before_source)
        after_hash = _sha256(after_source)

        # 1/2. Before and after security scans.
        with tempfile.TemporaryDirectory(prefix="craftsec-verify-before-") as before_dir, tempfile.TemporaryDirectory(
            prefix="craftsec-verify-after-"
        ) as after_dir:
            before_root = Path(before_dir)
            after_root = Path(after_dir)
            before_file = before_root / Path(file_path).name
            after_file = after_root / Path(file_path).name
            before_file.write_text(before_source, encoding="utf-8")
            after_file.write_text(after_source, encoding="utf-8")

            scan_before, scan_after, scan_checks, scan_limitations = self._run_static_scans(
                next_id,
                before_root,
                before_file.name,
                after_root,
                after_file.name,
            )
            checks.extend(scan_checks)
            limitations.extend(scan_limitations)

        # 3. Static-analysis comparison and 6. New vulnerability detection.
        comparison, comparison_checks = self._compare_static_findings(
            next_id,
            scan_before,
            scan_after,
            cwe=cwe,
        )
        checks.extend(comparison_checks)

        # 4. Taint-flow comparison.
        taint_comparison, taint_checks, taint_limitations = self._compare_taint(
            next_id,
            before_source,
            after_source,
            file_path=file_path,
            language=lang,
            cwe=cwe,
        )
        checks.extend(taint_checks)
        limitations.extend(taint_limitations)

        # 5. CWE-specific verification.
        cwe_check, cwe_limitation = self._cwe_specific_check(
            next_id,
            cwe=cwe,
            comparison=comparison,
            taint_comparison=taint_comparison,
            scan_available=scan_before is not None and scan_after is not None,
        )
        if cwe_check is not None:
            checks.append(cwe_check)
        if cwe_limitation:
            limitations.append(cwe_limitation)

        # 7. Regression-risk assessment.
        regression_check, regression_data = self._regression_risk(
            next_id,
            before_source=before_source,
            after_source=after_source,
            file_path=file_path,
            language=lang,
            touched_files=touched_files,
            comparison=comparison,
            taint_comparison=taint_comparison,
        )
        checks.append(regression_check)

        # 8. Execution/functional sandbox is not run in static-only mode.
        if run_execution or profile == "sandbox":
            checks.append(
                VerificationCheck(
                    next_id(),
                    "functional",
                    "Execution-based verification",
                    "skipped",
                    "No adequate isolated execution sandbox is configured for this request.",
                    evidence_sources=[{"kind": "other", "source": self.sandbox_backend}],
                )
            )
            limitations.append(
                "Execution-based verification was not run; an isolated sandbox is required."
            )
        else:
            checks.append(
                VerificationCheck(
                    next_id(),
                    "functional",
                    "Functional regression tests",
                    "skipped",
                    "Static-only verification does not execute functional or regression tests.",
                )
            )
            limitations.append(
                "Functional and regression tests were not executed in the static-only profile."
            )

        classification, analysis_available, verdict_limitations = self._classify(
            comparison=comparison,
            taint_comparison=taint_comparison,
            regression_data=regression_data,
            scan_before=scan_before,
            scan_after=scan_after,
            taint_supported=taint_comparison.get("supported", False),
            cwe=cwe,
        )
        limitations.extend(verdict_limitations)
        limitations.append("Automated verification is not a proof of security.")

        report = {
            "before": {
                "sha256": before_hash,
                "filePath": file_path,
            },
            "after": {
                "sha256": after_hash,
                "filePath": file_path,
                "touchedFiles": list(touched_files),
            },
            "staticAnalysisComparison": comparison,
            "taintFlowComparison": taint_comparison,
            "cweSpecificVerification": {
                "cwe": cwe,
                "status": cwe_check.status if cwe_check else "skipped",
            },
            "newVulnerabilityDetection": comparison.get("newFindings", []),
            "regressionRiskAssessment": regression_data,
            "classification": classification,
            "independentAuthority": True,
        }
        schema_verdict = _CLASSIFICATION_TO_SCHEMA_VERDICT[classification]
        return VerificationOutcome(
            analysis_available=analysis_available,
            verdict=schema_verdict,
            classification=classification,
            checks=checks,
            limitations=limitations,
            sandbox_backend=self.sandbox_backend,
            profile=profile,
            report=report,
        )

    def _inconclusive(
        self,
        next_id,
        profile: str,
        checks: list[VerificationCheck],
        limitations: list[str],
        *,
        reason: str,
        report_extra: Mapping[str, Any] | None = None,
    ) -> VerificationOutcome:
        checks.append(
            VerificationCheck(
                next_id(),
                "security",
                "Independent verification",
                "skipped",
                "Verification could not produce sufficient independent evidence.",
            )
        )
        report = {
            "classification": INCONCLUSIVE_VERIFICATION,
            "reason": reason,
            "independentAuthority": True,
        }
        if report_extra:
            report.update(dict(report_extra))
        return VerificationOutcome(
            analysis_available=False,
            verdict="inconclusive",
            classification=INCONCLUSIVE_VERIFICATION,
            checks=checks,
            limitations=list(dict.fromkeys([*limitations, "Automated verification is not a proof of security."])),
            sandbox_backend=self.sandbox_backend,
            profile=profile,
            report=report,
        )

    def _resolve_language(
        self,
        file_path: str,
        language_id: str | None,
        source: str,
    ) -> SupportedLanguage | None:
        try:
            detected = detect_language(path=file_path, text=source, language_id=language_id)
            return detected.language
        except Exception:
            return None

    def _apply_to_source(self, original: str, file_path: str, patch: str) -> str:
        with tempfile.TemporaryDirectory(prefix="craftsec-verify-apply-") as directory:
            root = Path(directory)
            target = root / Path(file_path).name
            target.write_text(original, encoding="utf-8")
            self._apply_patch(root, patch, target_name=target.name)
            return target.read_text(encoding="utf-8")

    def _apply_patch(self, root: Path, patch: str, *, target_name: str | None = None) -> None:
        lines = patch.splitlines()
        index = 0
        while index < len(lines):
            if not lines[index].startswith("--- "):
                index += 1
                continue
            if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                raise ValueError("malformed unified diff headers")
            raw_path = lines[index + 1][4:].split("\t", 1)[0].split(" ", 1)[0]
            raw_path = raw_path.removeprefix("b/")
            path = Path(raw_path).name if target_name else raw_path
            if raw_path == "/dev/null":
                raise ValueError("file creation patches are not supported")
            if target_name and Path(raw_path).name != target_name and raw_path != target_name:
                # Single-file verification: accept patch that targets the same basename.
                path = target_name
            target = root / path
            if not target.is_relative_to(root):
                raise ValueError("patch escapes workspace")
            original = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
            output: list[str] = []
            cursor = 0
            index += 2
            while index < len(lines) and lines[index].startswith("@@ "):
                match = _HUNK_RE.match(lines[index])
                if match is None:
                    raise ValueError("malformed patch hunk")
                old_count = int(match.group(2) or "1")
                start = int(match.group(1)) - 1 if old_count != 0 or int(match.group(1)) > 0 else 0
                if start < 0:
                    start = 0
                output.extend(original[cursor:start])
                cursor = start
                index += 1
                while index < len(lines) and not lines[index].startswith(("@@ ", "--- ")):
                    line = lines[index]
                    if line.startswith(" "):
                        if cursor >= len(original) or original[cursor] != line[1:]:
                            raise ValueError("patch context does not match source")
                        output.append(original[cursor])
                        cursor += 1
                    elif line.startswith("-"):
                        if cursor >= len(original) or original[cursor] != line[1:]:
                            raise ValueError("patch deletion does not match source")
                        cursor += 1
                    elif line.startswith("+"):
                        output.append(line[1:])
                    elif line != "\\ No newline at end of file":
                        raise ValueError("malformed patch line")
                    index += 1
            output.extend(original[cursor:])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(output) + ("\n" if output or original == [] else ""), encoding="utf-8")

    def _run_static_scans(self, next_id, before_root, before_name, after_root, after_name):
        adapters = [SemgrepAdapter(), BanditAdapter()]
        runner = StaticAnalysisRunner(adapters)
        before_result = None
        after_result = None
        checks: list[VerificationCheck] = []
        limitations: list[str] = []
        try:
            before_result = runner.scan(before_root, [before_name])
            after_result = runner.scan(after_root, [after_name])
        except Exception as exc:
            checks.append(
                VerificationCheck(
                    next_id(),
                    "security",
                    "Independent static-analysis scans",
                    "error",
                    f"Static analysis runner failed: {type(exc).__name__}: {exc}",
                    evidence_sources=[
                        {"kind": "static", "source": "semgrep"},
                        {"kind": "static", "source": "bandit"},
                    ],
                )
            )
            limitations.append("Independent static-analysis scans could not be completed.")
            return None, None, checks, limitations

        available_scans = [
            scan
            for scan in (*before_result.scans, *after_result.scans)
            if scan.status in {ScanStatus.OK, ScanStatus.PARTIAL}
        ]
        if not available_scans:
            details = "; ".join(
                f"{scan.tool}:{scan.status.value}:{scan.detail or scan.reason_code or 'unavailable'}"
                for scan in (*before_result.scans, *after_result.scans)
            )
            checks.append(
                VerificationCheck(
                    next_id(),
                    "security",
                    "Before-patch security scan",
                    "skipped",
                    f"No independent static analyzer completed successfully. {details}",
                    evidence_sources=[{"kind": "static", "source": scan.tool} for scan in before_result.scans],
                )
            )
            checks.append(
                VerificationCheck(
                    next_id(),
                    "security",
                    "After-patch security scan",
                    "skipped",
                    f"No independent static analyzer completed successfully. {details}",
                    evidence_sources=[{"kind": "static", "source": scan.tool} for scan in after_result.scans],
                )
            )
            limitations.extend(before_result.warnings)
            limitations.extend(after_result.warnings)
            limitations.append("No independent static analyzer was available for before/after comparison.")
            return before_result, after_result, checks, limitations

        checks.append(
            self._scan_check(next_id(), "Before-patch security scan", before_result)
        )
        checks.append(
            self._scan_check(next_id(), "After-patch security scan", after_result)
        )
        if before_result.warnings:
            limitations.extend(before_result.warnings)
        if after_result.warnings:
            limitations.extend(after_result.warnings)
        return before_result, after_result, checks, limitations

    def _scan_check(self, check_id: str, name: str, result) -> VerificationCheck:
        completed = [s for s in result.scans if s.status in {ScanStatus.OK, ScanStatus.PARTIAL}]
        status = "passed" if completed else "skipped"
        details = (
            f"status={result.status.value}; findings={len(result.findings)}; "
            f"tools=" + ",".join(f"{s.tool}:{s.status.value}" for s in result.scans)
        )
        return VerificationCheck(
            check_id,
            "security",
            name,
            status,
            details,
            evidence_sources=[{"kind": "static", "source": s.tool} for s in result.scans],
            data={"status": result.status.value, "findingCount": len(result.findings)},
        )

    def _finding_key(self, finding: StaticFinding) -> tuple[Any, ...]:
        cwes = tuple(sorted(finding.cwes or ()))
        # Location-sensitive key for same-file comparison; line can shift slightly after patch
        # so include rule+cwe+message bucket and coarse line band.
        line_band = finding.location.start_line // 5
        return (finding.tool, finding.rule_id, cwes, finding.severity, line_band, finding.message[:120])

    def _serialize_finding(self, finding: StaticFinding) -> dict[str, Any]:
        return {
            "findingId": finding.finding_id,
            "tool": finding.tool,
            "ruleId": finding.rule_id,
            "severity": finding.severity,
            "cwes": list(finding.cwes),
            "message": finding.message,
            "location": {
                "path": finding.location.path,
                "startLine": finding.location.start_line,
                "startColumn": finding.location.start_column,
                "endLine": finding.location.end_line,
                "endColumn": finding.location.end_column,
            },
        }

    def _compare_static_findings(self, next_id, before_result, after_result, *, cwe: str | None):
        if before_result is None or after_result is None:
            return {
                "available": False,
                "beforeCount": 0,
                "afterCount": 0,
                "resolvedFindings": [],
                "newFindings": [],
                "persistingFindings": [],
                "targetCweBefore": 0,
                "targetCweAfter": 0,
            }, []
        before_keys = {self._finding_key(f): f for f in before_result.findings}
        after_keys = {self._finding_key(f): f for f in after_result.findings}
        resolved = [self._serialize_finding(f) for k, f in before_keys.items() if k not in after_keys]
        introduced = [self._serialize_finding(f) for k, f in after_keys.items() if k not in before_keys]
        persisting = [self._serialize_finding(f) for k, f in after_keys.items() if k in before_keys]

        def count_cwe(findings: Sequence[StaticFinding]) -> int:
            if not cwe:
                return 0
            return sum(1 for f in findings if cwe in (f.cwes or ()))

        comparison = {
            "available": any(
                s.status in {ScanStatus.OK, ScanStatus.PARTIAL}
                for s in (*before_result.scans, *after_result.scans)
            ),
            "beforeStatus": before_result.status.value,
            "afterStatus": after_result.status.value,
            "beforeCount": len(before_result.findings),
            "afterCount": len(after_result.findings),
            "resolvedFindings": resolved,
            "newFindings": introduced,
            "persistingFindings": persisting,
            "targetCwe": cwe,
            "targetCweBefore": count_cwe(before_result.findings),
            "targetCweAfter": count_cwe(after_result.findings),
        }
        status = "passed"
        if introduced:
            status = "failed"
        elif after_result.status in {ScanStatus.FAILED, ScanStatus.TIMEOUT, ScanStatus.UNAVAILABLE} and before_result.status in {ScanStatus.OK, ScanStatus.PARTIAL}:
            status = "error"
        details = (
            f"before={comparison['beforeCount']} after={comparison['afterCount']} "
            f"resolved={len(resolved)} new={len(introduced)} persisting={len(persisting)}"
        )
        if cwe:
            details += f" targetCwe[{cwe}] before={comparison['targetCweBefore']} after={comparison['targetCweAfter']}"
        check = VerificationCheck(
            next_id(),
            "security",
            "Static-analysis comparison",
            status,
            details,
            evidence_sources=[{"kind": "static", "source": "comparison"}],
            data=comparison,
        )
        new_check = VerificationCheck(
            next_id(),
            "security",
            "New vulnerability detection",
            "failed" if introduced else "passed",
            f"new_findings={len(introduced)}",
            evidence_sources=[{"kind": "static", "source": "comparison"}],
            data={"newFindings": introduced},
        )
        return comparison, [check, new_check]

    def _compare_taint(self, next_id, before_source, after_source, *, file_path, language, cwe):
        limitations: list[str] = []
        if language not in {SupportedLanguage.PYTHON, SupportedLanguage.JAVASCRIPT}:
            limitations.append(
                "Taint-flow comparison is not supported for this language; comparison was skipped."
            )
            check = VerificationCheck(
                next_id(),
                "security",
                "Taint-flow comparison",
                "skipped",
                "Taint analysis is only available for supported Python and JavaScript sources.",
                evidence_sources=[{"kind": "static", "source": "craftsec.taint"}],
            )
            return {"supported": False, "reason": "unsupported_language"}, [check], limitations

        try:
            before_taint = analyze_taint_source(before_source, path=file_path)
            after_taint = analyze_taint_source(after_source, path=file_path)
        except Exception as exc:
            limitations.append(f"Taint-flow comparison failed: {type(exc).__name__}: {exc}")
            check = VerificationCheck(
                next_id(),
                "security",
                "Taint-flow comparison",
                "error",
                f"Taint analysis failed: {type(exc).__name__}: {exc}",
                evidence_sources=[{"kind": "static", "source": "craftsec.taint"}],
            )
            return {"supported": False, "reason": "error", "error": str(exc)}, [check], limitations

        target_kind = _CWE_TAINT_KIND.get(cwe) if cwe else None

        def summarize(analysis):
            findings = [f.to_dict() if hasattr(f, "to_dict") else _taint_finding_to_dict(f) for f in analysis.findings]
            by_kind: dict[str, int] = {}
            for f in findings:
                k = f.get("kind")
                if k:
                    by_kind[k] = by_kind.get(k, 0) + 1
            return findings, by_kind

        before_findings, before_by_kind = summarize(before_taint)
        after_findings, after_by_kind = summarize(after_taint)
        before_count = len(before_findings)
        after_count = len(after_findings)
        target_before = before_by_kind.get(target_kind, 0) if target_kind else None
        target_after = after_by_kind.get(target_kind, 0) if target_kind else None

        introduced = max(0, after_count - before_count)
        # Simple key-based delta for "new" flows
        def fkey(f):
            return (f.get("kind"), f.get("sink_rule"), f.get("source_rule"), (f.get("sink_span") or {}).get("start", {}).get("line"))
        before_keys = {fkey(f) for f in before_findings}
        new_flows = [f for f in after_findings if fkey(f) not in before_keys]
        resolved_flows = [f for f in before_findings if fkey(f) not in {fkey(x) for x in after_findings}]

        comparison = {
            "supported": True,
            "beforeFlowCount": before_count,
            "afterFlowCount": after_count,
            "beforeByKind": before_by_kind,
            "afterByKind": after_by_kind,
            "newFlows": new_flows,
            "resolvedFlows": resolved_flows,
            "targetKind": target_kind,
            "targetKindBefore": target_before,
            "targetKindAfter": target_after,
            "limitations": list(getattr(before_taint, "limitations", []) or []),
        }
        status = "failed" if new_flows or (target_kind and (target_after or 0) >= (target_before or 0) and (target_before or 0) > 0) else "passed"
        if target_kind and (target_before or 0) > 0 and (target_after or 0) < (target_before or 0) and not new_flows:
            status = "passed"
        elif target_kind and (target_before or 0) == 0 and (target_after or 0) == 0 and not new_flows:
            status = "passed"
        details = f"before={before_count} after={after_count} new={len(new_flows)} resolved={len(resolved_flows)}"
        if target_kind:
            details += f" targetKind[{target_kind}] before={target_before} after={target_after}"
        check = VerificationCheck(
            next_id(),
            "security",
            "Taint-flow comparison",
            status,
            details,
            evidence_sources=[{"kind": "static", "source": "craftsec.taint"}],
            data=comparison,
        )
        taint_limits = list(getattr(before_taint, "limitations", []) or [])
        if taint_limits:
            limitations.extend([f"Taint analysis limitation: {item}" for item in taint_limits])
        limitations.append("Taint analysis reports potential syntactic flows, not proof of exploitability.")
        return comparison, [check], limitations

    def _cwe_specific_check(self, next_id, *, cwe, comparison, taint_comparison, scan_available):
        if not cwe:
            return VerificationCheck(
                next_id(),
                "security",
                "CWE-specific verification",
                "skipped",
                "No target CWE was provided; CWE-specific verification was not applied.",
            ), "No target CWE was provided for CWE-specific verification."
        static_before = comparison.get("targetCweBefore", 0) if scan_available else None
        static_after = comparison.get("targetCweAfter", 0) if scan_available else None
        taint_supported = bool(taint_comparison.get("supported"))
        taint_before = taint_comparison.get("targetKindBefore") if taint_supported else None
        taint_after = taint_comparison.get("targetKindAfter") if taint_supported else None

        evidence = []
        improved = False
        persisting = False
        inconclusive = True
        if scan_available and static_before is not None:
            inconclusive = False
            evidence.append(f"static {cwe}: {static_before}->{static_after}")
            if static_after < static_before:
                improved = True
            if static_after > 0:
                persisting = True
        if taint_supported and taint_before is not None:
            inconclusive = False
            evidence.append(f"taint {taint_comparison.get('targetKind')}: {taint_before}->{taint_after}")
            if taint_after < taint_before:
                improved = True
            if taint_after > 0:
                persisting = True

        if inconclusive:
            status = "skipped"
            detail = f"Insufficient independent evidence to verify {cwe} specifically."
            limitation = f"CWE-specific verification for {cwe} was inconclusive due to unavailable independent evidence."
        elif persisting and not improved:
            status = "failed"
            detail = f"Target {cwe} evidence persists after patch. " + "; ".join(evidence)
            limitation = None
        elif persisting and improved:
            status = "failed"
            detail = f"Target {cwe} evidence partially reduced but still present. " + "; ".join(evidence)
            limitation = None
        elif improved:
            status = "passed"
            detail = f"Target {cwe} evidence reduced by available independent checks. " + "; ".join(evidence)
            limitation = None
        else:
            status = "passed"
            detail = f"No target {cwe} evidence detected by available independent checks before or after. " + "; ".join(evidence)
            limitation = f"No {cwe}-specific evidence was detected; absence of findings is not proof of security."

        return VerificationCheck(
            next_id(),
            "security",
            "CWE-specific verification",
            status,
            detail,
            evidence_sources=[{"kind": "static", "source": "cwe-comparison"}],
            data={"cwe": cwe, "evidence": evidence},
        ), limitation

    def _regression_risk(self, next_id, *, before_source, after_source, file_path, language, touched_files, comparison, taint_comparison):
        risks: list[str] = []
        notes: list[str] = []
        syntax_ok = self._syntax_valid(after_source, file_path, language)
        if not syntax_ok:
            risks.append("Patched source has syntax or parse errors.")
        new_findings = comparison.get("newFindings", []) or []
        if new_findings:
            risks.append(f"{len(new_findings)} potential new static findings detected after patch.")
        new_flows = taint_comparison.get("newFlows", []) or [] if taint_comparison.get("supported") else []
        if new_flows:
            risks.append(f"{len(new_flows)} potential new taint flows detected after patch.")
        if len(touched_files) > 1:
            risks.append(f"Patch touches {len(touched_files)} files; review scope is broader.")
        removed_security_tokens = self._removed_security_tokens(before_source, after_source)
        if removed_security_tokens:
            risks.append(
                "Potentially security-relevant tokens removed: " + ", ".join(sorted(removed_security_tokens))
            )
        change_size = abs(len(after_source.splitlines()) - len(before_source.splitlines()))
        if change_size > 200:
            notes.append(f"Large source size delta ({change_size} lines) increases regression uncertainty.")
        if not risks:
            notes.append("No obvious regression signals detected by static/taint comparison.")

        risk_level = "low"
        if not syntax_ok or new_findings or new_flows:
            risk_level = "high"
        elif removed_security_tokens or len(touched_files) > 1:
            risk_level = "medium"

        data = {
            "riskLevel": risk_level,
            "syntaxValid": syntax_ok,
            "touchedFiles": list(touched_files),
            "newStaticFindingCount": len(new_findings),
            "newTaintFlowCount": len(new_flows),
            "removedSecurityTokens": sorted(removed_security_tokens),
            "risks": risks,
            "notes": notes,
        }
        status = "failed" if risk_level == "high" else "passed"
        detail = f"risk={risk_level}; syntaxValid={syntax_ok}; risks={len(risks)}"
        return VerificationCheck(
            next_id(),
            "security",
            "Regression-risk assessment",
            status,
            detail,
            evidence_sources=[{"kind": "static", "source": "regression-assessment"}],
            data=data,
        ), data

    def _syntax_valid(self, source: str, file_path: str, language: SupportedLanguage | None) -> bool:
        suffix = Path(file_path).suffix.lower()
        if language is SupportedLanguage.PYTHON or suffix == ".py":
            try:
                ast.parse(source)
                return True
            except SyntaxError:
                return False
        if language in {SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT} or suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                parsed = analyze_source(source, path=file_path)
                return not getattr(parsed.parsed, "has_syntax_errors", False)
            except Exception:
                return False
        # Unknown language: do not claim syntax validity.
        return True

    def _removed_security_tokens(self, before: str, after: str) -> set[str]:
        tokens = ["sanitize", "escape", "validate", "allowlist", "whitelist", "parameterize", "prepared", "csrf", "auth", "permission"]
        removed = set()
        before_l = before.lower()
        after_l = after.lower()
        for token in tokens:
            if token in before_l and token not in after_l:
                removed.add(token)
        return removed

    def _classify(self, *, comparison, taint_comparison, regression_data, scan_before, scan_after, taint_supported, cwe):
        static_available = comparison.get("available", False)
        taint_ok = taint_supported and "error" not in taint_comparison
        evidence_available = static_available or taint_ok
        if not evidence_available:
            return INCONCLUSIVE_VERIFICATION, False, [
                "Verification is inconclusive because no independent analysis produced usable evidence."
            ]

        new_static = len(comparison.get("newFindings", []) or [])
        new_taint = len(taint_comparison.get("newFlows", []) or []) if taint_ok else 0
        syntax_ok = bool(regression_data.get("syntaxValid", True))
        risk_level = regression_data.get("riskLevel", "low")
        resolved_static = len(comparison.get("resolvedFindings", []) or [])
        resolved_taint = len(taint_comparison.get("resolvedFlows", []) or []) if taint_ok else 0
        target_improved = False
        target_persisting = False
        target_known = False
        if cwe:
            sb, sa = comparison.get("targetCweBefore"), comparison.get("targetCweAfter")
            if static_available and sb is not None:
                target_known = True
                target_improved = target_improved or (sa < sb)
                target_persisting = target_persisting or (sa > 0)
            if taint_ok and taint_comparison.get("targetKindBefore") is not None:
                tb, ta = taint_comparison.get("targetKindBefore"), taint_comparison.get("targetKindAfter")
                target_known = True
                target_improved = target_improved or (ta < tb)
                target_persisting = target_persisting or (ta > 0)

        limitations: list[str] = []
        if not syntax_ok or new_static > 0 or new_taint > 0:
            if target_improved and (resolved_static > 0 or resolved_taint > 0):
                limitations.append("Targeted evidence improved, but new issues or syntax problems prevent verified improvement.")
                return PARTIAL_IMPROVEMENT, True, limitations
            return VERIFICATION_FAILURE, True, [
                "Verification failed due to syntax errors, persisting targeted issues, or newly detected security issues."
            ]

        if target_known and target_persisting and not target_improved:
            return VERIFICATION_FAILURE, True, ["Targeted CWE evidence persists without independent improvement."]

        if target_known and target_persisting and target_improved:
            return PARTIAL_IMPROVEMENT, True, ["Targeted CWE evidence was reduced but not eliminated by available checks."]

        any_improvement = target_improved or resolved_static > 0 or resolved_taint > 0
        if not any_improvement:
            # No new issues, but also no observed improvement for target - inconclusive/partial.
            if cwe and target_known:
                limitations.append(
                    f"No {cwe}-specific improvement was observed by available independent checks."
                )
                return INCONCLUSIVE_VERIFICATION, True, limitations
            limitations.append("No independent evidence of security improvement was observed.")
            return INCONCLUSIVE_VERIFICATION, True, limitations

        if risk_level == "medium":
            limitations.append("Some regression-risk signals remain; improvement is not fully verified.")
            return PARTIAL_IMPROVEMENT, True, limitations

        if not static_available or (cwe and not target_known):
            limitations.append("Independent evidence is limited; classification is partial rather than fully verified.")
            return PARTIAL_IMPROVEMENT, True, limitations

        return VERIFIED_SECURITY_IMPROVEMENT, True, []


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _taint_finding_to_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()  # type: ignore[no-any-return]
    # Best-effort fallback
    span = getattr(finding, "sink_span", None)
    return {
        "kind": getattr(getattr(finding, "kind", None), "value", getattr(finding, "kind", None)),
        "sink_rule": getattr(finding, "sink_rule", None),
        "source_rule": getattr(finding, "source_rule", None),
        "sink_span": getattr(span, "to_dict", lambda: {})(),
    }


__all__ = [
    "INCONCLUSIVE_VERIFICATION",
    "PARTIAL_IMPROVEMENT",
    "VERIFICATION_FAILURE",
    "VERIFIED_SECURITY_IMPROVEMENT",
    "IndependentVerificationEngine",
    "VerificationCheck",
    "VerificationOutcome",
]
