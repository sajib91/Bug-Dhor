"""Functional verification and regression testing in isolated environments."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from bugdhor.parsing.languages import detect_language
from bugdhor.parsing.models import SupportedLanguage
from bugdhor.program_analysis.analysis import analyze_source
from bugdhor.repair.engine import normalize_patch
from bugdhor.sandbox.executor import ExecutionConsent, ExecutionRequest, ExecutionResult, IsolatedExecutor


@dataclass(slots=True)
class TestRunSummary:
    framework: str
    status: str  # passed|failed|timeout|unavailable|skipped|denied|error
    command: list[str]
    passed: int | None = None
    failed: int | None = None
    errors: int | None = None
    skipped: int | None = None
    total: int | None = None
    pass_rate: float | None = None
    duration_seconds: float = 0.0
    logs: dict[str, str] = field(default_factory=dict)
    reason_code: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "status": self.status,
            "command": self.command,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "total": self.total,
            "passRate": self.pass_rate,
            "durationSeconds": round(self.duration_seconds, 4),
            "logs": self.logs,
            "reasonCode": self.reason_code,
            "detail": self.detail,
        }


@dataclass(slots=True)
class FunctionalVerificationReport:
    status: str  # passed|failed|inconclusive|not_run
    checks: list[dict[str, Any]]
    limitations: list[str]
    syntax: dict[str, Any]
    compilation: dict[str, Any]
    before_tests: list[TestRunSummary]
    after_tests: list[TestRunSummary]
    comparison: dict[str, Any]
    regressions: list[dict[str, Any]]
    pass_rate: float | None
    missing_test_coverage: dict[str, Any]
    consent_required: bool
    executed: bool
    logs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "checks": self.checks,
            "limitations": list(dict.fromkeys(self.limitations)),
            "syntax": self.syntax,
            "compilation": self.compilation,
            "beforeTests": [t.to_dict() for t in self.before_tests],
            "afterTests": [t.to_dict() for t in self.after_tests],
            "comparison": self.comparison,
            "regressions": self.regressions,
            "passRate": self.pass_rate,
            "missingTestCoverage": self.missing_test_coverage,
            "consentRequired": self.consent_required,
            "executed": self.executed,
            "logs": self.logs,
        }


class FunctionalVerifier:
    """Run syntax checks and isolated project tests before/after a patch."""

    def __init__(self, sandbox_backend: str = "docker") -> None:
        self.executor = IsolatedExecutor(sandbox_backend)

    def verify_patch(
        self,
        *,
        workspace_root: Path,
        file_path: str,
        original_source: str,
        patched_source: str,
        language_id: str | None = None,
        consent: ExecutionConsent | None = None,
        test_timeout_seconds: float = 120.0,
        project_test_command: Sequence[str] | None = None,
        python_image: str = "python:3.11-slim",
        node_image: str = "node:20-slim",
    ) -> FunctionalVerificationReport:
        consent = consent or ExecutionConsent()
        checks: list[dict[str, Any]] = []
        limitations: list[str] = []
        root = Path(workspace_root)
        language = self._detect_language(file_path, language_id, original_source)

        with tempfile.TemporaryDirectory(prefix="bugdhor-func-before-") as before_dir, tempfile.TemporaryDirectory(
            prefix="bugdhor-func-after-"
        ) as after_dir:
            before_root = Path(before_dir)
            after_root = Path(after_dir)
            self._copy_workspace_snapshot(root, before_root)
            self._copy_workspace_snapshot(root, after_root)
            self._write_target(before_root, file_path, original_source)
            self._write_target(after_root, file_path, patched_source)

            syntax = self._syntax_checks(before_root, after_root, file_path, language)
            checks.append(self._check("check-syntax", "security", "Syntax and parse checks", syntax["status"], syntax["detail"], syntax))
            compilation = self._compilation_checks(after_root, language)
            checks.append(self._check("check-compilation", "build", "Compilation checks", compilation["status"], compilation["detail"], compilation))
            if compilation["status"] == "skipped":
                limitations.append("Compilation checks are not applicable or were not configured for this project/language.")

            needs_execution = True
            before_tests: list[TestRunSummary] = []
            after_tests: list[TestRunSummary] = []
            executed = False
            if not consent.granted:
                msg = "Project test execution was not run because explicit user consent was not provided."
                limitations.append(msg)
                checks.append(self._check("check-consent", "functional", "Test execution consent", "skipped", msg, {"consentGranted": False}))
                before_tests = [self._skipped_run("project-tests", reason="E_EXECUTION_CONSENT_REQUIRED", detail=msg)]
                after_tests = [self._skipped_run("project-tests", reason="E_EXECUTION_CONSENT_REQUIRED", detail=msg)]
                needs_execution = False
            elif consent.allow_privileged or consent.allow_destructive:
                msg = "Potentially destructive or privileged test execution requires explicit safe consent and is blocked."
                limitations.append(msg)
                checks.append(self._check("check-consent", "functional", "Test execution consent", "failed", msg, {"consentGranted": consent.granted}))
                before_tests = [self._skipped_run("project-tests", status="denied", reason="E_EXECUTION_CONSENT_UNSAFE", detail=msg)]
                after_tests = [self._skipped_run("project-tests", status="denied", reason="E_EXECUTION_CONSENT_UNSAFE", detail=msg)]
                needs_execution = False

            if needs_execution:
                available, reason, detail = self.executor.available()
                if not available:
                    msg = detail or "Isolated sandbox backend is unavailable; project tests were not executed on host."
                    limitations.append(msg)
                    checks.append(self._check("check-sandbox", "functional", "Isolated test execution", "skipped", msg, {"backend": self.executor.backend, "reasonCode": reason}))
                    before_tests = [self._skipped_run("project-tests", reason=reason, detail=msg)]
                    after_tests = [self._skipped_run("project-tests", reason=reason, detail=msg)]
                else:
                    executed = True
                    checks.append(self._check("check-sandbox", "functional", "Isolated test execution", "passed", f"Using isolated backend: {self.executor.backend}", {"backend": self.executor.backend}))
                    plans = self._discover_test_plans(
                        after_root,
                        language=language,
                        project_test_command=project_test_command,
                        python_image=python_image,
                        node_image=node_image,
                    )
                    if not plans:
                        limitations.append("No supported project test runner was detected.")
                        before_tests = [self._skipped_run("project-tests", reason="E_TESTS_NOT_FOUND", detail="No supported project tests detected.")]
                        after_tests = [self._skipped_run("project-tests", reason="E_TESTS_NOT_FOUND", detail="No supported project tests detected.")]
                        checks.append(self._check("check-tests-discovery", "functional", "Test discovery", "skipped", "No supported project tests detected.", {}))
                    else:
                        checks.append(self._check("check-tests-discovery", "functional", "Test discovery", "passed", f"Detected {len(plans)} test plan(s).", {"plans": [p["framework"] for p in plans]}))
                        for plan in plans:
                            before_tests.append(self._run_plan(before_root, plan, consent, test_timeout_seconds))
                            after_tests.append(self._run_plan(after_root, plan, consent, test_timeout_seconds))

        comparison, regressions = self._compare(before_tests, after_tests)
        pass_rate = comparison.get("afterPassRate")
        missing = self._missing_coverage(before_tests, after_tests, language)
        status = self._overall_status(syntax, compilation, after_tests, regressions, executed, consent)
        limitations.append("Functional pass rates are reported separately from missing test coverage.")
        limitations.append("Untrusted generated code and repository tests are not executed directly on the host.")

        logs = {
            "before": [t.logs for t in before_tests],
            "after": [t.logs for t in after_tests],
        }
        checks.append(self._check(
            "check-regression",
            "functional",
            "Before/after regression comparison",
            "failed" if regressions else ("passed" if executed or after_tests else "skipped"),
            f"regressions={len(regressions)}",
            comparison,
        ))
        return FunctionalVerificationReport(
            status=status,
            checks=checks,
            limitations=limitations,
            syntax=syntax,
            compilation=compilation,
            before_tests=before_tests,
            after_tests=after_tests,
            comparison=comparison,
            regressions=regressions,
            pass_rate=pass_rate,
            missing_test_coverage=missing,
            consent_required=not consent.granted,
            executed=executed,
            logs=logs,
        )

    def _detect_language(self, file_path: str, language_id: str | None, source: str) -> SupportedLanguage | None:
        try:
            return detect_language(path=file_path, text=source, language_id=language_id).language
        except Exception:
            return None

    def _copy_workspace_snapshot(self, src: Path, dst: Path) -> None:
        if not src.exists():
            return
        ignore_names = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build"}
        for item in src.iterdir():
            if item.name in ignore_names:
                continue
            target = dst / item.name
            try:
                if item.is_dir():
                    shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*ignore_names))
                else:
                    shutil.copy2(item, target)
            except Exception:
                continue

    def _write_target(self, root: Path, file_path: str, source: str) -> None:
        target = root / file_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")

    def _syntax_checks(self, before_root: Path, after_root: Path, file_path: str, language: SupportedLanguage | None) -> dict[str, Any]:
        before_ok, before_detail = self._syntax_ok(before_root / file_path, language)
        after_ok, after_detail = self._syntax_ok(after_root / file_path, language)
        status = "passed" if before_ok and after_ok else "failed"
        detail = f"before={'ok' if before_ok else 'error'} after={'ok' if after_ok else 'error'}"
        if not after_ok:
            detail += f"; after_error={after_detail}"
        return {
            "status": status,
            "detail": detail,
            "before": {"valid": before_ok, "detail": before_detail},
            "after": {"valid": after_ok, "detail": after_detail},
        }

    def _syntax_ok(self, path: Path, language: SupportedLanguage | None) -> tuple[bool, str | None]:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            return False, str(exc)
        suffix = path.suffix.lower()
        if language is SupportedLanguage.PYTHON or suffix == ".py":
            try:
                ast.parse(text)
                return True, None
            except SyntaxError as exc:
                return False, f"SyntaxError: {exc}"
        if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} or language in {SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT}:
            try:
                parsed = analyze_source(text, path=path)
                if getattr(parsed.parsed, "has_syntax_errors", False):
                    return False, "parse reported syntax errors"
                return True, None
            except Exception as exc:
                return False, str(exc)
        return True, "syntax check not applicable"

    def _compilation_checks(self, after_root: Path, language: SupportedLanguage | None) -> dict[str, Any]:
        # Python bytecode compilation check is a lightweight compilation/syntax validation.
        if language is SupportedLanguage.PYTHON:
            py_files = [p for p in after_root.rglob("*.py") if ".git" not in p.parts][:200]
            errors = []
            for p in py_files:
                try:
                    source = p.read_text(encoding="utf-8")
                    compile(source, str(p), "exec")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{p.relative_to(after_root)}: {exc}")
            status = "passed" if not errors else "failed"
            return {"status": status, "detail": f"compiled_files={len(py_files)} errors={len(errors)}", "errors": errors[:20]}
        # JS/TS compilation (tsc/build) is project-specific; report as not configured unless explicit.
        return {"status": "skipped", "detail": "No project compilation command configured.", "errors": []}

    def _discover_test_plans(
        self,
        root: Path,
        *,
        language: SupportedLanguage | None,
        project_test_command: Sequence[str] | None,
        python_image: str,
        node_image: str,
    ) -> list[dict[str, Any]]:
        plans: list[dict[str, Any]] = []
        if project_test_command:
            plans.append({
                "framework": "project-command",
                "argv": list(project_test_command),
                "image": python_image if language is SupportedLanguage.PYTHON else node_image,
                "cwd": ".",
            })
            return plans

        # Python / Pytest
        has_pyproject = (root / "pyproject.toml").exists()
        has_pytests = any(root.rglob("test_*.py")) or any(root.rglob("*_test.py")) or (root / "tests").exists() or (root / "pytest.ini").exists()
        if language is SupportedLanguage.PYTHON or has_pytests or has_pyproject:
            if has_pytests:
                plans.append({
                    "framework": "pytest",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "image": python_image,
                    "cwd": ".",
                })

        # JavaScript / Node ecosystem
        pkg = root / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            scripts = data.get("scripts") or {}
            test_script = scripts.get("test")
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            runner = None
            argv = None
            if isinstance(test_script, str) and test_script.strip() and "no test specified" not in test_script.lower():
                # Prefer npm test when script is defined.
                argv = ["npm", "test", "--silent"]
                runner = "npm-test"
            elif "vitest" in deps:
                argv = ["npx", "--no-install", "vitest", "run"]
                runner = "vitest"
            elif "jest" in deps:
                argv = ["npx", "--no-install", "jest", "--runInBand"]
                runner = "jest"
            elif "mocha" in deps:
                argv = ["npx", "--no-install", "mocha"]
                runner = "mocha"
            elif any(root.rglob("*.test.js")) or any(root.rglob("*.spec.js")) or any(root.rglob("test/*.js")):
                argv = ["node", "--test"]
                runner = "node-test"
            if argv:
                plans.append({"framework": runner or "javascript", "argv": argv, "image": node_image, "cwd": "."})
        return plans

    def _run_plan(self, root: Path, plan: dict[str, Any], consent: ExecutionConsent, timeout: float) -> TestRunSummary:
        req = ExecutionRequest(
            argv=tuple(plan["argv"]),
            cwd=str(plan.get("cwd", ".")),
            timeout_seconds=timeout,
            image=str(plan.get("image", "python:3.11-slim")),
            network=False,
        )
        result = self.executor.run(root, req, consent)
        return self._summary_from_result(plan["framework"], list(req.argv), result)

    def _summary_from_result(self, framework: str, argv: list[str], result: ExecutionResult) -> TestRunSummary:
        logs = {"stdout": result.stdout, "stderr": result.stderr}
        parsed = self._parse_counts(framework, result.stdout + "\n" + result.stderr)
        status = result.status
        if status == "ok" and result.exit_code == 0:
            status = "passed"
        elif status in {"failed"}:
            status = "failed"
        elif status == "timeout":
            status = "timeout"
        elif status in {"unavailable", "denied"}:
            status = result.status
        if parsed.get("failed") or parsed.get("errors"):
            status = "failed" if status == "passed" else status
        total = parsed.get("total")
        passed = parsed.get("passed")
        pass_rate = None
        if total and total > 0 and passed is not None:
            pass_rate = passed / total
        elif status == "passed":
            pass_rate = 1.0
        elif status == "failed" and total:
            pass_rate = (passed or 0) / total
        return TestRunSummary(
            framework=framework,
            status=status,
            command=argv,
            passed=passed,
            failed=parsed.get("failed"),
            errors=parsed.get("errors"),
            skipped=parsed.get("skipped"),
            total=total,
            pass_rate=pass_rate,
            duration_seconds=result.duration_seconds,
            logs=logs,
            reason_code=result.reason_code,
            detail=result.detail,
        )

    def _parse_counts(self, framework: str, output: str) -> dict[str, int | None]:
        text = output or ""
        # Pytest summary examples: "1 failed, 2 passed in 0.10s", "3 passed in 0.01s"
        counts = {"passed": None, "failed": None, "errors": None, "skipped": None, "total": None}
        for key, pattern in [
            ("passed", r"(\d+)\s+passed"),
            ("failed", r"(\d+)\s+failed"),
            ("errors", r"(\d+)\s+errors?"),
            ("skipped", r"(\d+)\s+skipped"),
        ]:
            m = re.search(pattern, text)
            if m:
                counts[key] = int(m.group(1))
        # Jest/Vitest/Mocha style
        if counts["passed"] is None:
            m = re.search(r"Tests:\s+.*?(\d+)\s+passed", text, re.IGNORECASE)
            if m:
                counts["passed"] = int(m.group(1))
        if counts["failed"] is None:
            m = re.search(r"Tests:\s+.*?(\d+)\s+failed", text, re.IGNORECASE)
            if m:
                counts["failed"] = int(m.group(1))
        if counts["total"] is None:
            m = re.search(r"Tests:\s+.*?(\d+)\s+total", text, re.IGNORECASE)
            if m:
                counts["total"] = int(m.group(1))
        vals = [v for k, v in counts.items() if k != "total" and isinstance(v, int)]
        if counts["total"] is None and vals:
            counts["total"] = sum(vals)
        return counts

    def _compare(self, before: list[TestRunSummary], after: list[TestRunSummary]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        regressions: list[dict[str, Any]] = []
        before_rate = self._aggregate_pass_rate(before)
        after_rate = self._aggregate_pass_rate(after)
        before_status = self._aggregate_status(before)
        after_status = self._aggregate_status(after)
        if before_status == "passed" and after_status in {"failed", "timeout", "error", "denied"}:
            regressions.append({"type": "status_regression", "before": before_status, "after": after_status})
        if before_rate is not None and after_rate is not None and after_rate < before_rate:
            regressions.append({"type": "pass_rate_regression", "beforePassRate": before_rate, "afterPassRate": after_rate})
        # Count-based regression
        b_fail = sum((t.failed or 0) + (t.errors or 0) for t in before)
        a_fail = sum((t.failed or 0) + (t.errors or 0) for t in after)
        if a_fail > b_fail:
            regressions.append({"type": "failure_count_regression", "beforeFailures": b_fail, "afterFailures": a_fail})
        comparison = {
            "beforeStatus": before_status,
            "afterStatus": after_status,
            "beforePassRate": before_rate,
            "afterPassRate": after_rate,
            "regressionDetected": bool(regressions),
        }
        return comparison, regressions

    def _aggregate_pass_rate(self, runs: list[TestRunSummary]) -> float | None:
        rates = [r.pass_rate for r in runs if isinstance(r.pass_rate, (int, float))]
        if not rates:
            # if executed and all passed with unknown counts
            if runs and all(r.status == "passed" for r in runs):
                return 1.0
            if runs and all(r.status in {"failed", "timeout", "error"} for r in runs):
                return 0.0
            return None
        return sum(float(r) for r in rates) / len(rates)

    def _aggregate_status(self, runs: list[TestRunSummary]) -> str:
        statuses = [r.status for r in runs]
        if not statuses:
            return "not_run"
        if any(s in {"failed", "timeout", "error", "denied"} for s in statuses):
            return "failed"
        if all(s == "passed" for s in statuses):
            return "passed"
        if any(s == "passed" for s in statuses):
            return "partial"
        if all(s in {"skipped", "unavailable"} for s in statuses):
            return "inconclusive"
        return "inconclusive"

    def _missing_coverage(self, before: list[TestRunSummary], after: list[TestRunSummary], language: SupportedLanguage | None) -> dict[str, Any]:
        executed = any(r.status in {"passed", "failed", "timeout", "error"} for r in [*before, *after])
        has_counts = any(isinstance(r.total, int) for r in [*before, *after])
        missing = not executed
        reasons = []
        if missing:
            reasons.append("No project tests were executed in an isolated environment.")
        if executed and not has_counts:
            reasons.append("Test count/coverage metrics were not reported by the test runner.")
        reasons.append("Line/branch coverage was not measured by this verifier.")
        return {
            "coverageMeasured": False,
            "testExecutionMissing": missing,
            "countsAvailable": has_counts,
            "language": getattr(language, "value", None),
            "reasons": reasons,
        }

    def _overall_status(self, syntax: dict[str, Any], compilation: dict[str, Any], after: list[TestRunSummary], regressions: list[dict[str, Any]], executed: bool, consent: ExecutionConsent) -> str:
        if syntax.get("status") == "failed" or compilation.get("status") == "failed":
            return "failed"
        if regressions:
            return "failed"
        after_status = self._aggregate_status(after)
        if after_status == "passed":
            return "passed"
        if after_status == "failed":
            return "failed"
        if not consent.granted or not executed:
            return "inconclusive"
        if after_status in {"inconclusive", "partial", "not_run"}:
            return "inconclusive"
        return "inconclusive"

    def _skipped_run(self, framework: str, *, status: str = "skipped", reason: str | None = None, detail: str | None = None) -> TestRunSummary:
        return TestRunSummary(framework=framework, status=status, command=[], reason_code=reason, detail=detail, logs={})

    def _check(self, check_id: str, kind: str, name: str, status: str, detail: str | None, data: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"checkId": check_id, "kind": kind, "name": name, "status": status}
        if detail:
            payload["details"] = detail
        if data is not None:
            payload["data"] = data
        return payload


__all__ = ["FunctionalVerificationReport", "FunctionalVerifier", "TestRunSummary"]
