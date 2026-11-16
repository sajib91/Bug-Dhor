"""Isolated execution for untrusted generated code and workspace tests.

Untrusted patches and repository tests are never executed directly on the host.
Execution requires explicit user consent and an available isolation backend.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from craftsec.static.execution import run_command, sanitized_environment


class SandboxUnavailableError(RuntimeError):
    """Raised when no adequate isolated execution environment is available."""


@dataclass(frozen=True, slots=True)
class ExecutionConsent:
    """Explicit user consent for potentially dangerous test execution."""

    granted: bool = False
    allow_network: bool = False
    allow_privileged: bool = False
    allow_destructive: bool = False
    source: str = "unspecified"

    @property
    def usable(self) -> bool:
        return self.granted and not self.allow_privileged and not self.allow_destructive


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: float = 120.0
    environment: Mapping[str, str] = field(default_factory=dict)
    network: bool = False
    image: str = "python:3.11-slim"
    writable_paths: tuple[str, ...] = ("/tmp",)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    status: str  # ok|failed|timeout|unavailable|denied
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    backend: str
    reason_code: str | None = None
    detail: str | None = None
    command: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status == "ok" and self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "exitCode": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "durationSeconds": round(self.duration_seconds, 4),
            "timedOut": self.timed_out,
            "backend": self.backend,
            "reasonCode": self.reason_code,
            "detail": self.detail,
            "command": list(self.command),
        }


class IsolatedExecutor:
    """Run commands inside an isolated container against a copied workspace."""

    def __init__(self, backend: str = "docker") -> None:
        self.backend = backend

    def available(self) -> tuple[bool, str | None, str | None]:
        if self.backend in {"none", ""}:
            return False, "E_SANDBOX_NOT_CONFIGURED", "No sandbox backend is configured."
        exe = shutil.which(self.backend)
        if exe is None:
            return False, "E_SANDBOX_UNAVAILABLE", f"{self.backend} executable not found."
        try:
            probe = subprocess.run(
                [exe, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return False, "E_SANDBOX_UNAVAILABLE", f"{self.backend} probe failed: {exc}"
        if probe.returncode != 0:
            detail = (probe.stderr or probe.stdout or "").strip()[:500]
            return False, "E_SANDBOX_UNAVAILABLE", detail or f"{self.backend} is not usable."
        return True, None, None

    def run(
        self,
        workspace: Path,
        request: ExecutionRequest,
        consent: ExecutionConsent,
    ) -> ExecutionResult:
        if not consent.granted:
            return ExecutionResult(
                status="denied",
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                timed_out=False,
                backend=self.backend,
                reason_code="E_EXECUTION_CONSENT_REQUIRED",
                detail="Explicit user consent is required before executing workspace tests or patched code.",
                command=request.argv,
            )
        if consent.allow_privileged or consent.allow_destructive:
            return ExecutionResult(
                status="denied",
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                timed_out=False,
                backend=self.backend,
                reason_code="E_EXECUTION_CONSENT_UNSAFE",
                detail="Privileged or destructive test execution is not permitted by this verifier.",
                command=request.argv,
            )
        ok, reason, detail = self.available()
        if not ok:
            return ExecutionResult(
                status="unavailable",
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                timed_out=False,
                backend=self.backend,
                reason_code=reason,
                detail=detail,
                command=request.argv,
            )

        network = "bridge" if (request.network and consent.allow_network) else "none"
        cwd = Path("/workspace") / request.cwd
        env = sanitized_environment(dict(request.environment))
        docker_cmd = [
            self.backend,
            "run",
            "--rm",
            "--network",
            network,
            "--workdir",
            str(cwd),
            "--mount",
            f"type=bind,source={workspace.resolve()},target=/workspace",
            "--security-opt",
            "no-new-privileges",
        ]
        # Keep root fs read-only when possible but allow common temp paths.
        docker_cmd.extend(["--read-only"])
        for path in request.writable_paths:
            docker_cmd.extend(["--tmpfs", path])
        for key, value in env.items():
            docker_cmd.extend(["-e", f"{key}={value}"])
        docker_cmd.append(request.image)
        docker_cmd.extend(request.argv)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, float(request.timeout_seconds)),
                check=False,
            )
            duration = time.monotonic() - start
            stdout = (proc.stdout or "")[:200000]
            stderr = (proc.stderr or "")[:200000]
            status = "ok" if proc.returncode == 0 else "failed"
            return ExecutionResult(
                status=status,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                timed_out=False,
                backend=self.backend,
                command=tuple(docker_cmd),
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            stdout = (exc.stdout or b"" if isinstance(exc.stdout, bytes) else exc.stdout or "")
            stderr = (exc.stderr or b"" if isinstance(exc.stderr, bytes) else exc.stderr or "")
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            return ExecutionResult(
                status="timeout",
                exit_code=None,
                stdout=str(stdout)[:200000],
                stderr=str(stderr)[:200000],
                duration_seconds=duration,
                timed_out=True,
                backend=self.backend,
                reason_code="E_EXECUTION_TIMEOUT",
                detail=f"Execution exceeded {request.timeout_seconds}s timeout.",
                command=tuple(docker_cmd),
            )
        except Exception as exc:  # noqa: BLE001
            duration = time.monotonic() - start
            return ExecutionResult(
                status="unavailable",
                exit_code=None,
                stdout="",
                stderr=str(exc)[:200000],
                duration_seconds=duration,
                timed_out=False,
                backend=self.backend,
                reason_code="E_EXECUTION_FAILED",
                detail=str(exc),
                command=tuple(docker_cmd),
            )

    def run_host_check(self, argv: Sequence[str], *, cwd: Path, timeout_seconds: float = 30.0) -> ExecutionResult:
        """Run a non-mutating local check (e.g. syntax parsing via trusted interpreter).

        This is used only for static/syntax checks on already-written temp files in
        controlled temp dirs, not for executing untrusted project test suites.
        """
        started = time.monotonic()
        exec_result = run_command(tuple(argv), cwd=cwd, timeout_seconds=timeout_seconds)
        duration = time.monotonic() - started
        status = "ok" if exec_result.exit_code == 0 and not exec_result.timed_out else "failed"
        if exec_result.timed_out:
            status = "timeout"
        return ExecutionResult(
            status=status,
            exit_code=exec_result.exit_code,
            stdout=exec_result.stdout[:200000],
            stderr=exec_result.stderr[:200000],
            duration_seconds=duration,
            timed_out=exec_result.timed_out,
            backend="host-check",
            reason_code="E_EXECUTION_TIMEOUT" if exec_result.timed_out else None,
            detail="timeout" if exec_result.timed_out else None,
            command=tuple(argv),
        )
