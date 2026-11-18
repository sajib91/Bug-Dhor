"""Optional CodeQL adapter.

CodeQL is available only when the CLI is installed, the operator has explicitly
accepted the CodeQL license terms, a pre-built database is configured, and at
least one query suite is named. This adapter analyzes an existing database; it
does not download query packs or build a database implicitly.

The ``license_accepted`` flag records an operator assertion. The CLI remains the
authority on license validity; a licensing failure becomes an explicit failed
scan, never an empty success.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from bugdhor.static.base import StaticToolAdapter, validate_common_config
from bugdhor.static.execution import DEFAULT_MAX_CAPTURE_BYTES, run_command
from bugdhor.static.models import (
    ScanStatus,
    ToolAvailability,
    ToolName,
    ToolScanResult,
)
from bugdhor.static.normalize import parse_sarif


@dataclass(frozen=True, slots=True)
class CodeQLConfig:
    """Configuration for analyzing a pre-built CodeQL database."""

    executable: str = "codeql"
    database_path: Path | None = None
    query_suites: tuple[str, ...] = ()
    license_accepted: bool = False
    timeout_seconds: float = 900.0
    extra_args: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    threads: int | None = None
    minimum_version: str = "2.0.0"
    sarif_format: str = "sarif-latest"

    def __post_init__(self) -> None:
        validate_common_config(
            executable=self.executable,
            timeout_seconds=self.timeout_seconds,
            extra_args=self.extra_args,
            environment=dict(self.environment),
            max_output_bytes=self.max_output_bytes,
        )
        for suite in self.query_suites:
            if not isinstance(suite, str) or not suite or "\x00" in suite:
                raise ValueError("CodeQL query suites must be non-empty strings")
        if self.threads is not None and self.threads < 1:
            raise ValueError("threads must be at least 1 when configured")
        if not self.sarif_format or "\x00" in self.sarif_format:
            raise ValueError("sarif_format must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "databasePath": str(self.database_path) if self.database_path else None,
            "querySuites": list(self.query_suites),
            "licenseAccepted": self.license_accepted,
            "timeoutSeconds": self.timeout_seconds,
            "extraArgs": list(self.extra_args),
            "maxOutputBytes": self.max_output_bytes,
            "threads": self.threads,
            "minimumVersion": self.minimum_version,
            "sarifFormat": self.sarif_format,
        }


class CodeQLAdapter(StaticToolAdapter):
    tool: ClassVar[ToolName] = ToolName.CODEQL

    def __init__(self, config: CodeQLConfig | None = None) -> None:
        super().__init__(config or CodeQLConfig())

    def _version_argv(self) -> tuple[str, ...]:
        return ("version",)

    def _configuration_issue(self) -> tuple[str, str] | None:
        if not self.config.license_accepted:
            return (
                "E_TOOL_LICENSE_NOT_ACCEPTED",
                "CodeQL license acceptance has not been asserted in the adapter "
                "configuration (license_accepted=False).",
            )
        if self.config.database_path is None:
            return (
                "E_TOOL_NOT_CONFIGURED",
                "No pre-built CodeQL database is configured.",
            )
        database = Path(self.config.database_path).expanduser()
        if not database.exists() or not database.is_dir():
            return (
                "E_TOOL_NOT_CONFIGURED",
                f"The configured CodeQL database does not exist: {database}",
            )
        if not self.config.query_suites:
            return (
                "E_TOOL_NOT_CONFIGURED",
                "No CodeQL query suites are configured.",
            )
        return None

    def _run_scan(
        self,
        root: Path,
        targets: Sequence[Path],
        availability: ToolAvailability,
    ) -> ToolScanResult:
        del targets
        executable = availability.executable
        database = self.config.database_path
        if executable is None or database is None:  # pragma: no cover - detect() enforces
            raise RuntimeError("CodeQL executable or database was not configured")

        with tempfile.TemporaryDirectory(prefix="bugdhor-codeql-") as temporary:
            output = Path(temporary) / "results.sarif"
            argv: list[str] = [
                executable,
                "database",
                "analyze",
                str(Path(database).expanduser()),
                *self.config.query_suites,
                f"--format={self.config.sarif_format}",
                f"--output={output}",
            ]
            if self.config.threads is not None:
                argv.append(f"--threads={self.config.threads}")
            argv.extend(self.config.extra_args)
            execution = run_command(
                argv,
                timeout_seconds=self.timeout_seconds,
                cwd=root,
                environment=self._environment(),
                max_capture_bytes=self.max_output_bytes,
            )

            warnings: list[str] = []
            if execution.timed_out:
                return self._result(
                    availability=availability,
                    status=ScanStatus.TIMEOUT,
                    parsed=None,
                    execution=execution,
                    warnings=[
                        f"CodeQL exceeded the {self.timeout_seconds:g}s timeout.",
                    ],
                    reason_code="E_ANALYZER_TIMEOUT",
                    detail=f"CodeQL did not finish within {self.timeout_seconds:g} seconds.",
                )
            if execution.launch_error:
                return self._result(
                    availability=availability,
                    status=ScanStatus.FAILED,
                    parsed=None,
                    execution=execution,
                    reason_code="E_ANALYZER_LAUNCH_FAILED",
                    detail=execution.launch_error,
                )
            if execution.stderr_truncated:
                warnings.append(
                    "CodeQL stderr exceeded the configured capture limit and was truncated."
                )
            if not output.is_file():
                return self._result(
                    availability=availability,
                    status=ScanStatus.FAILED,
                    parsed=None,
                    execution=execution,
                    warnings=warnings,
                    reason_code="E_ANALYZER_OUTPUT",
                    detail=(
                        "CodeQL did not produce a SARIF file. "
                        f"stderr: {execution.stderr.strip()[:4000]}"
                    ),
                )

            data = output.read_bytes()
            truncated_output = len(data) > self.max_output_bytes
            if truncated_output:
                data = data[: self.max_output_bytes]
                warnings.append(
                    "CodeQL SARIF output exceeded the configured capture limit and was truncated."
                )
            try:
                payload = json.loads(data.decode("utf-8", errors="replace"))
                parsed = parse_sarif(
                    payload,
                    workspace_root=root,
                    tool="codeql",
                    tool_version=availability.version,
                    config_hash=availability.config_hash,
                )
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                return self._result(
                    availability=availability,
                    status=ScanStatus.FAILED,
                    parsed=None,
                    execution=execution,
                    warnings=warnings,
                    reason_code="E_ANALYZER_OUTPUT",
                    detail=f"CodeQL SARIF output could not be parsed: {exc}",
                )

            successful_exit = execution.return_code == 0 and not truncated_output
            if not successful_exit:
                warnings.append(
                    f"CodeQL exited with code {execution.return_code}; the analysis is incomplete."
                )
                if execution.stderr.strip():
                    warnings.append(f"CodeQL stderr: {execution.stderr.strip()[:4000]}")
            status = ScanStatus.OK
            if parsed.warnings or warnings:
                status = ScanStatus.PARTIAL
            if not successful_exit and not parsed.findings:
                status = ScanStatus.FAILED
            return self._result(
                availability=availability,
                status=status,
                parsed=parsed,
                execution=execution,
                warnings=warnings,
                reason_code=None if successful_exit else "E_ANALYZER_FAILED",
                detail=(
                    None
                    if successful_exit
                    else (
                        f"CodeQL exited with code {execution.return_code}."
                        if not truncated_output
                        else "CodeQL output was truncated."
                    )
                ),
            )
