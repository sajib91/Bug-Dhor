"""Semgrep adapter."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from craftsec.static.base import StaticToolAdapter, validate_common_config
from craftsec.static.execution import DEFAULT_MAX_CAPTURE_BYTES, run_command
from craftsec.static.models import (
    ParsedOutput,
    ScanStatus,
    ToolAvailability,
    ToolName,
    ToolScanResult,
)
from craftsec.static.normalize import parse_semgrep


@dataclass(frozen=True, slots=True)
class SemgrepConfig:
    """Configuration for a Semgrep scan.

    ``configs`` accepts Semgrep registry identifiers and local rule paths. The
    default ``auto`` value is recorded explicitly so callers can tell whether a
    registry or local rule set was used.
    """

    executable: str = "semgrep"
    configs: tuple[str, ...] = ("auto",)
    timeout_seconds: float = 300.0
    extra_args: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    disable_version_check: bool = True
    metrics: bool = False

    def __post_init__(self) -> None:
        validate_common_config(
            executable=self.executable,
            timeout_seconds=self.timeout_seconds,
            extra_args=self.extra_args,
            environment=dict(self.environment),
            max_output_bytes=self.max_output_bytes,
        )
        if not self.configs:
            raise ValueError("at least one Semgrep config is required")
        for config in self.configs:
            if not isinstance(config, str) or not config or "\x00" in config:
                raise ValueError("Semgrep configs must be non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "configs": list(self.configs),
            "timeoutSeconds": self.timeout_seconds,
            "extraArgs": list(self.extra_args),
            "maxOutputBytes": self.max_output_bytes,
            "disableVersionCheck": self.disable_version_check,
            "metrics": self.metrics,
        }


class SemgrepAdapter(StaticToolAdapter):
    tool: ClassVar[ToolName] = ToolName.SEMGREP

    def __init__(self, config: SemgrepConfig | None = None) -> None:
        super().__init__(config or SemgrepConfig())

    def _run_scan(
        self,
        root: Path,
        targets: Sequence[Path],
        availability: ToolAvailability,
    ) -> ToolScanResult:
        executable = availability.executable
        if executable is None:  # pragma: no cover - detect() already guarantees this
            raise RuntimeError("Semgrep executable was not resolved")
        argv: list[str] = [
            executable,
            "scan",
            "--json",
            "--quiet",
            f"--metrics={'on' if self.config.metrics else 'off'}",
        ]
        if self.config.disable_version_check:
            argv.append("--disable-version-check")
        for config in self.config.configs:
            argv.append(f"--config={config}")
        argv.extend(self.config.extra_args)
        argv.append("--")
        argv.extend(str(target) for target in targets)

        execution = run_command(
            argv,
            timeout_seconds=self.timeout_seconds,
            cwd=root,
            environment=self._environment(),
            max_capture_bytes=self.max_output_bytes,
        )
        common_warnings: list[str] = []
        if execution.stdout_truncated:
            common_warnings.append(
                "Semgrep stdout exceeded the configured capture limit and was truncated."
            )
        if execution.stderr_truncated:
            common_warnings.append(
                "Semgrep stderr exceeded the configured capture limit and was truncated."
            )
        if execution.launch_error:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=common_warnings,
                reason_code="E_ANALYZER_LAUNCH_FAILED",
                detail=execution.launch_error,
            )
        if execution.timed_out:
            return self._result(
                availability=availability,
                status=ScanStatus.TIMEOUT,
                parsed=None,
                execution=execution,
                warnings=[
                    *common_warnings,
                    f"Semgrep exceeded the {self.timeout_seconds:g}s timeout.",
                ],
                reason_code="E_ANALYZER_TIMEOUT",
                detail=(f"Semgrep did not finish within {self.timeout_seconds:g} seconds."),
            )

        parsed: ParsedOutput | None = None
        parse_error: str | None = None
        if execution.stdout.strip():
            try:
                parsed = parse_semgrep(
                    json.loads(execution.stdout),
                    workspace_root=root,
                    tool_version=availability.version,
                    config_hash=availability.config_hash,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                parse_error = f"Semgrep output could not be parsed: {exc}"

        successful_exit = execution.return_code in {0, 1}
        if parse_error is not None:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=common_warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail=parse_error,
            )
        if parsed is None:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=common_warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail="Semgrep produced no JSON output.",
            )

        warnings = list(common_warnings)
        if execution.stderr.strip():
            warnings.append(f"Semgrep stderr: {execution.stderr.strip()[:2000]}")
        if not successful_exit:
            warnings.append(
                f"Semgrep exited with code {execution.return_code}; the scan is incomplete."
            )
        status = ScanStatus.OK
        if parsed.warnings or warnings:
            status = ScanStatus.PARTIAL
        if not successful_exit and not parsed.findings:
            status = ScanStatus.FAILED
        reason_code = None if successful_exit else "E_ANALYZER_FAILED"
        return self._result(
            availability=availability,
            status=status,
            parsed=parsed,
            execution=execution,
            warnings=warnings,
            reason_code=reason_code,
            detail=(
                None if successful_exit else f"Semgrep exited with code {execution.return_code}."
            ),
        )
