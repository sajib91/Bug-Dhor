"""Bandit adapter."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from bugdhor.core.redaction import redact_text
from bugdhor.static.base import StaticToolAdapter, validate_common_config
from bugdhor.static.execution import DEFAULT_MAX_CAPTURE_BYTES, run_command
from bugdhor.static.models import (
    ParsedOutput,
    ScanStatus,
    ToolAvailability,
    ToolName,
    ToolScanResult,
)
from bugdhor.static.normalize import parse_bandit


@dataclass(frozen=True, slots=True)
class BanditConfig:
    """Configuration for a Bandit scan."""

    executable: str = "bandit"
    timeout_seconds: float = 300.0
    config_file: Path | None = None
    tests: tuple[str, ...] = ()
    skips: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    recursive: bool = True

    def __post_init__(self) -> None:
        validate_common_config(
            executable=self.executable,
            timeout_seconds=self.timeout_seconds,
            extra_args=self.extra_args,
            environment=dict(self.environment),
            max_output_bytes=self.max_output_bytes,
        )
        for value in (*self.tests, *self.skips):
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError("Bandit test and skip identifiers must be non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "timeoutSeconds": self.timeout_seconds,
            "configFile": str(self.config_file) if self.config_file else None,
            "tests": list(self.tests),
            "skips": list(self.skips),
            "extraArgs": list(self.extra_args),
            "maxOutputBytes": self.max_output_bytes,
            "recursive": self.recursive,
        }


class BanditAdapter(StaticToolAdapter):
    tool: ClassVar[ToolName] = ToolName.BANDIT

    def __init__(self, config: BanditConfig | None = None) -> None:
        super().__init__(config or BanditConfig())

    def _run_scan(
        self,
        root: Path,
        targets: Sequence[Path],
        availability: ToolAvailability,
    ) -> ToolScanResult:
        executable = availability.executable
        if executable is None:  # pragma: no cover - detect() already guarantees this
            raise RuntimeError("Bandit executable was not resolved")
        argv: list[str] = [executable, "-f", "json", "-q"]
        if self.config.config_file is not None:
            argv.extend(["-c", str(self.config.config_file)])
        if self.config.tests:
            argv.extend(["--tests", ",".join(self.config.tests)])
        if self.config.skips:
            argv.extend(["--skips", ",".join(self.config.skips)])
        argv.extend(self.config.extra_args)
        if self.config.recursive and any(target.is_dir() for target in targets):
            argv.append("-r")
        argv.extend(str(target) for target in targets)

        execution = run_command(
            argv,
            timeout_seconds=self.timeout_seconds,
            cwd=root,
            environment=self._environment(),
            max_capture_bytes=self.max_output_bytes,
        )
        warnings: list[str] = []
        if execution.stdout_truncated:
            warnings.append(
                "Bandit stdout exceeded the configured capture limit and was truncated."
            )
        if execution.stderr_truncated:
            warnings.append(
                "Bandit stderr exceeded the configured capture limit and was truncated."
            )
        if execution.launch_error:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=warnings,
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
                    *warnings,
                    f"Bandit exceeded the {self.timeout_seconds:g}s timeout.",
                ],
                reason_code="E_ANALYZER_TIMEOUT",
                detail=f"Bandit did not finish within {self.timeout_seconds:g} seconds.",
            )

        parsed: ParsedOutput | None = None
        parse_error: str | None = None
        if execution.stdout.strip():
            try:
                parsed = parse_bandit(
                    json.loads(execution.stdout),
                    workspace_root=root,
                    tool_version=availability.version,
                    config_hash=availability.config_hash,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                parse_error = f"Bandit output could not be parsed: {redact_text(exc)}"

        successful_exit = execution.return_code in {0, 1}
        if parse_error is not None:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail=parse_error,
            )
        if parsed is None:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail="Bandit produced no JSON output.",
            )

        if execution.stderr.strip():
            warnings.append(f"Bandit stderr: {execution.stderr.strip()[:2000]}")
        if not successful_exit:
            warnings.append(
                f"Bandit exited with code {execution.return_code}; the scan is incomplete."
            )
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
                None if successful_exit else f"Bandit exited with code {execution.return_code}."
            ),
        )
