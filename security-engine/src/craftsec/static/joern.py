"""Optional Joern adapter.

Joern is a scripted query engine rather than a fixed rule runner. This adapter
supports an installed, supported Joern CLI with a pre-built CPG and an explicit
query script. The script must print the documented JSON/JSONL finding contract
on stdout; Joern's diagnostic logging on stderr is captured separately.
"""

from __future__ import annotations

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
from craftsec.static.normalize import parse_joern


@dataclass(frozen=True, slots=True)
class JoernConfig:
    """Configuration for a Joern query over an existing CPG."""

    executable: str = "joern"
    cpg_path: Path | None = None
    script_path: Path | None = None
    timeout_seconds: float = 900.0
    extra_args: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    minimum_version: str = "2.0.0"
    param_flag: str = "--param"

    def __post_init__(self) -> None:
        validate_common_config(
            executable=self.executable,
            timeout_seconds=self.timeout_seconds,
            extra_args=self.extra_args,
            environment=dict(self.environment),
            max_output_bytes=self.max_output_bytes,
        )
        if not self.param_flag or "\x00" in self.param_flag:
            raise ValueError("param_flag must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "cpgPath": str(self.cpg_path) if self.cpg_path else None,
            "scriptPath": str(self.script_path) if self.script_path else None,
            "timeoutSeconds": self.timeout_seconds,
            "extraArgs": list(self.extra_args),
            "maxOutputBytes": self.max_output_bytes,
            "minimumVersion": self.minimum_version,
            "paramFlag": self.param_flag,
        }


class JoernAdapter(StaticToolAdapter):
    tool: ClassVar[ToolName] = ToolName.JOERN

    def __init__(self, config: JoernConfig | None = None) -> None:
        super().__init__(config or JoernConfig())

    def _configuration_issue(self) -> tuple[str, str] | None:
        if self.config.cpg_path is None:
            return (
                "E_TOOL_NOT_CONFIGURED",
                "No pre-built Joern CPG is configured.",
            )
        cpg = Path(self.config.cpg_path).expanduser()
        if not cpg.exists():
            return (
                "E_TOOL_NOT_CONFIGURED",
                f"The configured Joern CPG does not exist: {cpg}",
            )
        if self.config.script_path is None:
            return (
                "E_TOOL_NOT_CONFIGURED",
                "No Joern query script is configured.",
            )
        script = Path(self.config.script_path).expanduser()
        if not script.is_file():
            return (
                "E_TOOL_NOT_CONFIGURED",
                f"The configured Joern query script does not exist: {script}",
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
        cpg = self.config.cpg_path
        script = self.config.script_path
        if executable is None or cpg is None or script is None:
            # detect() enforces these preconditions.
            raise RuntimeError("Joern executable, CPG, or script was not configured")

        argv: list[str] = [
            executable,
            "--script",
            str(Path(script).expanduser()),
            self.config.param_flag,
            f"cpgPath={Path(cpg).expanduser()}",
            self.config.param_flag,
            f"workspaceRoot={root}",
            self.config.param_flag,
            f"targetRoot={root}",
            "--nocolors",
            *self.config.extra_args,
        ]
        execution = run_command(
            argv,
            timeout_seconds=self.timeout_seconds,
            cwd=root,
            environment=self._environment(),
            max_capture_bytes=self.max_output_bytes,
        )
        warnings: list[str] = []
        if execution.stdout_truncated:
            warnings.append("Joern stdout exceeded the configured capture limit and was truncated.")
        if execution.stderr_truncated:
            warnings.append("Joern stderr exceeded the configured capture limit and was truncated.")
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
                    f"Joern exceeded the {self.timeout_seconds:g}s timeout.",
                ],
                reason_code="E_ANALYZER_TIMEOUT",
                detail=f"Joern did not finish within {self.timeout_seconds:g} seconds.",
            )
        if not execution.stdout.strip():
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail=(
                    f"Joern produced no finding JSON. stderr: {execution.stderr.strip()[:4000]}"
                ),
            )

        try:
            parsed: ParsedOutput = parse_joern(
                execution.stdout,
                workspace_root=root,
                tool_version=availability.version,
                config_hash=availability.config_hash,
            )
        except ValueError as exc:
            return self._result(
                availability=availability,
                status=ScanStatus.FAILED,
                parsed=None,
                execution=execution,
                warnings=warnings,
                reason_code="E_ANALYZER_OUTPUT",
                detail=f"Joern output could not be parsed: {exc}",
            )

        successful_exit = execution.return_code == 0
        if not successful_exit:
            warnings.append(
                f"Joern exited with code {execution.return_code}; the query is incomplete."
            )
            if execution.stderr.strip():
                warnings.append(f"Joern stderr: {execution.stderr.strip()[:4000]}")
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
                None if successful_exit else f"Joern exited with code {execution.return_code}."
            ),
        )
