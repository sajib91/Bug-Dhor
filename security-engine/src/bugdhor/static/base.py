"""Common lifecycle for external static-analyzer adapters.

Adapters discover an executable, probe its version, validate their own
configuration, execute a bounded subprocess, and return an explicit
``ToolScanResult``. The base class deliberately provides no fallback that turns
an unavailable or failed tool into an empty successful scan.
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

from bugdhor.static.execution import (
    DEFAULT_MAX_CAPTURE_BYTES,
    resolve_executable,
    run_command,
    sanitized_environment,
)
from bugdhor.static.models import (
    AvailabilityStatus,
    ParsedOutput,
    ScanStatus,
    ToolAvailability,
    ToolExecution,
    ToolName,
    ToolScanResult,
)

_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?\b")


def validate_common_config(
    *,
    executable: str,
    timeout_seconds: float,
    extra_args: Sequence[str],
    environment: Mapping[str, str],
    max_output_bytes: int,
) -> None:
    """Validate settings shared by every tool adapter."""
    if not executable or "\x00" in executable:
        raise ValueError("executable must be a non-empty string without NUL bytes")
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    for argument in extra_args:
        if not isinstance(argument, str) or not argument or "\x00" in argument:
            raise ValueError("extra_args must contain non-empty strings without NUL bytes")
    for name, value in environment.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("environment names and values must be strings")
        if "\x00" in name or "\x00" in value:
            raise ValueError("environment names and values must not contain NUL bytes")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be greater than zero")


def parse_version(text: str) -> str | None:
    """Extract the first semantic-looking version from tool output."""
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    parts = [match.group(1), match.group(2), match.group(3) or "0"]
    return ".".join(parts)


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts[:3])


def _shorten(text: str, limit: int = 5000) -> str:
    text = text.strip()
    return text if len(text) <= limit else f"{text[:limit]}…"


class StaticToolAdapter(ABC):
    """Base adapter for one external static-analysis tool."""

    tool: ClassVar[ToolName]

    def __init__(self, config: Any) -> None:
        self.config = config

    @property
    def timeout_seconds(self) -> float:
        return float(self.config.timeout_seconds)

    @property
    def max_output_bytes(self) -> int:
        return int(getattr(self.config, "max_output_bytes", DEFAULT_MAX_CAPTURE_BYTES))

    def configuration(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool": self.tool.value}
        if hasattr(self.config, "to_dict"):
            payload.update(self.config.to_dict())
        else:  # pragma: no cover - every shipped config implements to_dict
            payload.update(vars(self.config))
        return payload

    def configuration_hash(self) -> str:
        canonical = json.dumps(
            self.configuration(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _environment(self) -> dict[str, str]:
        overrides = dict(getattr(self.config, "environment", ()) or ())
        return sanitized_environment(overrides)

    def _version_argv(self) -> tuple[str, ...]:
        return ("--version",)

    def _configuration_issue(self) -> tuple[str, str] | None:
        return None

    def detect(self) -> ToolAvailability:
        """Detect the executable, probe its version, and validate configuration."""
        configuration = self.configuration()
        config_hash = self.configuration_hash()
        executable = resolve_executable(str(self.config.executable))
        if executable is None:
            return ToolAvailability(
                tool=self.tool.value,
                status=AvailabilityStatus.MISSING,
                executable=None,
                reason_code="E_TOOL_MISSING",
                detail=(
                    f"Configured executable {self.config.executable!r} was not found "
                    "or is not executable."
                ),
                configuration=configuration,
                config_hash=config_hash,
            )

        warnings: list[str] = []
        version: str | None = None
        argv = (executable, *self._version_argv())
        probe = run_command(
            argv,
            timeout_seconds=min(15.0, self.timeout_seconds),
            environment=self._environment(),
            max_capture_bytes=self.max_output_bytes,
        )
        if probe.launch_error:
            return ToolAvailability(
                tool=self.tool.value,
                status=AvailabilityStatus.LAUNCH_FAILED,
                executable=executable,
                reason_code="E_TOOL_LAUNCH_FAILED",
                detail=f"The tool could not be launched: {_shorten(probe.launch_error)}",
                configuration=configuration,
                config_hash=config_hash,
            )
        if probe.timed_out:
            warnings.append(
                f"The {self.tool.value} version probe exceeded its "
                f"{min(15.0, self.timeout_seconds):g}s timeout; the version is unknown."
            )
        else:
            version = parse_version(probe.stdout) or parse_version(probe.stderr)
            if version is None:
                warnings.append(
                    f"The {self.tool.value} version probe did not report a recognizable "
                    "version; the version is unknown."
                )
            elif probe.stderr.strip():
                warnings.append(
                    f"The {self.tool.value} version probe wrote to stderr: "
                    f"{_shorten(probe.stderr, 1000)}"
                )

        minimum = getattr(self.config, "minimum_version", None)
        if version and minimum:
            try:
                if _version_tuple(version) < _version_tuple(str(minimum)):
                    return ToolAvailability(
                        tool=self.tool.value,
                        status=AvailabilityStatus.UNSUPPORTED,
                        executable=executable,
                        version=version,
                        reason_code="E_TOOL_UNSUPPORTED_VERSION",
                        detail=(
                            f"{self.tool.value} {version} is older than the supported "
                            f"minimum {minimum}."
                        ),
                        configuration=configuration,
                        config_hash=config_hash,
                        warnings=tuple(warnings),
                    )
            except ValueError:  # pragma: no cover - defensive version parsing
                pass

        issue = self._configuration_issue()
        if issue is not None:
            reason_code, detail = issue
            return ToolAvailability(
                tool=self.tool.value,
                status=(
                    AvailabilityStatus.LICENSE_NOT_ACCEPTED
                    if reason_code == "E_TOOL_LICENSE_NOT_ACCEPTED"
                    else AvailabilityStatus.NOT_CONFIGURED
                ),
                executable=executable,
                version=version,
                reason_code=reason_code,
                detail=detail,
                configuration=configuration,
                config_hash=config_hash,
                warnings=tuple(warnings),
            )

        return ToolAvailability(
            tool=self.tool.value,
            status=AvailabilityStatus.AVAILABLE,
            executable=executable,
            version=version,
            configuration=configuration,
            config_hash=config_hash,
            warnings=tuple(warnings),
        )

    def scan(
        self,
        workspace_root: Path | str,
        targets: Sequence[Path | str] | None = None,
    ) -> ToolScanResult:
        """Run the analyzer or report an explicit unavailable result."""
        root, resolved_targets = self._validate_targets(workspace_root, targets)
        availability = self.detect()
        if not availability.available:
            return ToolScanResult(
                tool=self.tool.value,
                status=ScanStatus.UNAVAILABLE,
                availability=availability,
                version=availability.version,
                configuration=availability.configuration,
                config_hash=availability.config_hash or self.configuration_hash(),
                reason_code=availability.reason_code,
                detail=availability.detail,
                warnings=availability.warnings,
            )
        return self._run_scan(root, resolved_targets, availability)

    def _validate_targets(
        self,
        workspace_root: Path | str,
        targets: Sequence[Path | str] | None,
    ) -> tuple[Path, tuple[Path, ...]]:
        root = Path(workspace_root).expanduser()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"workspace_root must be an existing directory: {root}")
        root = root.resolve()
        if not targets:
            return root, (root,)
        resolved: list[Path] = []
        for target in targets:
            candidate = Path(target).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            candidate = candidate.resolve(strict=False)
            if candidate != root and root not in candidate.parents:
                raise ValueError(f"scan target is outside the workspace root: {candidate}")
            if not candidate.exists():
                raise ValueError(f"scan target does not exist: {candidate}")
            if candidate not in resolved:
                resolved.append(candidate)
        return root, tuple(resolved)

    def _result(
        self,
        *,
        availability: ToolAvailability,
        status: ScanStatus,
        parsed: ParsedOutput | None,
        execution: ToolExecution | None,
        warnings: Sequence[str] = (),
        reason_code: str | None = None,
        detail: str | None = None,
    ) -> ToolScanResult:
        findings = parsed.findings if parsed else ()
        version = (parsed.tool_version if parsed else None) or availability.version
        all_warnings: list[str] = list(availability.warnings)
        if parsed:
            all_warnings.extend(parsed.warnings)
        all_warnings.extend(warnings)
        return ToolScanResult(
            tool=self.tool.value,
            status=status,
            availability=availability,
            version=version,
            configuration=availability.configuration,
            config_hash=availability.config_hash or self.configuration_hash(),
            findings=findings,
            execution=execution,
            reason_code=reason_code,
            detail=_shorten(detail) if detail else None,
            warnings=tuple(dict.fromkeys(all_warnings)),
        )

    @abstractmethod
    def _run_scan(
        self,
        root: Path,
        targets: Sequence[Path],
        availability: ToolAvailability,
    ) -> ToolScanResult:
        raise NotImplementedError
