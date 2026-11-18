"""Combine, deduplicate, and report the results of multiple analyzers."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from bugdhor.static.base import StaticToolAdapter
from bugdhor.static.models import (
    AvailabilityStatus,
    ScanStatus,
    StaticAnalysisResult,
    StaticFinding,
    ToolAvailability,
    ToolName,
    ToolScanResult,
)
from bugdhor.static.normalize import deduplicate_findings


class StaticAnalysisRunner:
    """Run a configured set of analyzers against one workspace."""

    def __init__(self, adapters: Sequence[StaticToolAdapter]) -> None:
        if not adapters:
            raise ValueError("at least one static analyzer adapter is required")
        names = [adapter.tool.value for adapter in adapters]
        if len(names) != len(set(names)):
            raise ValueError("static analyzer tool names must be unique")
        self.adapters = tuple(adapters)

    def detect(self) -> tuple[ToolAvailability, ...]:
        """Report availability for every configured adapter."""
        return tuple(adapter.detect() for adapter in self.adapters)

    def scan(
        self,
        workspace_root: Path | str,
        targets: Sequence[Path | str] | None = None,
        *,
        tools: Sequence[ToolName | str] | None = None,
    ) -> StaticAnalysisResult:
        """Run selected tools and return a deduplicated, explicit result."""
        selected = self._select(tools)
        scans: list[ToolScanResult] = []
        for adapter in selected:
            try:
                scans.append(adapter.scan(workspace_root, targets))
            except ValueError:
                raise
            except Exception as exc:  # pragma: no cover - defensive failure isolation
                try:
                    availability = adapter.detect()
                except Exception:  # noqa: BLE001 - preserve an explicit failure
                    availability = ToolAvailability(
                        tool=adapter.tool.value,
                        status=AvailabilityStatus.LAUNCH_FAILED,
                        executable=None,
                        reason_code="E_TOOL_LAUNCH_FAILED",
                        detail=f"{type(exc).__name__}: {exc}",
                        configuration=adapter.configuration(),
                        config_hash=adapter.configuration_hash(),
                    )
                scans.append(
                    ToolScanResult(
                        tool=adapter.tool.value,
                        status=ScanStatus.FAILED,
                        availability=availability,
                        version=availability.version,
                        configuration=availability.configuration,
                        config_hash=availability.config_hash or adapter.configuration_hash(),
                        reason_code="E_ANALYZER_INTERNAL",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )

        result_scans = tuple(scans)
        findings: tuple[StaticFinding, ...] = deduplicate_findings(
            [finding for scan in result_scans for finding in scan.findings]
        )
        warnings = self._aggregate_warnings(result_scans)
        return StaticAnalysisResult(
            status=self._aggregate_status(result_scans),
            findings=findings,
            scans=result_scans,
            warnings=warnings,
        )

    def _select(
        self,
        tools: Sequence[ToolName | str] | None,
    ) -> tuple[StaticToolAdapter, ...]:
        if tools is None:
            return self.adapters
        wanted = {ToolName(tool).value for tool in tools}
        selected = tuple(adapter for adapter in self.adapters if adapter.tool.value in wanted)
        missing = sorted(wanted - {adapter.tool.value for adapter in selected})
        if missing:
            raise ValueError("requested tools are not configured: " + ", ".join(missing))
        if not selected:
            raise ValueError("at least one configured tool must be selected")
        return selected

    @staticmethod
    def _aggregate_status(scans: Sequence[ToolScanResult]) -> ScanStatus:
        if not scans:
            return ScanStatus.UNAVAILABLE
        statuses = [scan.status for scan in scans]
        successful = [
            status for status in statuses if status in {ScanStatus.OK, ScanStatus.PARTIAL}
        ]
        unavailable = statuses.count(ScanStatus.UNAVAILABLE)
        if not successful:
            if unavailable == len(statuses):
                return ScanStatus.UNAVAILABLE
            if ScanStatus.TIMEOUT in statuses:
                return ScanStatus.TIMEOUT
            return ScanStatus.FAILED
        if len(successful) == len(statuses):
            return ScanStatus.PARTIAL if ScanStatus.PARTIAL in statuses else ScanStatus.OK
        return ScanStatus.PARTIAL

    @staticmethod
    def _aggregate_warnings(scans: Sequence[ToolScanResult]) -> tuple[str, ...]:
        warnings: list[str] = []
        for scan in scans:
            if scan.status is ScanStatus.UNAVAILABLE:
                reason = scan.detail or scan.reason_code or "unknown reason"
                warnings.append(f"{scan.tool} was unavailable: {reason}")
            elif scan.status is ScanStatus.TIMEOUT:
                warnings.append(f"{scan.tool} timed out: {scan.detail or 'no detail reported'}")
            elif scan.status is ScanStatus.FAILED:
                warnings.append(
                    f"{scan.tool} failed: {scan.detail or scan.reason_code or 'unknown reason'}"
                )
            warnings.extend(scan.warnings)
        return tuple(dict.fromkeys(warnings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": [adapter.tool.value for adapter in self.adapters],
            "configured": [adapter.configuration() for adapter in self.adapters],
            "configHashes": [adapter.configuration_hash() for adapter in self.adapters],
        }
