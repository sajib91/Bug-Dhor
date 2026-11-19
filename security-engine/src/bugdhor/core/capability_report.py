"""Honest, runtime-derived capability reporting for analysis layers.

The existing ``/health.capabilities`` map describes wired operation paths and
must remain stable. This module produces a separate report that distinguishes:

* languages the workspace detector can identify,
* languages with an installed tree-sitter grammar,
* languages with implemented CFG/DFG/taint layers,
* configured external SAST adapters and their detected availability,
* language-specific linters/type checkers that may be installed but have no
  integrated adapter, and
* dependency-vulnerability checks, which are documented manual checks only.

Nothing here is a success signal: a missing tool is reported as missing, and an
installed linter without an adapter is reported as an explicit integration gap.
"""

from __future__ import annotations

import shutil
from typing import Any

from bugdhor.parsing.languages import language_capabilities
from bugdhor.static.bandit import BanditAdapter
from bugdhor.static.codeql import CodeQLAdapter
from bugdhor.static.joern import JoernAdapter
from bugdhor.static.semgrep import SemgrepAdapter

_SAST_ADAPTERS = (SemgrepAdapter, BanditAdapter, CodeQLAdapter, JoernAdapter)

_LINTERS: tuple[tuple[str, str], ...] = (
    ("ruff", "python"),
    ("mypy", "python"),
    ("pyright", "python"),
    ("pylint", "python"),
    ("eslint", "javascript/typescript"),
    ("tsc", "typescript"),
    ("go", "go"),
    ("cargo", "rust"),
    ("dotnet", "csharp"),
    ("rubocop", "ruby"),
    ("ktlint", "kotlin"),
    ("swiftlint", "swift"),
)


def _static_tool_report() -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for adapter_class in _SAST_ADAPTERS:
        try:
            availability = adapter_class().detect()
        except Exception as error:  # pragma: no cover - defensive boundary
            report.append(
                {
                    "tool": adapter_class.tool.value,
                    "available": False,
                    "status": "detection_failed",
                    "reasonCode": "E_TOOL_DETECTION_FAILED",
                    "version": None,
                    "detail": f"{type(error).__name__}",
                }
            )
            continue
        report.append(
            {
                "tool": availability.tool,
                "available": availability.available,
                "status": availability.status.value,
                "reasonCode": availability.reason_code,
                "version": availability.version,
                "detail": availability.detail,
            }
        )
    return report


def _linter_report() -> list[dict[str, Any]]:
    return [
        {
            "tool": executable,
            "languages": languages,
            "installed": shutil.which(executable) is not None,
            "adapterAvailable": False,
            "reasonCode": "E_NO_ADAPTER",
        }
        for executable, languages in _LINTERS
    ]


def analysis_capabilities() -> dict[str, Any]:
    """Return a structured report of analysis support actually present."""
    languages = [item.to_dict() for item in language_capabilities()]
    return {
        "languages": languages,
        "installedParsers": [item["language"] for item in languages if item["parserAvailable"]],
        "programAnalysis": {
            item["language"]: item["programAnalysis"]
            for item in languages
            if item["programAnalysis"]
        },
        "staticTools": _static_tool_report(),
        "linterTypeCheckers": _linter_report(),
        "dependencyVulnerabilityChecks": {
            "automated": True,
            "status": "ci_lockfile_sca",
            "observedCommands": [
                "pip-audit --require-hashes -r security-engine/requirements.lock.txt --strict",
                "npm audit --omit=dev"
            ],
            "note": (
                "CI regenerates and audits a hash-pinned runtime/dev/ML Python lockfile and "
                "the production npm closure. Analyzer CLIs are excluded from that lock. "
                "This runtime does not execute SCA and does not report CVE-free status."
            ),
        },
        "generalBugs": {
            "available": True,
            "enabledByDefault": False,
            "source": "conservative AST patterns and tree-sitter diagnostics",
        },
        "note": (
            "Operational capability flags in /health.capabilities describe wired "
            "paths, not parser language support, tool availability, or calibrated "
            "research results."
        ),
    }


__all__ = ["analysis_capabilities"]
