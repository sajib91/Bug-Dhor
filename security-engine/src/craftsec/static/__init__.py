"""External static-analysis adapters and normalization for CRAFT-Sec.

The package provides independent Semgrep, Bandit, optional CodeQL, and optional
Joern adapters. Each adapter detects its executable and version, validates its
own configuration, runs a bounded argv-only subprocess with a sanitized
environment, captures stdout/stderr, parses tool-native output, and normalizes
findings into shared immutable models. Missing tools and failed or timed-out
invocations are explicit results, never empty successful scans.

CodeQL requires an accepted license assertion plus a configured database and
query suites. Joern requires a supported CLI plus a configured CPG and query
script. The adapters are currently library-only; they are not wired into the
HTTP scan pipeline.
"""

from craftsec.static.bandit import BanditAdapter, BanditConfig
from craftsec.static.base import (
    StaticToolAdapter,
    parse_version,
    validate_common_config,
)
from craftsec.static.codeql import CodeQLAdapter, CodeQLConfig
from craftsec.static.cwe import (
    BANDIT_CWE_MAP,
    bandit_cwes,
    extract_cwes,
    merge_cwes,
    normalize_cwe,
)
from craftsec.static.execution import (
    DEFAULT_MAX_CAPTURE_BYTES,
    resolve_executable,
    run_command,
    sanitized_environment,
)
from craftsec.static.joern import JoernAdapter, JoernConfig
from craftsec.static.models import (
    AvailabilityStatus,
    ParsedOutput,
    RelatedFinding,
    ScanStatus,
    SourceLocation,
    StaticAnalysisResult,
    StaticFinding,
    ToolAvailability,
    ToolExecution,
    ToolName,
    ToolScanResult,
    max_severity,
    severity_rank,
    utc_now_iso,
)
from craftsec.static.normalize import (
    deduplicate_findings,
    finding_sort_key,
    normalize_path,
    normalize_severity,
    parse_bandit,
    parse_joern,
    parse_sarif,
    parse_semgrep,
    severity_from_score,
)
from craftsec.static.runner import StaticAnalysisRunner
from craftsec.static.semgrep import SemgrepAdapter, SemgrepConfig

__all__ = [
    "AvailabilityStatus",
    "BANDIT_CWE_MAP",
    "BanditAdapter",
    "BanditConfig",
    "CodeQLAdapter",
    "CodeQLConfig",
    "DEFAULT_MAX_CAPTURE_BYTES",
    "JoernAdapter",
    "JoernConfig",
    "ParsedOutput",
    "RelatedFinding",
    "ScanStatus",
    "SemgrepAdapter",
    "SemgrepConfig",
    "SourceLocation",
    "StaticAnalysisResult",
    "StaticAnalysisRunner",
    "StaticFinding",
    "StaticToolAdapter",
    "ToolAvailability",
    "ToolExecution",
    "ToolName",
    "ToolScanResult",
    "bandit_cwes",
    "deduplicate_findings",
    "extract_cwes",
    "finding_sort_key",
    "max_severity",
    "merge_cwes",
    "normalize_cwe",
    "normalize_path",
    "normalize_severity",
    "parse_bandit",
    "parse_joern",
    "parse_sarif",
    "parse_semgrep",
    "parse_version",
    "resolve_executable",
    "run_command",
    "sanitized_environment",
    "severity_from_score",
    "severity_rank",
    "utc_now_iso",
    "validate_common_config",
]
