"""Parsers that normalize Semgrep, Bandit, SARIF/CodeQL, and Joern output.

Every parser is deliberately tolerant of malformed individual records: one bad
record becomes a warning, not a dropped scan and not a fabricated finding. The
original rule identifiers and raw tool records are retained.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from bugdhor.core.redaction import redact_text
from bugdhor.static.cwe import bandit_cwes, extract_cwes, merge_cwes
from bugdhor.static.models import (
    ParsedOutput,
    RelatedFinding,
    SourceLocation,
    StaticFinding,
    max_severity,
    severity_rank,
)


def normalize_path(value: str, workspace_root: Path | str) -> str:
    """Normalize a tool path to a workspace-relative POSIX path when possible."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("finding path must be a non-empty string")
    text = value.strip()
    if text.startswith("file:"):
        parsed = urlsplit(text)
        if parsed.netloc and parsed.netloc not in {"", "localhost"}:
            text = f"//{parsed.netloc}{unquote(parsed.path)}"
        else:
            text = unquote(parsed.path)
    root = Path(workspace_root).expanduser().resolve()
    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            return str(resolved)
    normalized = os.path.normpath(text).replace(os.sep, "/")
    return normalized[2:] if normalized.startswith("./") else normalized


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _first_text(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _location(
    path: str,
    workspace_root: Path | str,
    *,
    start_line: Any,
    start_column: Any,
    end_line: Any,
    end_column: Any,
    one_based_line: bool,
    one_based_column: bool,
) -> SourceLocation:
    start = _as_int(start_line)
    end = _as_int(end_line)
    start_col = _as_int(start_column)
    end_col = _as_int(end_column)
    if start is None:
        raise ValueError("missing start line")
    start = start - 1 if one_based_line else start
    end = end if end is not None else start
    end = end - 1 if one_based_line else end
    start_col = start_col if start_col is not None else (1 if one_based_column else 0)
    start_col = start_col - 1 if one_based_column else start_col
    end_col = end_col if end_col is not None else (start_col + 1 if one_based_column else start_col)
    end_col = end_col - 1 if one_based_column else end_col
    if start < 0 or end < 0 or start_col < 0 or end_col < 0:
        raise ValueError("negative source coordinate")
    if (end, end_col) < (start, start_col):
        end, end_col = start, start_col
    return SourceLocation(
        path=normalize_path(path, workspace_root),
        start_line=start,
        start_column=start_col,
        end_line=end,
        end_column=end_col,
    )


def _finding_id(
    *,
    tool: str,
    rule_id: str,
    location: SourceLocation,
    message: str,
    fingerprint: str | None,
) -> str:
    if fingerprint:
        key = f"fingerprint:{fingerprint}"
    else:
        key = (
            f"{location.path}:{location.start_line}:{location.start_column}:"
            f"{location.end_line}:{location.end_column}:{rule_id}:{message}"
        )
    digest = hashlib.sha256(f"{tool}\x00{key}".encode()).hexdigest()[:24]
    return f"fnd-{digest}"


def _build_finding(
    *,
    tool: str,
    rule_id: str,
    message: str,
    severity: str,
    location: SourceLocation,
    cwes: Iterable[str] = (),
    rule_name: str | None = None,
    fingerprint: str | None = None,
    evidence: str | None = None,
    tool_version: str | None = None,
    config_hash: str | None = None,
    raw: Mapping[str, Any] | None = None,
) -> StaticFinding:
    normalized_message = message.strip() or rule_id
    normalized_cwes = merge_cwes(cwes)
    return StaticFinding(
        finding_id=_finding_id(
            tool=tool,
            rule_id=rule_id,
            location=location,
            message=normalized_message,
            fingerprint=fingerprint,
        ),
        tool=tool,
        rule_id=rule_id,
        rule_name=rule_name,
        message=normalized_message,
        severity=severity,
        cwes=normalized_cwes,
        location=location,
        fingerprint=fingerprint,
        evidence=evidence,
        tool_version=tool_version,
        config_hash=config_hash,
        raw=dict(raw or {}),
    )


_SEVERITY_ALIASES = {
    "critical": "critical",
    "blocker": "critical",
    "high": "high",
    "error": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "note": "info",
    "none": "info",
    "undefined": "info",
}


def normalize_severity(value: Any, *, default: str = "info") -> str:
    if isinstance(value, str):
        return _SEVERITY_ALIASES.get(value.strip().lower(), default)
    return default


def severity_from_score(value: Any) -> str | None:
    """Map a CVSS-style security score (0-10) to a severity band."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _codeql_level_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get(value.strip().lower())


def _error_warnings(errors: Any, tool: str) -> tuple[str, ...]:
    if not isinstance(errors, list):
        return ()
    warnings: list[str] = []
    for error in errors:
        if isinstance(error, Mapping):
            message = _first_text(
                error.get("message"),
                error.get("reason"),
                error.get("detail"),
                error.get("text"),
            )
            if message:
                warnings.append(f"{tool} reported an error: {message[:2000]}")
        elif isinstance(error, str) and error.strip():
            warnings.append(f"{tool} reported an error: {error.strip()[:2000]}")
    return tuple(warnings)


def parse_semgrep(
    payload: Any,
    *,
    workspace_root: Path | str,
    tool_version: str | None = None,
    config_hash: str | None = None,
) -> ParsedOutput:
    """Normalize Semgrep ``--json`` output."""
    if not isinstance(payload, Mapping):
        raise ValueError("Semgrep output is not a JSON object")
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep output is missing a results array")
    version = _first_text(payload.get("version"), tool_version)
    warnings = list(_error_warnings(payload.get("errors"), "Semgrep"))
    findings: list[StaticFinding] = []

    for index, item in enumerate(results):
        if not isinstance(item, Mapping):
            warnings.append(f"Semgrep result {index} is not an object and was skipped.")
            continue
        try:
            path = item.get("path")
            if not isinstance(path, str):
                raise ValueError("missing path")
            start = _as_mapping(item.get("start"))
            end = _as_mapping(item.get("end"))
            location = _location(
                path,
                workspace_root,
                start_line=start.get("line"),
                start_column=start.get("col"),
                end_line=end.get("line", start.get("line")),
                end_column=end.get("col"),
                one_based_line=True,
                one_based_column=True,
            )
            rule_id = _first_text(item.get("check_id"))
            if rule_id is None:
                raise ValueError("missing check_id")
            extra = _as_mapping(item.get("extra"))
            metadata = _as_mapping(extra.get("metadata"))
            message = _first_text(extra.get("message"), item.get("message"), rule_id)
            findings.append(
                _build_finding(
                    tool="semgrep",
                    rule_id=rule_id,
                    rule_name=_first_text(
                        metadata.get("shortDescription"),
                        metadata.get("short_description"),
                    ),
                    message=message or rule_id,
                    severity=normalize_severity(extra.get("severity")),
                    location=location,
                    cwes=extract_cwes(
                        [
                            metadata.get("cwe"),
                            metadata.get("cwes"),
                            metadata.get("references"),
                        ]
                    ),
                    fingerprint=_first_text(item.get("fingerprint")),
                    evidence=_first_text(extra.get("lines")),
                    tool_version=version,
                    config_hash=config_hash,
                    raw=item,
                )
            )
        except (TypeError, ValueError) as exc:
            warnings.append(f"Semgrep result {index} was skipped: {redact_text(exc)}")

    return ParsedOutput(tuple(findings), tuple(warnings), version)


def parse_bandit(
    payload: Any,
    *,
    workspace_root: Path | str,
    tool_version: str | None = None,
    config_hash: str | None = None,
) -> ParsedOutput:
    """Normalize Bandit ``-f json`` output."""
    if not isinstance(payload, Mapping):
        raise ValueError("Bandit output is not a JSON object")
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Bandit output is missing a results array")
    warnings = list(_error_warnings(payload.get("errors"), "Bandit"))
    findings: list[StaticFinding] = []

    for index, item in enumerate(results):
        if not isinstance(item, Mapping):
            warnings.append(f"Bandit result {index} is not an object and was skipped.")
            continue
        try:
            rule_id = _first_text(item.get("test_id"))
            filename = item.get("filename")
            if rule_id is None:
                raise ValueError("missing test_id")
            if not isinstance(filename, str):
                raise ValueError("missing filename")
            line_number = item.get("line_number")
            line_range = item.get("line_range")
            if isinstance(line_range, list) and line_range:
                end_line = max(
                    value for value in (_as_int(entry) for entry in line_range) if value is not None
                )
            else:
                end_line = line_number
            location = _location(
                filename,
                workspace_root,
                start_line=line_number,
                start_column=item.get("col_offset", 0),
                end_line=end_line,
                end_column=item.get("end_col_offset", item.get("col_offset", 0)),
                one_based_line=True,
                one_based_column=False,
            )
            cwes = bandit_cwes(
                rule_id,
                item.get("cwe"),
                item.get("cwes"),
                item.get("issue_cwe"),
            )
            findings.append(
                _build_finding(
                    tool="bandit",
                    rule_id=rule_id,
                    rule_name=_first_text(item.get("test_name")),
                    message=_first_text(item.get("issue_text"), rule_id) or rule_id,
                    severity=normalize_severity(item.get("issue_severity")),
                    location=location,
                    cwes=cwes,
                    evidence=_first_text(item.get("code")),
                    tool_version=tool_version,
                    config_hash=config_hash,
                    raw=item,
                )
            )
        except (TypeError, ValueError) as exc:
            warnings.append(f"Bandit result {index} was skipped: {redact_text(exc)}")

    return ParsedOutput(tuple(findings), tuple(warnings), tool_version)


def _sarif_rules(
    run: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], dict[int, Mapping[str, Any]]]:
    tool = _as_mapping(run.get("tool"))
    driver = _as_mapping(tool.get("driver"))
    driver_rules = [rule for rule in (driver.get("rules") or []) if isinstance(rule, Mapping)]
    by_id: dict[str, Mapping[str, Any]] = {}
    for rule in driver_rules:
        rule_id = _first_text(rule.get("id"), rule.get("name"))
        if rule_id:
            by_id[rule_id] = rule
    for extension in tool.get("extensions") or []:
        if not isinstance(extension, Mapping):
            continue
        for rule in extension.get("rules") or []:
            if isinstance(rule, Mapping):
                rule_id = _first_text(rule.get("id"), rule.get("name"))
                if rule_id:
                    by_id.setdefault(rule_id, rule)
    index_map: dict[int, Mapping[str, Any]] = dict(enumerate(driver_rules))
    return by_id, index_map


def parse_sarif(
    payload: Any,
    *,
    workspace_root: Path | str,
    tool: str = "codeql",
    tool_version: str | None = None,
    config_hash: str | None = None,
) -> ParsedOutput:
    """Normalize SARIF 2.1.0 results, preserving rule IDs and SARIF metadata."""
    if not isinstance(payload, Mapping):
        raise ValueError("SARIF output is not a JSON object")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF output is missing a runs array")
    warnings: list[str] = []
    findings: list[StaticFinding] = []
    versions: list[str] = []

    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            warnings.append(f"SARIF run {run_index} is not an object and was skipped.")
            continue
        tool_info = _as_mapping(_as_mapping(run.get("tool")).get("driver"))
        version = _first_text(
            tool_info.get("semanticVersion"),
            tool_info.get("version"),
            tool_version,
        )
        if version:
            versions.append(version)
        rules_by_id, rules_by_index = _sarif_rules(run)
        rule_map = dict(rules_by_id)
        rule_map.update(
            {
                str(rule.get("id") or rule.get("name")): rule
                for rule in rules_by_index.values()
                if rule.get("id") or rule.get("name")
            }
        )
        for result_index, result in enumerate(run.get("results") or []):
            if not isinstance(result, Mapping):
                warnings.append(
                    f"SARIF run {run_index} result {result_index} is not an object and was skipped."
                )
                continue
            try:
                rule_index = _as_int(result.get("ruleIndex"))
                rule = rules_by_index.get(rule_index) if rule_index is not None else None
                rule = rule or rule_map.get(str(result.get("ruleId") or ""))
                rule = _as_mapping(rule)
                rule_id = _first_text(
                    result.get("ruleId"),
                    rule.get("id"),
                    rule.get("name"),
                )
                if rule_id is None:
                    raise ValueError("missing ruleId")
                locations = result.get("locations")
                if not isinstance(locations, list) or not locations:
                    raise ValueError("missing locations")
                physical = _as_mapping(_as_mapping(locations[0]).get("physicalLocation"))
                artifact = _as_mapping(physical.get("artifactLocation"))
                uri = artifact.get("uri")
                if not isinstance(uri, str):
                    raise ValueError("missing artifact URI")
                region = _as_mapping(physical.get("region"))
                location = _location(
                    uri,
                    workspace_root,
                    start_line=region.get("startLine", 1),
                    start_column=region.get("startColumn", 1),
                    end_line=region.get("endLine", region.get("startLine", 1)),
                    end_column=region.get("endColumn", region.get("startColumn", 1)),
                    one_based_line=True,
                    one_based_column=True,
                )
                rule_properties = _as_mapping(rule.get("properties"))
                result_properties = _as_mapping(result.get("properties"))
                score = result_properties.get(
                    "security-severity",
                    rule_properties.get("security-severity"),
                )
                severity = severity_from_score(score)
                if severity is None:
                    default_level = _as_mapping(rule.get("defaultConfiguration")).get("level")
                    severity = (
                        _codeql_level_severity(result.get("level"))
                        or _codeql_level_severity(default_level)
                        or "info"
                    )
                message = _first_text(
                    _as_mapping(result.get("message")).get("text"),
                    _as_mapping(result.get("message")).get("markdown"),
                    _as_mapping(rule.get("shortDescription")).get("text"),
                    rule_id,
                )
                cwes = extract_cwes(
                    [
                        rule_properties.get("tags"),
                        result_properties.get("tags"),
                        rule_properties.get("cwe"),
                        result_properties.get("cwe"),
                    ]
                )
                fingerprints = result.get("partialFingerprints")
                fingerprint = None
                if isinstance(fingerprints, Mapping):
                    for key in sorted(fingerprints):
                        value = fingerprints[key]
                        if isinstance(value, str) and value:
                            fingerprint = value
                            break
                findings.append(
                    _build_finding(
                        tool=tool,
                        rule_id=rule_id,
                        rule_name=_first_text(
                            rule.get("name"),
                            _as_mapping(rule.get("shortDescription")).get("text"),
                        ),
                        message=message or rule_id,
                        severity=severity,
                        location=location,
                        cwes=cwes,
                        fingerprint=fingerprint,
                        evidence=_first_text(_as_mapping(region.get("snippet")).get("text")),
                        tool_version=version or tool_version,
                        config_hash=config_hash,
                        raw=result,
                    )
                )
            except (TypeError, ValueError) as exc:
                warnings.append(f"SARIF run {run_index} result {result_index} was skipped: {redact_text(exc)}")

    unique_versions = tuple(dict.fromkeys(versions))
    if len(unique_versions) > 1:
        warnings.append("SARIF runs reported multiple tool versions: " + ", ".join(unique_versions))
    return ParsedOutput(
        tuple(findings),
        tuple(warnings),
        unique_versions[0] if unique_versions else tool_version,
    )


def _joern_documents(text: str) -> tuple[list[Any], tuple[str, ...]]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("Joern produced no output")
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        documents: list[Any] = []
        ignored = 0
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                ignored += 1
        if not documents:
            raise ValueError("Joern output is not valid JSON or JSON Lines") from None
        warnings = (f"Ignored {ignored} non-JSON Joern output line(s).",) if ignored else ()
        return documents, warnings
    if isinstance(parsed, list):
        return [parsed], ()
    return [parsed], ()


def parse_joern(
    text: str,
    *,
    workspace_root: Path | str,
    tool_version: str | None = None,
    config_hash: str | None = None,
) -> ParsedOutput:
    """Normalize the JSON/JSONL finding contract emitted by a Joern query script.

    The custom script may emit one JSON array, one object containing a
    ``findings`` or ``results`` array, or one JSON object per line. Nested
    ``start``/``end`` objects use zero-based ``line``/``column`` values. Flat
    ``startLine``/``startColumn``/``line`` fields are treated as one-based to
    match Joern's own source positions.
    """
    documents, warnings = _joern_documents(text)
    items: list[Any] = []
    for document in documents:
        if isinstance(document, list):
            items.extend(document)
        elif isinstance(document, Mapping):
            nested = document.get("findings", document.get("results"))
            if isinstance(nested, list):
                items.extend(nested)
            else:
                items.append(document)
        else:
            warnings = (*warnings, "A Joern output document was not an object and was skipped.")

    findings: list[StaticFinding] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            warnings = (*warnings, f"Joern finding {index} is not an object and was skipped.")
            continue
        try:
            rule_id = _first_text(
                item.get("ruleId"),
                item.get("rule_id"),
                item.get("rule"),
                item.get("query"),
            )
            if rule_id is None:
                raise ValueError("missing ruleId")
            message = _first_text(
                item.get("message"),
                item.get("text"),
                item.get("description"),
            )
            path = _first_text(
                item.get("file"),
                item.get("path"),
                item.get("filename"),
                item.get("filePath"),
            )
            if message is None:
                raise ValueError("missing message")
            if path is None:
                raise ValueError("missing file path")
            start = _as_mapping(item.get("start"))
            end = _as_mapping(item.get("end"))
            if start:
                one_based_line = False
                start_line = start.get("line")
                start_column = start.get("column", 0)
                end_line = end.get("line", start_line)
                end_column = end.get("column", start_column)
            else:
                one_based_line = True
                start_line = item.get("startLine", item.get("line"))
                start_column = item.get("startColumn", item.get("column"))
                end_line = item.get("endLine", start_line)
                end_column = item.get("endColumn", start_column)
            location = _location(
                path,
                workspace_root,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                one_based_line=one_based_line,
                one_based_column=one_based_line,
            )
            severity = normalize_severity(item.get("severity"))
            if severity == "info":
                score = item.get("securitySeverity", item.get("score"))
                severity = severity_from_score(score) or severity
            findings.append(
                _build_finding(
                    tool="joern",
                    rule_id=rule_id,
                    rule_name=_first_text(item.get("ruleName"), item.get("rule_name")),
                    message=message,
                    severity=severity,
                    location=location,
                    cwes=extract_cwes([item.get("cwe"), item.get("cwes"), item.get("cweId")]),
                    fingerprint=_first_text(item.get("fingerprint")),
                    evidence=_first_text(item.get("evidence"), item.get("code")),
                    tool_version=tool_version,
                    config_hash=config_hash,
                    raw=item,
                )
            )
        except (TypeError, ValueError) as exc:
            warnings = (*warnings, f"Joern finding {index} was skipped: {redact_text(exc)}")

    return ParsedOutput(tuple(findings), tuple(warnings), tool_version)


def _compatible(left: StaticFinding, right: StaticFinding) -> bool:
    if left.fingerprint and left.fingerprint == right.fingerprint:
        return True
    if left.rule_id == right.rule_id:
        return True
    return bool(set(left.cwes) & set(right.cwes))


def _finding_order(finding: StaticFinding) -> tuple[Any, ...]:
    location = finding.location
    return (
        location.path,
        location.start_line,
        location.start_column,
        location.end_line,
        location.end_column,
        finding.tool,
        finding.rule_id,
        finding.finding_id,
    )


def deduplicate_findings(findings: Sequence[StaticFinding]) -> tuple[StaticFinding, ...]:
    """Merge overlapping findings that share a rule, fingerprint, or CWE.

    A merged finding keeps the primary record, unions CWE evidence, retains the
    highest severity, and exposes every other original rule ID through
    ``related`` and ``rule_ids``. Findings with no overlapping evidence remain
    separate even when they touch the same lines.
    """
    clusters: list[list[StaticFinding]] = []
    for finding in sorted(findings, key=_finding_order):
        for cluster in clusters:
            if any(
                finding.location.overlaps(member.location) and _compatible(finding, member)
                for member in cluster
            ):
                cluster.append(finding)
                break
        else:
            clusters.append([finding])

    merged: list[StaticFinding] = []
    for cluster in clusters:
        primary = min(cluster, key=_finding_order)
        cwes = merge_cwes(*(finding.cwes for finding in cluster))
        severity = max_severity(*(finding.severity for finding in cluster))
        existing_related = {item.finding_id: item for item in primary.related}
        related: list[RelatedFinding] = list(existing_related.values())
        known = {primary.finding_id, *existing_related}
        for finding in cluster:
            if finding is primary or finding.finding_id in known:
                continue
            related.append(
                RelatedFinding(
                    finding_id=finding.finding_id,
                    tool=finding.tool,
                    rule_id=finding.rule_id,
                    cwe=finding.cwe,
                    severity=finding.severity,
                )
            )
            known.add(finding.finding_id)
        merged.append(
            replace(
                primary,
                cwes=cwes,
                severity=severity,
                related=tuple(
                    sorted(
                        related,
                        key=lambda item: (item.tool, item.rule_id, item.finding_id),
                    )
                ),
            )
        )
    return tuple(merged)


def finding_sort_key(finding: StaticFinding) -> tuple[Any, ...]:
    """Stable public ordering used by result serialization and tests."""
    return (
        *_finding_order(finding),
        -severity_rank(finding.severity),
    )
