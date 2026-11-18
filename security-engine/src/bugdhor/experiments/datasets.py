"""Dataset loading, validation, deduplication, and leakage prevention.

This module implements dataset abstractions for reproducible evaluation.
Loaders only access data when it is actually available locally and when
licensing/access constraints are explicitly acknowledged by configuration.
No dataset contents are fabricated or bundled.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

SUPPORTED_DATASETS = (
    "Big-Vul",
    "Devign",
    "Juliet",
    "PrimeVul",
    "DiverseVul",
    "CodeXGLUE",
    "CyberSecEval",
)


@dataclass(slots=True)
class DatasetAvailability:
    dataset_id: str
    available: bool
    path: str | None = None
    license_acknowledged: bool = False
    license: str | None = None
    redistribution_allowed: bool | None = None
    reason: str | None = None
    files_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DatasetSample:
    """Normalized evaluation sample.

    Fields are populated only from available source records/metadata.
    Unknown or unavailable fields remain None/empty and must not be invented.
    """

    sample_id: str
    dataset: str
    code: str
    label: int | None = None  # 1 vulnerable, 0 non-vulnerable, None unknown
    cwe: str | None = None
    language: str | None = None
    repository: str | None = None
    commit: str | None = None
    timestamp: str | None = None
    file_path: str | None = None
    vulnerable_lines: list[int] = field(default_factory=list)
    split: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def content_hash(self) -> str:
        payload = f"{self.language or ''}\n{self.code.strip()}"
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def identity_key(self) -> str:
        # Conservative identity for dedup/leakage: prefer explicit IDs, else content hash.
        parts = [self.dataset]
        for key in ("repository", "commit", "file_path"):
            val = getattr(self, key)
            if val:
                parts.append(str(val))
        if self.sample_id:
            parts.append(self.sample_id)
        parts.append(self.content_hash())
        return "|".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ValidationIssue:
    level: str  # error|warning
    code: str
    message: str
    sample_id: str | None = None


@dataclass(slots=True)
class ValidationReport:
    ok: bool
    total: int
    valid: int
    issues: list[ValidationIssue] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "total": self.total,
            "valid": self.valid,
            "issues": [asdict(i) for i in self.issues],
            "stats": self.stats,
        }


@dataclass(slots=True)
class DuplicateReport:
    total: int
    unique_by_content: int
    duplicate_groups: int
    duplicate_samples: int
    groups: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class LeakageReport:
    ok: bool
    split_field: str
    overlaps: dict[str, dict[str, int]] = field(default_factory=dict)
    examples: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DATASET_LICENSE_NOTES = {
    "Big-Vul": "Check original Big-Vul/source repository and constituent project licenses before use or redistribution.",
    "Devign": "Check Devign dataset license/terms and upstream repository licenses.",
    "Juliet": "NIST Juliet Test Suite; verify current distribution/license terms for the obtained version.",
    "PrimeVul": "Check PrimeVul license/terms and source provenance.",
    "DiverseVul": "Check DiverseVul license/terms and source provenance.",
    "CodeXGLUE": "CodeXGLUE aggregates tasks/datasets with varying licenses; verify per-task license.",
    "CyberSecEval": "Check CyberSecEval/benchmark license and usage restrictions for the obtained release.",
}


class DatasetRegistry:
    """Registry of supported dataset loaders and availability checks."""

    def __init__(self) -> None:
        self._loaders: dict[str, Callable[[Path, Mapping[str, Any]], Iterator[DatasetSample]]] = {
            "Big-Vul": load_big_vul,
            "Devign": load_devign,
            "Juliet": load_juliet,
            "PrimeVul": load_primevul,
            "DiverseVul": load_diversevul,
            "CodeXGLUE": load_codexglue,
            "CyberSecEval": load_cyberseceval,
        }

    @property
    def supported(self) -> tuple[str, ...]:
        return SUPPORTED_DATASETS

    def availability(self, dataset_id: str, root: str | Path | None, *, license_acknowledged: bool = False) -> DatasetAvailability:
        if dataset_id not in self._loaders:
            return DatasetAvailability(dataset_id=dataset_id, available=False, reason="unsupported_dataset")
        if root is None:
            return DatasetAvailability(
                dataset_id=dataset_id,
                available=False,
                license_acknowledged=license_acknowledged,
                license=DATASET_LICENSE_NOTES.get(dataset_id),
                reason="no_local_path_configured",
            )
        path = Path(root)
        if not path.exists():
            return DatasetAvailability(
                dataset_id=dataset_id,
                available=False,
                path=str(path),
                license_acknowledged=license_acknowledged,
                license=DATASET_LICENSE_NOTES.get(dataset_id),
                reason="path_not_found",
            )
        files = _detect_dataset_files(dataset_id, path)
        if not files:
            return DatasetAvailability(
                dataset_id=dataset_id,
                available=False,
                path=str(path),
                license_acknowledged=license_acknowledged,
                license=DATASET_LICENSE_NOTES.get(dataset_id),
                reason="no_recognized_dataset_files",
            )
        if not license_acknowledged:
            return DatasetAvailability(
                dataset_id=dataset_id,
                available=False,
                path=str(path),
                license_acknowledged=False,
                license=DATASET_LICENSE_NOTES.get(dataset_id),
                reason="license_not_acknowledged",
                files_found=files,
            )
        return DatasetAvailability(
            dataset_id=dataset_id,
            available=True,
            path=str(path),
            license_acknowledged=True,
            license=DATASET_LICENSE_NOTES.get(dataset_id),
            redistribution_allowed=None,
            files_found=files,
        )

    def load(
        self,
        dataset_id: str,
        root: str | Path,
        *,
        license_acknowledged: bool,
        options: Mapping[str, Any] | None = None,
    ) -> tuple[list[DatasetSample], DatasetAvailability]:
        avail = self.availability(dataset_id, root, license_acknowledged=license_acknowledged)
        if not avail.available or avail.path is None:
            return [], avail
        loader = self._loaders[dataset_id]
        samples = list(loader(Path(avail.path), options or {}))
        return samples, avail


def _detect_dataset_files(dataset_id: str, path: Path) -> list[str]:
    patterns: dict[str, tuple[str, ...]] = {
        "Big-Vul": ("**/*.csv", "**/*.json", "**/*.jsonl", "**/*.parquet"),
        "Devign": ("**/*.json", "**/*.jsonl", "**/*.csv", "**/*.pkl"),
        "Juliet": ("**/*.c", "**/*.cpp", "**/*.java", "**/manifest*.xml", "**/*.csv"),
        "PrimeVul": ("**/*.json", "**/*.jsonl", "**/*.csv", "**/*.parquet"),
        "DiverseVul": ("**/*.json", "**/*.jsonl", "**/*.csv", "**/*.parquet"),
        "CodeXGLUE": ("**/*.json", "**/*.jsonl", "**/*.txt", "**/*.csv"),
        "CyberSecEval": ("**/*.json", "**/*.jsonl", "**/*.csv"),
    }
    found: list[str] = []
    for pat in patterns.get(dataset_id, ("**/*",)):
        for p in path.glob(pat):
            if p.is_file():
                try:
                    found.append(str(p.relative_to(path)))
                except ValueError:
                    found.append(str(p))
            if len(found) >= 50:
                return sorted(set(found))
    return sorted(set(found))


def _read_json_records(path: Path) -> Iterator[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
                except Exception:
                    continue
        return
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
        elif isinstance(data, dict):
            # common wrappers
            for key in ("data", "records", "samples", "items"):
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, dict):
                            yield item
                    return
            yield data


def _read_csv_records(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if isinstance(row, dict):
                    yield dict(row)
    except Exception:
        return


def _iter_records(root: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        if suf in {".json", ".jsonl"}:
            for rec in _read_json_records(p):
                yield p, rec
        elif suf == ".csv":
            for rec in _read_csv_records(p):
                yield p, rec


def _norm_label(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        if value in (0, 1):
            return int(value)
        return 1 if value > 0 else 0
    s = str(value).strip().lower()
    if s in {"1", "true", "vuln", "vulnerable", "bad", "positive", "yes"}:
        return 1
    if s in {"0", "false", "clean", "safe", "non-vulnerable", "non_vulnerable", "good", "negative", "no"}:
        return 0
    return None


def _pick(rec: Mapping[str, Any], *keys: str) -> Any:
    lower = {str(k).lower(): k for k in rec.keys()}
    for key in keys:
        if key in rec and rec[key] not in (None, ""):
            return rec[key]
        lk = key.lower()
        if lk in lower and rec[lower[lk]] not in (None, ""):
            return rec[lower[lk]]
    return None


def _sample_from_record(dataset: str, rec: Mapping[str, Any], idx: int, source: str) -> DatasetSample | None:
    code = _pick(rec, "func", "code", "func_before", "function", "source", "snippet", "content", "text", "program")
    if code is None or not str(code).strip():
        return None
    sample_id = str(_pick(rec, "id", "sample_id", "example_id", "index", "func_id", "commit_id") or f"{dataset}-{idx}")
    label = _norm_label(_pick(rec, "target", "label", "vul", "vulnerable", "is_vul", "is_vulnerable", "ground_truth"))
    cwe_raw = _pick(rec, "cwe", "cwe_id", "cwe_ids", "vul_type")
    cwe = None
    if cwe_raw is not None:
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_raw = cwe_raw[0]
        m = re.search(r"CWE-\d+", str(cwe_raw), re.IGNORECASE)
        cwe = m.group(0).upper() if m else (str(cwe_raw) if str(cwe_raw).strip() else None)
    repo = _pick(rec, "project", "repo", "repository", "project_url", "repo_name")
    commit = _pick(rec, "commit_id", "commit", "hash", "version")
    ts = _pick(rec, "publish_date", "timestamp", "date", "commit_date", "created_at")
    lang = _pick(rec, "lang", "language", "file_extension")
    file_path = _pick(rec, "file_name", "file_path", "filename", "path")
    lines = _pick(rec, "vulnerable_lines", "flaw_line", "line", "lines")
    vuln_lines: list[int] = []
    if isinstance(lines, list):
        for x in lines:
            try:
                vuln_lines.append(int(x))
            except Exception:
                pass
    elif isinstance(lines, (int, float)):
        vuln_lines = [int(lines)]
    elif isinstance(lines, str) and lines.strip():
        for part in re.split(r"[\s,]+", lines.strip()):
            try:
                vuln_lines.append(int(part))
            except Exception:
                pass
    meta = {k: v for k, v in rec.items() if k not in {"func", "code", "func_before", "function", "source", "snippet", "content"}}
    meta["_source_file"] = source
    return DatasetSample(
        sample_id=sample_id,
        dataset=dataset,
        code=str(code),
        label=label,
        cwe=cwe,
        language=str(lang) if lang is not None else None,
        repository=str(repo) if repo is not None else None,
        commit=str(commit) if commit is not None else None,
        timestamp=str(ts) if ts is not None else None,
        file_path=str(file_path) if file_path is not None else None,
        vulnerable_lines=vuln_lines,
        metadata=meta,
    )


def _generic_load(dataset: str, root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    limit = options.get("limit")
    idx = 0
    for src, rec in _iter_records(root):
        sample = _sample_from_record(dataset, rec, idx, str(src.relative_to(root) if src.is_relative_to(root) else src))
        idx += 1
        if sample is not None:
            yield sample
            if isinstance(limit, int) and limit > 0:
                limit -= 1
                if limit <= 0:
                    return


def load_big_vul(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("Big-Vul", root, options)


def load_devign(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("Devign", root, options)


def load_juliet(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    # Juliet is often distributed as source files/test cases; try structured records first.
    any_structured = any(p.suffix.lower() in {".json", ".jsonl", ".csv"} for p in root.rglob("*") if p.is_file())
    limit = options.get("limit")
    if any_structured:
        yield from _generic_load("Juliet", root, options)
        return
    idx = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".java"}:
            continue
        # Skip helper/support mains if they have no case markers? keep broad but honest.
        try:
            code = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        name = p.stem
        cwe_m = re.search(r"CWE\d+", name)
        cwe = cwe_m.group(0).replace("CWE", "CWE-") if cwe_m else None
        label = 1 if re.search(r"bad", name, re.IGNORECASE) else (0 if re.search(r"good", name, re.IGNORECASE) else None)
        yield DatasetSample(
            sample_id=f"juliet:{p.relative_to(root)}",
            dataset="Juliet",
            code=code,
            label=label,
            cwe=cwe,
            language="c/c++" if p.suffix.lower() != ".java" else "java",
            file_path=str(p.relative_to(root)),
            metadata={"_source_file": str(p.relative_to(root))},
        )
        idx += 1
        if isinstance(limit, int) and limit > 0 and idx >= limit:
            return


def load_primevul(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("PrimeVul", root, options)


def load_diversevul(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("DiverseVul", root, options)


def load_codexglue(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("CodeXGLUE", root, options)


def load_cyberseceval(root: Path, options: Mapping[str, Any]) -> Iterator[DatasetSample]:
    yield from _generic_load("CyberSecEval", root, options)


def validate_samples(samples: Sequence[DatasetSample], *, require_label: bool = False) -> ValidationReport:
    issues: list[ValidationIssue] = []
    valid = 0
    langs: dict[str, int] = {}
    cwes: dict[str, int] = {}
    labeled = 0
    for s in samples:
        sample_ok = True
        if not s.sample_id:
            issues.append(ValidationIssue("error", "missing_sample_id", "Sample is missing sample_id"))
            sample_ok = False
        if not s.dataset:
            issues.append(ValidationIssue("error", "missing_dataset", "Sample is missing dataset", s.sample_id))
            sample_ok = False
        if not s.code or not s.code.strip():
            issues.append(ValidationIssue("error", "empty_code", "Sample code is empty", s.sample_id))
            sample_ok = False
        if len(s.code.encode("utf-8", errors="replace")) > 2_000_000:
            issues.append(ValidationIssue("warning", "very_large_code", "Sample code is unusually large", s.sample_id))
        if s.label is not None and s.label not in (0, 1):
            issues.append(ValidationIssue("error", "invalid_label", f"Label must be 0/1/None, got {s.label}", s.sample_id))
            sample_ok = False
        if require_label and s.label is None:
            issues.append(ValidationIssue("error", "missing_label", "Label is required but missing", s.sample_id))
            sample_ok = False
        if s.cwe and not re.match(r"^CWE-\d+$", s.cwe):
            issues.append(ValidationIssue("warning", "nonstandard_cwe", f"CWE format not normalized: {s.cwe}", s.sample_id))
        if s.language:
            langs[str(s.language)] = langs.get(str(s.language), 0) + 1
        if s.cwe:
            cwes[str(s.cwe)] = cwes.get(str(s.cwe), 0) + 1
        if s.label is not None:
            labeled += 1
        if sample_ok:
            valid += 1
    ok = not any(i.level == "error" for i in issues)
    stats = {
        "labeled": labeled,
        "unlabeled": len(samples) - labeled,
        "languages": langs,
        "cwes": dict(sorted(cwes.items(), key=lambda x: -x[1])[:50]),
    }
    return ValidationReport(ok=ok, total=len(samples), valid=valid, issues=issues, stats=stats)


def detect_duplicates(samples: Sequence[DatasetSample]) -> DuplicateReport:
    by_hash: dict[str, list[str]] = {}
    for s in samples:
        h = s.content_hash()
        by_hash.setdefault(h, []).append(s.sample_id)
    groups = [ids for ids in by_hash.values() if len(ids) > 1]
    dup_samples = sum(len(g) - 1 for g in groups)
    return DuplicateReport(
        total=len(samples),
        unique_by_content=len(by_hash),
        duplicate_groups=len(groups),
        duplicate_samples=dup_samples,
        groups=groups,
    )


def deduplicate_samples(samples: Sequence[DatasetSample], *, strategy: str = "content_hash") -> list[DatasetSample]:
    seen: set[str] = set()
    out: list[DatasetSample] = []
    for s in samples:
        key = s.content_hash() if strategy == "content_hash" else s.identity_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def prevent_split_leakage(
    samples: Sequence[DatasetSample],
    split_assignments: Mapping[str, str],
    *,
    key_fields: Sequence[str] = ("content_hash", "repository", "commit"),
) -> LeakageReport:
    """Detect leakage between splits by shared identity/content keys.

    `split_assignments` maps sample_id -> split name. Samples not present are ignored.
    """
    # build key -> set(splits)
    split_of = dict(split_assignments)
    key_to_splits: dict[tuple[str, str], set[str]] = {}
    key_examples: dict[tuple[str, str], list[str]] = {}
    for s in samples:
        sp = split_of.get(s.sample_id)
        if not sp:
            continue
        keys: list[tuple[str, str]] = [("content_hash", s.content_hash())]
        if s.repository:
            keys.append(("repository", str(s.repository)))
        if s.commit:
            keys.append(("commit", str(s.commit)))
        for k in keys:
            key_to_splits.setdefault(k, set()).add(sp)
            key_examples.setdefault(k, [])
            if len(key_examples[k]) < 5:
                key_examples[k].append(s.sample_id)

    overlaps: dict[str, dict[str, int]] = {}
    examples: dict[str, list[str]] = {}
    for (kind, _), splits in key_to_splits.items():
        if len(splits) <= 1:
            continue
        pair = "+".join(sorted(splits))
        overlaps.setdefault(kind, {})[pair] = overlaps.get(kind, {}).get(pair, 0) + 1
        if kind not in examples:
            examples[kind] = list(key_examples.get((kind, _), []))[:5]
    ok = not overlaps
    return LeakageReport(ok=ok, split_field="sample_id", overlaps=overlaps, examples=examples)


__all__ = [
    "DATASET_LICENSE_NOTES",
    "DatasetAvailability",
    "DatasetRegistry",
    "DatasetSample",
    "DuplicateReport",
    "LeakageReport",
    "SUPPORTED_DATASETS",
    "ValidationIssue",
    "ValidationReport",
    "deduplicate_samples",
    "detect_duplicates",
    "prevent_split_leakage",
    "validate_samples",
]
