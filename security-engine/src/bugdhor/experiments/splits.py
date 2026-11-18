"""Dataset splitting strategies for reproducible evaluation.

Supports repository-level, temporal, CWE-based, and cross-language splits
when required metadata is available. Unsupported or unavailable strategies
are reported explicitly.
"""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from .datasets import DatasetSample, prevent_split_leakage


@dataclass(slots=True)
class SplitSpec:
    name: str
    strategy: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SplitResult:
    strategy: str
    supported: bool
    assignments: dict[str, str]  # sample_id -> split
    split_sizes: dict[str, int]
    split_hash: str
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    leakage: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "supported": self.supported,
            "assignments": self.assignments,
            "splitSizes": self.split_sizes,
            "splitHash": self.split_hash,
            "reason": self.reason,
            "warnings": self.warnings,
            "leakage": self.leakage,
            "metadata": self.metadata,
        }


def _stable_hash_assignments(assignments: Mapping[str, str]) -> str:
    payload = json_dumps_canonical({k: assignments[k] for k in sorted(assignments)})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def json_dumps_canonical(obj: Any) -> str:
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _finalize(strategy: str, assignments: dict[str, str], samples: Sequence[DatasetSample], *, supported: bool, reason: str | None = None, warnings: list[str] | None = None, metadata: dict[str, Any] | None = None) -> SplitResult:
    sizes: dict[str, int] = {}
    for sp in assignments.values():
        sizes[sp] = sizes.get(sp, 0) + 1
    leakage = prevent_split_leakage(samples, assignments).to_dict() if assignments else None
    return SplitResult(
        strategy=strategy,
        supported=supported,
        assignments=assignments,
        split_sizes=sizes,
        split_hash=_stable_hash_assignments(assignments) if assignments else hashlib.sha256(strategy.encode()).hexdigest(),
        reason=reason,
        warnings=warnings or [],
        leakage=leakage,
        metadata=metadata or {},
    )


def _group_round_robin(groups: dict[str, list[str]], ratios: dict[str, float], seed: int) -> dict[str, str]:
    rng = random.Random(seed)
    keys = list(groups.keys())
    rng.shuffle(keys)
    # assign whole groups to splits targeting ratio by sample count
    split_names = list(ratios.keys())
    total = sum(len(v) for v in groups.values()) or 1
    targets = {s: ratios[s] * total for s in split_names}
    counts = {s: 0 for s in split_names}
    assign: dict[str, str] = {}
    for k in keys:
        ids = groups[k]
        # choose split with largest remaining capacity
        best = max(split_names, key=lambda s: (targets[s] - counts[s], -counts[s]))
        for sid in ids:
            assign[sid] = best
        counts[best] += len(ids)
    return assign


def repository_level_split(
    samples: Sequence[DatasetSample],
    *,
    ratios: Mapping[str, float] | None = None,
    seed: int = 0,
    repository_field: str = "repository",
) -> SplitResult:
    ratios = dict(ratios or {"train": 0.8, "validation": 0.1, "test": 0.1})
    groups: dict[str, list[str]] = defaultdict(list)
    unknown = 0
    for s in samples:
        repo = getattr(s, repository_field, None) or s.metadata.get(repository_field) or s.metadata.get("project")
        if repo is None or str(repo).strip() == "":
            repo = f"__unknown_repo__:{s.sample_id}"
            unknown += 1
        groups[str(repo)].append(s.sample_id)
    if not groups:
        return _finalize("repository_level", {}, samples, supported=False, reason="no_samples")
    assignments = _group_round_robin(groups, ratios, seed)
    warnings = []
    if unknown:
        warnings.append(f"{unknown} samples missing repository metadata were isolated as singleton groups; true repository-level separation cannot be guaranteed for them.")
    return _finalize("repository_level", assignments, samples, supported=True, warnings=warnings, metadata={"groups": len(groups), "unknownRepositorySamples": unknown})


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    try:
        # ISO-ish fallback
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def temporal_split(
    samples: Sequence[DatasetSample],
    *,
    ratios: Mapping[str, float] | None = None,
    timestamp_field: str = "timestamp",
) -> SplitResult:
    ratios = dict(ratios or {"train": 0.8, "validation": 0.1, "test": 0.1})
    dated: list[tuple[datetime, str]] = []
    undated: list[str] = []
    for s in samples:
        ts = _parse_timestamp(getattr(s, timestamp_field, None) or s.metadata.get(timestamp_field) or s.metadata.get("commit_date") or s.metadata.get("date"))
        if ts is None:
            undated.append(s.sample_id)
        else:
            dated.append((ts, s.sample_id))
    if not dated:
        return _finalize(
            "temporal",
            {},
            samples,
            supported=False,
            reason="temporal_metadata_unavailable",
            warnings=["No parseable temporal metadata found; temporal split cannot be performed."],
            metadata={"datedSamples": 0, "undatedSamples": len(samples)},
        )
    dated.sort(key=lambda x: (x[0], x[1]))
    n = len(dated)
    names = list(ratios.keys())
    # cumulative cut points in order
    cuts = []
    acc = 0.0
    for name in names[:-1]:
        acc += float(ratios[name])
        cuts.append((name, int(round(acc * n))))
    cuts.append((names[-1], n))
    assignments: dict[str, str] = {}
    start = 0
    for name, end in cuts:
        for _, sid in dated[start:end]:
            assignments[sid] = name
        start = end
    # undated samples cannot be reliably placed temporally; report explicitly
    warnings = []
    if undated:
        warnings.append(f"{len(undated)} samples lack parseable temporal metadata and were excluded from temporal assignments.")
    supported = len(undated) == 0
    reason = None if supported else "partial_temporal_metadata"
    return _finalize(
        "temporal",
        assignments,
        samples,
        supported=supported,
        reason=reason,
        warnings=warnings,
        metadata={"datedSamples": len(dated), "undatedSamples": len(undated), "order": "ascending_timestamp"},
    )


def cwe_based_split(
    samples: Sequence[DatasetSample],
    *,
    holdout_cwes: Sequence[str] | None = None,
    ratios: Mapping[str, float] | None = None,
    seed: int = 0,
) -> SplitResult:
    """Split by CWE groups. If holdout_cwes provided, those CWEs go to test.

    Otherwise CWEs are grouped and assigned to splits (CWE-disjoint where feasible).
    """
    ratios = dict(ratios or {"train": 0.8, "validation": 0.1, "test": 0.1})
    groups: dict[str, list[str]] = defaultdict(list)
    unknown = 0
    for s in samples:
        cwe = s.cwe or s.metadata.get("cwe") or s.metadata.get("cwe_id")
        if cwe is None or str(cwe).strip() == "":
            cwe = "__unknown_cwe__"
            unknown += 1
        groups[str(cwe)].append(s.sample_id)
    if not groups:
        return _finalize("cwe_based", {}, samples, supported=False, reason="no_samples")
    assignments: dict[str, str] = {}
    warnings = []
    if holdout_cwes:
        hold = {str(c).upper() for c in holdout_cwes}
        remaining: dict[str, list[str]] = {}
        for cwe, ids in groups.items():
            if cwe.upper() in hold:
                for sid in ids:
                    assignments[sid] = "test"
            else:
                remaining[cwe] = ids
        # split remaining into train/val by group
        rem_ratios = {"train": ratios.get("train", 0.8) / max(1e-9, ratios.get("train", 0.8) + ratios.get("validation", 0.1)),
                      "validation": ratios.get("validation", 0.1) / max(1e-9, ratios.get("train", 0.8) + ratios.get("validation", 0.1))}
        if remaining:
            rem_assign = _group_round_robin(remaining, rem_ratios, seed)
            assignments.update(rem_assign)
        meta = {"holdoutCwes": sorted(hold), "groups": len(groups)}
    else:
        assignments = _group_round_robin(groups, ratios, seed)
        meta = {"groups": len(groups), "mode": "group_disjoint_assignment"}
    if unknown:
        warnings.append(f"{unknown} samples missing CWE metadata were grouped as unknown; CWE-based separation is partial for them.")
    return _finalize("cwe_based", assignments, samples, supported=True, warnings=warnings, metadata={**meta, "unknownCweSamples": unknown})


def cross_language_split(
    samples: Sequence[DatasetSample],
    *,
    train_languages: Sequence[str] | None = None,
    test_languages: Sequence[str] | None = None,
) -> SplitResult:
    if not train_languages or not test_languages:
        return _finalize(
            "cross_language",
            {},
            samples,
            supported=False,
            reason="train_and_test_languages_required",
            warnings=["Cross-language split requires explicit train_languages and test_languages."],
        )
    train_set = {str(x).lower() for x in train_languages}
    test_set = {str(x).lower() for x in test_languages}
    assignments: dict[str, str] = {}
    unknown = 0
    for s in samples:
        lang = (s.language or s.metadata.get("language") or "").strip().lower()
        if not lang:
            unknown += 1
            continue
        if lang in train_set:
            assignments[s.sample_id] = "train"
        elif lang in test_set:
            assignments[s.sample_id] = "test"
    if not assignments:
        return _finalize(
            "cross_language",
            {},
            samples,
            supported=False,
            reason="no_matching_language_samples",
            warnings=["No samples matched the requested train/test languages."],
            metadata={"unknownLanguageSamples": unknown},
        )
    warnings = []
    if unknown:
        warnings.append(f"{unknown} samples missing language metadata were excluded.")
    return _finalize(
        "cross_language",
        assignments,
        samples,
        supported=True,
        warnings=warnings,
        metadata={"trainLanguages": sorted(train_set), "testLanguages": sorted(test_set), "unknownLanguageSamples": unknown},
    )


SPLITTERS = {
    "repository_level": repository_level_split,
    "temporal": temporal_split,
    "cwe_based": cwe_based_split,
    "cross_language": cross_language_split,
}


__all__ = [
    "SPLITTERS",
    "SplitResult",
    "SplitSpec",
    "cross_language_split",
    "cwe_based_split",
    "repository_level_split",
    "temporal_split",
]
