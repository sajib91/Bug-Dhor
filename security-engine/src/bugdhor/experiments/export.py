"""Result export utilities for experiment runs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .config import canonical_json


def export_json(path: str | Path, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(canonical_json(data) + "\n", encoding="utf-8")
    return p


def export_jsonl(path: str | Path, records: Iterable[Mapping[str, Any]]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(canonical_json(dict(rec)) + "\n")
    return p


def export_csv(path: str | Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str] | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows_list = [dict(r) for r in rows]
    if fieldnames is None:
        keys: list[str] = []
        seen: set[str] = set()
        for r in rows_list:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        fieldnames = keys
    with p.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames))
        writer.writeheader()
        for r in rows_list:
            flat = {}
            for k in fieldnames:
                v = r.get(k)
                if isinstance(v, (dict, list)):
                    flat[k] = json.dumps(v, sort_keys=True, ensure_ascii=False)
                else:
                    flat[k] = v
            writer.writerow(flat)
    return p


def export_results_bundle(
    out_dir: str | Path,
    *,
    manifest: Mapping[str, Any],
    raw_outputs: Sequence[Mapping[str, Any]] | None = None,
    metrics: Mapping[str, Any] | None = None,
    per_sample: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, str]:
    """Export a self-describing result bundle (JSON/CSV)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    written["manifest"] = str(export_json(out / "manifest.json", dict(manifest)))
    if raw_outputs is not None:
        written["raw_outputs"] = str(export_json(out / "raw_outputs.json", list(raw_outputs)))
    if metrics is not None:
        written["metrics_json"] = str(export_json(out / "metrics.json", dict(metrics)))
        # flat metrics row for CSV convenience
        written["metrics_csv"] = str(export_csv(out / "metrics.csv", [dict(metrics)]))
    if per_sample is not None:
        written["per_sample_jsonl"] = str(export_jsonl(out / "per_sample.jsonl", per_sample))
        written["per_sample_csv"] = str(export_csv(out / "per_sample.csv", list(per_sample)))
    return written


__all__ = ["export_csv", "export_json", "export_jsonl", "export_results_bundle"]
