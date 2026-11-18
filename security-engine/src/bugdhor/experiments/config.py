"""Experiment configuration, hashing, and run manifest tracking."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .groups import EXPERIMENT_GROUPS


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


@dataclass(slots=True)
class ExperimentConfig:
    """Reproducible experiment configuration.

    Contains only declared configuration; results/outputs are recorded separately.
    """

    experiment_id: str
    name: str
    group: str  # E0-E8
    dataset: dict[str, Any]
    split: dict[str, Any]
    model: dict[str, Any]
    parameters: dict[str, Any] = field(default_factory=dict)
    seed: int = 0
    tools: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    notes: str | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.group not in EXPERIMENT_GROUPS:
            errors.append(f"unknown_experiment_group:{self.group}")
        if not self.experiment_id:
            errors.append("missing_experiment_id")
        if not self.name:
            errors.append("missing_name")
        return errors

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["configHash"] = self.config_hash()
        return d

    def config_hash(self) -> str:
        payload = {
            "experimentId": self.experiment_id,
            "name": self.name,
            "group": self.group,
            "dataset": self.dataset,
            "split": self.split,
            "model": self.model,
            "parameters": self.parameters,
            "seed": self.seed,
            "tools": self.tools,
            "tags": sorted(self.tags),
        }
        return sha256_text(canonical_json(payload))


@dataclass(slots=True)
class RunRecord:
    run_id: str
    experiment_id: str
    config_hash: str
    group: str
    status: str  # planned|running|completed|failed|unavailable
    started_at: str | None = None
    completed_at: str | None = None
    dataset: dict[str, Any] = field(default_factory=dict)
    split: dict[str, Any] = field(default_factory=dict)
    model: dict[str, Any] = field(default_factory=dict)
    tool_versions: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    raw_output_paths: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collect_environment() -> dict[str, Any]:
    return {
        "pythonVersion": sys.version.split()[0],
        "platform": platform.platform(),
        "implementation": platform.python_implementation(),
        "machine": platform.machine(),
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExperimentTracker:
    """Tracks experiment configs and writes raw outputs/manifests.

    Stores artifacts under a run directory; does not fabricate results.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def run_dir(self, run_id: str) -> Path:
        d = self.base_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "raw").mkdir(exist_ok=True)
        return d

    def create_manifest(self, config: ExperimentConfig, run_id: str) -> dict[str, Any]:
        errors = config.validate()
        manifest = {
            "runId": run_id,
            "experimentId": config.experiment_id,
            "name": config.name,
            "group": config.group,
            "groupDescription": EXPERIMENT_GROUPS.get(config.group),
            "status": "planned" if not errors else "invalid_config",
            "createdAt": now_iso(),
            "completedAt": None,
            "config": config.to_dict(),
            "configHash": config.config_hash(),
            "seed": config.seed,
            "dataset": config.dataset,
            "split": config.split,
            "model": config.model,
            "toolVersions": config.tools,
            "environment": collect_environment(),
            "rawOutputs": [],
            "artifacts": [],
            "metrics": None,
            "errors": errors,
            "notes": ["No results fabricated; metrics populated only from recorded observations."],
        }
        return manifest

    def save_manifest(self, run_id: str, manifest: Mapping[str, Any]) -> Path:
        path = self.run_dir(run_id) / "manifest.json"
        path.write_text(canonical_json(dict(manifest)) + "\n", encoding="utf-8")
        return path

    def record_raw_output(self, run_id: str, name: str, data: Any) -> Path:
        d = self.run_dir(run_id) / "raw"
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "output"
        path = d / f"{safe}.json"
        path.write_text(canonical_json(data) + "\n", encoding="utf-8")
        return path

    def append_jsonl(self, run_id: str, name: str, record: Mapping[str, Any]) -> Path:
        d = self.run_dir(run_id) / "raw"
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "records"
        path = d / f"{safe}.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(dict(record)) + "\n")
        return path


__all__ = [
    "ExperimentConfig",
    "ExperimentTracker",
    "RunRecord",
    "canonical_json",
    "collect_environment",
    "now_iso",
    "sha256_file",
    "sha256_text",
]
