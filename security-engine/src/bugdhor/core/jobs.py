"""In-process job tracking: progress, cancellation, and result persistence.

This is a lightweight integration layer for synchronous and asynchronous-style
operation tracking. It records explicit progress/events and persists completed
operation results as JSON artifacts under the configured data directory.
"""

from __future__ import annotations

import json
import stat
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from bugdhor.core.errors import ConflictAppError, NotFoundAppError
from bugdhor.core.persistence import sanitize_for_persistence, write_json_private


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ProgressEvent:
    timestamp: str
    stage: str
    status: str
    message: str
    percent: float | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class JobRecord:
    job_id: str
    operation: str
    request_id: str | None
    status: str  # queued|running|completed|failed|cancelled
    created_at: str
    updated_at: str
    progress: list[ProgressEvent] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "jobId": self.job_id,
            "operation": self.operation,
            "requestId": self.request_id,
            "status": self.status,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "progress": [p.to_dict() for p in self.progress],
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self, message: str = "Operation cancelled.") -> None:
        if self.cancelled:
            raise ConflictAppError(message, code="E_CANCELLED")


class JobStore:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        retention_days: int = 7,
        persist_full_payloads: bool = False,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.results_dir = self.data_dir / "results"
        self.retention_days = retention_days
        self.persist_full_payloads = persist_full_payloads
        for directory in (self.data_dir, self.jobs_dir, self.results_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(stat.S_IRWXU)
            except OSError:
                pass
        self._lock = threading.Lock()
        self._jobs: dict[str, JobRecord] = {}
        self._tokens: dict[str, CancellationToken] = {}

    def create(self, operation: str, request_id: str | None = None, metadata: Mapping[str, Any] | None = None) -> JobRecord:
        job_id = uuid.uuid4().hex[:16]
        now = _now()
        rec = JobRecord(
            job_id=job_id,
            operation=operation,
            request_id=request_id,
            status="queued",
            created_at=now,
            updated_at=now,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            self._jobs[job_id] = rec
            self._tokens[job_id] = CancellationToken()
            self._persist(rec)
        return rec

    def token(self, job_id: str) -> CancellationToken:
        with self._lock:
            tok = self._tokens.get(job_id)
            if tok is None:
                raise NotFoundAppError("Job not found.")
            return tok

    def progress(self, job_id: str, stage: str, status: str, message: str, percent: float | None = None, data: Mapping[str, Any] | None = None) -> ProgressEvent:
        evt = ProgressEvent(timestamp=_now(), stage=stage, status=status, message=message, percent=percent, data=dict(data or {}))
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                raise NotFoundAppError("Job not found.")
            if rec.status == "queued":
                rec.status = "running"
            rec.progress.append(evt)
            rec.updated_at = _now()
            self._persist(rec)
        return evt

    def complete(self, job_id: str, result: Mapping[str, Any]) -> JobRecord:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                raise NotFoundAppError("Job not found.")
            rec.status = "completed"
            rec.result = dict(result)
            rec.updated_at = _now()
            self._persist(rec)
            self._persist_result(job_id, rec.result)
        return rec

    def fail(self, job_id: str, error: Mapping[str, Any]) -> JobRecord:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                raise NotFoundAppError("Job not found.")
            rec.status = "failed"
            rec.error = dict(error)
            rec.updated_at = _now()
            self._persist(rec)
        return rec

    def cancel(self, job_id: str) -> JobRecord:
        with self._lock:
            tok = self._tokens.get(job_id)
            rec = self._jobs.get(job_id)
            if tok is None or rec is None:
                raise NotFoundAppError("Job not found.")
            tok.cancel()
            if rec.status not in {"completed", "failed"}:
                rec.status = "cancelled"
            rec.updated_at = _now()
            self._persist(rec)
        return rec

    def get(self, job_id: str) -> JobRecord:
        with self._lock:
            rec = self._jobs.get(job_id)
        if rec is not None:
            return rec
        # try disk
        path = self.jobs_dir / f"{job_id}.json"
        if not path.exists():
            raise NotFoundAppError("Job not found.")
        data = json.loads(path.read_text(encoding="utf-8"))
        # minimal reconstruction
        rec = JobRecord(
            job_id=data.get("jobId", job_id),
            operation=data.get("operation", ""),
            request_id=data.get("requestId"),
            status=data.get("status", "unknown"),
            created_at=data.get("createdAt", _now()),
            updated_at=data.get("updatedAt", _now()),
            result=data.get("result"),
            error=data.get("error"),
            metadata=data.get("metadata") or {},
        )
        with self._lock:
            self._jobs[job_id] = rec
            self._tokens.setdefault(job_id, CancellationToken())
        return rec

    def get_result(self, job_id: str) -> dict[str, Any]:
        rec = self.get(job_id)
        if rec.result is not None:
            return rec.result
        path = self.results_dir / f"{job_id}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        raise NotFoundAppError("Result not found for job.")

    def _persist(self, rec: JobRecord) -> None:
        path = self.jobs_dir / f"{rec.job_id}.json"
        payload = sanitize_for_persistence(
            rec.to_dict(), full_payloads=self.persist_full_payloads
        )
        write_json_private(path, payload, retention_days=self.retention_days)

    def _persist_result(self, job_id: str, result: Mapping[str, Any]) -> None:
        path = self.results_dir / f"{job_id}.json"
        payload = sanitize_for_persistence(dict(result), full_payloads=self.persist_full_payloads)
        write_json_private(path, payload, retention_days=self.retention_days)


__all__ = ["CancellationToken", "JobRecord", "JobStore", "ProgressEvent"]
