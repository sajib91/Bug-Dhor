"""Job progress, cancellation, and persisted result endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from bugdhor.api.dependencies import get_job_store, get_request_id
from bugdhor.api.routes.common import COMMON_ERROR_RESPONSES
from bugdhor.core.jobs import JobStore

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get(
    "/{job_id}",
    summary="Get job status, progress, and summary",
    responses=COMMON_ERROR_RESPONSES,
)
def get_job(
    job_id: str,
    job_store: Annotated[JobStore, Depends(get_job_store)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> dict[str, Any]:
    rec = job_store.get(job_id)
    data = rec.to_dict()
    data["apiVersion"] = "v1"
    data["requestId"] = request_id
    return data


@router.get(
    "/{job_id}/result",
    summary="Get persisted job result",
    responses=COMMON_ERROR_RESPONSES,
)
def get_job_result(
    job_id: str,
    job_store: Annotated[JobStore, Depends(get_job_store)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> dict[str, Any]:
    result = job_store.get_result(job_id)
    return {"jobId": job_id, "requestId": request_id, "apiVersion": "v1", "result": result}


@router.post(
    "/{job_id}/cancel",
    summary="Request cancellation of a tracked job",
    responses=COMMON_ERROR_RESPONSES,
)
def cancel_job(
    job_id: str,
    job_store: Annotated[JobStore, Depends(get_job_store)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> dict[str, Any]:
    rec = job_store.cancel(job_id)
    data = rec.to_dict()
    data["apiVersion"] = "v1"
    data["requestId"] = request_id
    return data
