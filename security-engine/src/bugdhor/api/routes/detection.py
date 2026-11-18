"""Detection endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from bugdhor.api.dependencies import get_job_store, get_orchestrator, get_request_id
from bugdhor.api.routes.common import COMMON_ERROR_RESPONSES
from bugdhor.api.schemas.analysis import DetectionRequest, DetectionResponse
from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator

router = APIRouter(prefix="/detection", tags=["detection"])


@router.post(
    "/analyze",
    response_model=DetectionResponse,
    summary="Analyze static and model evidence for a file",
    responses=COMMON_ERROR_RESPONSES,
)
def analyze_detection(
    payload: DetectionRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> DetectionResponse:
    return orchestrator.detection_analyze(payload, request_id, job_store=job_store)
