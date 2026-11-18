"""Explanation endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from bugdhor.api.dependencies import get_job_store, get_orchestrator, get_request_id
from bugdhor.api.routes.common import COMMON_ERROR_RESPONSES
from bugdhor.api.schemas.analysis import ExplanationRequest, ExplanationResponse
from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator

router = APIRouter(prefix="/explanation", tags=["explanation"])


@router.post(
    "/analyze",
    response_model=ExplanationResponse,
    summary="Build an evidence-grounded explanation for a finding",
    responses=COMMON_ERROR_RESPONSES,
)
def analyze_explanation(
    payload: ExplanationRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> ExplanationResponse:
    return orchestrator.explanation_analyze(payload, request_id, job_store=job_store)
