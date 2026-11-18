"""Secure code recommendation endpoint.

The backend generates, verifies, and ranks proposals only. It never applies a
patch; explicit client-side user approval remains mandatory.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from bugdhor.api.dependencies import get_job_store, get_orchestrator, get_request_id
from bugdhor.api.routes.common import COMMON_ERROR_RESPONSES
from bugdhor.api.schemas.recommendation import RecommendationRequest, RecommendationResponse
from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator

router = APIRouter(prefix="/recommendations", tags=["recommendations"])


@router.post(
    "/generate",
    response_model=RecommendationResponse,
    summary="Generate and verify a secure code recommendation proposal",
    responses=COMMON_ERROR_RESPONSES,
)
def generate_recommendation(
    payload: RecommendationRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> RecommendationResponse:
    return orchestrator.recommendation_generate(
        payload, request_id, job_store=job_store, job_id=None
    )
