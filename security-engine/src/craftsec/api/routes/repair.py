"""Repair workflow endpoint.

Runs the integrated repair verification workflow. Patches are never applied by
the engine; explicit user approval and client-side application are required.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from craftsec.api.dependencies import get_job_store, get_orchestrator, get_request_id
from craftsec.api.routes.common import COMMON_ERROR_RESPONSES
from craftsec.api.schemas.repair import RepairRequest, RepairResponse
from craftsec.core.jobs import JobStore
from craftsec.core.orchestrator import Orchestrator

router = APIRouter(prefix="/repair", tags=["repair"])


@router.post(
    "/generate",
    response_model=RepairResponse,
    summary="Generate/verify a repair candidate through the integrated security and functional workflow",
    responses=COMMON_ERROR_RESPONSES,
)
def generate_repair(
    payload: RepairRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> RepairResponse:
    return orchestrator.repair_generate(payload, request_id, job_store=job_store)
