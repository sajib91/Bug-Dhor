"""File and workspace scan endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from bugdhor.api.dependencies import get_job_store, get_orchestrator, get_request_id
from bugdhor.api.routes.common import COMMON_ERROR_RESPONSES
from bugdhor.api.schemas.scan import (
    ScanFileRequest,
    ScanFileResponse,
    ScanWorkspaceRequest,
    ScanWorkspaceResponse,
)
from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post(
    "/file",
    response_model=ScanFileResponse,
    summary="Inspect one file and run the available scan pipeline",
    responses=COMMON_ERROR_RESPONSES,
)
def scan_file(
    payload: ScanFileRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> ScanFileResponse:
    return orchestrator.scan_file(payload, request_id, job_store=job_store)


@router.post(
    "/workspace",
    response_model=ScanWorkspaceResponse,
    summary="Discover workspace sources and run the available scan pipeline",
    responses=COMMON_ERROR_RESPONSES,
)
def scan_workspace(
    payload: ScanWorkspaceRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    request_id: Annotated[str, Depends(get_request_id)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> ScanWorkspaceResponse:
    return orchestrator.scan_workspace(payload, request_id, job_store=job_store)
