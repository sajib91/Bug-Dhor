"""FastAPI dependency accessors for application state."""

from __future__ import annotations

from fastapi import Request

from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator
from bugdhor.core.settings import Settings


def get_orchestrator(request: Request) -> Orchestrator:
    return request.app.state.orchestrator


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "-"))


def get_job_store(request: Request) -> JobStore:
    return request.app.state.job_store
