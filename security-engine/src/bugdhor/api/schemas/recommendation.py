"""Secure code recommendation request and response contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from bugdhor.api.schemas.common import APIModel, OperationResponse
from bugdhor.api.schemas.repair import ExecutionConsentModel, RepairFindingContext
from bugdhor.api.schemas.scan import FileContext


class RecommendationProviderModel(APIModel):
    """Non-secret provenance for the configured generation provider."""

    provider_id: str | None = Field(default=None, max_length=200)
    model_id: str | None = Field(default=None, max_length=300)
    capabilities: list[str] = Field(default_factory=list, max_length=10)
    hosted: bool | None = None
    steering_requested: bool = False
    steering_validated: bool = False


class RecommendationRequest(FileContext):
    finding: RepairFindingContext
    candidates: list[str] = Field(default_factory=list, max_length=8)
    provider: RecommendationProviderModel = Field(default_factory=RecommendationProviderModel)
    security_evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    snapshot_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    execution_consent: ExecutionConsentModel = Field(default_factory=ExecutionConsentModel)
    run_functional_tests: bool = True
    test_timeout_seconds: float = Field(default=120.0, ge=1.0, le=3600.0)
    project_test_command: list[str] | None = Field(default=None, max_length=50)


class RecommendationResult(APIModel):
    analysis_available: bool
    finding_id: str
    cwe: str | None = None
    state: str = "unknown"
    original_code: str | None = None
    repaired_code: str | None = None
    selected: dict[str, Any] | None = None
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    prompt: dict[str, Any] = Field(default_factory=dict)
    stages: list[dict[str, Any]] = Field(default_factory=list)
    explanation: dict[str, Any] = Field(default_factory=dict)
    requires_approval: Literal[True] = True
    verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class RecommendationResponse(OperationResponse):
    result: RecommendationResult | None = None
