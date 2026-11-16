"""Repository-aware repair and integrated verification workflow contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from craftsec.api.schemas.common import APIModel, OperationResponse, Range
from craftsec.api.schemas.scan import FileContext


class RepairFindingContext(APIModel):
    finding_id: str = Field(min_length=1, max_length=200)
    document_uri: str | None = Field(default=None, max_length=4096)
    range: Range
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    rule_id: str | None = Field(default=None, max_length=500)


class ExecutionConsentModel(APIModel):
    granted: bool = False
    allow_network: bool = False
    allow_privileged: bool = False
    allow_destructive: bool = False
    source: str = "user"


class RepairRequest(FileContext):
    finding: RepairFindingContext
    snapshot_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    # Optional candidate patch to verify through the integrated workflow.
    patch: str | None = Field(default=None, max_length=5_000_000)
    generate: bool = False
    run_functional_tests: bool = True
    execution_consent: ExecutionConsentModel = Field(default_factory=ExecutionConsentModel)
    test_timeout_seconds: float = Field(default=120.0, ge=1.0, le=3600.0)
    project_test_command: list[str] | None = Field(default=None, max_length=50)


class RepairResult(APIModel):
    analysis_available: bool
    state: str | None = None
    patch: str | None = None
    touched_files: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)
    requires_approval: Literal[True] = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    workflow: dict[str, Any] | None = None


class RepairResponse(OperationResponse):
    result: RepairResult | None = None
