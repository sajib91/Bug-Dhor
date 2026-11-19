"""Independent verification contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from bugdhor.api.schemas.common import APIModel, OperationResponse
from bugdhor.api.schemas.scan import FileContext


class VerificationRequest(FileContext):
    repair_id: str | None = Field(default=None, min_length=1, max_length=200)
    patch: str | None = Field(default=None, max_length=5_000_000)
    patched_source: str | None = Field(default=None, max_length=5_000_000)
    cwe: str | None = Field(default=None, max_length=50)
    finding_id: str | None = Field(default=None, min_length=1, max_length=200)
    profile: Literal["static_only", "sandbox"] = "static_only"
    run_execution: bool = False

    @model_validator(mode="after")
    def _require_target(self) -> VerificationRequest:
        if self.repair_id is None and self.patch is None and self.patched_source is None:
            raise ValueError("provide a repairId, patch, or patchedSource")
        if self.run_execution and self.profile != "sandbox":
            raise ValueError("runExecution requires profile=sandbox")
        return self


class VerificationResult(APIModel):
    analysis_available: bool
    repair_id: str | None = Field(default=None, min_length=1, max_length=200)
    verdict: Literal["passed", "failed", "inconclusive", "not_run"] = "not_run"
    classification: Literal[
        "verified_security_improvement",
        "partial_improvement",
        "verification_failure",
        "inconclusive_verification",
    ] | None = None
    profile: Literal["static_only", "sandbox"] = "static_only"
    execution_executed: bool = Field(
        default=False,
        description="Whether code was actually executed for this verification.",
    )
    checks: list[dict[str, Any]] = Field(default_factory=list)
    sandbox_backend: str
    limitations: list[str] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)


class VerificationResponse(OperationResponse):
    result: VerificationResult | None = None
