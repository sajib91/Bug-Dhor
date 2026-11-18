"""Pydantic request and response schemas for the versioned API."""

from bugdhor.api.schemas.analysis import (
    DetectionRequest,
    DetectionResponse,
    DetectionResult,
    ExplanationRequest,
    ExplanationResponse,
    ExplanationResult,
)
from bugdhor.api.schemas.common import (
    APIModel,
    FileInfo,
    Finding,
    FindingLocation,
    HealthResponse,
    OperationResponse,
    Position,
    ProblemDetail,
    Range,
    RepairInfo,
    ScanScope,
    SourceReference,
    StageReport,
)
from bugdhor.api.schemas.counterfactual import (
    CounterfactualRequest,
    CounterfactualResponse,
    CounterfactualResult,
    Intervention,
)
from bugdhor.api.schemas.features import (
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    FeatureExtractionResult,
)
from bugdhor.api.schemas.prevention import (
    PreventionRequest,
    PreventionResponse,
    PreventionResult,
)
from bugdhor.api.schemas.recommendation import (
    RecommendationProviderModel,
    RecommendationRequest,
    RecommendationResponse,
    RecommendationResult,
)
from bugdhor.api.schemas.repair import (
    RepairFindingContext,
    RepairRequest,
    RepairResponse,
    RepairResult,
)
from bugdhor.api.schemas.scan import (
    FileContext,
    ScanFileRequest,
    ScanFileResponse,
    ScanResponse,
    ScanWorkspaceRequest,
    ScanWorkspaceResponse,
    WorkspaceFolder,
)
from bugdhor.api.schemas.verification import (
    VerificationRequest,
    VerificationResponse,
    VerificationResult,
)

__all__ = [
    "APIModel",
    "CounterfactualRequest",
    "CounterfactualResponse",
    "CounterfactualResult",
    "DetectionRequest",
    "DetectionResponse",
    "DetectionResult",
    "ExplanationRequest",
    "ExplanationResponse",
    "ExplanationResult",
    "FeatureExtractionRequest",
    "FeatureExtractionResponse",
    "FeatureExtractionResult",
    "FileContext",
    "FileInfo",
    "Finding",
    "FindingLocation",
    "HealthResponse",
    "Intervention",
    "OperationResponse",
    "Position",
    "PreventionRequest",
    "PreventionResponse",
    "PreventionResult",
    "ProblemDetail",
    "Range",
    "RecommendationProviderModel",
    "RecommendationRequest",
    "RecommendationResponse",
    "RecommendationResult",
    "RepairFindingContext",
    "RepairInfo",
    "RepairRequest",
    "RepairResponse",
    "RepairResult",
    "ScanFileRequest",
    "ScanFileResponse",
    "ScanResponse",
    "ScanScope",
    "ScanWorkspaceRequest",
    "ScanWorkspaceResponse",
    "SourceReference",
    "StageReport",
    "VerificationRequest",
    "VerificationResponse",
    "VerificationResult",
    "WorkspaceFolder",
]
