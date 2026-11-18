"""Secure Code Recommendation Engine.

Proposal-only secure repair generation with explicit workflow stages, CWE
requirements, independent verification, mandatory ranking gates, and explanations.
"""

from bugdhor.recommendation.engine import (
    RecommendationConstraints,
    SecurePromptBuilder,
    SecureRecommendationEngine,
)
from bugdhor.recommendation.models import (
    WORKFLOW_STAGES,
    CandidateEvaluation,
    RecommendationExplanation,
    RecommendationResult,
    SecurePrompt,
    StageRecord,
)
from bugdhor.recommendation.requirements import (
    RemediationRequirement,
    evaluate_requirement,
    requirement_for_cwe,
    requirement_is_supported,
)

__all__ = [
    "WORKFLOW_STAGES",
    "CandidateEvaluation",
    "RecommendationConstraints",
    "RecommendationExplanation",
    "RecommendationResult",
    "RemediationRequirement",
    "SecurePrompt",
    "SecurePromptBuilder",
    "SecureRecommendationEngine",
    "StageRecord",
    "evaluate_requirement",
    "requirement_for_cwe",
    "requirement_is_supported",
]
