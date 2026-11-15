"""CRAFT-Sec repair package.

Repository-aware context assembly, patch generation, and shadow workspaces.

The context builder is available to repair stages; patch generation remains
explicitly opt-in and does not apply changes to user source.
"""

from craftsec.repair.context import (
    RepositoryContext,
    RepositoryContextBuilder,
    RepositoryContextFile,
)
from craftsec.repair.engine import (
    CandidatePatch,
    RepairConstraints,
    RepairEngine,
    RepairHistory,
    RepairPrompt,
    RepairPromptBuilder,
    RepairProposal,
    normalize_patch,
)
from craftsec.repair.ranking import (
    CandidateDecision,
    MandatoryConstraints,
    PatchRanker,
    RankingPolicy,
)

__all__ = [
    "CandidatePatch",
    "CandidateDecision",
    "RepairConstraints",
    "RepairEngine",
    "RepairHistory",
    "RepairProposal",
    "RepairPrompt",
    "RepairPromptBuilder",
    "RepairProposal",
    "MandatoryConstraints",
    "PatchRanker",
    "RankingPolicy",
    "RepositoryContext",
    "RepositoryContextBuilder",
    "RepositoryContextFile",
    "normalize_patch",
]
