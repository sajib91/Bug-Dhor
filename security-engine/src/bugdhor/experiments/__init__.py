"""Bug Dhor experimental evaluation framework.

Provides dataset loading/validation/splitting (subject to local availability and
licensing), experiment configuration tracking, E0-E8 evaluation runners, raw
output recording, and result export. No results are fabricated.
"""

from .config import ExperimentConfig, ExperimentTracker, RunRecord
from .datasets import DatasetRegistry, DatasetSample, SUPPORTED_DATASETS
from .evaluation import ExperimentRunner, ModelEvaluator, check_group_prerequisites
from .export import export_csv, export_json, export_jsonl, export_results_bundle
from .groups import EXPERIMENT_GROUPS, list_groups
from .splits import (
    SplitResult,
    cross_language_split,
    cwe_based_split,
    repository_level_split,
    temporal_split,
)

__all__ = [
    "DatasetRegistry",
    "DatasetSample",
    "EXPERIMENT_GROUPS",
    "ExperimentConfig",
    "ExperimentRunner",
    "ExperimentTracker",
    "ModelEvaluator",
    "RunRecord",
    "SUPPORTED_DATASETS",
    "SplitResult",
    "check_group_prerequisites",
    "cross_language_split",
    "cwe_based_split",
    "export_csv",
    "export_json",
    "export_jsonl",
    "export_results_bundle",
    "list_groups",
    "repository_level_split",
    "temporal_split",
]

