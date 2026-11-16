"""Evaluation metrics, statistical analysis, ablations, and reporting for CRAFT-Sec experiments."""

from .ablation import ABLATIONS, AblationResult, run_ablation, summarize_ablation_multiple_comparisons
from .comparisons import (
    ComparisonResult,
    correct_comparison_pvalues,
    cross_dataset_comparison,
    cross_model_comparison,
)
from .metrics import (
    DetectionMetrics,
    ExplainabilityMetrics,
    LocalizationMetrics,
    PerformanceMetrics,
    RepairMetrics,
    aggregate_detection_metrics,
    compute_explainability_metrics,
    compute_localization_metrics,
    compute_performance_metrics,
    compute_repair_metrics,
)
from .reporting import export_statistical_report
from .statistics import (
    PairedComparisonResult,
    apply_multiple_comparison_correction,
    bootstrap_ci,
    check_paired_assumptions,
    cliffs_delta,
    cohens_d_paired,
    mann_whitney_u,
    paired_comparison,
    paired_permutation_test,
    paired_t_test,
    wilcoxon_signed_rank,
)

__all__ = [
    "ABLATIONS",
    "AblationResult",
    "ComparisonResult",
    "DetectionMetrics",
    "ExplainabilityMetrics",
    "LocalizationMetrics",
    "PairedComparisonResult",
    "PerformanceMetrics",
    "RepairMetrics",
    "aggregate_detection_metrics",
    "apply_multiple_comparison_correction",
    "bootstrap_ci",
    "check_paired_assumptions",
    "cliffs_delta",
    "cohens_d_paired",
    "compute_explainability_metrics",
    "compute_localization_metrics",
    "compute_performance_metrics",
    "compute_repair_metrics",
    "correct_comparison_pvalues",
    "cross_dataset_comparison",
    "cross_model_comparison",
    "export_statistical_report",
    "mann_whitney_u",
    "paired_comparison",
    "paired_permutation_test",
    "paired_t_test",
    "run_ablation",
    "summarize_ablation_multiple_comparisons",
    "wilcoxon_signed_rank",
]
