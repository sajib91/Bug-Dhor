"""Bug Dhor vulnerability detection and evidence fusion.

The package is a standalone library. It classifies vulnerabilities and CWEs,
localizes source code, aggregates heterogeneous evidence, resolves duplicate
findings, prioritizes risk with a documented heuristic, and emits explainable
finding records. Uncalibrated heuristic risk and calibrated probabilities are
separate fields; only evidence from a validated calibrator is ever labeled a
probability.

Program-analysis evidence (AST, CFG, DFG, taint) is one dependent family.
Semgrep, Bandit, CodeQL, and Joern are separate static-tool signals. Compatible
LLM output is a capped hypothesis family. The engine does not average
heterogeneous scores.
"""

from bugdhor.detection.ast_analysis import StructuralMatch, analyze_ast
from bugdhor.detection.classification import (
    CATEGORY_INFO,
    CATEGORY_ORDER,
    CategoryInfo,
    Classification,
    category_for_cwe,
    category_for_taint,
    classify_evidence,
    classify_text,
    default_cwe,
    infer_category,
)
from bugdhor.detection.config import (
    DEFAULT_DETECTION_CONFIG,
    DetectionConfig,
    FusionWeights,
    RiskThresholds,
)
from bugdhor.detection.context import ContextAssessor
from bugdhor.detection.engine import (
    DETECTION_LIMITATIONS,
    DetectionEngine,
    detect_source,
)
from bugdhor.detection.evidence import (
    EvidenceBundle,
    LLMEvidenceBundle,
    StaticEvidenceBundle,
    ast_evidence,
    build_evidence,
    llm_evidence,
    static_evidence,
    taint_evidence,
)
from bugdhor.detection.fusion import (
    CalibrationProvider,
    FusionResult,
    fuse_evidence,
    with_calibration,
)
from bugdhor.detection.llm import LLMAnalyzer, LLMClaim, collect_llm_claims
from bugdhor.detection.models import (
    CalibratedProbability,
    ClaimKind,
    CweSupport,
    DetectionCoverage,
    DetectionResult,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidencePolarity,
    EvidenceType,
    HeuristicRisk,
    Provenance,
    RiskAssessment,
    RiskContribution,
    UnclassifiedCandidate,
    VulnerabilityCategory,
    VulnerabilityFinding,
    stable_finding_id,
    strongest_severity,
)

__all__ = [
    "CATEGORY_INFO",
    "CATEGORY_ORDER",
    "CalibratedProbability",
    "CalibrationProvider",
    "CategoryInfo",
    "ClaimKind",
    "Classification",
    "ContextAssessor",
    "CweSupport",
    "DEFAULT_DETECTION_CONFIG",
    "DETECTION_LIMITATIONS",
    "DetectionConfig",
    "DetectionCoverage",
    "DetectionEngine",
    "DetectionResult",
    "EvidenceBundle",
    "EvidenceFamily",
    "EvidenceItem",
    "EvidenceLocation",
    "EvidencePolarity",
    "EvidenceType",
    "FusionResult",
    "FusionWeights",
    "HeuristicRisk",
    "LLMAnalyzer",
    "LLMClaim",
    "LLMEvidenceBundle",
    "Provenance",
    "RiskAssessment",
    "RiskContribution",
    "RiskThresholds",
    "StaticEvidenceBundle",
    "StructuralMatch",
    "UnclassifiedCandidate",
    "VulnerabilityCategory",
    "VulnerabilityFinding",
    "analyze_ast",
    "ast_evidence",
    "build_evidence",
    "category_for_cwe",
    "category_for_taint",
    "classify_evidence",
    "classify_text",
    "collect_llm_claims",
    "default_cwe",
    "detect_source",
    "fuse_evidence",
    "infer_category",
    "llm_evidence",
    "stable_finding_id",
    "static_evidence",
    "strongest_severity",
    "taint_evidence",
    "with_calibration",
]
