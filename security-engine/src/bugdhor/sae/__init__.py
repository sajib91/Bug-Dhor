"""Bug Dhor sparse autoencoder training and feature extraction."""

from bugdhor.sae.association import (
    CodeSampleLabel,
    CrossDatasetMetric,
    FeatureAssociation,
    FeatureDictionary,
    FeatureDictionaryEntry,
    FeatureExperimentMetadata,
    FeatureSample,
    FeatureStability,
    analyze_features,
    extract_feature_samples,
    samples_from_token_features,
)
from bugdhor.sae.checkpoint import load_checkpoint, save_checkpoint
from bugdhor.sae.config import SAEConfig
from bugdhor.sae.errors import SAECheckpointError, SAEConfigurationError, SAEError
from bugdhor.sae.interpretation import (
    FeatureAnnotation,
    FeatureAnnotationBook,
    FeatureExample,
    FeatureInterpretationEngine,
    FeatureInterpretationReport,
    InterventionObservation,
    export_reports_csv,
    export_reports_json,
    feature_activations_to_examples,
)
from bugdhor.sae.metrics import FeatureStatistics, SAEValidationMetrics, feature_statistics
from bugdhor.sae.model import SAEOutput, SparseAutoencoder
from bugdhor.sae.training import SAEEpochMetrics, SAETrainer, SAETrainingResult

__all__ = [
    "FeatureStatistics",
    "CodeSampleLabel",
    "CrossDatasetMetric",
    "FeatureAssociation",
    "FeatureAnnotation",
    "FeatureAnnotationBook",
    "FeatureDictionary",
    "FeatureDictionaryEntry",
    "FeatureExperimentMetadata",
    "FeatureExample",
    "FeatureInterpretationEngine",
    "FeatureInterpretationReport",
    "FeatureSample",
    "FeatureStability",
    "InterventionObservation",
    "SAECheckpointError",
    "SAEConfig",
    "SAEConfigurationError",
    "SAEEpochMetrics",
    "SAEError",
    "SAEOutput",
    "SAETrainer",
    "SAETrainingResult",
    "SAEValidationMetrics",
    "SparseAutoencoder",
    "feature_statistics",
    "analyze_features",
    "extract_feature_samples",
    "export_reports_csv",
    "export_reports_json",
    "feature_activations_to_examples",
    "load_checkpoint",
    "samples_from_token_features",
    "save_checkpoint",
]
