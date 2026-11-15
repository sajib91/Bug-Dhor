"""CRAFT-Sec sparse autoencoder training and feature extraction."""

from craftsec.sae.checkpoint import load_checkpoint, save_checkpoint
from craftsec.sae.config import SAEConfig
from craftsec.sae.errors import SAECheckpointError, SAEConfigurationError, SAEError
from craftsec.sae.metrics import FeatureStatistics, SAEValidationMetrics, feature_statistics
from craftsec.sae.model import SAEOutput, SparseAutoencoder
from craftsec.sae.training import SAEEpochMetrics, SAETrainer, SAETrainingResult

__all__ = [
    "FeatureStatistics",
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
    "load_checkpoint",
    "save_checkpoint",
]
