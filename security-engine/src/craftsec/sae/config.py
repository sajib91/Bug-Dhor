"""Reproducible sparse autoencoder configuration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from craftsec.sae.errors import SAEConfigurationError


@dataclass(frozen=True, slots=True)
class SAEConfig:
    """Hyperparameters and reproducibility controls for one SAE experiment."""

    input_dim: int
    latent_dim: int
    sparsity_coefficient: float = 1e-3
    batch_size: int = 64
    learning_rate: float = 1e-3
    epochs: int = 10
    validation_fraction: float = 0.1
    l0_threshold: float = 1e-6
    seed: int = 0

    def __post_init__(self) -> None:
        if self.input_dim < 1 or self.latent_dim < 1:
            raise SAEConfigurationError("input_dim and latent_dim must be positive")
        if self.sparsity_coefficient < 0:
            raise SAEConfigurationError("sparsity_coefficient must be non-negative")
        if self.batch_size < 1 or self.epochs < 1:
            raise SAEConfigurationError("batch_size and epochs must be positive")
        if self.learning_rate <= 0:
            raise SAEConfigurationError("learning_rate must be positive")
        if not 0 <= self.validation_fraction < 1:
            raise SAEConfigurationError("validation_fraction must be in [0, 1)")
        if self.l0_threshold < 0:
            raise SAEConfigurationError("l0_threshold must be non-negative")

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)

    @property
    def config_hash(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

