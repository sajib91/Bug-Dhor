"""Reproducible SAE training and validation pipelines."""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass

import torch
from torch import Tensor
from torch.utils.data import DataLoader, TensorDataset

from craftsec.sae.config import SAEConfig
from craftsec.sae.errors import SAEConfigurationError
from craftsec.sae.metrics import (
    SAEValidationMetrics,
    convergence_delta,
    validation_metrics,
)
from craftsec.sae.model import SparseAutoencoder


@dataclass(frozen=True, slots=True)
class SAEEpochMetrics:
    """Metrics recorded after one training epoch."""

    epoch: int
    train_loss: float
    train_reconstruction_error: float
    train_mean_l0: float
    train_feature_utilization: tuple[float, ...]
    train_dead_features: tuple[int, ...]
    validation: SAEValidationMetrics | None
    convergence_delta: float | None


@dataclass(frozen=True, slots=True)
class SAETrainingResult:
    """Completed training history and final validation metrics."""

    config_hash: str
    epochs: tuple[SAEEpochMetrics, ...]
    validation: SAEValidationMetrics | None


class SAETrainer:
    """Train a sparse autoencoder over materialized activation vectors."""

    def __init__(self, config: SAEConfig) -> None:
        self.config = config
        self._seed(config.seed)

    @staticmethod
    def _seed(seed: int) -> None:
        random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

    def fit(
        self,
        model: SparseAutoencoder,
        activations: Tensor,
        *,
        validation_activations: Tensor | None = None,
    ) -> SAETrainingResult:
        self._validate_data(activations)
        if model.config != self.config:
            raise SAEConfigurationError("model configuration does not match trainer configuration")
        train_data, validation_data = self._split(activations, validation_activations)
        optimizer = torch.optim.Adam(model.parameters(), lr=self.config.learning_rate)
        history: list[SAEEpochMetrics] = []
        previous_loss: float | None = None

        for epoch in range(1, self.config.epochs + 1):
            model.train()
            loader = self._loader(train_data, epoch)
            loss_total = 0.0
            reconstruction_total = 0.0
            active_total = torch.zeros(self.config.latent_dim, dtype=torch.float64)
            l0_total = 0.0
            sample_count = 0
            for (batch,) in loader:
                optimizer.zero_grad(set_to_none=True)
                output = model(batch)
                reconstruction_error = torch.mean((output.reconstruction - batch) ** 2)
                sparsity_penalty = torch.mean(torch.abs(output.latents))
                total = reconstruction_error + (
                    self.config.sparsity_coefficient * sparsity_penalty
                )
                total.backward()
                optimizer.step()
                count = batch.shape[0]
                sample_count += count
                loss_total += float(total.detach().item()) * count
                reconstruction_total += float(reconstruction_error.detach().item()) * count
                active = output.latents.detach().abs() > self.config.l0_threshold
                active_total += active.sum(dim=0).cpu().to(torch.float64)
                l0_total += float(active.sum(dim=1).float().sum().item())

            train_loss = loss_total / sample_count
            train_error = reconstruction_total / sample_count
            utilization = active_total / sample_count
            dead_features = tuple(
                index for index, value in enumerate(utilization.tolist()) if value == 0.0
            )
            validation = (
                self.validate(model, validation_data) if validation_data is not None else None
            )
            history.append(
                SAEEpochMetrics(
                    epoch=epoch,
                    train_loss=train_loss,
                    train_reconstruction_error=train_error,
                    train_mean_l0=l0_total / sample_count,
                    train_feature_utilization=tuple(float(value) for value in utilization.tolist()),
                    train_dead_features=dead_features,
                    validation=validation,
                    convergence_delta=convergence_delta(previous_loss, train_loss),
                )
            )
            previous_loss = train_loss

        return SAETrainingResult(
            config_hash=self.config.config_hash,
            epochs=tuple(history),
            validation=(
                self.validate(model, validation_data) if validation_data is not None else None
            ),
        )

    def validate(
        self,
        model: SparseAutoencoder,
        activations: Tensor,
    ) -> SAEValidationMetrics:
        self._validate_data(activations)
        model.eval()
        with torch.inference_mode():
            output = model(activations)
        return validation_metrics(
            activations,
            output.reconstruction,
            output.latents,
            self.config.l0_threshold,
        )

    def extract_features(
        self,
        model: SparseAutoencoder,
        activations: Tensor,
        *,
        batch_size: int | None = None,
    ) -> Tensor:
        """Extract detached latent features in bounded batches."""
        self._validate_data(activations)
        model.eval()
        chunks = []
        size = batch_size or self.config.batch_size
        for batch in activations.split(size):
            chunks.append(
                model.feature_activations(batch, threshold=self.config.l0_threshold).cpu()
            )
        return torch.cat(chunks, dim=0)

    def _split(
        self,
        activations: Tensor,
        validation_activations: Tensor | None,
    ) -> tuple[Tensor, Tensor | None]:
        if validation_activations is not None:
            self._validate_data(validation_activations)
            return activations, validation_activations
        if self.config.validation_fraction == 0 or len(activations) < 2:
            return activations, None
        generator = torch.Generator(device="cpu").manual_seed(self.config.seed)
        indices = torch.randperm(len(activations), generator=generator)
        validation_size = max(1, int(len(activations) * self.config.validation_fraction))
        return activations[indices[validation_size:]], activations[indices[:validation_size]]

    def _loader(self, activations: Tensor, epoch: int) -> DataLoader[Sequence[Tensor]]:
        generator = torch.Generator(device="cpu").manual_seed(self.config.seed + epoch)
        return DataLoader(
            TensorDataset(activations),
            batch_size=self.config.batch_size,
            shuffle=True,
            generator=generator,
        )

    def _validate_data(self, activations: Tensor) -> None:
        if activations.ndim != 2 or activations.shape[1] != self.config.input_dim:
            raise SAEConfigurationError(
                f"activation data must have shape [batch, {self.config.input_dim}]"
            )
        if not torch.is_floating_point(activations) or not torch.isfinite(activations).all():
            raise SAEConfigurationError("activation data must be finite floating-point values")

