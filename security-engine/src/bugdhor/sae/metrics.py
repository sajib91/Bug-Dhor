"""Reconstruction and sparse-feature quality metrics."""

from __future__ import annotations

from dataclasses import dataclass

import torch


@dataclass(frozen=True, slots=True)
class FeatureStatistics:
    """Observed feature utilization, L0 activity, and dead-feature counts."""

    mean_l0: float
    feature_utilization: tuple[float, ...]
    dead_features: tuple[int, ...]

    @property
    def active_feature_count(self) -> int:
        return len(self.feature_utilization) - len(self.dead_features)


@dataclass(frozen=True, slots=True)
class SAEValidationMetrics:
    """Metrics computed on held-out activation vectors."""

    reconstruction_error: float
    relative_reconstruction_error: float
    mean_l0: float
    feature_utilization: tuple[float, ...]
    dead_features: tuple[int, ...]


def feature_statistics(latents: torch.Tensor, threshold: float) -> FeatureStatistics:
    """Compute sparse statistics from actual latent values."""
    if latents.ndim != 2:
        raise ValueError("latents must have shape [batch, latent]")
    active = latents.abs() > threshold
    utilization = active.float().mean(dim=0)
    return FeatureStatistics(
        mean_l0=float(active.sum(dim=1).float().mean().item()),
        feature_utilization=tuple(float(value) for value in utilization.cpu()),
        dead_features=tuple(
            index for index, value in enumerate(utilization.cpu().tolist()) if value == 0.0
        ),
    )


def validation_metrics(
    inputs: torch.Tensor,
    reconstructions: torch.Tensor,
    latents: torch.Tensor,
    threshold: float,
) -> SAEValidationMetrics:
    """Calculate reconstruction quality and sparse feature statistics."""
    error = torch.mean((reconstructions - inputs) ** 2)
    baseline = torch.mean(inputs**2).clamp_min(torch.finfo(inputs.dtype).eps)
    stats = feature_statistics(latents, threshold)
    return SAEValidationMetrics(
        reconstruction_error=float(error.item()),
        relative_reconstruction_error=float((error / baseline).item()),
        mean_l0=stats.mean_l0,
        feature_utilization=stats.feature_utilization,
        dead_features=stats.dead_features,
    )


def convergence_delta(previous: float | None, current: float) -> float | None:
    """Return the absolute loss change from the previous epoch."""
    return None if previous is None else abs(previous - current)

