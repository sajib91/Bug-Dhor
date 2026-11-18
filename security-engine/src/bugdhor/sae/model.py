"""PyTorch sparse autoencoder model."""

from __future__ import annotations

from dataclasses import dataclass

try:
    import torch
    from torch import Tensor, nn
except ImportError as error:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "Install the optional ML dependencies with `pip install -e '.[ml]'`."
    ) from error

from bugdhor.sae.config import SAEConfig


@dataclass(frozen=True, slots=True)
class SAEOutput:
    """Encoder latents and decoder reconstruction for one forward pass."""

    latents: Tensor
    reconstruction: Tensor


class SparseAutoencoder(nn.Module):
    """ReLU encoder/linear decoder with explicit sparse latent activations."""

    def __init__(self, config: SAEConfig) -> None:
        super().__init__()
        self.config = config
        self.encoder = nn.Linear(config.input_dim, config.latent_dim)
        self.decoder = nn.Linear(config.latent_dim, config.input_dim)

    def encode(self, activations: Tensor) -> Tensor:
        self._validate_input(activations)
        return torch.relu(self.encoder(activations))

    def decode(self, latents: Tensor) -> Tensor:
        if latents.ndim != 2 or latents.shape[1] != self.config.latent_dim:
            raise ValueError(
                f"latents must have shape [batch, {self.config.latent_dim}], "
                f"got {tuple(latents.shape)}"
            )
        return self.decoder(latents)

    def forward(self, activations: Tensor) -> SAEOutput:
        latents = self.encode(activations)
        return SAEOutput(latents=latents, reconstruction=self.decode(latents))

    def loss(self, activations: Tensor) -> tuple[Tensor, Tensor, Tensor]:
        """Return total loss, reconstruction MSE, and L1 sparsity penalty."""
        output = self(activations)
        reconstruction_error = torch.mean((output.reconstruction - activations) ** 2)
        sparsity_penalty = torch.mean(torch.abs(output.latents))
        total = reconstruction_error + self.config.sparsity_coefficient * sparsity_penalty
        return total, reconstruction_error, sparsity_penalty

    def feature_activations(self, activations: Tensor, *, threshold: float | None = None) -> Tensor:
        """Extract actual encoder activations without retaining an autograd graph."""
        with torch.inference_mode():
            latents = self.encode(activations)
        if threshold is not None:
            latents = torch.where(latents.abs() > threshold, latents, torch.zeros_like(latents))
        return latents

    def _validate_input(self, activations: Tensor) -> None:
        if activations.ndim != 2 or activations.shape[1] != self.config.input_dim:
            raise ValueError(
                f"activations must have shape [batch, {self.config.input_dim}], "
                f"got {tuple(activations.shape)}"
            )
        if not torch.is_floating_point(activations):
            raise ValueError("activations must use a floating-point dtype")
        if not torch.isfinite(activations).all():
            raise ValueError("activations must contain only finite values")

