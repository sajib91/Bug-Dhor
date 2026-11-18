"""Sparse autoencoder encoding, decoding, and objective (Eq. 5-7).

Equations
---------
Eq. (5):  ``z = ReLU(W_e h + b_e)``
Eq. (6):  ``h_hat = W_d z + b_d``
Eq. (7):  ``L_SAE = (1/N) sum_i ||h_i - h_hat_i||^2 + lambda (1/N) sum_i ||z_i||_1``

Inputs
------
``h`` : activation matrix ``[N, d]`` (or a single vector ``[d]``).
``W_e`` : encoder weights ``[d_s, d]``; ``b_e`` : encoder bias ``[d_s]``.
``W_d`` : decoder weights ``[d, d_s]``; ``b_d`` : decoder bias ``[d]``.
``lambda`` : non-negative sparsity coefficient.

Outputs
-------
``z`` : latent matrix ``[N, d_s]``; ``h_hat`` : reconstruction ``[N, d]``.
Loss returns total, reconstruction, and sparsity terms separately.

Missing values
--------------
Complete activation vectors are required for the paper-literal objective.
For partially observed activations, pass an ``observed`` mask and use
``reduction="elementwise"``.  Missing entries are excluded from the
reconstruction numerator and denominator; latents are still computed from the
full input, so callers must impute or mask before encoding when an activation
is genuinely unavailable.  NaN inputs are rejected.

Numerical stability
-------------------
ReLU is exact; the L1 term uses ``abs``; the reconstruction term is computed in
float64.  Degenerate R^2 returns NaN rather than an arbitrary value.

Complexity
----------
Encode/decode: O(N * d * d_s).  Loss: O(N * (d + d_s)).  Memory: O(N * d_s).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import numpy as np

from mathematics.common import as_float_array, require_2d

Array = np.ndarray


@dataclass(frozen=True, slots=True)
class SAEParameters:
    """Weights of a ReLU-encoder / linear-decoder sparse autoencoder."""

    encoder_weight: Array
    encoder_bias: Array
    decoder_weight: Array
    decoder_bias: Array

    def __post_init__(self) -> None:
        encoder_weight = as_float_array(self.encoder_weight, name="encoder_weight")
        encoder_bias = as_float_array(self.encoder_bias, name="encoder_bias")
        decoder_weight = as_float_array(self.decoder_weight, name="decoder_weight")
        decoder_bias = as_float_array(self.decoder_bias, name="decoder_bias")
        require_2d(encoder_weight, name="encoder_weight")
        require_2d(decoder_weight, name="decoder_weight")
        if encoder_bias.ndim != 1:
            raise ValueError("encoder_bias must be one-dimensional")
        if decoder_bias.ndim != 1:
            raise ValueError("decoder_bias must be one-dimensional")
        latent_dim, input_dim = encoder_weight.shape
        if decoder_weight.shape != (input_dim, latent_dim):
            raise ValueError(
                "decoder_weight must have shape "
                f"{(input_dim, latent_dim)}, got {decoder_weight.shape}"
            )
        if encoder_bias.shape != (latent_dim,):
            raise ValueError(
                f"encoder_bias must have shape {(latent_dim,)}, got {encoder_bias.shape}"
            )
        if decoder_bias.shape != (input_dim,):
            raise ValueError(
                f"decoder_bias must have shape {(input_dim,)}, got {decoder_bias.shape}"
            )
        for name, value in (
            ("encoder_weight", encoder_weight),
            ("encoder_bias", encoder_bias),
            ("decoder_weight", decoder_weight),
            ("decoder_bias", decoder_bias),
        ):
            if not np.isfinite(value).all():
                raise ValueError(f"{name} must contain only finite values")
        object.__setattr__(self, "encoder_weight", encoder_weight)
        object.__setattr__(self, "encoder_bias", encoder_bias)
        object.__setattr__(self, "decoder_weight", decoder_weight)
        object.__setattr__(self, "decoder_bias", decoder_bias)

    @property
    def input_dim(self) -> int:
        return int(self.encoder_weight.shape[1])

    @property
    def latent_dim(self) -> int:
        return int(self.encoder_weight.shape[0])

    @classmethod
    def from_torch(cls, module: Any) -> SAEParameters:
        """Build parameters from a compatible PyTorch SAE module.

        The module must expose ``encoder`` and ``decoder`` ``nn.Linear``
        layers, matching ``bugdhor.sae.model.SparseAutoencoder``.
        """
        if not hasattr(module, "encoder") or not hasattr(module, "decoder"):
            raise TypeError("module must expose encoder and decoder linear layers")
        return cls(
            encoder_weight=module.encoder.weight.detach().cpu().numpy(),
            encoder_bias=module.encoder.bias.detach().cpu().numpy(),
            decoder_weight=module.decoder.weight.detach().cpu().numpy(),
            decoder_bias=module.decoder.bias.detach().cpu().numpy(),
        )

    def decoder_direction(self, feature_index: int) -> Array:
        """Return ``W_d[:, j]``, the decoder direction for feature ``j``."""
        if not 0 <= feature_index < self.latent_dim:
            raise ValueError(
                f"feature_index must lie in [0, {self.latent_dim}), got {feature_index}"
            )
        return self.decoder_weight[:, feature_index].copy()


@dataclass(frozen=True, slots=True)
class SAELoss:
    """Separated terms of the SAE objective."""

    total: float
    reconstruction: float
    sparsity: float
    sparsity_coefficient: float


@dataclass(frozen=True, slots=True)
class ReconstructionMetrics:
    """Reconstruction and sparsity diagnostics for a batch."""

    reconstruction_error: float
    relative_reconstruction_error: float
    r2: float
    mean_l0: float
    dead_feature_fraction: float
    dead_features: tuple[int, ...]
    sample_count: int
    latent_dim: int


def _promote(
    value: Any,
    *,
    name: str,
    width: int,
    allow_missing: bool = False,
) -> tuple[Array, bool]:
    array = as_float_array(value, name=name)
    if array.ndim == 1:
        if array.shape[0] != width:
            raise ValueError(f"{name} must have width {width}, got {array.shape[0]}")
        array = array.reshape(1, -1)
        single = True
    elif array.ndim == 2:
        if array.shape[1] != width:
            raise ValueError(f"{name} must have width {width}, got {array.shape[1]}")
        single = False
    else:
        raise ValueError(f"{name} must be one- or two-dimensional, got {array.ndim}")
    if np.isinf(array).any():
        raise ValueError(f"{name} must not contain infinite values")
    if not allow_missing and not np.isfinite(array).all():
        raise ValueError(f"{name} must not contain NaN or infinite values")
    return array, single


def encode(
    activations: Any,
    parameters: SAEParameters,
    *,
    threshold: float | None = None,
) -> Array:
    """Encode activations with Eq. (5).

    ``z_ij = max(0, W_e[j] . h_i + b_e[j])``.

    If ``threshold`` is supplied, latents with ``|z| < threshold`` are set to
    zero.  This is a post-hoc sparsification, not part of Eq. (5).
    """
    h, single = _promote(activations, name="activations", width=parameters.input_dim)
    z = h @ parameters.encoder_weight.T + parameters.encoder_bias
    np.maximum(z, 0.0, out=z)
    if threshold is not None:
        if not math.isfinite(threshold) or threshold < 0:
            raise ValueError("threshold must be finite and non-negative")
        z = np.where(np.abs(z) >= threshold, z, 0.0)
    return z[0] if single else z


def decode(latents: Any, parameters: SAEParameters) -> Array:
    """Decode latents with Eq. (6): ``h_hat = W_d z + b_d``."""
    z, single = _promote(latents, name="latents", width=parameters.latent_dim)
    h_hat = z @ parameters.decoder_weight.T + parameters.decoder_bias
    return h_hat[0] if single else h_hat


def forward(activations: Any, parameters: SAEParameters) -> tuple[Array, Array]:
    """Return encoded latents and decoded reconstruction."""
    latents = encode(activations, parameters)
    return latents, decode(latents, parameters)


def sae_loss(
    activations: Any,
    parameters: SAEParameters,
    *,
    sparsity_coefficient: float,
    latents: Any | None = None,
    reconstruction: Any | None = None,
    observed: Any | None = None,
    reduction: str = "paper",
) -> SAELoss:
    """Compute Eq. (7) with explicit reconstruction and sparsity terms.

    Parameters
    ----------
    reduction:
        ``"paper"`` computes the paper-literal per-sample sums and requires
        complete activations.  ``"elementwise"`` computes the mean over observed
        entries; it is the missing-value extension and is not identical to
        Eq. (7) when a mask is present.
    observed:
        Boolean mask aligned with ``activations``; ``True`` means observed.
        Only supported with ``reduction="elementwise"``.

    Returns
    -------
    :class:`SAELoss`
        ``total = reconstruction + sparsity_coefficient * sparsity``.
    """
    if not math.isfinite(sparsity_coefficient) or sparsity_coefficient < 0:
        raise ValueError("sparsity_coefficient must be finite and non-negative")
    if reduction not in {"paper", "elementwise"}:
        raise ValueError("reduction must be 'paper' or 'elementwise'")
    # The elementwise extension is the only path that may accept NaN targets;
    # the observed mask determines which entries enter the objective.
    allow_missing = reduction == "elementwise" and observed is not None
    h, _ = _promote(
        activations,
        name="activations",
        width=parameters.input_dim,
        allow_missing=allow_missing,
    )
    z = (
        _promote(latents, name="latents", width=parameters.latent_dim)[0]
        if latents is not None
        else encode(h, parameters)
    )
    h_hat = (
        _promote(reconstruction, name="reconstruction", width=parameters.input_dim)[0]
        if reconstruction is not None
        else decode(z, parameters)
    )
    if h_hat.shape != h.shape:
        raise ValueError(f"reconstruction must match activations shape {h.shape}")
    if observed is not None:
        mask = np.asarray(observed, dtype=bool)
        if mask.shape != h.shape:
            raise ValueError(f"observed mask must have shape {h.shape}, got {mask.shape}")
    else:
        mask = None

    if reduction == "paper":
        if mask is not None and not mask.all():
            raise ValueError(
                "reduction='paper' requires complete activations; "
                "use reduction='elementwise' for partially observed inputs"
            )
        squared_error = np.sum((h - h_hat) ** 2, axis=1)
        reconstruction_term = float(squared_error.mean())
        sparsity_term = float(np.sum(np.abs(z), axis=1).mean())
    else:
        if mask is None:
            mask = np.ones_like(h, dtype=bool)
        if mask.shape != h.shape:
            raise ValueError(f"observed mask must have shape {h.shape}, got {mask.shape}")
        if not mask.any():
            raise ValueError("observed mask contains no observed entries")
        squared_error = np.where(mask, h - h_hat, 0.0) ** 2
        reconstruction_term = float(np.sum(squared_error) / mask.sum())
        sparsity_term = float(np.mean(np.abs(z)))
    return SAELoss(
        total=reconstruction_term + sparsity_coefficient * sparsity_term,
        reconstruction=reconstruction_term,
        sparsity=sparsity_term,
        sparsity_coefficient=sparsity_coefficient,
    )


def reconstruction_metrics(
    activations: Any,
    parameters: SAEParameters,
    *,
    latents: Any | None = None,
    reconstruction: Any | None = None,
    observed: Any | None = None,
    active_threshold: float = 0.0,
) -> ReconstructionMetrics:
    """Compute R^2, relative error, L0, and dead-feature diagnostics.

    ``R^2 = 1 - SSE / SST`` with ``SST = sum_i ||h_i - mean(h)||^2``.
    A degenerate target returns NaN.  Dead features are those with no active
    value anywhere in the supplied batch.
    """
    if active_threshold < 0 or not math.isfinite(active_threshold):
        raise ValueError("active_threshold must be finite and non-negative")
    h, _ = _promote(activations, name="activations", width=parameters.input_dim)
    z = (
        _promote(latents, name="latents", width=parameters.latent_dim)[0]
        if latents is not None
        else encode(h, parameters)
    )
    h_hat = (
        _promote(reconstruction, name="reconstruction", width=parameters.input_dim)[0]
        if reconstruction is not None
        else decode(z, parameters)
    )
    mask = np.ones_like(h, dtype=bool) if observed is None else np.asarray(observed, bool)
    if mask.shape != h.shape:
        raise ValueError(f"observed mask must have shape {h.shape}, got {mask.shape}")
    count = int(mask.sum())
    if count == 0:
        raise ValueError("observed mask contains no observed entries")
    squared_error = float(np.sum(mask * (h - h_hat) ** 2))
    mse = squared_error / count
    centered_mean = float(h[mask].mean())
    centered = np.where(mask, h - centered_mean, 0.0)
    total_sum_squares = float(np.sum(centered**2))
    r2 = 1.0 - squared_error / total_sum_squares if total_sum_squares > 0 else math.nan
    active = np.abs(z) > active_threshold
    mean_l0 = float(active.sum(axis=1).mean())
    utilization = active.mean(axis=0)
    dead = tuple(int(index) for index in np.flatnonzero(utilization == 0.0))
    relative = squared_error / total_sum_squares if total_sum_squares > 0 else math.nan
    return ReconstructionMetrics(
        reconstruction_error=mse,
        relative_reconstruction_error=float(relative),
        r2=float(r2),
        mean_l0=mean_l0,
        dead_feature_fraction=len(dead) / parameters.latent_dim,
        dead_features=dead,
        sample_count=int(h.shape[0]),
        latent_dim=parameters.latent_dim,
    )


def normalize_decoder_columns(parameters: SAEParameters) -> SAEParameters:
    """Return parameters whose decoder columns have unit L2 norm.

    Zero columns are left unchanged.  Normalization changes the scale of latent
    features; it must be documented whenever it is applied.
    """
    norms = np.linalg.norm(parameters.decoder_weight, axis=0)
    safe = np.where(norms > 0, norms, 1.0)
    return SAEParameters(
        encoder_weight=parameters.encoder_weight,
        encoder_bias=parameters.encoder_bias,
        decoder_weight=parameters.decoder_weight / safe,
        decoder_bias=parameters.decoder_bias,
    )


__all__ = [
    "ReconstructionMetrics",
    "SAELoss",
    "SAEParameters",
    "decode",
    "encode",
    "forward",
    "normalize_decoder_columns",
    "reconstruction_metrics",
    "sae_loss",
]
