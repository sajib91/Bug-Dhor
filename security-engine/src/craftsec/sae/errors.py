"""Errors raised by the CRAFT-Sec sparse autoencoder runtime."""

from __future__ import annotations


class SAEError(RuntimeError):
    """Base class for expected SAE failures."""


class SAEConfigurationError(SAEError):
    """The SAE configuration or input data is invalid."""


class SAECheckpointError(SAEError):
    """An SAE checkpoint is invalid or incompatible."""

