"""Safe SAE checkpoint persistence."""

from __future__ import annotations

from pathlib import Path

import torch

from craftsec.sae.config import SAEConfig
from craftsec.sae.errors import SAECheckpointError
from craftsec.sae.model import SparseAutoencoder
from craftsec.sae.training import SAETrainingResult


def save_checkpoint(
    path: str | Path,
    model: SparseAutoencoder,
    *,
    training: SAETrainingResult | None = None,
) -> Path:
    """Save model weights and reproducibility metadata atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    payload = {
        "format_version": 1,
        "config": model.config.to_dict(),
        "config_hash": model.config.config_hash,
        "state_dict": {key: value.detach().cpu() for key, value in model.state_dict().items()},
        "training": training,
    }
    torch.save(payload, temporary)
    temporary.replace(target)
    return target


def load_checkpoint(
    path: str | Path,
    *,
    config: SAEConfig | None = None,
) -> tuple[SparseAutoencoder, SAETrainingResult | None]:
    """Load an SAE checkpoint and reject incompatible configurations."""
    try:
        payload = torch.load(path, map_location="cpu", weights_only=False)
        checkpoint_config = SAEConfig(**payload["config"])
        if payload["config_hash"] != checkpoint_config.config_hash:
            raise SAECheckpointError(
                "checkpoint configuration hash does not match its configuration"
            )
        if config is not None and config.config_hash != checkpoint_config.config_hash:
            raise SAECheckpointError(
                "checkpoint configuration is incompatible with requested config"
            )
        model = SparseAutoencoder(checkpoint_config)
        model.load_state_dict(payload["state_dict"])
        return model, payload.get("training")
    except SAECheckpointError:
        raise
    except Exception as error:
        raise SAECheckpointError(f"Unable to load SAE checkpoint {str(path)!r}") from error

