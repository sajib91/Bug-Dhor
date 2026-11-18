# Sparse autoencoder

`bugdhor.sae` learns sparse representations from actual activation tensors,
such as the detached layer/token activations produced by
[`bugdhor.models`](../security-engine/src/bugdhor/models/). It uses a ReLU
encoder and linear decoder:

`total loss = reconstruction MSE + sparsity_coefficient * mean(abs(latents))`

The trainer supports configurable input and latent dimensions, batch size,
learning rate, epochs, validation split, L0 threshold, and seed. It records
reconstruction error, relative reconstruction error, mean L0 activity, feature
utilization, dead features, and per-epoch convergence deltas.

Checkpoints contain CPU state dictionaries, the complete configuration, a
configuration hash, and optional training history. Checkpoint loading rejects
configuration mismatches.

SAE features are mathematical latent directions. Activation, utilization, or
reconstruction statistics do **not** establish that a feature represents a
vulnerability, secure behavior, or any other semantic concept. Such claims
require separate controlled interpretation and validation experiments.
