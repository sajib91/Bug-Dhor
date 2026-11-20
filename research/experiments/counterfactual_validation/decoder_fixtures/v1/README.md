# Decoder-column fixture bundle v1

`bundle_id`: `counterfactual-decoder-cosines-v1`

This bundle lets `mathematical-regression-tests/test_artifact_recomputation.py`
recompute the saved cross-checkpoint decoder cosines on macOS, Linux, Windows,
and GitHub Actions without shipping the ~100 MiB full SAE checkpoints, which
are ignored by `.gitignore` (`*.pt`).

Each `.npz` file contains only the decoder columns for the features selected in
`results/real_model_validation.json`.  The values were extracted from the real
SAE checkpoints by `../build_decoder_fixtures.py`; they are not retrained or
synthetic.  `manifest.json` records the SHA-256 of every fixture and of its
source checkpoint.  The regression test verifies the fixture checksum before
loading it and fails explicitly on a missing or mismatched file.

The full-checkpoint integration test remains available with the
`real_model_integration` pytest marker.  It requires the full checkpoints to be
provisioned under `../artifacts/` and verifies their recorded SHA-256 digests
before `torch.load()`.
