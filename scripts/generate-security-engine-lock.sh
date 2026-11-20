#!/usr/bin/env bash
# Regenerate security-engine/requirements.lock.txt on Linux x86_64 with Python 3.11.
#
# Prerequisites (use a clean environment, not the host macOS Python):
#   python3.11 -m pip install "pip-tools==7.7.0"
#
# Run from the repository root:
#   bash scripts/generate-security-engine-lock.sh
#
# The PyTorch CPU wheel is selected explicitly with --find-links instead of
# --extra-index-url: pip-compile cannot hash-resolve the full PyTorch CPU index
# in reasonable time, and the PyPI torch 2.15.0 wheel pulls Linux CUDA/NVIDIA
# packages. The wheel URL and hash below are from the official PyTorch CPU index
# and are re-verified against the generated lock by this script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="${REPO_ROOT}/security-engine/requirements.lock.txt"
CPU_WHEEL_URL="https://download-r2.pytorch.org/whl/cpu/torch-2.15.0%2Bcpu-cp311-cp311-manylinux_2_28_x86_64.whl"
CPU_WHEEL_SHA256="cee15855a32ad89a9bb27b8a9d6e07a859dcd2e11ed1b5561f3d6206e31a103b"

if ! command -v pip-compile >/dev/null 2>&1; then
  echo "error: pip-compile not found; install pip-tools==7.7.0 for Python 3.11 first" >&2
  exit 1
fi

PY="$(python3 -c 'import sys; print(sys.executable)')"
PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
ARCH="$(uname -m)"
if [[ "${PY_VER}" != "3.11" || "${ARCH}" != "x86_64" ]]; then
  echo "error: expected Linux x86_64 + Python 3.11, got ${ARCH} + Python ${PY_VER} (${PY})" >&2
  exit 1
fi

TMP_LOCK="$(mktemp)"
trap 'rm -f "${TMP_LOCK}"' EXIT

(
  cd "${REPO_ROOT}/security-engine"
  pip-compile \
    --allow-unsafe \
    --extra=dev \
    --extra=ml \
    --find-links="${CPU_WHEEL_URL}" \
    --generate-hashes \
    --output-file="${TMP_LOCK}" \
    pyproject.toml
)

python3 - "${TMP_LOCK}" "${LOCK_FILE}" "${CPU_WHEEL_SHA256}" <<'PY'
import sys
from pathlib import Path

tmp_path, out_path, expected_sha = sys.argv[1:]
text = Path(tmp_path).read_text()

# Keep the generated header accurate for the committed filename.
text = text.replace(
    f"--output-file={tmp_path} pyproject.toml",
    "--output-file=requirements.lock.txt pyproject.toml",
)

anchor = (
    "--find-links https://download-r2.pytorch.org/whl/cpu/"
    "torch-2.15.0%2Bcpu-cp311-cp311-manylinux_2_28_x86_64.whl\n"
)
note = anchor + """
# PyTorch CPU wheel note:
# The pin uses the PyPI-visible base version 2.15.0 so pip-audit can query the
# PyPI vulnerability service. The hash below and the --find-links URL above
# select the official CPU-only wheel (2.15.0+cpu), which has no CUDA/NVIDIA
# dependencies. Do not replace this with the PyPI CUDA-linked wheel.
"""
if anchor not in text:
    raise SystemExit("error: expected --find-links line not found in pip-compile output")
text = text.replace(anchor, note, 1)

old = (
    "torch==2.15.0+cpu \\\n"
    f"    --hash=sha256:{expected_sha}\n"
    "    # via bugdhor-engine (pyproject.toml)\n"
)
new = (
    "torch==2.15.0 \\\n"
    f"    --hash=sha256:{expected_sha}\n"
    "    # via bugdhor-engine (pyproject.toml); official CPU wheel 2.15.0+cpu\n"
)
if old not in text:
    raise SystemExit("error: expected torch CPU pin not found in pip-compile output")
text = text.replace(old, new, 1)

requirement_lines = [
    line for line in text.splitlines() if line and not line.lstrip().startswith("#")
]
lowered = "\n".join(requirement_lines).lower()
for forbidden in ("cuda", "nvidia", "triton"):
    if forbidden in lowered:
        raise SystemExit(f"error: generated lock contains {forbidden!r} dependency")

Path(out_path).write_text(text)
PY

echo "Wrote ${LOCK_FILE}"
echo "Verifying hash lock..."
python3 -m pip install --dry-run --ignore-installed --require-hashes -r "${LOCK_FILE}" >/dev/null
echo "Lock verification OK"
