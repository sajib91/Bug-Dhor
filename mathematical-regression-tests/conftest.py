"""Path setup and shared fixtures for the independent regression suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "security-engine" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

ARTIFACT = (
    ROOT
    / "research"
    / "experiments"
    / "counterfactual_validation"
    / "results"
    / "real_model_validation.json"
)
ARTIFACT_DIR = ARTIFACT.parent.parent / "artifacts"


@pytest.fixture(scope="session")
def artifact_path() -> Path:
    return ARTIFACT


@pytest.fixture(scope="session")
def artifact_dir() -> Path:
    return ARTIFACT_DIR
