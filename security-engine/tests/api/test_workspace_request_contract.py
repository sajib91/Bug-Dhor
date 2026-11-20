"""Regression tests for the stable /api/v1/scan/workspace request contract.

The published extension must send only ``workspaceFolders``. Older engine
releases declare a strict Pydantic model with ``extra="forbid"`` and reject any
additional field with ``body.filePaths: Extra inputs are not permitted``. These
tests use the real Pydantic validation mechanism to pin that compatibility
requirement without weakening the current engine's optional explicit-path
support.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from bugdhor.api.schemas.scan import ScanWorkspaceRequest, WorkspaceFolder


class PublishedWorkspaceRequest(BaseModel):
    """The stable, documented published-engine contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    workspaceFolders: list[WorkspaceFolder] = Field(min_length=1, max_length=50)  # noqa: N815


def _folders() -> list[dict[str, str]]:
    root = Path("/workspace")
    return [{"name": "workspace", "path": str(root), "uri": root.as_uri()}]


def test_client_payload_with_only_workspace_folders_is_valid_for_every_engine_version() -> None:
    payload = {"workspaceFolders": _folders()}

    PublishedWorkspaceRequest.model_validate(payload)
    ScanWorkspaceRequest.model_validate(payload)


def test_file_paths_is_rejected_by_the_published_contract() -> None:
    payload = {
        "workspaceFolders": _folders(),
        "filePaths": ["/workspace/app.py"],
    }

    with pytest.raises(ValidationError) as error:
        PublishedWorkspaceRequest.model_validate(payload)

    assert "filePaths" in str(error.value)
    assert "Extra inputs are not permitted" in str(error.value)

    # The current engine still accepts the optional field for backwards
    # compatibility, but the client must not rely on it being present.
    ScanWorkspaceRequest.model_validate(payload)


def test_unknown_fields_are_rejected_instead_of_being_ignored() -> None:
    payload = {
        "workspaceFolders": _folders(),
        "sourceText": "print('secret')",
    }

    with pytest.raises(ValidationError):
        PublishedWorkspaceRequest.model_validate(payload)
    with pytest.raises(ValidationError):
        ScanWorkspaceRequest.model_validate(payload)
