"""Scan request and response contracts."""

from __future__ import annotations

from pydantic import AliasChoices, Field, field_validator

from bugdhor.api.schemas.common import (
    APIModel,
    FileInfo,
    Finding,
    OperationResponse,
    Range,
    ScanScope,
)
from bugdhor.core.safe_patch import reject_absolute_file_path


class FileContext(APIModel):
    """Common editor/file context accepted by analysis endpoints."""

    workspace_root: str = Field(
        min_length=1,
        max_length=4096,
        validation_alias=AliasChoices("workspaceRoot", "workspaceFolder"),
        serialization_alias="workspaceRoot",
    )
    workspace_folder_name: str | None = Field(default=None, max_length=200)
    file_path: str = Field(min_length=1, max_length=4096)
    document_uri: str | None = Field(default=None, max_length=4096)
    language_id: str | None = Field(default=None, max_length=100)
    document_version: int | None = Field(default=None, ge=0)
    selection: Range | None = None
    selected_text: str | None = Field(default=None, max_length=2_000_000)
    source_text: str | None = Field(
        default=None,
        max_length=2_000_000,
        description=(
            "Current editor text supplied by the client. When present, it is inspected instead "
            "of re-reading the file from disk. The file path must still resolve inside the "
            "workspace root and the configured file-size limit is enforced."
        ),
    )

    @field_validator("file_path", mode="before")
    @classmethod
    def _reject_absolute_file_path(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return reject_absolute_file_path(value)
        except Exception as exc:
            raise ValueError(str(exc)) from None


class ScanFileRequest(FileContext):
    pass


class WorkspaceFolder(APIModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=4096)
    uri: str | None = Field(default=None, max_length=4096)


class ScanWorkspaceRequest(APIModel):
    workspace_folders: list[WorkspaceFolder] = Field(min_length=1, max_length=50)
    file_paths: list[str] | None = Field(
        default=None,
        max_length=50_000,
        validation_alias=AliasChoices("filePaths", "file_paths"),
        serialization_alias="filePaths",
        description=(
            "Optional explicit absolute source paths. When present, the engine scans only these "
            "already-discovered files instead of enumerating every workspace source. Every path "
            "is still resolved and containment-checked against a workspace root."
        ),
    )


class ScanResponse(OperationResponse):
    findings: list[Finding] = Field(default_factory=list, max_length=100_000)
    scope: ScanScope
    files_scanned: int = Field(ge=0)
    analysis_available: bool


class ScanFileResponse(ScanResponse):
    file: FileInfo


class ScanWorkspaceResponse(ScanResponse):
    pass
