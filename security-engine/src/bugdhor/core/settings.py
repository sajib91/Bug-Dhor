"""Typed environment configuration for the Bug Dhor engine.

Secrets are read from the environment or a local ``.env`` file and are never
included in redacted configuration output.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
Device = Literal["auto", "cpu", "cuda", "mps"]
SandboxBackend = Literal["docker", "process", "none"]


def is_loopback_host(host: str) -> bool:
    """Return whether a bind host is loopback without performing DNS lookups."""
    value = host.strip().lower().strip("[]")
    if value in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    """Environment-backed runtime settings.

    Environment variables use the ``BUGDHOR_`` prefix, for example
    ``BUGDHOR_DEVICE=cpu``. A Hugging Face token is accepted as either
    ``BUGDHOR_HF_TOKEN`` or the conventional ``HF_TOKEN`` and is redacted from
    serialized output.
    """

    model_config = SettingsConfigDict(
        env_prefix="BUGDHOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    log_level: LogLevel = "INFO"
    data_dir: Path = Path(".bugdhor-data")
    log_dir: Path = Path(".bugdhor-data/logs")
    persist_full_payloads: bool = False
    result_retention_days: int = Field(default=7, ge=0, le=365)

    # HTTP transport. Keep the loopback default unless the deployment is
    # intentionally isolated; the engine has no remote multi-user auth layer.
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=0, le=65_535)
    environment: Literal["development", "production"] = "production"
    enable_docs: bool | None = None
    remote_transport: Literal["loopback", "https-terminated"] = "loopback"
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    workspace_roots: Annotated[list[Path], NoDecode] = Field(default_factory=lambda: [Path.cwd()])
    max_request_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    max_file_bytes: int = Field(default=1024 * 1024, ge=1, le=10 * 1024 * 1024)
    max_workspace_files: int = Field(default=50_000, ge=1, le=200_000)
    api_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("BUGDHOR_API_TOKEN", "BUGDHOR_ENGINE_TOKEN"),
    )

    model_id: str | None = None
    model_revision: str | None = None
    device: Device = "auto"
    gpu_concurrency: int = Field(default=1, ge=1, le=8)

    sae_manifest: Path | None = None

    sandbox_backend: SandboxBackend = "docker"
    sandbox_timeout_seconds: int = Field(default=900, ge=1, le=86_400)

    semgrep_path: str = "semgrep"
    semgrep_configs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            str(Path(__file__).resolve().parents[3] / "semgrep-rules" / "bugdhor.yml")
        ]
    )
    semgrep_require_local_rules: bool = True
    bandit_path: str = "bandit"
    codeql_path: str | None = None
    joern_path: str | None = None

    hf_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("BUGDHOR_HF_TOKEN", "HF_TOKEN"),
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("device", "sandbox_backend", mode="before")
    @classmethod
    def _normalize_lowercase(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    @field_validator("cors_origins", "workspace_roots", "semgrep_configs", mode="before")
    @classmethod
    def _split_list_setting(cls, value: object) -> object:
        """Accept a JSON array or a comma-separated environment value."""
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                raise ValueError("expected a JSON array")
            return parsed
        return [item.strip() for item in text.split(",") if item.strip()]

    @field_validator("cors_origins")
    @classmethod
    def _validate_cors_origins(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            if value == "*":
                raise ValueError("wildcard CORS origins are not allowed")
            parts = urlsplit(value)
            if parts.scheme not in {"http", "https"}:
                raise ValueError("CORS origins must use http or https")
            if not parts.netloc or parts.username or parts.password:
                raise ValueError("CORS origins must not contain credentials")
            if parts.path not in {"", "/"} or parts.query or parts.fragment:
                raise ValueError("CORS origins must contain only scheme, host, and port")
            origin = urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))
            if origin not in normalized:
                normalized.append(origin)
        return normalized

    @model_validator(mode="after")
    def _validate_remote_transport(self) -> Settings:
        """Require authentication and explicit HTTPS transport beyond loopback."""
        if is_loopback_host(self.host):
            return self
        if not self.api_token:
            raise ValueError("non-loopback binding requires BUGDHOR_API_TOKEN")
        if self.remote_transport != "https-terminated":
            raise ValueError(
                "non-loopback binding requires explicit HTTPS termination "
                "(BUGDHOR_REMOTE_TRANSPORT=https-terminated)"
            )
        return self

    def validate_runtime(self) -> None:
        """Re-check transport policy after CLI overrides."""
        self._validate_remote_transport()

    def docs_enabled(self) -> bool:
        """Docs are opt-in in production and available by default in development."""
        if self.enable_docs is not None:
            return self.enable_docs
        return self.environment == "development"

    def ensure_directories(self) -> None:
        """Create private local data and log directories, including parents."""
        for directory in (self.data_dir, self.log_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except OSError:
                pass

    def redacted(self) -> dict[str, object]:
        """Return JSON-safe settings with secrets removed."""
        data = self.model_dump(mode="json")
        data.pop("hf_token", None)
        data.pop("api_token", None)
        return data
