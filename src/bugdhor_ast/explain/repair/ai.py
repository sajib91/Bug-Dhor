"""Optional, provider-independent AI repair fallback.

Deterministic strategies are always tried first. This module contains no SDK
or network client, registers no provider by default, and is disabled unless an
explicit :class:`AiRepairConfig` enables it. Provider output is treated as an
untrusted patch candidate: it is never executed, applied, or promoted to a
trusted recommendation automatically.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from ...languages import detect_language
from ..evidence import _finding_location, finding_id_for
from ..schema import ConfidenceLevel
from .recommendation import (
    RepairRecommendation,
    validate_recommendation,
)
from .strategies import _extract_snippet, recommend_repair

AI_REPAIR_SCHEMA_VERSION = "1.0"

_DEFAULT_MAX_SOURCE_CHARS = 4000
_DEFAULT_MAX_RESPONSE_CHARS = 20000

_CONFIG_KEYS = frozenset(
    {
        "enabled",
        "provider",
        "model",
        "endpoint",
        "api_key_environment_variable",
        "max_source_chars",
        "max_response_chars",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "finding_id",
        "rule_id",
        "language",
        "file",
        "message",
        "snippet",
        "cwe_ids",
        "root_cause",
        "deterministic_recommendation",
    }
)
_RESPONSE_KEYS = frozenset(
    {
        "provider_id",
        "model",
        "patch_text",
        "rationale",
        "confidence",
        "limitations",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "provider_id",
        "model",
        "patch_text",
        "rationale",
        "confidence",
        "validation_notes",
        "requires_approval",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "source",
        "provider_id",
        "model",
        "reason",
        "recommendation",
        "candidate",
        "limitations",
    }
)

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}"),
    re.compile(r"\bsk-[A-Za-z0-9._~+/=-]{8,}\b"),
)


class AiRepairStatus(str, Enum):
    """Outcome of the optional AI repair fallback."""

    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    DETERMINISTIC = "deterministic"
    CANDIDATE = "candidate"
    FAILED = "failed"


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


def _check_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    keys = set(value)
    expected_set = set(expected)
    missing = sorted(expected_set - keys)
    unknown = sorted(keys - expected_set)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ValueError(f"{label} has invalid keys ({', '.join(details)})")


def _as_str(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} must not be empty")
    return value


def _as_optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _as_str(value, label)


def _as_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")
    return value


def _as_int(value: Any, label: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _as_str_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list")
    return tuple(
        _as_str(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )


def sanitize_text(value: str, *, secret_values: Iterable[str] = ()) -> str:
    """Redact common credential forms before placing text in a result."""

    text = _as_str(value, "text", allow_empty=True)
    for secret in sorted(
        (item for item in secret_values if isinstance(item, str) and item),
        key=len,
        reverse=True,
    ):
        text = text.replace(secret, "[REDACTED]")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


@dataclass(frozen=True)
class AiRepairConfig:
    """Explicit opt-in configuration for an AI repair provider."""

    enabled: bool = False
    provider: str = ""
    model: str = ""
    endpoint: str = ""
    api_key_environment_variable: str = ""
    max_source_chars: int = _DEFAULT_MAX_SOURCE_CHARS
    max_response_chars: int = _DEFAULT_MAX_RESPONSE_CHARS

    def __post_init__(self) -> None:
        _as_bool(self.enabled, "config.enabled")
        _as_str(self.provider, "config.provider", allow_empty=True)
        _as_str(self.model, "config.model", allow_empty=True)
        _as_str(self.endpoint, "config.endpoint", allow_empty=True)
        _as_str(
            self.api_key_environment_variable,
            "config.api_key_environment_variable",
            allow_empty=True,
        )
        _as_int(self.max_source_chars, "config.max_source_chars")
        _as_int(self.max_response_chars, "config.max_response_chars")
        if self.enabled and not self.provider:
            raise ValueError("config.provider is required when AI repair is enabled")
        if "@" in self.endpoint.split("://", 1)[-1].split("/", 1)[0]:
            raise ValueError("config.endpoint must not contain URL credentials")

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.endpoint,
            "api_key_environment_variable": self.api_key_environment_variable,
            "max_source_chars": self.max_source_chars,
            "max_response_chars": self.max_response_chars,
        }

    @classmethod
    def from_dict(cls, value: Any) -> AiRepairConfig:
        value = _as_mapping(value, "AI repair config")
        _check_keys(value, _CONFIG_KEYS, "AI repair config")
        return cls(**dict(value))


@dataclass(frozen=True)
class RepairProviderRequest:
    """Provider-neutral request containing bounded, non-secret context."""

    finding_id: str
    rule_id: str
    language: str
    file: str
    message: str
    snippet: str
    cwe_ids: tuple[str, ...]
    root_cause: str
    deterministic_recommendation: Mapping[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "language": self.language,
            "file": self.file,
            "message": self.message,
            "snippet": self.snippet,
            "cwe_ids": list(self.cwe_ids),
            "root_cause": self.root_cause,
            "deterministic_recommendation": (
                dict(self.deterministic_recommendation)
                if self.deterministic_recommendation is not None
                else None
            ),
        }


@dataclass(frozen=True)
class RepairProviderResponse:
    """Provider-neutral output. ``patch_text`` is always untrusted text."""

    provider_id: str
    patch_text: str
    model: str = ""
    rationale: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _as_str(self.provider_id, "response.provider_id")
        _as_str(self.patch_text, "response.patch_text")
        _as_str(self.model, "response.model", allow_empty=True)
        _as_str(self.rationale, "response.rationale", allow_empty=True)
        if not isinstance(self.confidence, ConfidenceLevel):
            object.__setattr__(
                self, "confidence", ConfidenceLevel(self.confidence)
            )
        object.__setattr__(
            self, "limitations", _as_str_list(self.limitations, "response.limitations")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "model": self.model,
            "patch_text": self.patch_text,
            "rationale": self.rationale,
            "confidence": self.confidence.value,
            "limitations": list(self.limitations),
        }


@runtime_checkable
class RepairProvider(Protocol):
    """Minimal contract any optional AI repair adapter must implement."""

    def generate(self, request: RepairProviderRequest) -> RepairProviderResponse:
        """Return an untrusted patch candidate for one finding."""

        ...


ProviderFactory = Callable[[AiRepairConfig], RepairProvider]
_PROVIDER_FACTORIES: dict[str, ProviderFactory] = {}


def register_repair_provider(name: str, factory: ProviderFactory) -> None:
    """Register a provider factory. No provider is registered by default."""

    key = _as_str(name, "provider name")
    if not callable(factory):
        raise TypeError("provider factory must be callable")
    if key in _PROVIDER_FACTORIES:
        raise ValueError(f"Repair provider is already registered: {key}")
    _PROVIDER_FACTORIES[key] = factory


def unregister_repair_provider(name: str) -> None:
    """Remove a provider factory if present."""

    _PROVIDER_FACTORIES.pop(_as_str(name, "provider name"), None)


def registered_repair_providers() -> tuple[str, ...]:
    """Return the names of explicitly registered provider factories."""

    return tuple(sorted(_PROVIDER_FACTORIES))


def _reset_provider_registry() -> None:
    """Clear provider registrations. Intended for isolated tests."""

    _PROVIDER_FACTORIES.clear()


@dataclass(frozen=True)
class UntrustedPatchCandidate:
    """A validated-shape patch proposal that still requires human approval."""

    provider_id: str
    model: str
    patch_text: str
    rationale: str
    confidence: ConfidenceLevel
    validation_notes: tuple[str, ...] = field(default_factory=tuple)
    requires_approval: bool = True

    def __post_init__(self) -> None:
        _as_str(self.provider_id, "candidate.provider_id")
        _as_str(self.model, "candidate.model", allow_empty=True)
        _as_str(self.patch_text, "candidate.patch_text")
        _as_str(self.rationale, "candidate.rationale", allow_empty=True)
        if not isinstance(self.confidence, ConfidenceLevel):
            object.__setattr__(
                self, "confidence", ConfidenceLevel(self.confidence)
            )
        object.__setattr__(
            self,
            "validation_notes",
            _as_str_list(self.validation_notes, "candidate.validation_notes"),
        )
        _as_bool(self.requires_approval, "candidate.requires_approval")
        if self.requires_approval is not True:
            raise ValueError("candidate.requires_approval must always be true")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "model": self.model,
            "patch_text": self.patch_text,
            "rationale": self.rationale,
            "confidence": self.confidence.value,
            "validation_notes": list(self.validation_notes),
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, value: Any) -> UntrustedPatchCandidate:
        value = _as_mapping(value, "untrusted patch candidate")
        _check_keys(value, _CANDIDATE_KEYS, "untrusted patch candidate")
        return cls(**dict(value))


@dataclass(frozen=True)
class AiRepairResult:
    """Stable result of the optional AI repair fallback."""

    status: AiRepairStatus
    source: str
    reason: str
    recommendation: RepairRecommendation | None = None
    candidate: UntrustedPatchCandidate | None = None
    provider_id: str = ""
    model: str = ""
    limitations: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = AI_REPAIR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.status, AiRepairStatus):
            object.__setattr__(self, "status", AiRepairStatus(self.status))
        _as_str(self.source, "result.source")
        _as_str(self.reason, "result.reason", allow_empty=True)
        if self.recommendation is not None and not isinstance(
            self.recommendation, RepairRecommendation
        ):
            raise TypeError("result.recommendation must be a RepairRecommendation")
        if self.candidate is not None and not isinstance(
            self.candidate, UntrustedPatchCandidate
        ):
            raise TypeError("result.candidate must be an UntrustedPatchCandidate")
        _as_str(self.provider_id, "result.provider_id", allow_empty=True)
        _as_str(self.model, "result.model", allow_empty=True)
        object.__setattr__(
            self, "limitations", _as_str_list(self.limitations, "result.limitations")
        )
        if self.schema_version != AI_REPAIR_SCHEMA_VERSION:
            raise ValueError(
                f"result.schema_version must be {AI_REPAIR_SCHEMA_VERSION}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "source": self.source,
            "provider_id": self.provider_id,
            "model": self.model,
            "reason": self.reason,
            "recommendation": (
                self.recommendation.to_dict()
                if self.recommendation is not None
                else None
            ),
            "candidate": self.candidate.to_dict() if self.candidate is not None else None,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, value: Any) -> AiRepairResult:
        value = _as_mapping(value, "AI repair result")
        _check_keys(value, _RESULT_KEYS, "AI repair result")
        recommendation = value["recommendation"]
        candidate = value["candidate"]
        if recommendation is not None:
            validate_recommendation(recommendation)
        return cls(
            schema_version=value["schema_version"],
            status=AiRepairStatus(value["status"]),
            source=value["source"],
            provider_id=value["provider_id"],
            model=value["model"],
            reason=value["reason"],
            recommendation=(
                RepairRecommendation.from_dict(recommendation)
                if recommendation is not None
                else None
            ),
            candidate=(
                UntrustedPatchCandidate.from_dict(candidate)
                if candidate is not None
                else None
            ),
            limitations=value["limitations"],
        )


def _finding_value(finding: Any) -> dict[str, Any]:
    value = _as_mapping(finding, "finding")
    return dict(value)


def _build_request(
    finding: Mapping[str, Any],
    explanation: Any,
    deterministic: RepairRecommendation,
    source_code: str,
    file: str,
    config: AiRepairConfig,
) -> RepairProviderRequest:
    location = _finding_location(finding)
    target_file = file or str(finding.get("file") or location.file or "<source>")
    language = str(
        finding.get("language")
        or deterministic.target.language
        or detect_language(target_file)
        or "unknown"
    )
    snippet, _ = (
        _extract_snippet(source_code, location) if source_code else (None, "")
    )
    if not snippet:
        snippet = source_code[: config.max_source_chars]
        if len(source_code) > config.max_source_chars:
            snippet += "\n[TRUNCATED]"
    elif len(snippet) > config.max_source_chars:
        snippet = snippet[: config.max_source_chars] + "\n[TRUNCATED]"

    cwe_ids: tuple[str, ...] = ()
    root_cause = ""
    if explanation is not None and hasattr(explanation, "to_dict"):
        payload = explanation.to_dict()
        cwe_ids = tuple(
            str(item.get("id"))
            for item in payload.get("cwe", ())
            if isinstance(item, Mapping) and item.get("id")
        )
        root_cause = str(
            (payload.get("root_cause") or {}).get("rationale", "")
        )
    return RepairProviderRequest(
        finding_id=str(finding.get("finding_id") or finding_id_for(finding)),
        rule_id=str(finding.get("rule_id", "unknown")),
        language=language,
        file=target_file,
        message=str(finding.get("message", "")),
        snippet=snippet,
        cwe_ids=cwe_ids,
        root_cause=root_cause,
        deterministic_recommendation=deterministic.to_dict(),
    )


def _patch_targets(patch_text: str) -> tuple[str, ...]:
    targets: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ "):
            targets.append(line[4:].split("\t", 1)[0].strip())
    return tuple(targets)


def _validate_candidate_text(
    response: RepairProviderResponse, request: RepairProviderRequest, config: AiRepairConfig
) -> tuple[UntrustedPatchCandidate | None, str]:
    patch_text = response.patch_text
    notes = [
        "Provider output is untrusted text; no generated code was executed.",
        "Manual review and the normal explicit-approval patch workflow are required.",
    ]
    if len(patch_text) > config.max_response_chars:
        return None, "Provider patch exceeded the configured response limit."
    if "GIT binary patch" in patch_text or "Binary files" in patch_text:
        return None, "Binary patches are not accepted."
    if any(ord(char) < 32 and char not in "\n\t\r" for char in patch_text):
        return None, "Provider patch contained unsupported control characters."

    targets = _patch_targets(patch_text)
    if len(targets) != 1:
        return None, "Provider patch must contain exactly one +++ target line."
    target = targets[0]
    if not target.startswith("b/"):
        return None, "Provider patch target must use the b/ prefix."
    relative = target[2:]
    expected_paths = {request.file, request.file.lstrip("/")}
    if (
        not relative
        or relative not in expected_paths
        or relative.startswith("/")
        or "\\" in relative
        or ".." in relative.split("/")
        or re.match(r"^[A-Za-z]:", relative)
    ):
        return None, "Provider patch target does not match the requested file."
    if "--- a/" not in patch_text:
        return None, "Provider patch must contain a matching --- a/ source line."
    notes.append("Unified diff target path matched the requested file.")

    candidate = UntrustedPatchCandidate(
        provider_id=response.provider_id,
        model=response.model,
        patch_text=patch_text,
        rationale=response.rationale,
        confidence=response.confidence,
        validation_notes=tuple(notes),
        requires_approval=True,
    )
    return candidate, ""


def _provider_for(config: AiRepairConfig) -> RepairProvider | None:
    if config.provider:
        factory = _PROVIDER_FACTORIES.get(config.provider)
        return factory(config) if factory is not None else None
    if len(_PROVIDER_FACTORIES) == 1:
        factory = next(iter(_PROVIDER_FACTORIES.values()))
        return factory(config)
    return None


def request_ai_repair(
    finding: Any,
    analysis: Any = None,
    explanation: Any = None,
    source_code: str = "",
    file: str | None = None,
    *,
    config: AiRepairConfig | None = None,
    secret_values: Iterable[str] = (),
) -> AiRepairResult:
    """Return a deterministic repair first, or an explicit AI candidate.

    ``analysis`` is accepted for interface compatibility but is not sent to a
    provider. The provider sees only bounded finding context, never secrets.
    """

    del analysis
    config = config or AiRepairConfig()
    finding_dict = _finding_value(finding)
    deterministic = recommend_repair(
        finding_dict, source_code=source_code, file=file, explanation=explanation
    )
    if deterministic.status.value in {"ready", "needs_review"}:
        return AiRepairResult(
            status=AiRepairStatus.DETERMINISTIC,
            source="deterministic",
            reason="A deterministic repair recommendation was available.",
            recommendation=deterministic,
            limitations=deterministic.known_limitations,
        )

    if not config.enabled:
        return AiRepairResult(
            status=AiRepairStatus.DISABLED,
            source="none",
            reason="AI repair is disabled by default; enable it explicitly.",
            limitations=(
                "No provider was contacted.",
                "Deterministic repair was unsupported for this finding.",
            ),
        )

    provider = _provider_for(config)
    if provider is None or not isinstance(provider, RepairProvider):
        return AiRepairResult(
            status=AiRepairStatus.UNAVAILABLE,
            source="none",
            reason="No registered AI repair provider is available for this configuration.",
            limitations=("No provider output was accepted or applied.",),
        )

    request = _build_request(
        finding_dict, explanation, deterministic, source_code, file or "", config
    )
    try:
        response = provider.generate(request)
    except Exception as error:  # noqa: BLE001 - provider failures must be reported honestly
        detail = sanitize_text(
            f"{type(error).__name__}: {error}", secret_values=secret_values
        )
        return AiRepairResult(
            status=AiRepairStatus.FAILED,
            source="provider",
            reason=f"AI repair provider failed: {detail}",
            provider_id=config.provider,
            model=config.model,
            limitations=("No provider output was accepted or applied.",),
        )

    if not isinstance(response, RepairProviderResponse):
        return AiRepairResult(
            status=AiRepairStatus.FAILED,
            source="provider",
            reason="AI repair provider returned an unsupported response type.",
            provider_id=config.provider,
            model=config.model,
            limitations=("No provider output was accepted or applied.",),
        )

    candidate, validation_error = _validate_candidate_text(
        response, request, config
    )
    if candidate is None:
        return AiRepairResult(
            status=AiRepairStatus.FAILED,
            source="provider",
            reason=sanitize_text(validation_error, secret_values=secret_values),
            provider_id=response.provider_id,
            model=response.model,
            limitations=("Provider output was rejected before any review or apply.",),
        )

    return AiRepairResult(
        status=AiRepairStatus.CANDIDATE,
        source="provider",
        reason="An untrusted patch candidate requires manual review and explicit approval.",
        provider_id=response.provider_id,
        model=response.model,
        candidate=candidate,
        limitations=(*candidate.validation_notes, *response.limitations),
    )


__all__ = [
    "AI_REPAIR_SCHEMA_VERSION",
    "AiRepairConfig",
    "AiRepairResult",
    "AiRepairStatus",
    "RepairProvider",
    "RepairProviderRequest",
    "RepairProviderResponse",
    "UntrustedPatchCandidate",
    "register_repair_provider",
    "registered_repair_providers",
    "request_ai_repair",
    "sanitize_text",
    "unregister_repair_provider",
]
