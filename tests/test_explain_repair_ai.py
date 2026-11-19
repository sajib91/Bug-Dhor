import pytest

from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.explain.repair.ai import (
    AiRepairConfig,
    AiRepairResult,
    AiRepairStatus,
    RepairProviderResponse,
    _reset_provider_registry,
    register_repair_provider,
    registered_repair_providers,
    request_ai_repair,
    sanitize_text,
    unregister_repair_provider,
)
from bugdhor_ast.flow import FlowEngine, taint_diagnostics

PYTHON_UNDEFINED = "def f():\n    return missing_name\n"
PYTHON_SQL = (
    "q = request.args.get('q')\n"
    "cursor.execute(\"SELECT * FROM users WHERE name = '\" + q + \"'\")\n"
)

VALID_DIFF = (
    "--- a/sample.py\n"
    "+++ b/sample.py\n"
    "@@ -1,2 +1,2 @@\n"
    " def f():\n"
    "-    return missing_name\n"
    "+    return 1\n"
)


class FakeProvider:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.response


@pytest.fixture(autouse=True)
def clean_provider_registry():
    _reset_provider_registry()
    yield
    _reset_provider_registry()


def undefined_finding():
    detection = BugDhorDetectionEngine().analyze_source(
        PYTHON_UNDEFINED, "python", file="sample.py"
    )
    return next(item.to_dict() for item in detection.diagnostics)


def sql_finding():
    flow = FlowEngine().analyze_source(PYTHON_SQL, "python", file="sample.py")
    return next(item.to_dict() for item in taint_diagnostics(flow))


def test_default_config_is_disabled_and_contacts_no_provider():
    result = request_ai_repair(
        undefined_finding(),
        source_code=PYTHON_UNDEFINED,
        file="sample.py",
    )

    assert result.status is AiRepairStatus.DISABLED
    assert result.source == "none"
    assert result.candidate is None
    assert result.recommendation is None
    assert "disabled by default" in result.reason
    assert registered_repair_providers() == ()


def test_deterministic_recommendation_wins_over_registered_provider():
    provider = FakeProvider(
        response=RepairProviderResponse(
            provider_id="fake", patch_text=VALID_DIFF
        )
    )
    register_repair_provider("fake", lambda config: provider)
    config = AiRepairConfig(enabled=True, provider="fake")

    result = request_ai_repair(
        sql_finding(),
        source_code=PYTHON_SQL,
        file="sample.py",
        config=config,
    )

    assert result.status is AiRepairStatus.DETERMINISTIC
    assert result.source == "deterministic"
    assert result.recommendation is not None
    assert result.recommendation.status.value == "ready"
    assert result.candidate is None
    assert provider.requests == []


def test_enabled_provider_returns_untrusted_candidate():
    response = RepairProviderResponse(
        provider_id="fake-provider",
        model="fake-model",
        patch_text=VALID_DIFF,
        rationale="Replace the undefined name with a literal.",
        confidence="medium",
        limitations=("Model output was not executed.",),
    )
    provider = FakeProvider(response=response)
    register_repair_provider("fake-provider", lambda config: provider)
    config = AiRepairConfig(
        enabled=True,
        provider="fake-provider",
        model="fake-model",
        api_key_environment_variable="BUGDHOR_LLM_API_KEY",
    )

    result = request_ai_repair(
        undefined_finding(),
        source_code=PYTHON_UNDEFINED,
        file="sample.py",
        config=config,
    )

    assert result.status is AiRepairStatus.CANDIDATE
    assert result.source == "provider"
    assert result.provider_id == "fake-provider"
    assert result.model == "fake-model"
    assert result.recommendation is None
    assert result.candidate is not None
    assert result.candidate.requires_approval is True
    assert result.candidate.confidence.value == "medium"
    assert "no generated code was executed" in " ".join(
        result.candidate.validation_notes
    ).lower()
    assert len(provider.requests) == 1
    assert provider.requests[0].file == "sample.py"
    assert result.to_dict()["candidate"]["patch_text"] == VALID_DIFF
    assert AiRepairResult.from_dict(result.to_dict()).to_dict() == result.to_dict()


def test_provider_failure_redacts_common_secret_forms():
    provider = FakeProvider(
        error=RuntimeError(
            "api_key=supersecret-value Bearer abcdefgh sk-abcdefghijklmnop"
        )
    )
    register_repair_provider("fake", lambda config: provider)
    config = AiRepairConfig(enabled=True, provider="fake")

    result = request_ai_repair(
        undefined_finding(),
        source_code=PYTHON_UNDEFINED,
        file="sample.py",
        config=config,
        secret_values=["supersecret-value"],
    )

    serialized = result.to_dict()
    assert result.status is AiRepairStatus.FAILED
    assert "supersecret-value" not in serialized["reason"]
    assert "abcdefgh" not in serialized["reason"]
    assert "sk-abcdefghijklmnop" not in serialized["reason"]
    assert "[REDACTED]" in serialized["reason"]
    assert result.candidate is None


def test_provider_patch_with_unsafe_target_is_rejected():
    unsafe_diff = VALID_DIFF.replace(
        "+++ b/sample.py", "+++ b/../../etc/passwd"
    )
    provider = FakeProvider(
        response=RepairProviderResponse(
            provider_id="fake", patch_text=unsafe_diff
        )
    )
    register_repair_provider("fake", lambda config: provider)

    result = request_ai_repair(
        undefined_finding(),
        source_code=PYTHON_UNDEFINED,
        file="sample.py",
        config=AiRepairConfig(enabled=True, provider="fake"),
    )

    assert result.status is AiRepairStatus.FAILED
    assert "target" in result.reason
    assert result.candidate is None


def test_missing_provider_is_unavailable():
    result = request_ai_repair(
        undefined_finding(),
        source_code=PYTHON_UNDEFINED,
        file="sample.py",
        config=AiRepairConfig(enabled=True, provider="missing"),
    )

    assert result.status is AiRepairStatus.UNAVAILABLE
    assert result.candidate is None


def test_provider_registration_rejects_duplicates_and_supports_removal():
    register_repair_provider("one", lambda config: FakeProvider())
    with pytest.raises(ValueError, match="already registered"):
        register_repair_provider("one", lambda config: FakeProvider())
    assert registered_repair_providers() == ("one",)

    unregister_repair_provider("one")
    assert registered_repair_providers() == ()


def test_config_validation_and_direct_redaction():
    with pytest.raises(ValueError, match="provider is required"):
        AiRepairConfig(enabled=True)
    with pytest.raises(ValueError, match="credentials"):
        AiRepairConfig(endpoint="https://user:pass@example.com/v1")

    redacted = sanitize_text(
        "token=abc123 and normal text", secret_values=["abc123"]
    )
    assert redacted == "[REDACTED] and normal text"
    assert "abc123" not in redacted
