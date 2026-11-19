from __future__ import annotations

import hashlib
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import bugdhor.sandbox.executor as sandbox_executor
from bugdhor.api.app import create_app
from bugdhor.api.middleware.problem import problem_payload
from bugdhor.core.errors import ValidationAppError
from bugdhor.core.jobs import JobStore
from bugdhor.core.orchestrator import Orchestrator
from bugdhor.core.redaction import redact_text
from bugdhor.core.safe_patch import apply_patch_in_temp, patch_paths
from bugdhor.core.settings import Settings
from bugdhor.sandbox.executor import ExecutionConsent, ExecutionRequest, IsolatedExecutor
from bugdhor.static.semgrep import SemgrepConfig
from bugdhor.verification.engine import INCONCLUSIVE_VERIFICATION, IndependentVerificationEngine
from bugdhor.verification.functional import FunctionalVerifier

SOURCE = """\
# PRIVATE_SOURCE_MARKER
import sqlite3


def connect(value):
    return sqlite3.connect(value)
"""

PATCH = """\
--- a/app.py
+++ b/app.py
@@ -1,5 +1,5 @@
-# PRIVATE_SOURCE_MARKER
+# REPAIRED_SOURCE_MARKER
 import sqlite3
 
 
 def connect(value):
"""


def _finding(api) -> dict[str, object]:
    return {
        "findingId": "finding-1",
        "documentUri": (api.root / "app.py").resolve().as_uri(),
        "range": {"start": {"line": 4, "character": 4}, "end": {"line": 4, "character": 10}},
        "cwe": "CWE-89",
    }


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_direct_inspection_rejects_non_source_files(api) -> None:
    secret = api.root / "secrets.env"
    secret.write_text("API_KEY=should-not-be-analyzed\n", encoding="utf-8")
    response = api.client.post(
        "/api/v1/scan/file",
        json=api.payload(filePath="secrets.env"),
    )
    assert response.status_code == 415
    assert response.json()["code"] == "E_UNSUPPORTED_FILE"


def test_api_rejects_absolute_file_path_at_the_boundary(api) -> None:
    response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            filePath=str(api.root / "app.py"),
            finding=_finding(api),
        ),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "E_VALIDATION"


def test_repair_generate_never_changes_original_file_hash(api) -> None:
    target = api.root / "app.py"
    before = _hash(target)

    relative_response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding=_finding(api),
            patch=PATCH,
            runFunctionalTests=False,
        ),
    )
    assert relative_response.status_code == 200
    assert _hash(target) == before

    absolute_patch = PATCH.replace("+++ b/app.py", f"+++ b/{target}")
    absolute_response = api.client.post(
        "/api/v1/repair/generate",
        json=api.payload(
            finding=_finding(api),
            patch=absolute_patch,
            runFunctionalTests=False,
        ),
    )
    assert absolute_response.status_code == 422
    assert _hash(target) == before


def test_recommendation_generate_never_changes_original_file_hash(api) -> None:
    target = api.root / "app.py"
    before = _hash(target)

    relative_response = api.client.post(
        "/api/v1/recommendations/generate",
        json=api.payload(
            finding=_finding(api),
            candidates=[PATCH],
            runFunctionalTests=False,
        ),
    )
    assert relative_response.status_code == 200
    assert _hash(target) == before

    absolute_patch = PATCH.replace("+++ b/app.py", f"+++ b/{target}")
    absolute_response = api.client.post(
        "/api/v1/recommendations/generate",
        json=api.payload(
            finding=_finding(api),
            candidates=[absolute_patch],
            runFunctionalTests=False,
        ),
    )
    assert absolute_response.status_code == 422
    assert _hash(target) == before


def test_absolute_patch_targets_are_rejected_before_any_write(api) -> None:
    target = api.root / "app.py"
    absolute_patch = PATCH.replace("+++ b/app.py", f"+++ b/{target}")
    with pytest.raises(ValidationAppError):
        apply_patch_in_temp(api.root, "app.py", SOURCE, absolute_patch)
    with pytest.raises(ValidationAppError):
        patch_paths(absolute_patch)


def test_verification_snapshot_skips_symlinked_files_and_directories(tmp_path: Path) -> None:
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    (source_root / "app.py").write_text(SOURCE, encoding="utf-8")
    subdirectory = source_root / "pkg"
    subdirectory.mkdir()
    (subdirectory / "module.py").write_text("value = 1\n", encoding="utf-8")

    outside_file = tmp_path / "outside.py"
    outside_file.write_text("OUTSIDE = 'secret'\n", encoding="utf-8")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "secret.py").write_text("SECRET = 1\n", encoding="utf-8")

    try:
        (source_root / "link.py").symlink_to(outside_file)
        (source_root / "linkdir").symlink_to(outside_dir, target_is_directory=True)
        (subdirectory / "nested_link.py").symlink_to(outside_file)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are unavailable on this platform")

    verifier = FunctionalVerifier(sandbox_backend="none")
    with tempfile.TemporaryDirectory() as destination:
        target = Path(destination)
        verifier._copy_workspace_snapshot(source_root, target)
        assert (target / "app.py").exists()
        assert (target / "pkg" / "module.py").exists()
        assert not (target / "link.py").exists()
        assert not (target / "linkdir").exists()
        assert not (target / "pkg" / "nested_link.py").exists()


def test_persisted_results_are_metadata_only_and_private(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "app.py"
    target.write_text(SOURCE, encoding="utf-8")
    settings = Settings(
        _env_file=None,
        workspace_roots=[root],
        data_dir=tmp_path / "data",
        log_level="ERROR",
    )
    store = JobStore(settings.data_dir)
    job = store.create("repair_generate", request_id="req-1")
    orchestrator = Orchestrator(settings)
    type(
        "Request",
        (),
        {
            "workspace_root": str(root),
            "file_path": "app.py",
            "source_text": SOURCE,
            "selection": None,
            "language_id": None,
            "finding": type(
                "Finding",
                (),
                {
                    "document_uri": None,
                    "model_dump": lambda self, **kwargs: {
                        "findingId": "finding-1",
                        "documentUri": None,
                        "cwe": "CWE-89",
                    },
                },
            )(),
            "patch": PATCH,
            "generate": False,
            "execution_consent": None,
            "run_functional_tests": False,
            "test_timeout_seconds": 120.0,
            "project_test_command": None,
        },
    )()
    orchestrator._persist_result(
        store, "repair_generate", "req-1", {"result": {"originalCode": SOURCE}}
    )

    for artifact in list(settings.data_dir.rglob("*.json")):
        text = artifact.read_text(encoding="utf-8")
        assert "PRIVATE_SOURCE_MARKER" not in text
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE((settings.data_dir / "results").stat().st_mode) == 0o700
    assert job.job_id


def test_production_docs_are_disabled_by_default(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(_env_file=None, workspace_roots=[root], data_dir=tmp_path / "data")
    client = TestClient(create_app(settings))
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_non_loopback_binding_requires_token_and_explicit_https(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, host="0.0.0.0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, host="0.0.0.0", api_token="secret-token")
    settings = Settings(
        _env_file=None,
        host="0.0.0.0",
        api_token="secret-token",
        remote_transport="https-terminated",
    )
    assert settings.host == "0.0.0.0"


def test_semgrep_uses_pinned_offline_rules_by_default() -> None:
    config = SemgrepConfig()
    assert config.require_local_rules is True
    assert all(Path(item).is_file() for item in config.configs)
    assert all(not item == "auto" for item in config.configs)
    with pytest.raises(ValueError):
        SemgrepConfig(configs=("auto",))


def test_redaction_removes_secret_values() -> None:
    redacted = redact_text("token=abc123 and password: hunter2")
    assert "abc123" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted


def test_problem_details_are_redacted() -> None:
    payload = problem_payload(
        request_id="req-1",
        instance="/api/v1/scan/file",
        status=500,
        code="E_TEST",
        title="token=abc123",
        detail="password: hunter2",
        details={"secret": "do-not-leak", "stage": "detection"},
    )
    serialized = str(payload)
    assert "abc123" not in serialized
    assert "hunter2" not in serialized
    assert "do-not-leak" not in serialized
    assert "detection" in serialized


def test_create_app_revalidates_programmatic_non_loopback_settings(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(_env_file=None, workspace_roots=[root], data_dir=tmp_path / "data")
    mutated = settings.model_copy(update={"host": "0.0.0.0"})
    with pytest.raises(ValueError, match="non-loopback binding"):
        create_app(mutated)


def test_analysis_cache_persists_metadata_without_source_text(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(_env_file=None, workspace_roots=[root], data_dir=tmp_path / "data")
    orchestrator = Orchestrator(settings)
    orchestrator._store_analysis_cache(
        "cache-key",
        {
            "_kind": "analysis-v1",
            "language_id": "python",
            "parsed_ok": False,
            "parse_error": "SyntaxError: PRIVATE_SOURCE_MARKER",
        },
    )
    artifact = settings.data_dir / "cache" / "analysis" / "cache-key.json"
    text = artifact.read_text(encoding="utf-8")
    assert "PRIVATE_SOURCE_MARKER" not in text
    assert "parse_error" not in text
    assert '"_kind": "analysis-v1"' in text
    assert '"parsed_ok": false' in text
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


def test_verification_engine_rejects_absolute_target_path() -> None:
    outcome = IndependentVerificationEngine().verify(
        original_source="print('x')\n",
        file_path="/etc/passwd",
        patch=PATCH,
        profile="static_only",
    )
    assert outcome.classification == INCONCLUSIVE_VERIFICATION
    assert "canonical workspace-relative" in outcome.limitations[0]


def test_sandbox_recorded_command_redacts_environment_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv, *args, **kwargs):  # noqa: ARG001
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sandbox_executor.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(sandbox_executor.subprocess, "run", fake_run)
    result = IsolatedExecutor("docker").run(
        tmp_path,
        ExecutionRequest(argv=("true",), environment={"API_TOKEN": "super-secret-value"}),
        ExecutionConsent(granted=True),
    )
    recorded = " ".join(result.command)
    assert result.status == "ok"
    assert "super-secret-value" not in recorded
    assert "[REDACTED]" in recorded
