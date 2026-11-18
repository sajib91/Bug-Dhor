from __future__ import annotations

import os
import sys

import pytest

from bugdhor.static.execution import (
    resolve_executable,
    run_command,
    sanitized_environment,
)


def test_run_command_captures_output_without_shell_interpretation() -> None:
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "value; echo should-not-run",
        ],
        timeout_seconds=5,
    )

    assert result.return_code == 0
    assert result.stdout.strip() == "value; echo should-not-run"
    assert not result.timed_out
    assert result.launch_error is None


def test_run_command_applies_a_timeout_and_terminates_the_child() -> None:
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_seconds=0.2,
    )

    assert result.timed_out is True
    assert result.return_code is not None
    assert result.duration_seconds < 5


def test_run_command_reports_a_missing_executable_instead_of_raising() -> None:
    result = run_command(
        ["/definitely/not/a/real/analyzer", "--version"],
        timeout_seconds=1,
    )

    assert result.return_code is None
    assert result.launch_error is not None
    assert result.stdout == ""


def test_run_command_truncates_bounded_output() -> None:
    result = run_command(
        [sys.executable, "-c", "print('x' * 1000)"],
        timeout_seconds=5,
        max_capture_bytes=32,
    )

    assert result.stdout_truncated is True
    assert len(result.stdout) == 32


def test_run_command_rejects_empty_arguments() -> None:
    with pytest.raises(ValueError):
        run_command([], timeout_seconds=1)
    with pytest.raises(ValueError):
        run_command([sys.executable], timeout_seconds=0)
    with pytest.raises(ValueError):
        run_command([sys.executable, ""], timeout_seconds=1)


def test_sanitized_environment_removes_credential_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGDHOR_TEST_SECRET_TOKEN", "do-not-pass")
    monkeypatch.setenv("ORDINARY_SETTING", "visible")

    environment = sanitized_environment()

    assert "BUGDHOR_TEST_SECRET_TOKEN" not in environment
    assert environment["ORDINARY_SETTING"] == "visible"


def test_resolve_executable_accepts_an_executable_path(tmp_path) -> None:
    executable = tmp_path / "fake-tool"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)

    assert resolve_executable(str(executable)) == str(executable.resolve())
    assert resolve_executable(str(tmp_path / "missing")) is None
    if os.name != "nt":
        assert resolve_executable("sh") is not None
