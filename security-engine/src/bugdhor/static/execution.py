"""Safe subprocess execution for external static analyzers.

Commands are always argv lists executed without a shell. The child receives a
sanitized environment, its stdin is closed, output is captured, and a timeout
terminates the whole process group so wrapper scripts cannot leave children
running. Captured output is bounded to avoid unbounded memory use.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from bugdhor.core.redaction import redact_text
from bugdhor.static.models import ToolExecution

_SECRET_ENV_RE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
    re.IGNORECASE,
)

DEFAULT_MAX_CAPTURE_BYTES = 16 * 1024 * 1024


def sanitized_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the inherited environment without credential-looking variables.

    Explicit per-adapter overrides are added after filtering so a deployment can
    opt into a specific variable deliberately. Neither the environment nor its
    values are ever written to scan results or logs.
    """
    environment = {
        name: value for name, value in os.environ.items() if not _SECRET_ENV_RE.search(name)
    }
    for name, value in (overrides or {}).items():
        if "\x00" in name or "\x00" in value:
            raise ValueError("environment names and values must not contain NUL bytes")
        environment[str(name)] = str(value)
    return environment


def resolve_executable(configured: str) -> str | None:
    """Resolve a configured executable without invoking a shell."""
    if not configured or "\x00" in configured:
        return None
    candidate = Path(configured).expanduser()
    if candidate.is_absolute() or os.sep in configured or (os.altsep and os.altsep in configured):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        return None
    resolved = shutil.which(configured)
    return str(Path(resolved).resolve()) if resolved else None


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        raise ValueError("a command must contain at least one argument")
    arguments: list[str] = []
    for argument in argv:
        if not isinstance(argument, str):
            raise TypeError("command arguments must be strings")
        if not argument:
            raise ValueError("command arguments must not be empty")
        if "\x00" in argument:
            raise ValueError("command arguments must not contain NUL bytes")
        arguments.append(argument)
    return tuple(arguments)


def _decode_captured(data: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    return data.decode("utf-8", errors="replace"), truncated


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.kill()
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


def run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: Path | str | None = None,
    environment: Mapping[str, str] | None = None,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> ToolExecution:
    """Execute one command safely and return captured process metadata."""
    arguments = _validate_argv(argv)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if max_capture_bytes <= 0:
        raise ValueError("max_capture_bytes must be greater than zero")

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            arguments,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(environment) if environment is not None else sanitized_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        return ToolExecution(
            argv=arguments,
            return_code=None,
            duration_seconds=time.monotonic() - started,
            launch_error=f"{type(exc).__name__}: {redact_text(exc)}",
        )

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(process)
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_bytes, stderr_bytes = process.communicate()

    stdout, stdout_truncated = _decode_captured(stdout_bytes, max_capture_bytes)
    stderr, stderr_truncated = _decode_captured(stderr_bytes, max_capture_bytes)
    return ToolExecution(
        argv=arguments,
        return_code=process.returncode,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )
