from __future__ import annotations

from pathlib import Path

from craftsec.core.settings import Settings
from craftsec.repair import RepositoryContextBuilder


def _settings(root: Path) -> Settings:
    return Settings(workspace_roots=[root], max_file_bytes=100_000)


def test_context_follows_imports_and_collects_security_and_test_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from security import sanitize\n"
        "from package.service import load\n\n"
        "def run(value):\n"
        "    return sanitize(load(value))\n",
        encoding="utf-8",
    )
    (tmp_path / "security.py").write_text(
        "def sanitize(value):\n    return value.strip()\n",
        encoding="utf-8",
    )
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "package" / "service.py").write_text(
        "def load(value):\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "test_app.py").write_text(
        "from app import run\n\ndef test_run():\n    run('value')\n",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.py").write_text("password = 'not scanned'\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.py").write_text("secret = 1\n", encoding="utf-8")

    context = RepositoryContextBuilder(_settings(tmp_path)).build(tmp_path, "app.py")
    paths = {item.path for item in context.files}

    assert {"app.py", "security.py", "package/service.py", "test_app.py"} <= paths
    assert "unrelated.py" not in paths
    assert all("secret" not in item.to_dict().__repr__() for item in context.files)
    assert "security.py" in context.security_utilities
    assert context.sanitization_and_validation[0]["status"] == "candidate"
    assert context.files[0].analysis["cfg"]["functions"] == 1


def test_context_excludes_source_text_and_reports_analysis_shape(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "def safe(value):\n    return value\n",
        encoding="utf-8",
    )

    context = RepositoryContextBuilder(_settings(tmp_path)).build(tmp_path, "main.py")
    payload = context.to_dict()

    assert "return value" not in repr(payload)
    assert payload["target"] == "main.py"
    assert payload["files"][0]["analysis"]["available"] is True
    assert payload["files"][0]["analysis"]["dfg"]["nodes"] >= 0
    assert ".git" in payload["exclusions"]
