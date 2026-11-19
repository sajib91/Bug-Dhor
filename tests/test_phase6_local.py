import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bugdhor_ast.phase6 import (
    Phase6Session,
    apply_preview,
    build_preview,
    explain_selected,
    list_findings,
    list_history,
    revert_applied,
    suggest_selected,
    verify_applied,
)
from bugdhor_ast.phase6.service import Phase6Error

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
CLI = [sys.executable, "-m", "bugdhor_ast.phase6.cli"]

JS_SOURCE = "const q = req.query.user;\ndocument.body.innerHTML = q;\n"
PYTHON_SOURCE = "def f():\n    return missing_name\n"
JAVA_SOURCE = (
    "class C {\n"
    "  void f(HttpServletRequest request, Statement stmt) {\n"
    "    String q = request.getParameter(\"q\");\n"
    "    stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + q + \"'\");\n"
    "  }\n"
    "}\n"
)


def write_source(directory: Path, name: str, source: str) -> Path:
    path = directory / name
    path.write_text(source, encoding="utf-8")
    return path


def taint_index(source_path: Path) -> int:
    findings = list_findings(source_path)["findings"]
    matches = [
        item["index"] for item in findings if item["rule_id"].endswith("TAINT001")
    ]
    assert len(matches) == 1
    return matches[0]


def run_cli(*args: str, cwd: Path) -> tuple[int, dict, str, str]:
    environment = {**os.environ, "PYTHONPATH": SRC}
    completed = subprocess.run(
        [*CLI, *args],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return (
        completed.returncode,
        json.loads(completed.stdout),
        completed.stdout,
        completed.stderr,
    )


def test_session_round_trip_preserves_exact_state(tmp_path: Path):
    source = write_source(tmp_path, "sample.js", JS_SOURCE)
    session_path = tmp_path / "session.json"
    session = Phase6Session.load(session_path)
    assert session.path == session_path
    assert session.history.entries == []

    preview = build_preview(
        source, index=taint_index(source), session=session
    )
    assert preview["patch"] is not None
    session.save()

    loaded = Phase6Session.load(session_path)
    assert loaded.to_dict() == session.to_dict()
    assert loaded.get_patch(preview["patch"]["patch_id"]).to_dict() == preview["patch"]
    assert loaded.get_recommendation(preview["finding_id"]).to_dict() == preview["recommendation"]
    assert loaded.get_finding(preview["finding_id"]) == preview["finding"]
    assert session_path.stat().st_mode & 0o777 == 0o600


def test_session_load_rejects_invalid_schema(tmp_path: Path):
    path = tmp_path / "bad-session.json"
    path.write_text(json.dumps({"schema_version": "wrong"}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid keys"):
        Phase6Session.load(path)

    path.write_text(json.dumps({}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid keys"):
        Phase6Session.load(path)

    valid_empty = Phase6Session(path=path).to_dict()
    valid_empty["schema_version"] = "wrong"
    path.write_text(json.dumps(valid_empty), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        Phase6Session.load(path)


def test_preview_is_reviewable_and_never_writes_source(tmp_path: Path):
    source = write_source(tmp_path, "sample.js", JS_SOURCE)
    session = Phase6Session.load(tmp_path / "session.json")

    preview = build_preview(source, index=taint_index(source), session=session)

    assert source.read_text(encoding="utf-8") == JS_SOURCE
    assert preview["can_apply"] is True
    assert preview["requires_approval"] is True
    assert "innerHTML" in preview["patch"]["unified_diff"]
    assert "textContent" in preview["patch"]["unified_diff"]
    assert preview["explanation"]["schema_version"] == "1.0"
    assert preview["recommendation"]["requires_approval"] is True


def test_apply_verify_and_revert_round_trip(tmp_path: Path):
    source = write_source(tmp_path, "sample.js", JS_SOURCE)
    session = Phase6Session.load(tmp_path / "session.json")
    preview = build_preview(source, index=taint_index(source), session=session)
    patch_id = preview["patch"]["patch_id"]

    with pytest.raises(Phase6Error, match="confirmation"):
        apply_preview(
            source,
            patch_id=patch_id,
            confirmation="not-the-patch-id",
            session=session,
        )
    assert source.read_text(encoding="utf-8") == JS_SOURCE

    applied = apply_preview(
        source, patch_id=patch_id, confirmation=patch_id, session=session
    )
    assert "textContent" in source.read_text(encoding="utf-8")
    assert applied["entry"]["backup_code"] == JS_SOURCE

    verification = verify_applied(applied["entry"]["entry_id"], session)
    assert verification["status"] == "verified"
    assert verification["scope"] == "static_reanalysis"
    assert verification["summary"]["target_resolved"] is True

    reverted = revert_applied(
        applied["entry"]["entry_id"], confirmation=patch_id, session=session
    )
    before_source = next(
        item
        for item in verification["evidence"]["observed"]
        if item["id"] == "verify.source.before"
    )
    assert reverted["restored_sha256"] == before_source["value"]["sha256"]
    assert source.read_text(encoding="utf-8") == JS_SOURCE
    assert list_history(session)["entry_count"] == 1
    assert session.history.entries[0].reverted_at is not None
    with pytest.raises(Phase6Error, match="reverted"):
        verify_applied(applied["entry"]["entry_id"], session)


def test_revert_refuses_to_overwrite_external_change(tmp_path: Path):
    source = write_source(tmp_path, "sample.js", JS_SOURCE)
    session = Phase6Session.load(tmp_path / "session.json")
    preview = build_preview(source, index=taint_index(source), session=session)
    patch_id = preview["patch"]["patch_id"]
    applied = apply_preview(
        source, patch_id=patch_id, confirmation=patch_id, session=session
    )

    source.write_text("const edited = true;\n", encoding="utf-8")
    assert "textContent" not in source.read_text(encoding="utf-8")
    with pytest.raises(Phase6Error, match="changed after apply"):
        revert_applied(
            applied["entry"]["entry_id"], confirmation=patch_id, session=session
        )


def test_explain_and_suggest_cover_python_javascript_and_java(tmp_path: Path):
    cases = (
        ("sample.py", PYTHON_SOURCE),
        ("sample.js", JS_SOURCE),
        ("Sample.java", JAVA_SOURCE),
    )
    for name, text in cases:
        source = write_source(tmp_path, name, text)
        explanation = explain_selected(source, index=0)
        suggestion = suggest_selected(source, index=0)
        assert explanation["explanation"]["finding_id"] == explanation["finding_id"]
        assert explanation["explanation"]["location"]["start_line"] >= 1
        assert suggestion["recommendation"]["finding_id"] == explanation["finding_id"]
        assert "ai" in suggestion
        assert list_findings(source)["language"] == {
            "sample.py": "python",
            "sample.js": "javascript",
            "Sample.java": "java",
        }[name]


def test_suggest_supports_explicit_ai_config(tmp_path: Path):
    source = write_source(tmp_path, "sample.py", PYTHON_SOURCE)
    result = suggest_selected(
        source,
        index=0,
        ai_config=None,
    )
    assert result["ai"] is None

    from bugdhor_ast.explain.repair import AiRepairConfig

    with_ai = suggest_selected(
        source,
        index=0,
        ai_config=AiRepairConfig(enabled=False),
    )
    assert with_ai["ai"]["status"] == "disabled"


def test_cli_actions_emit_one_json_object_and_no_extra_text(tmp_path: Path):
    source = write_source(tmp_path, "sample.js", JS_SOURCE)
    session = tmp_path / "session.json"

    code, analyzed, stdout, stderr = run_cli(
        "analyze", "--file", str(source), cwd=tmp_path
    )
    assert code == 0 and analyzed["ok"] is True
    assert stdout.strip().startswith("{") and stdout.strip().endswith("}")
    assert json.loads(stdout) == analyzed
    assert stderr == ""

    code, explained, _, _ = run_cli(
        "explain", "--file", str(source), "--index", "1", cwd=tmp_path
    )
    assert code == 0 and explained["result"]["explanation"]["evidence"]

    code, suggested, _, _ = run_cli(
        "suggest", "--file", str(source), "--index", "1", cwd=tmp_path
    )
    assert code == 0 and suggested["result"]["recommendation"]["status"] == "ready"

    code, preview, _, _ = run_cli(
        "preview",
        "--file",
        str(source),
        "--index",
        "1",
        "--session",
        str(session),
        cwd=tmp_path,
    )
    assert code == 0 and preview["result"]["can_apply"] is True
    patch_id = preview["result"]["patch"]["patch_id"]

    code, denied, _, _ = run_cli(
        "apply",
        "--file",
        str(source),
        "--session",
        str(session),
        "--patch-id",
        patch_id,
        "--confirmation",
        patch_id,
        cwd=tmp_path,
    )
    assert code == 1 and denied["ok"] is False
    assert "write" in denied["error"]["message"].lower()
    assert source.read_text(encoding="utf-8") == JS_SOURCE

    code, applied, _, _ = run_cli(
        "apply",
        "--file",
        str(source),
        "--session",
        str(session),
        "--patch-id",
        patch_id,
        "--confirmation",
        patch_id,
        "--allow-source-write",
        cwd=tmp_path,
    )
    assert code == 0 and applied["ok"] is True

    code, history, _, _ = run_cli("history", "--session", str(session), cwd=tmp_path)
    assert code == 0 and history["result"]["entry_count"] == 1
    entry_id = history["result"]["history"]["entries"][0]["entry_id"]

    code, verification, _, _ = run_cli(
        "verify", "--session", str(session), "--entry-id", entry_id, cwd=tmp_path
    )
    assert code == 0 and verification["result"]["status"] == "verified"

    code, reverted, _, _ = run_cli(
        "revert",
        "--session",
        str(session),
        "--entry-id",
        entry_id,
        "--confirmation",
        patch_id,
        "--allow-source-write",
        cwd=tmp_path,
    )
    assert code == 0 and reverted["ok"] is True
    assert source.read_text(encoding="utf-8") == JS_SOURCE


def test_cli_error_envelopes(tmp_path: Path):
    code, payload, _, stderr = run_cli("unknown-action", cwd=tmp_path)
    assert code == 2
    assert payload["ok"] is False
    assert payload["error"]["type"] == "CliArgumentError"
    assert stderr == ""

    code, payload, _, _ = run_cli("analyze", cwd=tmp_path)
    assert code == 1
    assert payload["error"]["type"] == "Phase6Error"
    assert "--file" in payload["error"]["message"]
