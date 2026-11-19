from dataclasses import replace

import pytest

from bugdhor_ast.detection import BugDhorDetectionEngine
from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.explain.repair import (
    Patch,
    PatchApproval,
    PatchApprovalError,
    PatchConflictError,
    PatchFreshness,
    PatchHistory,
    PatchStaleError,
    PatchValidationError,
    RepairStatus,
    apply_patch,
    build_patch,
    check_patch_freshness,
    find_overlaps,
    recommend_repair,
    revert_patch,
    sha256_text,
    source_size,
    validate_patch,
    validate_patch_set,
)
from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine, taint_diagnostics

SOURCE = (
    "q = request.args.get('q')\n"
    "cursor.execute(\"SELECT * FROM users WHERE name = '\" + q + \"'\")\n"
)


def sql_recommendation(source=SOURCE):
    ast_payload = BugDhorASTEngine().analyze_source(source, "python")
    detection = BugDhorDetectionEngine().analyze_source(source, "python").to_dict()
    flow = FlowEngine().analyze_source(source, "python")
    flow_payload = flow.to_dict(FLOW_SECTIONS)

    payload = dict(detection)
    payload["diagnostics"] = list(detection["diagnostics"]) + [
        item.to_dict() for item in taint_diagnostics(flow)
    ]
    for section in FLOW_SECTIONS:
        payload[section] = flow_payload[section]
    payload["unresolved_references"] = flow_payload["unresolved_references"]
    for key in (
        "functions",
        "classes",
        "variables",
        "function_calls",
        "imports",
        "syntax_errors",
    ):
        payload[key] = ast_payload[key]

    finding = next(
        item
        for item in payload["diagnostics"]
        if item["rule_id"].endswith("-TAINT001")
    )
    return recommend_repair(
        finding, payload, source_code=source, file="sample.py"
    )


def test_build_patch_creates_reviewable_diff_and_round_trips(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    recommendation = sql_recommendation()

    patch = build_patch(recommendation, SOURCE, file=str(target))
    serialized = patch.to_dict()

    assert patch.patch_id.startswith("patch:")
    assert patch.source_size == source_size(SOURCE)
    assert patch.source_sha256 == sha256_text(SOURCE)
    assert patch.edits[0].original_code == SOURCE.splitlines()[1]
    assert patch.edits[0].proposed_code == recommendation.proposed_code
    assert "-cursor.execute(" in patch.unified_diff
    assert "+cursor.execute(" in patch.unified_diff
    assert patch.requires_approval is True
    assert Patch.from_dict(serialized).to_dict() == serialized

    serialized["unified_diff"] = ""
    with pytest.raises(ValueError, match="unified_diff"):
        validate_patch(serialized)


def test_build_patch_rejects_non_ready_recommendation(tmp_path):
    recommendation = replace(
        sql_recommendation(),
        strategy="unsupported",
        status=RepairStatus.UNSUPPORTED,
        proposed_code=None,
    )

    with pytest.raises(PatchValidationError, match="ready"):
        build_patch(recommendation, SOURCE, file=str(tmp_path / "sample.py"))


def test_freshness_check_detects_changed_source(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    patch = build_patch(sql_recommendation(), SOURCE, file=str(target))

    fresh = check_patch_freshness(patch, SOURCE)
    assert fresh.status is PatchFreshness.FRESH
    assert fresh.current_sha256 == sha256_text(SOURCE)

    changed = SOURCE.replace("WHERE name", "WHERE id")
    stale = check_patch_freshness(patch, changed)
    assert stale.status is PatchFreshness.STALE
    assert stale.current_sha256 == sha256_text(changed)


def test_apply_requires_explicit_matching_approval(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    patch = build_patch(sql_recommendation(), SOURCE, file=str(target))
    history = PatchHistory()

    with pytest.raises(PatchApprovalError, match="Explicit approval"):
        apply_patch(
            patch,
            PatchApproval(approved=False, confirmation=patch.patch_id),
            history=history,
        )
    with pytest.raises(PatchApprovalError, match="confirmation"):
        apply_patch(
            patch,
            PatchApproval(approved=True, confirmation="wrong"),
            history=history,
        )

    assert target.read_text(encoding="utf-8") == SOURCE
    assert history.entries == []


def test_apply_and_revert_restore_exact_source(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    recommendation = sql_recommendation()
    patch = build_patch(recommendation, SOURCE, file=str(target))
    history = PatchHistory()

    applied = apply_patch(
        patch,
        PatchApproval(approved=True, confirmation=patch.patch_id),
        history=history,
    )
    expected = (
        "q = request.args.get('q')\n"
        "cursor.execute('SELECT * FROM users WHERE name = ?', (q,))\n"
    )
    assert target.read_text(encoding="utf-8") == expected
    assert len(history.entries) == 1
    assert history.entries[0].entry_id == applied.entry.entry_id
    assert history.entries[0].reverted_at is None

    reverted = revert_patch(
        applied.entry,
        PatchApproval(approved=True, confirmation=patch.patch_id),
        history=history,
    )
    assert target.read_text(encoding="utf-8") == SOURCE
    assert reverted.restored_sha256 == sha256_text(SOURCE)
    assert history.entries[0].reverted_at is not None


def test_revert_refuses_to_overwrite_file_changed_after_apply(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    patch = build_patch(sql_recommendation(), SOURCE, file=str(target))
    history = PatchHistory()
    applied = apply_patch(
        patch,
        PatchApproval(approved=True, confirmation=patch.patch_id),
        history=history,
    )

    externally_changed = "q = 1\n" + SOURCE.splitlines()[1] + "\n"
    target.write_text(externally_changed, encoding="utf-8")

    with pytest.raises(PatchStaleError, match="changed after apply"):
        revert_patch(
            applied.entry,
            PatchApproval(approved=True, confirmation=patch.patch_id),
            history=history,
        )
    assert target.read_text(encoding="utf-8") == externally_changed
    assert history.entries[0].reverted_at is None


def test_overlapping_patches_are_detected(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    recommendation = sql_recommendation()
    first = build_patch(recommendation, SOURCE, file=str(target))
    second = build_patch(
        replace(
            recommendation,
            proposed_code="cursor.execute('SELECT 1')",
        ),
        SOURCE,
        file=str(target),
    )

    overlaps = find_overlaps([first, second])

    assert len(overlaps) == 1
    assert {overlaps[0].left_patch_id, overlaps[0].right_patch_id} == {
        first.patch_id,
        second.patch_id,
    }
    with pytest.raises(PatchConflictError, match="Overlapping patches"):
        validate_patch_set([first, second])


def test_non_overlapping_patch_set_is_allowed(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SOURCE, encoding="utf-8")
    patch = build_patch(sql_recommendation(), SOURCE, file=str(target))

    assert find_overlaps([patch]) == ()
    validate_patch_set([patch])
