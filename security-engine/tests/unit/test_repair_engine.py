from __future__ import annotations

from pathlib import Path

from craftsec.core.settings import Settings
from craftsec.repair import (
    MandatoryConstraints,
    RepairConstraints,
    RepairEngine,
    RepositoryContextBuilder,
    normalize_patch,
)


class FakeAdapter:
    model_id = "Qwen/Qwen2.5-Coder-7B-Instruct"
    model_version = "local-test"
    device = "cpu"
    supports_activations = False

    def __init__(self, outputs: list[str]) -> None:
        self.outputs = outputs

    def generate(self, prompt: str, *, generation_kwargs: dict[str, int]):
        del prompt
        return type(
            "Result",
            (),
            {"text": self.outputs[generation_kwargs["candidate_index"] % len(self.outputs)]},
        )()

    def unload(self) -> None:
        pass


def _context(tmp_path: Path):
    source = "def run(value):\n    return value\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / "security.py").write_text(
        "def sanitize(value):\n    return value.strip()\n",
        encoding="utf-8",
    )
    return source, RepositoryContextBuilder(
        Settings(workspace_roots=[tmp_path], max_file_bytes=100_000)
    ).build(tmp_path, "app.py")


def test_engine_generates_candidates_in_isolation_and_requires_verification(tmp_path: Path) -> None:
    source, context = _context(tmp_path)
    patch = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def run(value):\n"
        "-    return value\n"
        "+    return sanitize(value)\n"
    )
    engine = RepairEngine()

    proposal = engine.propose(
        source_text=source,
        file_path="app.py",
        finding={"findingId": "f-1", "cwe": "CWE-89"},
        repository_context=context,
        security_evidence=[{"type": "static", "description": "unsafe query construction"}],
        adapter=FakeAdapter([patch]),
        verification=lambda candidate: {"verdict": "passed", "checks": ["independent"]},
    )

    assert proposal.selected is not None
    assert proposal.secure is True
    assert proposal.selected.touched_files == ("app.py",)
    assert proposal.requires_approval is True
    assert proposal.history_id in proposal.history_id
    assert len(engine.history.records) == 1


def test_engine_rejects_unrelated_or_invalid_candidates_and_preserves_original(
    tmp_path: Path,
) -> None:
    source, context = _context(tmp_path)
    unrelated = (
        "--- a/unrelated.py\n+++ b/unrelated.py\n@@ -1,1 +1,1 @@\n"
        "-old\n+new\n"
    )
    invalid = (
        "```diff\n--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n"
        "-def run(value):\n+def run(value:\n```\n"
    )
    proposal = RepairEngine().propose(
        source_text=source,
        file_path="app.py",
        finding={"findingId": "f-2", "cwe": "CWE-79"},
        repository_context=context,
        adapter=FakeAdapter([unrelated, invalid]),
        constraints=RepairConstraints(max_candidates=2, require_independent_verification=False),
    )

    assert proposal.selected is None
    assert proposal.candidates == ()
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == source


def test_patch_normalization_accepts_fenced_diff_only() -> None:
    patch = "```diff\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n```"
    assert normalize_patch(patch).endswith("\n")
    assert normalize_patch("not a patch") is None


def test_ranker_selects_only_candidates_meeting_hard_constraints(tmp_path: Path) -> None:
    source, context = _context(tmp_path)
    candidates = [
        (
            "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
            " def run(value):\n-    return value\n+    return sanitize(value)\n"
        ),
        (
            "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
            " def run(value):\n-    return value\n+    return value.strip()\n"
        ),
    ]

    def verify(candidate):
        if candidate.candidate_id == "candidate-1":
            return {
                "verdict": "passed",
                "securityImprovement": True,
                "functionalTestPassRate": 0.5,
                "regressionTestsPassed": True,
                "cweRequirementsMet": True,
                "repositoryConsistencyScore": 1.0,
            }
        return {
            "verdict": "passed",
            "securityImprovement": True,
            "functionalTestPassRate": 1.0,
            "regressionTestsPassed": True,
            "cweRequirementsMet": True,
            "repositoryConsistencyScore": 0.8,
            "unnecessaryChangesRatio": 0.0,
        }

    proposal = RepairEngine().propose(
        source_text=source,
        file_path="app.py",
        finding={"findingId": "f-3", "cwe": "CWE-89"},
        repository_context=context,
        adapter=FakeAdapter(candidates),
        constraints=RepairConstraints(
            max_candidates=2,
            mandatory_constraints=MandatoryConstraints(
                require_security_improvement=True,
                require_functional_tests=True,
                require_regression_tests=True,
            ),
        ),
        verification=verify,
    )

    assert proposal.selected is not None
    assert proposal.selected.candidate_id == "candidate-2"
    first = proposal.decisions[0]
    assert first.accepted is False
    assert "functional-test threshold" in " ".join(first.reasons)
    assert proposal.decisions[1].score is not None
