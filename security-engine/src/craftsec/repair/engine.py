"""Approval-gated automated vulnerability repair proposals."""

from __future__ import annotations

import ast
import hashlib
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from craftsec.models.adapter import ModelAdapter, validate_adapter
from craftsec.program_analysis.analysis import analyze_source
from craftsec.repair.context import RepositoryContext
from craftsec.repair.ranking import (
    CandidateDecision,
    MandatoryConstraints,
    PatchRanker,
    RankingPolicy,
)

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_SUPPORTED_CWES = {
    "CWE-89": "SQL injection",
    "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting",
    "CWE-22": "path traversal",
    "CWE-502": "unsafe deserialization",
}


@dataclass(frozen=True, slots=True)
class RepairConstraints:
    """Safety and scope limits applied before a candidate can be selected."""

    max_candidates: int = 3
    max_touched_files: int = 2
    require_syntax_valid: bool = True
    require_independent_verification: bool = True
    allowed_cwes: frozenset[str] = frozenset(_SUPPORTED_CWES)
    ranking_policy: RankingPolicy = field(default_factory=RankingPolicy)
    mandatory_constraints: MandatoryConstraints | None = None

    def __post_init__(self) -> None:
        if self.max_candidates < 1 or self.max_touched_files < 1:
            raise ValueError("repair candidate limits must be positive")


@dataclass(frozen=True, slots=True)
class RepairPrompt:
    text: str
    model_id: str
    model_version: str
    cwe: str | None
    prompt_hash: str


@dataclass(frozen=True, slots=True)
class CandidatePatch:
    candidate_id: str
    patch: str
    touched_files: tuple[str, ...]
    syntax_valid: bool
    security_score: float
    verification: Mapping[str, Any] | None
    metadata: Mapping[str, Any]

    @property
    def verified(self) -> bool:
        return bool(self.verification and self.verification.get("verdict") == "passed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidateId": self.candidate_id,
            "patch": self.patch,
            "touchedFiles": list(self.touched_files),
            "syntaxValid": self.syntax_valid,
            "securityScore": self.security_score,
            "verification": self.verification,
            "metadata": dict(self.metadata),
            "status": "verified" if self.verified else "pending_verification",
        }


@dataclass(frozen=True, slots=True)
class RepairProposal:
    """A proposal suitable for user review, never an applied repair."""

    selected: CandidatePatch | None
    candidates: tuple[CandidatePatch, ...]
    prompt: RepairPrompt
    history_id: str
    decisions: tuple[CandidateDecision, ...] = ()
    requires_approval: bool = True

    @property
    def secure(self) -> bool:
        return bool(self.selected and self.selected.verified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected": self.selected.to_dict() if self.selected else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "prompt": {
                "modelId": self.prompt.model_id,
                "modelVersion": self.prompt.model_version,
                "cwe": self.prompt.cwe,
                "promptHash": self.prompt.prompt_hash,
            },
            "historyId": self.history_id,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "requiresApproval": self.requires_approval,
            "secure": self.secure,
        }


@dataclass(slots=True)
class RepairHistory:
    """In-memory research history; callers may persist its serialized records."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def append(self, proposal: RepairProposal) -> None:
        self.records.append(proposal.to_dict())


class RepairPromptBuilder:
    """Construct a provenance-preserving repair prompt."""

    def build(
        self,
        *,
        source_text: str,
        file_path: str,
        finding: Mapping[str, Any],
        repository_context: RepositoryContext,
        security_evidence: Sequence[Mapping[str, Any]],
        adapter: ModelAdapter,
        constraints: RepairConstraints,
    ) -> RepairPrompt:
        cwe = finding.get("cwe")
        weakness = _SUPPORTED_CWES.get(cwe, "the reported vulnerability")
        evidence = "\n".join(
            f"- {item.get('type', 'evidence')}: {item.get('description', item.get('message', ''))}"
            for item in security_evidence
        ) or "- No additional security evidence was supplied."
        context = repository_context.to_dict()
        text = (
            "You are proposing a security repair. Return ONLY a unified diff; do not return "
            "markdown, explanations, or unrelated formatting.\n"
            f"Vulnerability: {weakness} ({cwe or 'CWE unavailable'})\n"
            f"Finding: {finding.get('findingId', finding.get('id', 'unknown'))}\n"
            f"Target file: {file_path}\n"
            "Security evidence:\n"
            f"{evidence}\n"
            "Repository context (metadata only):\n"
            f"{context}\n"
            "Constraints:\n"
            f"- Preserve unrelated code and touch at most {constraints.max_touched_files} files.\n"
            "- Do not weaken validation, escaping, authorization, or error handling.\n"
            "- The proposal is not secure until independent verification passes.\n"
            "Source file:\n"
            f"{source_text}\n"
        )
        return RepairPrompt(
            text=text,
            model_id=adapter.model_id,
            model_version=adapter.model_version,
            cwe=cwe,
            prompt_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )


class RepairEngine:
    """Generate and rank isolated repair proposals."""

    def __init__(
        self,
        *,
        prompt_builder: RepairPromptBuilder | None = None,
        history: RepairHistory | None = None,
    ) -> None:
        self.prompt_builder = prompt_builder or RepairPromptBuilder()
        self.history = history or RepairHistory()

    def propose(
        self,
        *,
        source_text: str,
        file_path: str,
        finding: Mapping[str, Any],
        repository_context: RepositoryContext,
        security_evidence: Sequence[Mapping[str, Any]] = (),
        adapter: ModelAdapter,
        constraints: RepairConstraints | None = None,
        generator: Callable[[RepairPrompt, int], str] | None = None,
        verification: Callable[[CandidatePatch], Mapping[str, Any]] | None = None,
        repository_sources: Mapping[str, str] | None = None,
    ) -> RepairProposal:
        constraints = constraints or RepairConstraints()
        validate_adapter(adapter)
        cwe = finding.get("cwe")
        if cwe is not None and cwe not in constraints.allowed_cwes:
            raise ValueError(f"unsupported repair CWE: {cwe}")
        prompt = self.prompt_builder.build(
            source_text=source_text,
            file_path=file_path,
            finding=finding,
            repository_context=repository_context,
            security_evidence=security_evidence,
            adapter=adapter,
            constraints=constraints,
        )
        candidates: list[CandidatePatch] = []
        for index in range(constraints.max_candidates):
            raw = (
                generator(prompt, index)
                if generator is not None
                else adapter.generate(
                    prompt.text,
                    generation_kwargs={"candidate_index": index},
                ).text
            )
            normalized = normalize_patch(raw)
            if normalized is None:
                continue
            candidate = self._evaluate(
                normalized,
                source_text=source_text,
                file_path=file_path,
                context=repository_context,
                repository_sources=repository_sources or {},
                candidate_id=f"candidate-{index + 1}",
                constraints=constraints,
                metadata={
                    "modelId": adapter.model_id,
                    "modelVersion": adapter.model_version,
                    "cwe": cwe,
                    "sourceSha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
                },
            )
            if candidate is None:
                continue
            if verification is not None:
                result = dict(verification(candidate))
                candidate = replace(
                    candidate,
                    verification=result,
                    metadata={**candidate.metadata, "evidence": result},
                )
            candidates.append(candidate)
        ranker = PatchRanker(
            constraints.ranking_policy,
            constraints.mandatory_constraints
            or MandatoryConstraints(
                require_syntax_valid=constraints.require_syntax_valid,
                require_independent_verification=constraints.require_independent_verification,
                max_touched_files=constraints.max_touched_files,
            ),
        )
        selected, decisions = ranker.rank(candidates, cwe=cwe)
        history_id = hashlib.sha256(
            f"{prompt.prompt_hash}:{file_path}:{len(candidates)}".encode()
        ).hexdigest()[:16]
        proposal = RepairProposal(
            selected=selected,
            candidates=tuple(candidates),
            prompt=prompt,
            history_id=history_id,
            decisions=decisions,
        )
        self.history.append(proposal)
        return proposal

    def _evaluate(
        self,
        patch: str,
        *,
        source_text: str,
        file_path: str,
        context: RepositoryContext,
        repository_sources: Mapping[str, str],
        candidate_id: str,
        constraints: RepairConstraints,
        metadata: Mapping[str, Any],
    ) -> CandidatePatch | None:
        touched = patch_paths(patch)
        allowed = {item.path for item in context.files}
        if (
            not touched
            or len(touched) > constraints.max_touched_files
            or not set(touched).issubset(allowed)
        ):
            return None
        with tempfile.TemporaryDirectory(prefix="craftsec-repair-") as directory:
            root = Path(directory)
            target = root / file_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source_text, encoding="utf-8")
            for relative, text in repository_sources.items():
                destination = root / relative
                if not destination.is_relative_to(root):
                    return None
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(text, encoding="utf-8")
            try:
                _apply_patch(root, patch)
            except ValueError:
                return None
            syntax_valid = _validate_tree(root, touched)
        if constraints.require_syntax_valid and not syntax_valid:
            return None
        score = _security_score(patch, context)
        return CandidatePatch(
            candidate_id=candidate_id,
            patch=patch,
            touched_files=tuple(touched),
            syntax_valid=syntax_valid,
            security_score=score,
            verification=None,
            metadata={
                **metadata,
                "verificationRequired": constraints.require_independent_verification,
                "patchSha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
            },
        )

def normalize_patch(raw: str) -> str | None:
    """Extract a unified diff and normalize line endings."""
    if not isinstance(raw, str):
        return None
    text = raw.replace("\r\n", "\n").strip()
    fenced = re.fullmatch(r"```(?:diff)?\s*\n(.*?)\n```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    if "--- " not in text or "+++ " not in text or "@@ " not in text:
        return None
    lines = text.splitlines()
    # Accept git-style headers (diff --git, index, etc.) before the first file header.
    start = None
    for idx, line in enumerate(lines):
        if line.startswith("--- "):
            start = idx
            break
    if start is None:
        return None
    if not any(line.startswith("+++ ") for line in lines[start:]):
        return None
    normalized = lines[start:]
    return "\n".join(normalized) + "\n"


def patch_paths(patch: str) -> tuple[str, ...]:
    paths: list[str] = []
    for line in patch.splitlines():
        if line.startswith("+++ "):
            value = line[4:].split("\t", 1)[0].split(" ", 1)[0]
            value = value.removeprefix("b/")
            if value != "/dev/null":
                paths.append(value)
    return tuple(dict.fromkeys(paths))


def _apply_patch(root: Path, patch: str) -> None:
    lines = patch.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            index += 1
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            raise ValueError("malformed unified diff headers")
        path = lines[index + 1][4:].split("\t", 1)[0].split(" ", 1)[0].removeprefix("b/")
        if path == "/dev/null":
            raise ValueError("file creation patches are not supported")
        target = root / path
        if not target.is_relative_to(root):
            raise ValueError("patch escapes workspace")
        original = target.read_text(encoding="utf-8").splitlines()
        output: list[str] = []
        cursor = 0
        index += 2
        while index < len(lines) and lines[index].startswith("@@ "):
            match = _HUNK_RE.match(lines[index])
            if match is None:
                raise ValueError("malformed patch hunk")
            start = int(match.group(1)) - 1
            output.extend(original[cursor:start])
            cursor = start
            index += 1
            while index < len(lines) and not lines[index].startswith(("@@ ", "--- ")):
                line = lines[index]
                if line.startswith(" "):
                    if cursor >= len(original) or original[cursor] != line[1:]:
                        raise ValueError("patch context does not match source")
                    output.append(original[cursor])
                    cursor += 1
                elif line.startswith("-"):
                    if cursor >= len(original) or original[cursor] != line[1:]:
                        raise ValueError("patch deletion does not match source")
                    cursor += 1
                elif line.startswith("+"):
                    output.append(line[1:])
                elif line != "\\ No newline at end of file":
                    raise ValueError("malformed patch line")
                index += 1
        output.extend(original[cursor:])
        target.write_text("\n".join(output) + ("\n" if output else ""), encoding="utf-8")


def _validate_tree(root: Path, touched: Sequence[str]) -> bool:
    for relative in touched:
        path = root / relative
        if path.suffix == ".py":
            try:
                ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                return False
        elif path.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                parsed = analyze_source(
                    path.read_text(encoding="utf-8"),
                    path=path,
                    language_id="javascript",
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                return False
            if parsed.parsed.has_syntax_errors:
                return False
    return True


def _security_score(patch: str, context: RepositoryContext) -> float:
    lowered = patch.lower()
    score = 0.0
    for token in ("parameter", "prepared", "escape", "sanitize", "allowlist", "resolve"):
        if token in lowered:
            score += 1.0
    for record in context.sanitization_and_validation:
        if record["file"] in patch:
            score += 0.5
    return score


__all__ = [
    "CandidatePatch",
    "RepairConstraints",
    "RepairEngine",
    "RepairHistory",
    "RepairPrompt",
    "RepairPromptBuilder",
    "RepairProposal",
    "normalize_patch",
    "patch_paths",
]
