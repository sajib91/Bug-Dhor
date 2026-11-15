"""Bounded repository context for repository-aware repair.

The context contains metadata and analysis products, never source text. Files
are selected from the requested target, its imports, and narrowly related
tests/configuration/security utilities.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from craftsec.core.paths import (
    SourceFile,
    ensure_allowed_root,
    enumerate_workspace_sources,
    resolve_file,
)
from craftsec.core.settings import Settings
from craftsec.program_analysis.analysis import analyze_source

_RELATED_NAMES = re.compile(
    r"(test|spec|config|settings|security|auth|sanitize|validation|validator|utility|util)",
    re.IGNORECASE,
)
_IMPORT_RE = re.compile(
    r"""(?:import\s+[\w$]+(?:\s+as\s+[\w$]+)?|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])"""
)


@dataclass(frozen=True, slots=True)
class RepositoryContextFile:
    """Privacy-safe metadata and analysis for one related file."""

    path: str
    language: str | None
    size: int
    sha256: str
    role: str
    imports: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    interfaces: tuple[str, ...] = ()
    analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "size": self.size,
            "sha256": self.sha256,
            "role": self.role,
            "imports": list(self.imports),
            "symbols": list(self.symbols),
            "functions": list(self.functions),
            "dependencies": list(self.dependencies),
            "interfaces": list(self.interfaces),
            "analysis": self.analysis,
        }


@dataclass(frozen=True, slots=True)
class RepositoryContext:
    """Structured context supplied to a repository-aware repair engine."""

    root: str
    target: str
    files: tuple[RepositoryContextFile, ...]
    configuration_files: tuple[str, ...]
    security_utilities: tuple[str, ...]
    sanitization_and_validation: tuple[dict[str, Any], ...]
    exclusions: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "target": self.target,
            "files": [item.to_dict() for item in self.files],
            "configurationFiles": list(self.configuration_files),
            "securityUtilities": list(self.security_utilities),
            "sanitizationAndValidation": list(self.sanitization_and_validation),
            "exclusions": list(self.exclusions),
            "limitations": list(self.limitations),
        }


class RepositoryContextBuilder:
    """Build bounded repository context from an allowed workspace root."""

    def __init__(self, settings: Settings, *, max_files: int = 32) -> None:
        if max_files < 1:
            raise ValueError("max_files must be positive")
        self.settings = settings
        self.max_files = max_files

    def build(self, root: str | Path, target: str | Path) -> RepositoryContext:
        workspace = ensure_allowed_root(root, self.settings)
        target_path = self._resolve_target(workspace, target)
        discovered = enumerate_workspace_sources(workspace, self.settings)
        by_path = {item.path: item for item in discovered}
        selected: list[tuple[SourceFile, str]] = []
        seen: set[Path] = set()

        def add(path: Path, role: str) -> None:
            if path in seen or len(selected) >= self.max_files:
                return
            source = by_path.get(path)
            if source is None:
                return
            seen.add(path)
            selected.append((source, role))

        add(target_path, "target")
        queue = [target_path]
        while queue and len(selected) < self.max_files:
            current = queue.pop(0)
            source = by_path.get(current)
            if source is None:
                continue
            imports = self._read_imports(source.path)
            for imported in imports:
                resolved = self._resolve_import(current, imported, by_path)
                if resolved is not None and resolved not in seen:
                    add(resolved, "import")
                    queue.append(resolved)

        target_stem = target_path.stem.lower()
        for source in discovered:
            if len(selected) >= self.max_files:
                break
            name = source.path.name.lower()
            stem = source.path.stem.lower()
            if source.path in seen:
                continue
            if stem.startswith(("test_", "test-")) and target_stem in stem:
                add(source.path, "related_test")
            elif _RELATED_NAMES.search(name) and (
                target_stem in stem or source.path.parent == target_path.parent
            ):
                add(source.path, self._role_for_name(name))

        context_files = tuple(
            self._inspect_file(source, role, workspace) for source, role in selected
        )
        def relative(path: Path) -> str:
            return str(path.relative_to(workspace))
        config_files = tuple(
            relative(item.path)
            for item, _ in selected
            if self._role_for_name(item.path.name) == "configuration"
        )
        security_files = tuple(
            relative(item.path)
            for item, _ in selected
            if self._role_for_name(item.path.name) == "security_utility"
        )
        sanitization = tuple(
            record
            for item in context_files
            for record in self._sanitization_records(item)
        )
        limitations = ["Source text is excluded from repository context for privacy."]
        if len(selected) >= self.max_files:
            limitations.append("Context file limit reached; unrelated files were not scanned.")
        return RepositoryContext(
            root=str(workspace),
            target=relative(target_path),
            files=context_files,
            configuration_files=config_files,
            security_utilities=security_files,
            sanitization_and_validation=sanitization,
            exclusions=(
                ".git",
                "node_modules",
                "build",
                "dist",
                "virtual or symlinked files",
            ),
            limitations=tuple(limitations),
        )

    def _resolve_target(self, root: Path, target: str | Path) -> Path:
        return resolve_file(root, target, self.settings)

    @staticmethod
    def _read_imports(path: Path) -> tuple[str, ...]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ()
        if path.suffix == ".py":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                return ()
            values: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    values.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    values.append(node.module)
            return tuple(dict.fromkeys(values))
        return tuple(
            dict.fromkeys(match.group(1) or match.group(2) for match in _IMPORT_RE.finditer(text))
        )

    @staticmethod
    def _resolve_import(current: Path, imported: str, files: dict[Path, SourceFile]) -> Path | None:
        if imported.startswith("."):
            base = current.parent / imported
            candidates = [base, Path(f"{base}.py"), Path(f"{base}.js"), base / "__init__.py"]
        elif current.suffix == ".py":
            relative = Path(*imported.split("."))
            candidates = [current.parents[0] / relative.with_suffix(".py")]
        else:
            return None
        return next(
            (candidate.resolve() for candidate in candidates if candidate.resolve() in files),
            None,
        )

    @staticmethod
    def _role_for_name(name: str) -> str:
        lowered = name.lower()
        if lowered in {"makefile", "dockerfile"} or "config" in lowered or "settings" in lowered:
            return "configuration"
        if any(
            token in lowered
            for token in ("security", "auth", "sanitize", "validation", "validator")
        ):
            return "security_utility"
        if "test" in lowered or "spec" in lowered:
            return "test"
        return "related"

    def _inspect_file(self, source: SourceFile, role: str, root: Path) -> RepositoryContextFile:
        text = source.path.read_text(encoding="utf-8")
        imports = self._read_imports(source.path)
        symbols, functions, interfaces, dependencies = self._symbols(text, source.path)
        analysis = self._analysis(text, source)
        return RepositoryContextFile(
            path=str(source.path.relative_to(root)),
            language=source.language_id,
            size=source.size,
            sha256=self._sha256(text),
            role=role,
            imports=imports,
            symbols=symbols,
            functions=functions,
            dependencies=dependencies,
            interfaces=interfaces,
            analysis=analysis,
        )

    @staticmethod
    def _sha256(text: str) -> str:
        import hashlib

        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _symbols(
        text: str, path: Path
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        if path.suffix != ".py":
            names = tuple(
                dict.fromkeys(
                    re.findall(r"\b(?:class|interface|function)\s+([A-Za-z_$][\w$]*)", text)
                )
            )
            functions = tuple(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", text))
            return names, functions, (), functions
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return (), (), (), ()
        symbols: list[str] = []
        functions: list[str] = []
        interfaces: list[str] = []
        dependencies: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(node.name)
                dependencies.extend(
                    child.func.id
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                )
            if isinstance(node, ast.ClassDef):
                interfaces.extend(base.id for base in node.bases if isinstance(base, ast.Name))
        return (
            tuple(dict.fromkeys(symbols)),
            tuple(dict.fromkeys(functions)),
            tuple(dict.fromkeys(interfaces)),
            tuple(dict.fromkeys(dependencies)),
        )

    @staticmethod
    def _analysis(text: str, source: SourceFile) -> dict[str, Any] | None:
        if source.language_id not in {"python", "javascript", "typescript"}:
            return None
        try:
            result = analyze_source(
                text,
                path=source.path,
                language_id=source.language_id,
            )
        except (ValueError, RuntimeError, TypeError):
            return {"available": False}
        return {
            "available": True,
            "syntaxErrors": result.parsed.error_count,
            "cfg": {
                "blocks": len(result.module_cfg.blocks),
                "edges": len(result.module_cfg.edges),
                "functions": len(result.functions),
            },
            "dfg": {
                "nodes": len(result.module_dfg.nodes),
                "edges": len(result.module_dfg.edges),
            },
        }

    @staticmethod
    def _sanitization_records(item: RepositoryContextFile) -> tuple[dict[str, Any], ...]:
        if not any(
            token in (item.path + " " + " ".join(item.functions)).lower()
            for token in ("sanitize", "validate", "escape", "encode", "normalize")
        ):
            return ()
        return (
            {
                "file": item.path,
                "symbols": list(item.functions),
                "evidence": "name_match",
                "status": "candidate",
            },
        )

