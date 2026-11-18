"""Language detection, parser availability, and tree-sitter grammar registration.

Detection covers the project languages Bug-Dhor can identify from an editor
language id, a file extension, a shebang, or conservative content evidence.
Parsing is a separate capability: only languages with an installed tree-sitter
grammar are parsed. CFG, DFG, and taint support is narrower still and is reported
explicitly so an identified language is never presented as semantically analysed
without an implemented and tested layer.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language

from bugdhor.parsing.models import DetectionSource, LanguageDetection, SupportedLanguage

_LANGUAGE_BY_SUFFIX: Mapping[str, SupportedLanguage] = {
    ".py": SupportedLanguage.PYTHON,
    ".pyi": SupportedLanguage.PYTHON,
    ".pyw": SupportedLanguage.PYTHON,
    ".js": SupportedLanguage.JAVASCRIPT,
    ".jsx": SupportedLanguage.JAVASCRIPT,
    ".mjs": SupportedLanguage.JAVASCRIPT,
    ".cjs": SupportedLanguage.JAVASCRIPT,
    ".ts": SupportedLanguage.TYPESCRIPT,
    ".tsx": SupportedLanguage.TYPESCRIPT,
    ".mts": SupportedLanguage.TYPESCRIPT,
    ".cts": SupportedLanguage.TYPESCRIPT,
    ".java": SupportedLanguage.JAVA,
    ".c": SupportedLanguage.C,
    ".h": SupportedLanguage.C,
    ".cc": SupportedLanguage.CPP,
    ".cpp": SupportedLanguage.CPP,
    ".cxx": SupportedLanguage.CPP,
    ".hh": SupportedLanguage.CPP,
    ".hpp": SupportedLanguage.CPP,
    ".hxx": SupportedLanguage.CPP,
    ".php": SupportedLanguage.PHP,
    ".php3": SupportedLanguage.PHP,
    ".phtml": SupportedLanguage.PHP,
    ".go": SupportedLanguage.GO,
    ".rs": SupportedLanguage.RUST,
    ".cs": SupportedLanguage.CSHARP,
    ".rb": SupportedLanguage.RUBY,
    ".kt": SupportedLanguage.KOTLIN,
    ".kts": SupportedLanguage.KOTLIN,
    ".swift": SupportedLanguage.SWIFT,
}

_LANGUAGE_BY_ID: Mapping[str, SupportedLanguage] = {
    "py": SupportedLanguage.PYTHON,
    "python": SupportedLanguage.PYTHON,
    "python3": SupportedLanguage.PYTHON,
    "js": SupportedLanguage.JAVASCRIPT,
    "javascript": SupportedLanguage.JAVASCRIPT,
    "javascriptreact": SupportedLanguage.JAVASCRIPT,
    "jsx": SupportedLanguage.JAVASCRIPT,
    "node": SupportedLanguage.JAVASCRIPT,
    "nodejs": SupportedLanguage.JAVASCRIPT,
    "ts": SupportedLanguage.TYPESCRIPT,
    "tsx": SupportedLanguage.TYPESCRIPT,
    "typescript": SupportedLanguage.TYPESCRIPT,
    "typescriptreact": SupportedLanguage.TYPESCRIPT,
    "java": SupportedLanguage.JAVA,
    "c": SupportedLanguage.C,
    "cpp": SupportedLanguage.CPP,
    "c++": SupportedLanguage.CPP,
    "php": SupportedLanguage.PHP,
    "go": SupportedLanguage.GO,
    "golang": SupportedLanguage.GO,
    "rust": SupportedLanguage.RUST,
    "rustlang": SupportedLanguage.RUST,
    "cs": SupportedLanguage.CSHARP,
    "csharp": SupportedLanguage.CSHARP,
    "c#": SupportedLanguage.CSHARP,
    "rb": SupportedLanguage.RUBY,
    "ruby": SupportedLanguage.RUBY,
    "kt": SupportedLanguage.KOTLIN,
    "kts": SupportedLanguage.KOTLIN,
    "kotlin": SupportedLanguage.KOTLIN,
    "swift": SupportedLanguage.SWIFT,
}

_SHEBANG_PATTERNS: tuple[tuple[SupportedLanguage, re.Pattern[str]], ...] = (
    (
        SupportedLanguage.PYTHON,
        re.compile(r"^#!.*\bpython(?:\d+(?:\.\d+)*)?\b", re.IGNORECASE),
    ),
    (SupportedLanguage.JAVASCRIPT, re.compile(r"^#!.*\bnode(?:js)?\b", re.IGNORECASE)),
    (SupportedLanguage.PHP, re.compile(r"^#!.*\bphp\b", re.IGNORECASE)),
    (SupportedLanguage.RUBY, re.compile(r"^#!.*\bruby\b", re.IGNORECASE)),
)

_CONTENT_SIGNALS: Mapping[SupportedLanguage, tuple[re.Pattern[str], ...]] = {
    SupportedLanguage.PYTHON: (
        re.compile(
            r"^\s*(?:from\s+[\w.]+\s+import\s+|import\s+[\w.]+|def\s+\w+\s*\(|class\s+\w+)",
            re.MULTILINE,
        ),
        re.compile(
            r"^\s*(?:async\s+def|if\s+__name__\s*==\s*['\"]__main__['\"])",
            re.MULTILINE,
        ),
    ),
    SupportedLanguage.JAVASCRIPT: (
        re.compile(
            r"^\s*(?:const|let|var)\s+[\w$]+\s*=|"
            r"^\s*(?:export\s+)?(?:async\s+)?function\s+[\w$]*\s*\(|"
            r"^\s*(?:export\s+)?class\s+[\w$]+|"
            r"^\s*import\s+.+\s+from\s+['\"]",
            re.MULTILINE,
        ),
        re.compile(r"console\.log\s*\("),
    ),
    SupportedLanguage.TYPESCRIPT: (
        re.compile(r"^\s*(?:export\s+)?interface\s+\w+", re.MULTILINE),
        re.compile(r"^\s*(?:export\s+)?type\s+\w+\s*=", re.MULTILINE),
    ),
    SupportedLanguage.JAVA: (
        re.compile(r"^\s*public\s+(?:final\s+)?class\s+\w+", re.MULTILINE),
        re.compile(r"^\s*package\s+[\w.]+;", re.MULTILINE),
    ),
    SupportedLanguage.C: (
        re.compile(r"^\s*#include\s*<[^>]+>", re.MULTILINE),
        re.compile(r"^\s*int\s+main\s*\(", re.MULTILINE),
    ),
    SupportedLanguage.CPP: (
        re.compile(r"^\s*#include\s*<(?:iostream|vector|string)>", re.MULTILINE),
        re.compile(r"\bstd::\w+"),
    ),
    SupportedLanguage.PHP: (re.compile(r"^\s*<\?php\b", re.IGNORECASE),),
    SupportedLanguage.GO: (
        re.compile(r"^\s*package\s+\w+", re.MULTILINE),
        re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?\w+\s*\(", re.MULTILINE),
    ),
    SupportedLanguage.RUST: (
        re.compile(r"^\s*fn\s+main\s*\(", re.MULTILINE),
        re.compile(r"^\s*use\s+std::", re.MULTILINE),
    ),
    SupportedLanguage.CSHARP: (
        re.compile(r"^\s*using\s+System(?:[.;])", re.MULTILINE),
        re.compile(r"^\s*namespace\s+[\w.]+", re.MULTILINE),
    ),
    SupportedLanguage.RUBY: (
        re.compile(r"^\s*require\s+['\"]", re.MULTILINE),
        re.compile(r"^\s*def\s+\w+", re.MULTILINE),
    ),
    SupportedLanguage.KOTLIN: (
        re.compile(r"^\s*fun\s+main\s*\(", re.MULTILINE),
        re.compile(r"^\s*package\s+[\w.]+", re.MULTILINE),
    ),
    SupportedLanguage.SWIFT: (
        re.compile(r"^\s*import\s+Foundation\b", re.MULTILINE),
        re.compile(r"^\s*(?:@main\s+)?struct\s+\w+", re.MULTILINE),
    ),
}

_GRAMMAR_FACTORIES: Mapping[SupportedLanguage, Callable[[], Any]] = {
    SupportedLanguage.PYTHON: tree_sitter_python.language,
    SupportedLanguage.JAVASCRIPT: tree_sitter_javascript.language,
    SupportedLanguage.TYPESCRIPT: tree_sitter_typescript.language_typescript,
}

_TSX_GRAMMAR_FACTORY = tree_sitter_typescript.language_tsx

_PROGRAM_ANALYSIS_SUPPORT: Mapping[SupportedLanguage, tuple[str, ...]] = {
    SupportedLanguage.PYTHON: ("cfg", "dfg", "taint"),
    SupportedLanguage.JAVASCRIPT: ("cfg", "dfg", "taint"),
}


@dataclass(frozen=True, slots=True)
class LanguageCapability:
    """What the current installation can actually do for one language."""

    language: SupportedLanguage
    parser: str | None
    program_analysis: tuple[str, ...] = ()
    note: str = ""

    @property
    def parser_available(self) -> bool:
        return self.parser is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language.value,
            "parser": self.parser,
            "parserAvailable": self.parser_available,
            "programAnalysis": list(self.program_analysis),
            "note": self.note,
        }


def language_capability(language: SupportedLanguage) -> LanguageCapability:
    """Return installed parser and tested program-analysis support for a language."""
    if not isinstance(language, SupportedLanguage):
        language = SupportedLanguage(str(language).lower())
    parser = "tree_sitter" if language in _GRAMMAR_FACTORIES else None
    program_analysis = _PROGRAM_ANALYSIS_SUPPORT.get(language, ())
    note = ""
    if parser is None:
        note = "Detected language has no installed tree-sitter grammar; parsing is unavailable."
    elif not program_analysis:
        note = "Parsing is available; CFG, DFG, and taint layers are not implemented for this language."
    return LanguageCapability(
        language=language,
        parser=parser,
        program_analysis=program_analysis,
        note=note,
    )


def language_capabilities() -> tuple[LanguageCapability, ...]:
    """Return capability rows for every detectable language, including unsupported ones."""
    return tuple(language_capability(language) for language in SupportedLanguage)


def is_parser_available(language: SupportedLanguage) -> bool:
    return language_capability(language).parser_available


class UnsupportedLanguageError(ValueError):
    """Raised when a source cannot be parsed or cannot be identified."""

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        language_id: str | None = None,
        detail: str | None = None,
        language: SupportedLanguage | None = None,
    ) -> None:
        target = detail or "the source language is not supported"
        if path is not None:
            target = f"{target} for {Path(path)}"
        elif language_id:
            target = f"{target} for language id {language_id!r}"
        detected = ", ".join(item.value for item in SupportedLanguage)
        parsers = ", ".join(
            item.language.value for item in language_capabilities() if item.parser_available
        )
        message = (
            f"{target}. Supported languages for parsing: {parsers}. "
            f"Detectable languages: {detected}."
        )
        super().__init__(message)
        self.path = str(path) if path is not None else None
        self.language_id = language_id
        self.language = language
        self.parser_available = language is not None and is_parser_available(language)


@cache
def _tree_sitter_language(language: SupportedLanguage, tsx: bool) -> Language:
    if language is SupportedLanguage.TYPESCRIPT and tsx:
        return Language(_TSX_GRAMMAR_FACTORY())
    factory = _GRAMMAR_FACTORIES.get(language)
    if factory is None:
        raise UnsupportedLanguageError(
            language=language,
            detail=f"no installed tree-sitter grammar for {language.value!r}",
        )
    return Language(factory())


def tree_sitter_language(
    language: SupportedLanguage,
    *,
    path: str | Path | None = None,
    language_id: str | None = None,
) -> Language:
    """Return the cached tree-sitter grammar for an installed parser.

    TypeScript has two installed grammars. A ``.tsx`` path or a TSX language id
    selects the JSX-capable grammar; other TypeScript inputs use the base one.
    """
    if not isinstance(language, SupportedLanguage):
        language = SupportedLanguage(str(language).lower())
    tsx_hint = (language_id or "").strip().lower() in {"tsx", "typescriptreact"}
    tsx = language is SupportedLanguage.TYPESCRIPT and (
        tsx_hint or Path(path or "").suffix.lower() == ".tsx"
    )
    return _tree_sitter_language(language, tsx)


def detect_language(
    *,
    path: str | Path | None = None,
    text: str | None = None,
    language_id: str | None = None,
) -> LanguageDetection:
    """Identify one of the supported project languages.

    An explicit ``language_id`` is authoritative. Detection reports languages
    without installed parsers rather than hiding them; callers must consult
    :func:`language_capability` before claiming parse or semantic support.
    """
    if language_id is not None:
        normalized = language_id.strip().lower()
        language = _LANGUAGE_BY_ID.get(normalized)
        if language is None:
            return LanguageDetection(
                language=None,
                source=DetectionSource.EXPLICIT,
                detail=f"unsupported language id {language_id!r}",
            )
        return LanguageDetection(
            language=language,
            source=DetectionSource.EXPLICIT,
            detail=language_id,
        )

    if path is not None:
        suffix = Path(path).suffix.lower()
        language = _LANGUAGE_BY_SUFFIX.get(suffix)
        if language is not None:
            return LanguageDetection(
                language=language,
                source=DetectionSource.EXTENSION,
                detail=suffix,
            )
        if suffix:
            return LanguageDetection(
                language=None,
                source=DetectionSource.UNKNOWN,
                detail=f"unsupported source extension {suffix!r}",
            )

    if text is not None:
        first_line = text.splitlines()[0] if text.splitlines() else ""
        for language, pattern in _SHEBANG_PATTERNS:
            if pattern.search(first_line):
                return LanguageDetection(
                    language=language,
                    source=DetectionSource.SHEBANG,
                    detail=f"{language.value} shebang",
                )
        content_language = _detect_from_content(text)
        if content_language is not None:
            return LanguageDetection(
                language=content_language,
                source=DetectionSource.CONTENT,
                detail="syntax-pattern heuristic",
            )

    return LanguageDetection(
        language=None,
        source=DetectionSource.UNKNOWN,
        detail="no supported extension, language id, shebang, or syntax pattern",
    )


def require_language(
    detection: LanguageDetection, *, path: str | Path | None = None
) -> SupportedLanguage:
    """Return a detected language or raise a typed error."""
    if detection.language is None:
        raise UnsupportedLanguageError(path=path, detail=detection.detail)
    return detection.language


def require_parser(
    detection: LanguageDetection, *, path: str | Path | None = None
) -> SupportedLanguage:
    """Return a detected language only when a parser is installed."""
    language = require_language(detection, path=path)
    if not is_parser_available(language):
        raise UnsupportedLanguageError(
            path=path,
            language=language,
            detail=f"detected {language.value} but no installed parser is available",
        )
    return language


def _detect_from_content(text: str) -> SupportedLanguage | None:
    """Use conservative line-level evidence for extensionless source files."""
    sample = text[:8192]
    if not sample.strip():
        return None
    scores: dict[SupportedLanguage, int] = {}
    for language, patterns in _CONTENT_SIGNALS.items():
        score = sum(len(pattern.findall(sample)) for pattern in patterns)
        if score:
            scores[language] = score
    if not scores:
        return None
    best = max(scores.values())
    winners = [language for language, score in scores.items() if score == best]
    if len(winners) != 1:
        return None
    return winners[0]


__all__ = [
    "LanguageCapability",
    "UnsupportedLanguageError",
    "detect_language",
    "is_parser_available",
    "language_capabilities",
    "language_capability",
    "require_language",
    "require_parser",
    "tree_sitter_language",
]
