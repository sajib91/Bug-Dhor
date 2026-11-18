"""Language detection and parser capability contracts.

A detected language is not the same as a parsed language, and a parsed language
is not the same as one with implemented CFG/DFG/taint layers. These tests keep
that distinction explicit for every language the extension can encounter.
"""

from __future__ import annotations

import pytest

from bugdhor.parsing import (
    DetectionSource,
    LanguageCapability,
    SupportedLanguage,
    UnsupportedLanguageError,
    detect_language,
    is_parser_available,
    language_capabilities,
    language_capability,
    parse_source,
    require_language,
    require_parser,
    tree_sitter_language,
)

_REQUESTED_LANGUAGES = {
    SupportedLanguage.PYTHON,
    SupportedLanguage.JAVASCRIPT,
    SupportedLanguage.TYPESCRIPT,
    SupportedLanguage.JAVA,
    SupportedLanguage.C,
    SupportedLanguage.CPP,
    SupportedLanguage.PHP,
    SupportedLanguage.GO,
    SupportedLanguage.RUST,
    SupportedLanguage.CSHARP,
    SupportedLanguage.RUBY,
    SupportedLanguage.KOTLIN,
    SupportedLanguage.SWIFT,
}

_PARSER_LANGUAGES = {
    SupportedLanguage.PYTHON,
    SupportedLanguage.JAVASCRIPT,
    SupportedLanguage.TYPESCRIPT,
}

_PROGRAM_ANALYSIS_LANGUAGES = {
    SupportedLanguage.PYTHON,
    SupportedLanguage.JAVASCRIPT,
}


def test_all_requested_languages_are_detectable() -> None:
    assert set(SupportedLanguage) == _REQUESTED_LANGUAGES


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("app.py", SupportedLanguage.PYTHON),
        ("app.js", SupportedLanguage.JAVASCRIPT),
        ("app.ts", SupportedLanguage.TYPESCRIPT),
        ("App.java", SupportedLanguage.JAVA),
        ("main.c", SupportedLanguage.C),
        ("main.cpp", SupportedLanguage.CPP),
        ("index.php", SupportedLanguage.PHP),
        ("main.go", SupportedLanguage.GO),
        ("main.rs", SupportedLanguage.RUST),
        ("Program.cs", SupportedLanguage.CSHARP),
        ("app.rb", SupportedLanguage.RUBY),
        ("Main.kt", SupportedLanguage.KOTLIN),
        ("main.swift", SupportedLanguage.SWIFT),
    ],
)
def test_requested_extensions_are_detected(path: str, expected: SupportedLanguage) -> None:
    detection = detect_language(path=path)

    assert detection.language is expected
    assert detection.source is DetectionSource.EXTENSION
    assert detection.detected is True


@pytest.mark.parametrize(
    ("language_id", "expected"),
    [
        ("python", SupportedLanguage.PYTHON),
        ("javascript", SupportedLanguage.JAVASCRIPT),
        ("typescriptreact", SupportedLanguage.TYPESCRIPT),
        ("java", SupportedLanguage.JAVA),
        ("c", SupportedLanguage.C),
        ("cpp", SupportedLanguage.CPP),
        ("php", SupportedLanguage.PHP),
        ("go", SupportedLanguage.GO),
        ("rust", SupportedLanguage.RUST),
        ("csharp", SupportedLanguage.CSHARP),
        ("ruby", SupportedLanguage.RUBY),
        ("kotlin", SupportedLanguage.KOTLIN),
        ("swift", SupportedLanguage.SWIFT),
    ],
)
def test_editor_language_ids_are_detected(language_id: str, expected: SupportedLanguage) -> None:
    detection = detect_language(language_id=language_id)

    assert detection.language is expected
    assert detection.source is DetectionSource.EXPLICIT


def test_capability_matrix_distinguishes_detection_parsing_and_program_analysis() -> None:
    capabilities = language_capabilities()

    assert {item.language for item in capabilities} == _REQUESTED_LANGUAGES
    assert all(isinstance(item, LanguageCapability) for item in capabilities)
    assert {item.language for item in capabilities if item.parser_available} == _PARSER_LANGUAGES
    assert {
        item.language for item in capabilities if item.program_analysis
    } == _PROGRAM_ANALYSIS_LANGUAGES
    for item in capabilities:
        payload = item.to_dict()
        assert payload["parserAvailable"] is item.parser_available
        assert payload["programAnalysis"] == list(item.program_analysis)
        if not item.parser_available:
            assert "no installed tree-sitter grammar" in item.note
        elif not item.program_analysis:
            assert "CFG, DFG, and taint layers are not implemented" in item.note


def test_require_language_allows_detected_but_unparsed_languages() -> None:
    detection = detect_language(path="App.java")

    assert require_language(detection, path="App.java") is SupportedLanguage.JAVA
    assert is_parser_available(SupportedLanguage.JAVA) is False
    with pytest.raises(UnsupportedLanguageError, match="no installed parser"):
        require_parser(detection, path="App.java")


def test_parse_source_uses_installed_grammars_only() -> None:
    python = parse_source("value = 1\n", path="app.py")
    javascript = parse_source("const value = 1;\n", path="app.js")
    typescript = parse_source("const value: number = 1;\n", path="app.ts")
    tsx = parse_source("const element = <div>ok</div>;\n", path="app.tsx")

    assert python.language is SupportedLanguage.PYTHON
    assert javascript.language is SupportedLanguage.JAVASCRIPT
    assert typescript.language is SupportedLanguage.TYPESCRIPT
    assert tsx.language is SupportedLanguage.TYPESCRIPT
    assert not any(parsed.has_syntax_errors for parsed in (python, javascript, typescript, tsx))

    with pytest.raises(UnsupportedLanguageError, match="no installed"):
        parse_source("package main\n", path="main.go")


def test_tsx_language_id_selects_the_jsx_grammar() -> None:
    base = tree_sitter_language(SupportedLanguage.TYPESCRIPT, path="component.ts")
    tsx = tree_sitter_language(
        SupportedLanguage.TYPESCRIPT,
        path="component.js",
        language_id="typescriptreact",
    )
    parsed = parse_source(
        "const element = <div>ok</div>;\n",
        path="component.js",
        language_id="typescriptreact",
    )

    assert base is not tsx
    assert parsed.language is SupportedLanguage.TYPESCRIPT
    assert parsed.has_syntax_errors is False


def test_capability_lookup_rejects_unknown_language_values() -> None:
    with pytest.raises(ValueError):
        language_capability("cobol")  # type: ignore[arg-type]
