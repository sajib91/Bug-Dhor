import pytest

from bugdhor_ast.languages import (
    EXTENSION_MAP,
    LANGUAGES,
    detect_language,
    get_language,
)


@pytest.mark.parametrize(
    ("extension", "language"),
    sorted(EXTENSION_MAP.items()),
)
def test_detect_language_supported_extensions(
    extension, language
):
    assert detect_language(f"src/main{extension}") == language


@pytest.mark.parametrize(
    "file_path",
    [
        "src/MAIN.PY",
        "src/Component.JSX",
        "src/Main.JAVA",
    ],
)
def test_detect_language_is_case_insensitive(file_path):
    assert detect_language(file_path) is not None


@pytest.mark.parametrize(
    "file_path",
    [
        "Makefile",
        "notes.txt",
        "archive.tar.gz",
        "weird.",
        ".py",
    ],
)
def test_detect_language_unsupported_paths(file_path):
    assert detect_language(file_path) is None


@pytest.mark.parametrize("language", sorted(LANGUAGES))
def test_get_language_known_languages(language):
    assert get_language(language) is LANGUAGES[language]


def test_get_language_unknown_language():
    with pytest.raises(
        ValueError, match="Unsupported language: ruby"
    ):
        get_language("ruby")
