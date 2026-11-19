
from tree_sitter import Language
import tree_sitter_python
import tree_sitter_javascript
import tree_sitter_java
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_go


# Supported language grammars
LANGUAGES = {
    "python": Language(tree_sitter_python.language()),
    "javascript": Language(tree_sitter_javascript.language()),
    "java": Language(tree_sitter_java.language()),
    "c": Language(tree_sitter_c.language()),
    "cpp": Language(tree_sitter_cpp.language()),
    "go": Language(tree_sitter_go.language()),
}


# File extension mapping
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".go": "go",
}


def detect_language(file_path: str) -> str | None:
    """
    Detect programming language from file extension.
    """

    from pathlib import Path

    extension = Path(file_path).suffix.lower()

    return EXTENSION_MAP.get(extension)


def get_language(language_name: str) -> Language:
    """
    Return the Tree-sitter language grammar.
    """

    if language_name not in LANGUAGES:
        raise ValueError(
            f"Unsupported language: {language_name}"
        )

    return LANGUAGES[language_name]
