"""Source-code preprocessing for Bug Dhor.

Language detection covers the project's requested source languages. Parsing is
available only where an installed tree-sitter grammar exists. The package also
provides lossless normalization, exact source spans, function extraction,
syntax-aware chunking, and explicit capability reporting. Syntax errors are
reported as diagnostics and never converted into a silent success.
"""

from bugdhor.parsing.chunking import chunk_source
from bugdhor.parsing.functions import extract_functions
from bugdhor.parsing.languages import (
    LanguageCapability,
    UnsupportedLanguageError,
    detect_language,
    is_parser_available,
    language_capabilities,
    language_capability,
    require_language,
    require_parser,
    tree_sitter_language,
)
from bugdhor.parsing.metadata import (
    RepositoryFileMetadata,
    RepositoryMetadata,
    SkippedFile,
    extract_repository_metadata,
)
from bugdhor.parsing.models import (
    ChunkKind,
    CodeChunk,
    DetectionSource,
    FunctionKind,
    FunctionSymbol,
    LanguageDetection,
    LineEnding,
    NormalizedSource,
    ParseDiagnostic,
    SourceMap,
    SourcePoint,
    SourceSpan,
    SupportedLanguage,
    Token,
)
from bugdhor.parsing.normalization import normalize_source
from bugdhor.parsing.parser import ParsedSource, parse_source
from bugdhor.parsing.preprocess import PreprocessedSource, preprocess_file, preprocess_source
from bugdhor.parsing.tokens import tokenize_source

__all__ = [
    "ChunkKind",
    "CodeChunk",
    "DetectionSource",
    "FunctionKind",
    "FunctionSymbol",
    "LanguageCapability",
    "LanguageDetection",
    "LineEnding",
    "NormalizedSource",
    "ParseDiagnostic",
    "ParsedSource",
    "PreprocessedSource",
    "RepositoryFileMetadata",
    "RepositoryMetadata",
    "SkippedFile",
    "SourceMap",
    "SourcePoint",
    "SourceSpan",
    "SupportedLanguage",
    "Token",
    "UnsupportedLanguageError",
    "chunk_source",
    "detect_language",
    "extract_functions",
    "is_parser_available",
    "language_capabilities",
    "language_capability",
    "extract_repository_metadata",
    "normalize_source",
    "parse_source",
    "preprocess_file",
    "preprocess_source",
    "require_language",
    "require_parser",
    "tokenize_source",
    "tree_sitter_language",
]
