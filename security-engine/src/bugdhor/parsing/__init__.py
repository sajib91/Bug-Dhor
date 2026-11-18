"""Source-code preprocessing for Bug Dhor.

Python and JavaScript are supported. The package provides language detection,
lossless normalization, tree-sitter tokenization, exact source spans, function
extraction, syntax-aware chunking, and repository metadata extraction. Syntax
errors are reported as diagnostics and never converted into a silent success.
"""

from bugdhor.parsing.chunking import chunk_source
from bugdhor.parsing.functions import extract_functions
from bugdhor.parsing.languages import (
    UnsupportedLanguageError,
    detect_language,
    require_language,
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
    "extract_repository_metadata",
    "normalize_source",
    "parse_source",
    "preprocess_file",
    "preprocess_source",
    "require_language",
    "tokenize_source",
    "tree_sitter_language",
]
