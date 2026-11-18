"""Library entry points for the Bug Dhor vulnerability detection engine.

The engine fuses program-analysis evidence (AST, CFG, DFG, taint), normalized
external-tool findings (Semgrep, Bandit, CodeQL, Joern), and compatible LLM
hypotheses. It is intentionally not wired into the default HTTP pipeline: the
existing API keeps reporting the stage as unavailable until a deployment
chooses to supply analyzers and coverage metadata.

Typical use::

    engine = DetectionEngine()
    result = engine.detect_source(source, path="app.py")
    result.findings
    result.to_contract_dicts()

Coverage is explicit. A missing, failed, or timed-out analyzer never becomes a
clean scan. Pass ``expected_tools=()`` when a run genuinely does not expect
external tools.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from bugdhor.detection.config import DEFAULT_DETECTION_CONFIG, DetectionConfig
from bugdhor.detection.context import ContextAssessor
from bugdhor.detection.evidence import build_evidence
from bugdhor.detection.fusion import (
    DETECTION_LIMITATIONS,
    CalibrationProvider,
    fuse_evidence,
)
from bugdhor.detection.llm import LLMAnalyzer, LLMClaim, collect_llm_claims
from bugdhor.detection.models import (
    DetectionCoverage,
    DetectionResult,
)
from bugdhor.parsing.languages import UnsupportedLanguageError
from bugdhor.parsing.parser import ParsedSource, parse_source
from bugdhor.program_analysis.analysis import ProgramAnalysis, analyze_parsed
from bugdhor.program_analysis.taint import TaintAnalysis, analyze_taint
from bugdhor.static.models import StaticAnalysisResult, StaticFinding, utc_now_iso

_DEFAULT_EXPECTED_TOOLS = ("semgrep", "bandit", "codeql", "joern")


@dataclass(frozen=True, slots=True)
class DetectionEngine:
    """Deterministic evidence-fusion engine with explicit coverage accounting."""

    config: DetectionConfig = DEFAULT_DETECTION_CONFIG
    calibration: CalibrationProvider | None = None
    expected_tools: tuple[str, ...] = _DEFAULT_EXPECTED_TOOLS
    producer_version: str = "0.1.0"
    limitations: tuple[str, ...] = DETECTION_LIMITATIONS

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_tools",
            tuple(dict.fromkeys(tool.lower() for tool in self.expected_tools)),
        )

    def detect(
        self,
        parsed: ParsedSource,
        *,
        path: str | None = None,
        static: StaticAnalysisResult | Sequence[StaticFinding] | None = None,
        llm_analyzer: LLMAnalyzer | None = None,
        llm_claims: Sequence[LLMClaim] | None = None,
        analysis: ProgramAnalysis | None = None,
        taint: TaintAnalysis | None = None,
        finding_ids: Sequence[str] | None = None,
    ) -> DetectionResult:
        """Detect vulnerabilities in one parsed source file."""
        file_path = path or parsed.path or "<memory>"
        warnings: list[str] = []
        gaps: list[str] = []
        program_analysis_available = False

        if analysis is None:
            try:
                analysis = analyze_parsed(parsed)
                program_analysis_available = True
            except Exception as error:  # pragma: no cover - defensive boundary
                gaps.append(f"Program analysis (CFG/DFG) failed: {error}")
        else:
            program_analysis_available = True

        if taint is None:
            try:
                taint = analyze_taint(
                    parsed,
                    config=self.config.taint_config,
                    analysis=analysis,
                )
            except Exception as error:  # pragma: no cover - defensive boundary
                gaps.append(f"Taint analysis failed: {error}")

        claims: list[LLMClaim] = list(llm_claims or ())
        if llm_analyzer is not None:
            try:
                claims.extend(collect_llm_claims(llm_analyzer, parsed))
            except Exception as error:  # pragma: no cover - defensive boundary
                gaps.append(f"Compatible LLM analyzer failed: {error}")

        bundle = build_evidence(
            parsed=parsed,
            weights=self.config.weights,
            path=file_path,
            taint=taint,
            static=static,
            llm_claims=tuple(claims) if claims or llm_analyzer is not None else None,
            config_hash=self.config.config_hash(),
            llm_min_confidence=self.config.llm_min_confidence,
        )
        warnings.extend(bundle.warnings)
        gaps.extend(bundle.gaps)

        if parsed.error_count:
            gaps.append(
                f"Parsing produced {parsed.error_count} diagnostic(s); analysis "
                "coverage is incomplete."
            )

        reported = set(
            (
                *bundle.tools_available,
                *bundle.tools_missing,
                *bundle.tools_failed,
                *bundle.tools_timed_out,
            )
        )
        missing = list(bundle.tools_missing)
        for tool in self.expected_tools:
            if tool not in reported:
                missing.append(tool)
                gaps.append(
                    f"{tool} was expected but no availability or result was "
                    "reported; its findings are unknown."
                )

        coverage = DetectionCoverage(
            program_analysis=program_analysis_available,
            syntax_error_count=parsed.error_count,
            tools_available=bundle.tools_available,
            tools_missing=tuple(dict.fromkeys(missing)),
            tools_failed=bundle.tools_failed,
            tools_timed_out=bundle.tools_timed_out,
            llm_accepted=bundle.llm_accepted,
            llm_rejected=bundle.llm_rejected,
            evidence_gaps=tuple(dict.fromkeys(gaps)),
        )

        assessor = ContextAssessor(
            parsed=parsed,
            path=file_path,
            analysis=analysis,
            taint=taint,
            config_hash=self.config.config_hash(),
        )
        fusion = fuse_evidence(
            bundle.items,
            assessor=assessor,
            config=self.config,
            coverage=coverage,
            calibration=self.calibration,
            generated_at=utc_now_iso(),
        )
        warnings.extend(fusion.warnings)

        findings = fusion.findings
        if finding_ids is not None:
            requested = set(finding_ids)
            findings = tuple(item for item in findings if item.finding_id in requested)
            missing_ids = requested - {item.finding_id for item in findings}
            if missing_ids:
                warnings.append(
                    "Requested finding IDs were not present: " + ", ".join(sorted(missing_ids))
                )

        return DetectionResult(
            findings=findings,
            unclassified=fusion.unclassified,
            coverage=coverage,
            warnings=tuple(dict.fromkeys(warnings)),
            generated_at=utc_now_iso(),
            config_hash=self.config.config_hash(),
        )

    detect_parsed = detect

    def detect_source(
        self,
        source: str,
        *,
        path: str | Path | None = None,
        language: str | None = None,
        language_id: str | None = None,
        **kwargs: object,
    ) -> DetectionResult:
        """Parse and detect from source text."""
        parsed = parse_source(
            source,
            path=path,
            language=language,
            language_id=language_id,
        )
        return self.detect(parsed, path=str(path) if path is not None else None, **kwargs)

    def detect_file(
        self,
        path: str | Path,
        *,
        language_id: str | None = None,
        **kwargs: object,
    ) -> DetectionResult:
        """Read a UTF-8 file and detect vulnerabilities in it."""
        file_path = Path(path)
        source = file_path.read_text(encoding="utf-8")
        return self.detect_source(
            source,
            path=file_path,
            language_id=language_id,
            **kwargs,
        )

    @property
    def config_hash(self) -> str:
        return self.config.config_hash()


def detect_source(
    source: str,
    *,
    path: str | Path | None = None,
    language: str | None = None,
    language_id: str | None = None,
    config: DetectionConfig = DEFAULT_DETECTION_CONFIG,
    calibration: CalibrationProvider | None = None,
    expected_tools: tuple[str, ...] = _DEFAULT_EXPECTED_TOOLS,
    **kwargs: object,
) -> DetectionResult:
    """Convenience wrapper around :class:`DetectionEngine` for source text."""
    engine = DetectionEngine(
        config=config,
        calibration=calibration,
        expected_tools=expected_tools,
    )
    return engine.detect_source(
        source,
        path=path,
        language=language,
        language_id=language_id,
        **kwargs,
    )


__all__ = [
    "DETECTION_LIMITATIONS",
    "DetectionEngine",
    "UnsupportedLanguageError",
    "detect_source",
]
