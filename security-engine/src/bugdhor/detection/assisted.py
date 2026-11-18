"""Incremental vulnerability identification during AI-assisted coding.

This module orchestrates the editor-facing analysis workflow without assuming
anything about the assistant or model that produced a change. Editors report
ordinary source changes; this layer receives source text and bounded change
regions. It never identifies an author or a model from the edit shape.

The twelve stages are reported individually. Optional model-internal stages
(SAE features and counterfactual interventions) are only marked ``completed``
when an explicitly validated provider is configured and returns a real result.
An absent, unvalidated, or failed provider is reported as ``skipped`` or
``unavailable`` and contributes no evidence. No stage is simulated.

The module is intentionally a library: publishing VS Code diagnostics is the
responsibility of the extension, which consumes :meth:`to_api_findings`.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from bugdhor.detection.classification import category_for_cwe, default_cwe
from bugdhor.detection.config import DEFAULT_DETECTION_CONFIG
from bugdhor.detection.engine import DetectionEngine
from bugdhor.detection.models import (
    ClaimKind,
    DetectionCoverage,
    DetectionResult,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidencePolarity,
    EvidenceType,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from bugdhor.parsing.functions import extract_functions
from bugdhor.parsing.parser import parse_source
from bugdhor.program_analysis.analysis import analyze_parsed
from bugdhor.program_analysis.taint import analyze_taint
from bugdhor.static.models import StaticAnalysisResult, StaticFinding, utc_now_iso

WORKFLOW_STAGES: tuple[str, ...] = (
    "change_detection",
    "region_identification",
    "syntax_analysis",
    "ast_analysis",
    "cfg_dfg_analysis",
    "taint_analysis",
    "static_analysis",
    "sae_features",
    "counterfactual_analysis",
    "evidence_fusion",
    "classification",
    "diagnostic_export",
)

_STAGE_COMPLETED = "completed"
_STAGE_SKIPPED = "skipped"
_STAGE_UNAVAILABLE = "unavailable"
_STAGE_FAILED = "failed"
_STAGE_CACHED = "cached"

_CONFIRMED_MIN_FAMILIES = 2
_CONFIRMED_MIN_EVIDENCE = 2
_SAE_MAX_STRENGTH = 0.25
_COUNTERFACTUAL_MAX_STRENGTH = 0.20


@dataclass(frozen=True, slots=True)
class ChangeRegion:
    """A zero-based, half-open line range originating from an editor change."""

    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if not isinstance(self.start_line, int) or self.start_line < 0:
            raise ValueError("change region start_line must be a non-negative integer")
        if not isinstance(self.end_line, int) or self.end_line < self.start_line:
            raise ValueError("change region end_line must not precede start_line")

    @property
    def line_count(self) -> int:
        return max(1, self.end_line - self.start_line)

    def overlaps(self, start_line: int, end_line: int) -> bool:
        return self.start_line <= end_line and start_line <= self.end_line

    def to_dict(self) -> dict[str, int]:
        return {"startLine": self.start_line, "endLine": self.end_line}


@dataclass(frozen=True, slots=True)
class StageRecord:
    """Honest status for one workflow stage."""

    stage: str
    status: str
    reason_code: str | None = None
    detail: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in WORKFLOW_STAGES and self.stage != "incremental_cache":
            raise ValueError(f"unknown workflow stage: {self.stage!r}")
        if self.status not in {
            _STAGE_COMPLETED,
            _STAGE_SKIPPED,
            _STAGE_UNAVAILABLE,
            _STAGE_FAILED,
            _STAGE_CACHED,
        }:
            raise ValueError(f"unknown stage status: {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "reasonCode": self.reason_code,
            "detail": self.detail,
            "data": dict(self.data),
        }


@dataclass(frozen=True, slots=True)
class SaeFeature:
    """One feature from a validated SAE artifact."""

    feature_id: str
    activation: float
    category: VulnerabilityCategory | None = None
    cwe: str | None = None
    line: int | None = None
    column: int | None = None
    limitation: str = ""

    def __post_init__(self) -> None:
        if not self.feature_id.strip():
            raise ValueError("SAE feature_id must not be empty")
        if not math.isfinite(self.activation):
            raise ValueError("SAE activation must be finite")
        if self.line is not None and self.line < 0:
            raise ValueError("SAE feature line must be non-negative")
        if self.column is not None and self.column < 0:
            raise ValueError("SAE feature column must be non-negative")
        if self.cwe is not None and category_for_cwe(self.cwe) is None:
            raise ValueError(f"unsupported SAE CWE: {self.cwe!r}")


@dataclass(frozen=True, slots=True)
class SaeFeaturePayload:
    """Result of an optional SAE stage. Absence is never a successful result."""

    available: bool
    validated: bool
    provider_id: str | None = None
    artifact_id: str | None = None
    features: tuple[SaeFeature, ...] = ()
    reason_code: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.available and self.validated and not self.artifact_id:
            raise ValueError("a validated SAE payload must identify its artifact")
        if not (self.available and self.validated) and self.features:
            raise ValueError("unvalidated SAE providers must not return features")

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "validated": self.validated,
            "providerId": self.provider_id,
            "artifactId": self.artifact_id,
            "featureCount": len(self.features),
            "reasonCode": self.reason_code,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class CounterfactualPayload:
    """Result of an optional counterfactual intervention stage."""

    available: bool
    configured: bool
    provider_id: str | None = None
    effect: float | None = None
    category: VulnerabilityCategory | None = None
    cwe: str | None = None
    line: int | None = None
    column: int | None = None
    reason_code: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.effect is not None and not math.isfinite(self.effect):
            raise ValueError("counterfactual effect must be finite")
        if not (self.available and self.configured) and self.effect is not None:
            raise ValueError("an unavailable counterfactual stage must not report an effect")

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "configured": self.configured,
            "providerId": self.provider_id,
            "effect": self.effect,
            "category": self.category.value if self.category is not None else None,
            "cwe": self.cwe,
            "reasonCode": self.reason_code,
            "limitations": list(self.limitations),
        }


@runtime_checkable
class SaeFeatureProvider(Protocol):
    """A provider with a locally validated SAE artifact and accessible activations."""

    provider_id: str
    artifact_id: str
    validated: bool

    def extract(
        self,
        *,
        source: str,
        path: str,
        language_id: str | None,
        regions: Sequence[ChangeRegion],
    ) -> SaeFeaturePayload: ...


@runtime_checkable
class CounterfactualProvider(Protocol):
    """A provider that can perform explicitly configured model interventions."""

    provider_id: str
    configured: bool

    def run(
        self,
        *,
        source: str,
        path: str,
        language_id: str | None,
        regions: Sequence[ChangeRegion],
    ) -> CounterfactualPayload: ...


@dataclass(frozen=True, slots=True)
class AssistedAnalysisRequest:
    """One incremental analysis request for changed editor source."""

    source: str
    path: str
    language_id: str | None = None
    document_uri: str | None = None
    changes: tuple[ChangeRegion, ...] = ()
    static_result: StaticAnalysisResult | Sequence[StaticFinding] | None = None
    run_sae: bool = False
    run_counterfactual: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("analysis source must not be empty")
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("analysis path must not be empty")
        if any(not isinstance(region, ChangeRegion) for region in self.changes):
            raise ValueError("changes must contain ChangeRegion entries")


@dataclass(frozen=True, slots=True)
class AssistedAnalysisResult:
    """Complete workflow output with per-stage coverage and evidence provenance."""

    path: str
    document_uri: str | None
    analysis_id: str
    detection: DetectionResult
    findings: tuple[VulnerabilityFinding, ...]
    stages: tuple[StageRecord, ...]
    changed_regions: tuple[ChangeRegion, ...]
    functions: tuple[str, ...]
    sae: SaeFeaturePayload | None = None
    counterfactual: CounterfactualPayload | None = None
    from_cache: bool = False

    def stage(self, name: str) -> StageRecord | None:
        for record in self.stages:
            if record.stage == name:
                return record
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysisId": self.analysis_id,
            "path": self.path,
            "documentUri": self.document_uri,
            "fromCache": self.from_cache,
            "changedRegions": [region.to_dict() for region in self.changed_regions],
            "functions": list(self.functions),
            "stages": [record.to_dict() for record in self.stages],
            "sae": self.sae.to_dict() if self.sae is not None else None,
            "counterfactual": (
                self.counterfactual.to_dict() if self.counterfactual is not None else None
            ),
            "detection": self.detection.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_api_findings(self) -> list[dict[str, Any]]:
        """Serialize findings in the shape consumed by the VS Code diagnostics layer."""
        return [finding.to_api_finding() for finding in self.findings]


def classify_confirmation(finding: VulnerabilityFinding) -> str:
    """Classify a finding as ``confirmed`` or ``potential`` from evidence only.

    Confirmation requires at least two independent evidence families with
    observation/inference claim kinds, a mapped category, and no recorded
    conflict or refutation. Model hypotheses (including SAE and counterfactual
    hypotheses) are intentionally excluded from confirmation.
    """

    if not finding.category.is_classified or finding.conflicts:
        return "potential"
    supports = [
        item
        for item in finding.evidence
        if item.polarity is EvidencePolarity.SUPPORTS
        and item.claim_kind in {ClaimKind.OBSERVATION, ClaimKind.INFERENCE}
    ]
    families = {item.family for item in supports}
    if len(supports) >= _CONFIRMED_MIN_EVIDENCE and len(families) >= _CONFIRMED_MIN_FAMILIES:
        return "confirmed"
    return "potential"


def _empty_detection(reason: str) -> DetectionResult:
    return DetectionResult(
        findings=(),
        coverage=DetectionCoverage(
            program_analysis=False,
            evidence_gaps=(reason,),
        ),
        generated_at=utc_now_iso(),
        config_hash=DEFAULT_DETECTION_CONFIG.config_hash(),
    )


def _sae_evidence(
    payload: SaeFeaturePayload,
    *,
    path: str,
    config_hash: str,
) -> tuple[EvidenceItem, ...]:
    if payload is None or not (payload.available and payload.validated and payload.artifact_id):
        return ()
    items: list[EvidenceItem] = []
    for feature in payload.features:
        category = feature.category or VulnerabilityCategory.UNKNOWN
        cwe = feature.cwe
        if cwe is None and category.is_classified:
            cwe = default_cwe(category)
        if cwe is not None and category.is_classified:
            mapped = category_for_cwe(cwe)
            if mapped is not None and mapped is not category:
                cwe = None
        line = feature.line or 0
        column = feature.column or 0
        location = EvidenceLocation(path, line, column, line, column + 1)
        items.append(
            EvidenceItem(
                evidence_id=f"sae:{payload.artifact_id}:{feature.feature_id}",
                evidence_type=EvidenceType.LLM,
                family=EvidenceFamily.LLM,
                claim_kind=ClaimKind.HYPOTHESIS,
                source=f"bugdhor.sae:{payload.artifact_id}",
                location=location,
                category=category,
                cwe=cwe,
                strength=min(_SAE_MAX_STRENGTH, abs(feature.activation)),
                reliability=0.4,
                rule_id=f"sae/{feature.feature_id}",
                title=f"SAE feature {feature.feature_id}",
                detail=(
                    f"Validated SAE artifact {payload.artifact_id} activated feature "
                    f"{feature.feature_id} ({feature.activation:.4f}). "
                    "This model-internal hypothesis is not independent verification."
                ),
                config_hash=config_hash,
                limitations=(
                    "SAE feature evidence is a model-internal hypothesis.",
                    feature.limitation
                    or "Feature-to-vulnerability association is validated separately.",
                ),
            )
        )
    return tuple(items)


def _counterfactual_evidence(
    payload: CounterfactualPayload,
    *,
    path: str,
    config_hash: str,
) -> tuple[EvidenceItem, ...]:
    if (
        payload is None
        or not (payload.available and payload.configured and payload.effect is not None)
    ):
        return ()
    category = payload.category or VulnerabilityCategory.UNKNOWN
    cwe = payload.cwe
    if cwe is not None and category.is_classified:
        mapped = category_for_cwe(cwe)
        if mapped is not None and mapped is not category:
            cwe = None
    line = payload.line or 0
    column = payload.column or 0
    location = EvidenceLocation(path, line, column, line, column + 1)
    return (
        EvidenceItem(
            evidence_id=f"counterfactual:{payload.provider_id}:{line}:{column}",
            evidence_type=EvidenceType.LLM,
            family=EvidenceFamily.LLM,
            claim_kind=ClaimKind.HYPOTHESIS,
            source=f"bugdhor.counterfactual:{payload.provider_id}",
            location=location,
            category=category,
            cwe=cwe,
            strength=min(_COUNTERFACTUAL_MAX_STRENGTH, abs(payload.effect)),
            reliability=0.3,
            title="Counterfactual intervention effect",
            detail=(
                f"Configured counterfactual intervention changed the model-internal "
                f"measure by {payload.effect:+.4f}. This is not a real-world causal effect."
            ),
            config_hash=config_hash,
            limitations=(
                "Counterfactual effects describe model-internal interventions.",
                *payload.limitations,
            ),
        ),
    )


def _fingerprint(value: Any) -> str:
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):
        text = repr(value)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class IncrementalAssistedAnalyzer:
    """Run the assisted-coding workflow with explicit, honest stage coverage."""

    engine: DetectionEngine = field(
        default_factory=lambda: DetectionEngine(expected_tools=()),
    )
    sae_provider: SaeFeatureProvider | None = None
    counterfactual_provider: CounterfactualProvider | None = None
    max_cached_files: int = 32
    _cache: dict[str, tuple[str, AssistedAnalysisResult]] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._cache = {}
        if self.max_cached_files < 1:
            raise ValueError("max_cached_files must be at least 1")

    def analyze(self, request: AssistedAnalysisRequest) -> AssistedAnalysisResult:
        """Analyze changed source and return annotated, deduplicated findings."""

        config_hash = self.engine.config_hash
        static_hash = _fingerprint(request.static_result)
        region_hash = _fingerprint([region.to_dict() for region in request.changes])
        cache_key = hashlib.sha256(
            "\x1f".join(
                (
                    request.path,
                    request.document_uri or "",
                    request.language_id or "",
                    config_hash,
                    region_hash,
                    static_hash,
                    str(request.run_sae),
                    str(request.run_counterfactual),
                    getattr(self.sae_provider, "artifact_id", "") or "",
                    getattr(self.counterfactual_provider, "provider_id", "") or "",
                    request.source,
                )
            ).encode("utf-8")
        ).hexdigest()
        cached = self._cache.get(cache_key)
        if cached is not None and cached[0] == config_hash:
            result = cached[1]
            stages = (*result.stages, StageRecord("incremental_cache", _STAGE_CACHED))
            cached_result = replace(result, stages=stages, from_cache=True)
            self._cache[cache_key] = (config_hash, cached_result)
            return cached_result

        changes = request.changes or ()
        stages: list[StageRecord] = [
            StageRecord(
                "change_detection",
                _STAGE_COMPLETED,
                data={
                    "regionCount": len(changes),
                    "origin": "editor_change_regions",
                    "authorAttribution": "none",
                },
            )
        ]

        try:
            parsed = parse_source(
                request.source,
                path=request.path,
                language=request.language_id,
            )
        except Exception as error:  # unsupported language or parser failure
            reason = f"{type(error).__name__}: {error}"
            stages.append(
                StageRecord(
                    "region_identification", _STAGE_UNAVAILABLE, "E_PARSE_UNAVAILABLE", reason
                )
            )
            for stage in WORKFLOW_STAGES[2:]:
                stages.append(
                    StageRecord(
                        stage,
                        _STAGE_UNAVAILABLE,
                        "E_PARSE_UNAVAILABLE",
                        "Syntax-aware analysis could not start.",
                    )
                )
            detection = _empty_detection("Syntax-aware analysis could not start.")
            result = AssistedAnalysisResult(
                path=request.path,
                document_uri=request.document_uri,
                analysis_id=cache_key[:16],
                detection=detection,
                findings=(),
                stages=tuple(stages),
                changed_regions=changes,
                functions=(),
            )
            self._remember(cache_key, config_hash, result)
            return result

        functions = self._changed_functions(parsed, changes)
        line_errors = getattr(parsed, "error_count", 0) or 0
        stages.append(
            StageRecord(
                "region_identification",
                _STAGE_COMPLETED if line_errors == 0 else _STAGE_FAILED,
                None if line_errors == 0 else "E_SYNTAX_ERRORS",
                None if line_errors == 0 else f"Parser reported {line_errors} diagnostic(s).",
                {"functions": list(functions), "regions": [region.to_dict() for region in changes]},
            )
        )
        stages.append(
            StageRecord(
                "syntax_analysis",
                _STAGE_COMPLETED if line_errors == 0 else _STAGE_FAILED,
                None if line_errors == 0 else "E_SYNTAX_ERRORS",
                data={"syntaxErrorCount": line_errors},
            )
        )
        stages.append(StageRecord("ast_analysis", _STAGE_COMPLETED))

        analysis = None
        try:
            analysis = analyze_parsed(parsed)
            stages.append(
                StageRecord(
                    "cfg_dfg_analysis",
                    _STAGE_COMPLETED,
                    data={"cfg": True, "dfg": True},
                )
            )
        except Exception as error:
            stages.append(
                StageRecord(
                    "cfg_dfg_analysis",
                    _STAGE_UNAVAILABLE,
                    "E_CFG_DFG_UNAVAILABLE",
                    f"{type(error).__name__}: {error}",
                )
            )

        taint = None
        if analysis is not None:
            try:
                taint = analyze_taint(
                    parsed,
                    config=self.engine.config.taint_config,
                    analysis=analysis,
                )
                stages.append(
                    StageRecord(
                        "taint_analysis",
                        _STAGE_COMPLETED,
                        data={"findingCount": len(getattr(taint, "findings", ()))},
                    )
                )
            except Exception as error:
                stages.append(
                    StageRecord(
                        "taint_analysis",
                        _STAGE_UNAVAILABLE,
                        "E_TAINT_UNAVAILABLE",
                        f"{type(error).__name__}: {error}",
                    )
                )
        else:
            stages.append(
                StageRecord(
                    "taint_analysis",
                    _STAGE_UNAVAILABLE,
                    "E_TAINT_UNAVAILABLE",
                    "Program analysis was unavailable.",
                )
            )

        stages.append(self._static_stage(request.static_result))
        sae, sae_stage = self._run_sae_stage(request, config_hash)
        stages.append(sae_stage)
        counterfactual, cf_stage = self._run_counterfactual_stage(request, config_hash)
        stages.append(cf_stage)

        extra_evidence = (
            _sae_evidence(sae, path=request.path, config_hash=config_hash)
            + _counterfactual_evidence(counterfactual, path=request.path, config_hash=config_hash)
        )
        try:
            detection = self.engine.detect(
                parsed,
                path=request.path,
                static=request.static_result,
                taint=taint,
                analysis=analysis,
                extra_evidence=extra_evidence,
            )
            stages.append(
                StageRecord(
                    "evidence_fusion",
                    _STAGE_COMPLETED,
                    data={"evidenceCount": sum(len(f.evidence) for f in detection.findings)},
                )
            )
        except Exception as error:
            detection = _empty_detection(f"Evidence fusion failed: {type(error).__name__}")
            stages.append(
                StageRecord(
                    "evidence_fusion",
                    _STAGE_FAILED,
                    "E_FUSION_FAILED",
                    f"{type(error).__name__}: {error}",
                )
            )

        findings = tuple(
            replace(finding, verification_status=classify_confirmation(finding))
            for finding in detection.findings
        )
        confirmed = sum(1 for finding in findings if finding.verification_status == "confirmed")
        stages.append(
            StageRecord(
                "classification",
                _STAGE_COMPLETED,
                data={
                    "findingCount": len(findings),
                    "confirmed": confirmed,
                    "potential": len(findings) - confirmed,
                },
            )
        )
        stages.append(
            StageRecord(
                "diagnostic_export",
                _STAGE_COMPLETED,
                data={"apiFindings": len(findings), "publishedByExtension": False},
            )
        )

        result = AssistedAnalysisResult(
            path=request.path,
            document_uri=request.document_uri,
            analysis_id=cache_key[:16],
            detection=detection,
            findings=findings,
            stages=tuple(stages),
            changed_regions=changes,
            functions=functions,
            sae=sae,
            counterfactual=counterfactual,
        )
        self._remember(cache_key, config_hash, result)
        return result

    @staticmethod
    def _changed_functions(parsed: Any, changes: Sequence[ChangeRegion]) -> tuple[str, ...]:
        if not changes:
            return ()
        names: list[str] = []
        for symbol in extract_functions(parsed):
            span = symbol.span
            start = getattr(span.start, "line", 0)
            end = getattr(span.end, "line", start)
            if any(region.overlaps(start, end) for region in changes):
                name = symbol.qualified_name or symbol.name
                if name and name not in names:
                    names.append(name)
        return tuple(names)

    @staticmethod
    def _static_stage(
        static_result: StaticAnalysisResult | Sequence[StaticFinding] | None,
    ) -> StageRecord:
        if static_result is None:
            return StageRecord(
                "static_analysis",
                _STAGE_UNAVAILABLE,
                "E_STATIC_TOOLS_NOT_CONFIGURED",
                "No static-analysis result was supplied; no tool output was inferred.",
            )
        if isinstance(static_result, StaticAnalysisResult):
            status = getattr(static_result, "status", None)
            status_value = getattr(status, "value", str(status)).lower()
            finding_count = len(getattr(static_result, "findings", ()))
            if status_value == "ok":
                return StageRecord(
                    "static_analysis", _STAGE_COMPLETED, data={"findingCount": finding_count}
                )
            return StageRecord(
                "static_analysis",
                _STAGE_UNAVAILABLE,
                "E_STATIC_TOOLS_PARTIAL",
                f"Static-analysis runner status: {status_value}.",
                {"findingCount": finding_count},
            )
        return StageRecord(
            "static_analysis",
            _STAGE_COMPLETED,
            data={"findingCount": len(tuple(static_result))},
        )

    def _run_sae_stage(
        self,
        request: AssistedAnalysisRequest,
        config_hash: str,
    ) -> tuple[SaeFeaturePayload | None, StageRecord]:
        if not request.run_sae:
            return None, StageRecord(
                "sae_features",
                _STAGE_SKIPPED,
                "E_SAE_NOT_CONFIGURED",
                "SAE feature extraction was not enabled for this request.",
            )
        provider = self.sae_provider
        if provider is None:
            return None, StageRecord(
                "sae_features",
                _STAGE_UNAVAILABLE,
                "E_SAE_PROVIDER_REQUIRED",
                "No SAE provider is attached to this analyzer.",
            )
        if not getattr(provider, "validated", False):
            return None, StageRecord(
                "sae_features",
                _STAGE_UNAVAILABLE,
                "E_SAE_ARTIFACT_NOT_VALIDATED",
                "The attached SAE artifact has not been validated.",
            )
        try:
            payload = provider.extract(
                source=request.source,
                path=request.path,
                language_id=request.language_id,
                regions=request.changes,
            )
        except Exception as error:
            return None, StageRecord(
                "sae_features",
                _STAGE_FAILED,
                "E_SAE_EXTRACTION_FAILED",
                f"{type(error).__name__}: {error}",
            )
        if not (payload.available and payload.validated):
            return payload, StageRecord(
                "sae_features",
                _STAGE_UNAVAILABLE,
                payload.reason_code or "E_SAE_UNAVAILABLE",
                "The SAE provider did not return validated features.",
                payload.to_dict(),
            )
        return payload, StageRecord(
            "sae_features",
            _STAGE_COMPLETED,
            data={**payload.to_dict(), "configHash": config_hash},
        )

    def _run_counterfactual_stage(
        self,
        request: AssistedAnalysisRequest,
        config_hash: str,
    ) -> tuple[CounterfactualPayload | None, StageRecord]:
        if not request.run_counterfactual:
            return None, StageRecord(
                "counterfactual_analysis",
                _STAGE_SKIPPED,
                "E_COUNTERFACTUAL_NOT_CONFIGURED",
                "Counterfactual analysis was not enabled for this request.",
            )
        provider = self.counterfactual_provider
        if provider is None or not getattr(provider, "configured", False):
            return None, StageRecord(
                "counterfactual_analysis",
                _STAGE_UNAVAILABLE,
                "E_COUNTERFACTUAL_PROVIDER_REQUIRED",
                "No configured counterfactual provider is attached to this analyzer.",
            )
        try:
            payload = provider.run(
                source=request.source,
                path=request.path,
                language_id=request.language_id,
                regions=request.changes,
            )
        except Exception as error:
            return None, StageRecord(
                "counterfactual_analysis",
                _STAGE_FAILED,
                "E_COUNTERFACTUAL_FAILED",
                f"{type(error).__name__}: {error}",
            )
        if not (payload.available and payload.configured):
            return payload, StageRecord(
                "counterfactual_analysis",
                _STAGE_UNAVAILABLE,
                payload.reason_code or "E_COUNTERFACTUAL_UNAVAILABLE",
                "The counterfactual provider did not return a result.",
                payload.to_dict(),
            )
        return payload, StageRecord(
            "counterfactual_analysis",
            _STAGE_COMPLETED,
            data={**payload.to_dict(), "configHash": config_hash},
        )

    def _remember(
        self, key: str, config_hash: str, result: AssistedAnalysisResult
    ) -> None:
        if key in self._cache:
            del self._cache[key]
        self._cache[key] = (config_hash, result)
        while len(self._cache) > self.max_cached_files:
            oldest = next(iter(self._cache))
            del self._cache[oldest]


__all__ = [
    "WORKFLOW_STAGES",
    "AssistedAnalysisRequest",
    "AssistedAnalysisResult",
    "ChangeRegion",
    "CounterfactualPayload",
    "CounterfactualProvider",
    "IncrementalAssistedAnalyzer",
    "SaeFeature",
    "SaeFeaturePayload",
    "SaeFeatureProvider",
    "StageRecord",
    "classify_confirmation",
]
