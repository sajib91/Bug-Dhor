"""Operation orchestration over explicit pipeline stages.

Integrates real, available components (preprocessing/parsing, AST/CFG/DFG,
taint, configured static analyzers, vulnerability detection, evidence-grounded
explanation, repair workflow, independent verification) while reporting
unavailable research/runtime components explicitly without simulated outputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import traceback
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bugdhor.api.schemas import (
    CounterfactualRequest,
    CounterfactualResponse,
    CounterfactualResult,
    DetectionRequest,
    DetectionResponse,
    DetectionResult,
    ExplanationRequest,
    ExplanationResponse,
    ExplanationResult,
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    FeatureExtractionResult,
    FileInfo,
    Finding,
    PreventionRequest,
    PreventionResponse,
    PreventionResult,
    RecommendationProviderModel,
    RecommendationRequest,
    RecommendationResponse,
    RecommendationResult,
    RepairRequest,
    RepairResponse,
    RepairResult,
    ScanFileRequest,
    ScanFileResponse,
    ScanScope,
    ScanWorkspaceRequest,
    ScanWorkspaceResponse,
    StageReport,
    VerificationRequest,
    VerificationResponse,
    VerificationResult,
)
from bugdhor.config import API_VERSION
from bugdhor.core.capability_report import analysis_capabilities as build_analysis_capabilities
from bugdhor.core.errors import (
    AppError,
    ConflictAppError,
    InternalAppError,
    ResourceLimitAppError,
    ValidationAppError,
)
from bugdhor.core.jobs import CancellationToken, JobStore
from bugdhor.core.logging import get_logger
from bugdhor.core.paths import (
    FileSnapshot,
    SourceFile,
    ensure_allowed_root,
    enumerate_workspace_sources,
    inspect_explicit_workspace_sources,
    inspect_source_file,
    inspect_source_text,
    validate_selection,
)
from bugdhor.core.persistence import sanitize_for_persistence, write_json_private
from bugdhor.core.redaction import redact_text
from bugdhor.core.pipeline import (
    Pipeline,
    PipelineExecution,
    PipelineStage,
    PipelineStatus,
    StageContext,
    StageResult,
    StageStatus,
    UnavailableStage,
    combine_stage_results,
)
from bugdhor.core.safe_patch import canonical_relative_path
from bugdhor.core.settings import Settings
from bugdhor.recommendation.engine import SecureRecommendationEngine
from bugdhor.repair.context import RepositoryContextBuilder
from bugdhor.repair.workflow import RepairWorkflow
from bugdhor.sandbox.executor import ExecutionConsent
from bugdhor.verification.engine import IndependentVerificationEngine

DEFAULT_STAGE_DEFINITIONS: dict[str, tuple[str, str]] = {
    "static_evidence": (
        "E_ANALYZER_UNAVAILABLE",
        "No static analyzer adapter is implemented or enabled.",
    ),
    "detection": (
        "E_DETECTOR_UNAVAILABLE",
        "No evidence-fusion detector is implemented.",
    ),
    "explanation": (
        "E_EXPLANATION_UNAVAILABLE",
        "No explanation-graph builder is implemented.",
    ),
    "model_capture": (
        "E_MODEL_UNAVAILABLE",
        "No model runtime or activation capture is configured.",
    ),
    "sae_features": (
        "E_SAE_UNAVAILABLE",
        "No compatible SAE artifact is registered.",
    ),
    "feature_aggregation": (
        "E_FEATURE_UNAVAILABLE",
        "No feature aggregation implementation is available.",
    ),
    "counterfactual": (
        "E_COUNTERFACTUAL_UNAVAILABLE",
        "No counterfactual engine is implemented.",
    ),
    "steering_plan": (
        "E_STEERING_UNAVAILABLE",
        "No interaction-aware steering planner is implemented.",
    ),
    "steering_evaluation": (
        "E_STEERING_UNAVAILABLE",
        "No paired steering evaluation harness is implemented.",
    ),
    "repair": (
        "E_REPAIR_UNAVAILABLE",
        "No repository-aware repair generator is implemented.",
    ),
    "recommendation": (
        "E_RECOMMENDATION_UNAVAILABLE",
        "No secure code recommendation workflow is implemented.",
    ),
    "verification": (
        "E_VERIFICATION_UNAVAILABLE",
        "No independent verification implementation or adequate sandbox is available.",
    ),
}

OPERATION_STAGES: dict[str, tuple[str, ...]] = {
    # Real local analysis stages are executed inside orchestrator methods for scan/detection/explanation
    # to produce honest findings/evidence; unavailable research/model stages remain explicit.
    "scan_file": (),
    "scan_workspace": (),
    "detection_analyze": (),
    "explanation_analyze": (),
    "features_extract": ("model_capture", "sae_features", "feature_aggregation"),
    "counterfactual_analyze": ("counterfactual",),
    "prevention_steer": ("steering_plan", "steering_evaluation"),
    "repair_generate": ("repair",),
    "recommendation_generate": ("recommendation",),
    "verification_run": ("verification",),
}


def _progress_noop(
    stage: str,
    status: str,
    message: str,
    percent: float | None = None,
    data: Mapping[str, Any] | None = None,
) -> None:
    return None


ProgressCallback = Callable[[str, str, str, float | None, Mapping[str, Any] | None], None]


@dataclass(slots=True)
class _FileAnalysis:
    path: str
    uri: str
    language_id: str | None
    source_text: str
    source_sha256: str | None = None
    parsed_ok: bool = False
    program_analysis: Any = None
    taint: Any = None
    detection: Any = None
    parse_error: str | None = None
    analysis_error: str | None = None
    from_cache: bool = False


class _VerificationStage:
    name = "verification"
    available = True

    def __init__(self, sandbox_backend: str) -> None:
        self._engine = IndependentVerificationEngine(sandbox_backend=sandbox_backend)

    def run(self, context: StageContext) -> StageResult:
        payload = dict(context.payload)
        outcome = self._engine.verify(
            original_source=str(payload.get("sourceText") or ""),
            file_path=str(payload.get("filePath") or ""),
            language_id=payload.get("languageId"),
            patch=payload.get("patch"),
            patched_source=payload.get("patchedSource"),
            repair_id=payload.get("repairId"),
            cwe=payload.get("cwe"),
            finding_id=payload.get("findingId"),
            profile=str(payload.get("profile") or "static_only"),
            run_execution=bool(payload.get("runExecution")),
        )
        result = outcome.to_result(payload.get("repairId"))
        status = StageStatus.OK if outcome.analysis_available else StageStatus.PARTIAL
        reason = None if outcome.analysis_available else "E_VERIFICATION_INCONCLUSIVE"
        detail = None if outcome.analysis_available else outcome.classification
        return StageResult(
            stage=self.name,
            status=status,
            reason_code=reason,
            detail=detail,
            warnings=list(outcome.limitations),
            data={"verificationResult": result},
        )


class Orchestrator:
    """Select a pipeline for each operation and build typed responses."""

    _ANALYSIS_CACHE_VERSION = "v1"

    def __init__(
        self, settings: Settings, stages: Mapping[str, PipelineStage] | None = None
    ) -> None:
        self.settings = settings
        self.logger = get_logger("bugdhor.orchestrator")
        self.stages: dict[str, PipelineStage] = {
            name: UnavailableStage(name=name, reason_code=code, detail=detail)
            for name, (code, detail) in DEFAULT_STAGE_DEFINITIONS.items()
        }
        self.stages["verification"] = _VerificationStage(self.settings.sandbox_backend)
        self.stages["repair"] = type(
            "_RepairStage",
            (),
            {
                "name": "repair",
                "available": True,
                "run": lambda self, ctx: StageResult(stage="repair", status=StageStatus.OK),
            },
        )()
        self.stages["recommendation"] = type(
            "_RecommendationStage",
            (),
            {
                "name": "recommendation",
                "available": True,
                "run": lambda self, ctx: StageResult(stage="recommendation", status=StageStatus.OK),
            },
        )()
        # Bounded in-memory record of proposal patches. The local backend keeps
        # this only so a later explicit verification can resolve a repairId
        # without trusting a patch supplied by the client. Source snapshots are
        # never persisted to disk by this store.
        self._repair_store: dict[str, dict[str, Any]] = {}
        self._analysis_cache: dict[str, dict[str, Any]] = {}
        self._analysis_cache_dir = (
            Path(getattr(self.settings, "data_dir", Path(".bugdhor-data"))) / "cache" / "analysis"
        )
        try:
            self._analysis_cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        if stages:
            for name, stage in stages.items():
                if stage.name != name:
                    raise ValueError(f"Stage registry key {name!r} does not match stage.name.")
                self.stages[name] = stage

    def _analysis_cache_key(self, path: str, source_sha256: str, language_id: str | None) -> str:
        raw = json.dumps(
            {
                "v": self._ANALYSIS_CACHE_VERSION,
                "path": path,
                "sha256": source_sha256,
                "languageId": language_id or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _load_analysis_cache(self, key: str) -> dict[str, Any] | None:
        if key in self._analysis_cache:
            return self._analysis_cache[key]
        cache_file = self._analysis_cache_dir / f"{key}.json"
        try:
            if cache_file.exists():
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._analysis_cache[key] = data
                    return data
        except Exception:
            return None
        return None

    def _store_analysis_cache(self, key: str, data: dict[str, Any]) -> None:
        self._analysis_cache[key] = data
        try:
            cache_file = self._analysis_cache_dir / f"{key}.json"
            write_json_private(cache_file, sanitize_for_persistence(data))
        except Exception:
            # Cache persistence is best-effort; analysis correctness does not depend on it.
            pass

    def capabilities(self) -> dict[str, bool]:
        caps = {
            operation: all(getattr(self.stages[name], "available", False) for name in stage_names)
            for operation, stage_names in OPERATION_STAGES.items()
            if stage_names
        }
        # Integrated local analysis is available for scan/detection/explanation paths.
        caps["scan_file"] = True
        caps["scan_workspace"] = True
        caps["detection_analyze"] = True
        caps["explanation_analyze"] = True
        caps["repair_generate"] = True
        caps["recommendation_generate"] = True
        caps["verification_run"] = getattr(self.stages.get("verification"), "available", False)
        return caps

    def analysis_capabilities(self) -> dict[str, Any]:
        """Return parser, analyzer, and tool support with explicit gaps."""
        return build_analysis_capabilities()

    # ---- job/persistence helpers ----
    def _run_with_job(
        self,
        operation: str,
        request_id: str,
        job_store: JobStore | None,
        job_id: str | None,
        fn: Callable[[ProgressCallback, CancellationToken | None], Any],
    ) -> Any:
        if job_store is None or job_id is None:
            return fn(_progress_noop, None)
        token = job_store.token(job_id)

        def progress(
            stage: str,
            status: str,
            message: str,
            percent: float | None = None,
            data: Mapping[str, Any] | None = None,
        ) -> None:
            job_store.progress(job_id, stage, status, message, percent, data)
            self.logger.info(
                message,
                extra={"operation": operation, "request_id": request_id, "path": stage},
            )

        try:
            progress("operation", "running", f"Started {operation}", 0.0)
            result = fn(progress, token)
            payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
            job_store.complete(job_id, payload if isinstance(payload, dict) else {"value": payload})
            return result
        except ConflictAppError as exc:
            if getattr(exc, "code", "") == "E_CANCELLED":
                progress("operation", "cancelled", redact_text(exc), None)
            job_store.fail(
                job_id, {"code": exc.code, "detail": exc.detail, "statusCode": exc.status_code}
            )
            raise
        except AppError as exc:
            job_store.fail(
                job_id, {"code": exc.code, "detail": exc.detail, "statusCode": exc.status_code}
            )
            raise
        except Exception as exc:
            self.logger.exception(
                "Operation failed.", extra={"request_id": request_id, "operation": operation}
            )
            job_store.fail(
                job_id,
                {
                    "code": "E_INTERNAL",
                    "detail": "Internal engine error.",
                    "type": type(exc).__name__,
                },
            )
            raise

    def _persist_result(
        self, job_store: JobStore | None, operation: str, request_id: str, result: Any
    ) -> None:
        if job_store is None:
            return
        try:
            payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
            safe_payload = sanitize_for_persistence(
                payload if isinstance(payload, dict) else {"value": payload},
                full_payloads=getattr(job_store, "persist_full_payloads", False),
            )
            path = job_store.results_dir / f"{operation}-{request_id}.json"
            write_json_private(
                path,
                safe_payload,
                retention_days=getattr(job_store, "retention_days", 7),
            )
        except Exception:
            self.logger.warning(
                "Failed to persist operation result.",
                extra={"operation": operation, "request_id": request_id},
            )

    # ---- real analysis helpers ----
    def _run_static_analysis(
        self, root: Path, targets: list[Path], progress: ProgressCallback
    ) -> tuple[Any | None, list[StageReport], list[str]]:
        """Best-effort static analysis using available configured adapters. Never fabricated."""
        reports: list[StageReport] = []
        warnings: list[str] = []
        try:
            from bugdhor.static.bandit import BanditAdapter
            from bugdhor.static.runner import StaticAnalysisRunner
            from bugdhor.static.semgrep import SemgrepAdapter
        except Exception as exc:
            msg = f"Static-analysis adapters unavailable: {type(exc).__name__}"
            reports.append(
                StageReport(
                    stage="static_evidence",
                    status=StageStatus.UNAVAILABLE,
                    reason_code="E_ANALYZER_UNAVAILABLE",
                    detail=msg,
                )
            )
            return None, reports, [msg]
        adapters = []
        for cls in (SemgrepAdapter, BanditAdapter):
            try:
                if cls is SemgrepAdapter:
                    from bugdhor.static.semgrep import SemgrepConfig

                    adapters.append(
                        cls(
                            SemgrepConfig(
                                executable=self.settings.semgrep_path,
                                configs=tuple(self.settings.semgrep_configs),
                                require_local_rules=self.settings.semgrep_require_local_rules,
                            )
                        )
                    )
                else:
                    adapters.append(cls())
            except Exception:
                continue
        if not adapters:
            reports.append(
                StageReport(
                    stage="static_evidence",
                    status=StageStatus.UNAVAILABLE,
                    reason_code="E_ANALYZER_UNAVAILABLE",
                    detail="No static analyzer adapters could be initialized.",
                )
            )
            return None, reports, []
        progress(
            "static_evidence", "running", "Detecting/running configured static analyzers", None
        )
        try:
            runner = StaticAnalysisRunner(adapters)
            result = runner.scan(root, targets)
            warnings.extend(list(result.warnings))
            if result.status.value in {"ok", "partial"} and any(s.succeeded for s in result.scans):
                st = StageStatus.OK if result.status.value == "ok" else StageStatus.PARTIAL
            elif any(s.status.value == "unavailable" for s in result.scans) and not any(
                s.succeeded for s in result.scans
            ):
                st = StageStatus.UNAVAILABLE
            else:
                st = StageStatus.PARTIAL
            reasons = [s.reason_code for s in result.scans if s.reason_code]
            detail = (
                "; ".join(dict.fromkeys([s.detail for s in result.scans if s.detail]))[:500] or None
            )
            reports.append(
                StageReport(
                    stage="static_evidence",
                    status=st,
                    reason_code=reasons[0] if reasons and st != StageStatus.OK else None,
                    detail=detail,
                    warnings=list(result.warnings),
                    data={
                        "toolStatuses": {s.tool: s.status.value for s in result.scans},
                        "findingCount": len(result.findings),
                    },
                )
            )
            return result, reports, warnings
        except Exception as exc:
            msg = f"Static analysis failed: {type(exc).__name__}"
            reports.append(
                StageReport(
                    stage="static_evidence",
                    status=StageStatus.FAILED,
                    reason_code="E_ANALYZER_FAILED",
                    detail=msg,
                )
            )
            warnings.append(msg)
            return None, reports, warnings

    def _analyze_one_file(
        self,
        path: str,
        uri: str,
        source_text: str,
        language_id: str | None,
        progress: ProgressCallback,
    ) -> _FileAnalysis:
        source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        cache_key = self._analysis_cache_key(path, source_sha256, language_id)
        cached = self._load_analysis_cache(cache_key)
        if cached and cached.get("_kind") == "analysis-v1":
            fa = _FileAnalysis(
                path=path,
                uri=uri,
                language_id=cached.get("language_id") or language_id,
                source_text=source_text,
                source_sha256=source_sha256,
                parsed_ok=bool(cached.get("parsed_ok")),
                program_analysis=cached.get("program_analysis"),
                taint=cached.get("taint"),
                parse_error=cached.get("parse_error"),
                analysis_error=cached.get("analysis_error"),
                from_cache=True,
            )
            progress("preprocessing", "cached", f"Reused cached parse/analysis for {path}", None)
            return fa

        fa = _FileAnalysis(
            path=path,
            uri=uri,
            language_id=language_id,
            source_text=source_text,
            source_sha256=source_sha256,
        )
        try:
            progress("preprocessing", "running", f"Parsing and preprocessing {path}", None)
            from bugdhor.parsing.parser import parse_source

            parsed = parse_source(source_text, path=path, language_id=language_id)
            fa.language_id = fa.language_id or getattr(
                getattr(parsed, "language", None), "value", None
            )
            fa.parsed_ok = True
        except Exception as exc:
            fa.parse_error = f"{type(exc).__name__}: {redact_text(exc)}"
            self._store_analysis_cache(
                cache_key,
                {
                    "_kind": "analysis-v1",
                    "language_id": fa.language_id,
                    "parsed_ok": False,
                    "program_analysis": None,
                    "taint": None,
                    "parse_error": fa.parse_error,
                    "analysis_error": None,
                },
            )
            return fa
        try:
            progress(
                "program_analysis",
                "running",
                f"Building AST/CFG/DFG and taint analysis for {path}",
                None,
            )
            from bugdhor.program_analysis.analysis import analyze_parsed
            from bugdhor.program_analysis.taint import analyze_taint

            pa = analyze_parsed(parsed)
            fa.program_analysis = pa
            try:
                fa.taint = analyze_taint(parsed, analysis=pa)
            except Exception as exc:
                fa.analysis_error = f"taint analysis error: {type(exc).__name__}"
        except Exception as exc:
            fa.analysis_error = (
                f"program analysis error: {type(exc).__name__}: {redact_text(exc)}"
            )
        # Cache in-memory only for complex objects; avoid non-serializable disk persistence.
        self._analysis_cache[cache_key] = {
            "_kind": "analysis-v1",
            "language_id": fa.language_id,
            "parsed_ok": fa.parsed_ok,
            "program_analysis": fa.program_analysis,
            "taint": fa.taint,
            "parse_error": fa.parse_error,
            "analysis_error": fa.analysis_error,
        }
        return fa

    @staticmethod
    def _risk_summary(finding: Any) -> dict[str, Any] | None:
        """Assess one real detector finding with the unified risk engine.

        Evidence values and reliabilities come from the detector's measured
        evidence items. No missing observation is inferred, and the HTTP path
        supplies no calibration artifact, so the only score emitted is a
        ``heuristic_index``.
        """
        try:
            from bugdhor.detection.models import EvidenceType
            from bugdhor.risk.config import default_risk_config
            from bugdhor.risk.engine import FindingRiskInput, UnifiedRiskEngine
            from bugdhor.risk.models import (
                ClaimKind as RiskClaimKind,
            )
            from bugdhor.risk.models import (
                EvidenceObservation,
                EvidenceSource,
                ReliabilityEvidence,
            )
            from bugdhor.risk.models import (
                EvidencePolarity as RiskPolarity,
            )

            source_map = {
                EvidenceType.AST.value: EvidenceSource.AST,
                EvidenceType.CFG.value: EvidenceSource.CFG,
                EvidenceType.DFG.value: EvidenceSource.DFG,
                EvidenceType.TAINT.value: EvidenceSource.TAINT,
                EvidenceType.SEMGREP.value: EvidenceSource.STATIC_ANALYSIS,
                EvidenceType.BANDIT.value: EvidenceSource.STATIC_ANALYSIS,
                EvidenceType.CODEQL.value: EvidenceSource.STATIC_ANALYSIS,
                EvidenceType.JOERN.value: EvidenceSource.STATIC_ANALYSIS,
                EvidenceType.LLM.value: EvidenceSource.MODEL_PREDICTION,
            }
            observations: list[EvidenceObservation] = []
            for item in finding.evidence:
                source = source_map.get(item.evidence_type.value)
                if source is None:
                    continue
                observations.append(
                    EvidenceObservation(
                        source=source,
                        source_id=item.evidence_id or f"{source.value}-{len(observations) + 1}",
                        value=float(item.strength),
                        reliability=ReliabilityEvidence(
                            reported_confidence=float(item.reliability),
                            coverage=1.0,
                            run_status="complete",
                            basis=(
                                "detector_evidence_reported_reliability; "
                                "no validation metrics supplied"
                            ),
                        ),
                        claim_kind=RiskClaimKind(item.claim_kind.value),
                        polarity=RiskPolarity(item.polarity.value),
                        dependency_group=source.value,
                        normalized_from="detector_evidence_strength",
                        rationale=item.detail[:500] or item.title or finding.title,
                        limitations=tuple(item.limitations),
                    )
                )
            if not observations:
                return None
            result = UnifiedRiskEngine(default_risk_config()).assess(
                FindingRiskInput(
                    finding_id=finding.finding_id,
                    cwe=finding.cwe,
                    observations=tuple(observations),
                )
            )
            payload = result.to_dict()
            return {
                "index": payload["index"],
                "scoreKind": payload["scoreKind"],
                "band": payload["band"],
                "probability": payload["probability"],
                "probabilityKind": payload["probabilityKind"],
                "components": payload["components"],
                "uncertainty": {
                    "value": payload["uncertainty"]["value"],
                    "level": payload["uncertainty"]["level"],
                    "coverage": payload["uncertainty"]["coverage"],
                    "basis": payload["uncertainty"]["basis"],
                },
                "configHash": payload["configHash"],
                "evidenceCount": len(payload["evidence"]),
                "excludedEvidenceCount": len(payload["excludedEvidence"]),
                "explanation": payload["explanation"][:20],
            }
        except Exception:
            # Risk is an explicit enrichment. A failure must not discard the
            # underlying detector finding or turn into an invented score.
            return None

    @staticmethod
    def _analysis_available_from_reports(reports: list[StageReport]) -> bool:
        """True only when the program/detection analysis stage actually ran."""
        return any(
            report.stage in {"program_analysis", "detection"}
            and report.status in {StageStatus.OK, StageStatus.PARTIAL}
            for report in reports
        )

    def _run_detection(
        self, analyses: list[_FileAnalysis], static_result: Any | None, progress: ProgressCallback
    ) -> tuple[list[Finding], list[str], list[StageReport], list[str], dict[str, Any]]:
        findings: list[Finding] = []
        evidence_sources: list[str] = []
        stage_reports: list[StageReport] = []
        warnings: list[str] = []
        coverage: dict[str, Any] = {}
        try:
            from bugdhor.detection.engine import DetectionEngine
        except Exception as exc:
            stage_reports.append(
                StageReport(
                    stage="detection",
                    status=StageStatus.UNAVAILABLE,
                    reason_code="E_DETECTOR_UNAVAILABLE",
                    detail=f"Detection engine unavailable: {type(exc).__name__}",
                )
            )
            return findings, evidence_sources, stage_reports, warnings, coverage
        engine = DetectionEngine()
        progress("detection", "running", "Fusing evidence for vulnerability detection", None)
        try:
            # Pass static result once; detection engine treats it as external tool evidence/coverage.
            for idx, fa in enumerate(analyses):
                det = engine.detect_source(
                    fa.source_text,
                    path=fa.path,
                    language_id=fa.language_id,
                    taint=fa.taint,
                    static=static_result if idx == 0 else None,
                )
                fa.detection = det
                for vulnerability in det.findings:
                    fdict = vulnerability.to_api_finding()
                    risk_summary = self._risk_summary(vulnerability)
                    if risk_summary is not None:
                        fdict["riskAssessment"] = risk_summary
                    try:
                        findings.append(Finding(**fdict))
                    except Exception:
                        # keep honest minimal finding
                        try:
                            findings.append(
                                Finding(
                                    id=str(fdict.get("id", f"finding-{idx}")),
                                    message=str(fdict.get("message", "Potential vulnerability")),
                                    severity=str(fdict.get("severity", "info")),
                                    cwe=fdict.get("cwe"),
                                    rule_id=fdict.get("ruleId"),
                                    location=fdict["location"],
                                    evidence=fdict.get("evidence"),
                                    explanation=fdict.get("explanation"),
                                    source_references=fdict.get("sourceReferences", []),
                                    risk_assessment=risk_summary,
                                )
                            )
                        except Exception:
                            pass
                evidence_sources.extend(list(det.evidence_sources))
                warnings.extend(list(det.warnings))
                cov = det.coverage.to_dict() if hasattr(det, "coverage") else {}
                coverage[fa.path] = cov
            st = StageStatus.OK
            detail = None
            reason = None
            if not analyses:
                st = StageStatus.UNAVAILABLE
                reason = "E_DETECTOR_NO_INPUT"
                detail = "No analyzable input provided."
            stage_reports.append(
                StageReport(
                    stage="detection",
                    status=st,
                    reason_code=reason,
                    detail=detail,
                    warnings=warnings[:20],
                    data={"findingCount": len(findings), "coverage": coverage},
                )
            )
        except Exception as exc:
            stage_reports.append(
                StageReport(
                    stage="detection",
                    status=StageStatus.PARTIAL,
                    reason_code="E_DETECTOR_ERROR",
                    detail=f"{type(exc).__name__}: {redact_text(exc)}",
                )
            )
            warnings.append(f"detection error: {type(exc).__name__}")
        evidence_sources = list(dict.fromkeys(evidence_sources))
        return findings, evidence_sources, stage_reports, warnings, coverage

    def _build_scan_reports(
        self,
        analyses: list[_FileAnalysis],
        static_reports: list[StageReport],
        det_reports: list[StageReport],
        extra_warnings: list[str],
    ) -> tuple[list[StageReport], list[str]]:
        reports: list[StageReport] = []
        warnings: list[str] = list(extra_warnings)
        # preprocessing/program_analysis summary
        parsed = sum(1 for a in analyses if a.parsed_ok)
        tainted = sum(1 for a in analyses if a.taint is not None)
        pa_ok = sum(1 for a in analyses if a.program_analysis is not None)
        cached = sum(1 for a in analyses if getattr(a, "from_cache", False))
        if analyses and parsed == 0:
            reports.append(
                StageReport(
                    stage="preprocessing",
                    status=StageStatus.PARTIAL,
                    reason_code="E_PARSE_FAILED",
                    detail="Parsing failed for analyzed inputs.",
                    data={"files": len(analyses), "parsed": parsed, "cached": cached},
                )
            )
        else:
            reports.append(
                StageReport(
                    stage="preprocessing",
                    status=StageStatus.OK if analyses else StageStatus.UNAVAILABLE,
                    reason_code=None if analyses else "E_NO_INPUT",
                    detail=None,
                    data={"files": len(analyses), "parsed": parsed, "cached": cached},
                )
            )
        if pa_ok == 0 and analyses:
            reports.append(
                StageReport(
                    stage="program_analysis",
                    status=StageStatus.PARTIAL,
                    reason_code="E_PROGRAM_ANALYSIS_PARTIAL",
                    detail="AST/CFG/DFG/taint analysis unavailable or failed for inputs.",
                    data={
                        "files": len(analyses),
                        "programAnalysis": pa_ok,
                        "taint": tainted,
                        "cached": cached,
                    },
                )
            )
        else:
            reports.append(
                StageReport(
                    stage="program_analysis",
                    status=StageStatus.OK
                    if tainted == pa_ok and analyses
                    else (StageStatus.PARTIAL if analyses else StageStatus.UNAVAILABLE),
                    data={
                        "files": len(analyses),
                        "programAnalysis": pa_ok,
                        "taint": tainted,
                        "cached": cached,
                    },
                )
            )
        for a in analyses:
            if a.parse_error:
                warnings.append(f"{a.path}: {a.parse_error}")
            if a.analysis_error:
                warnings.append(f"{a.path}: {a.analysis_error}")
        reports.extend(static_reports)
        reports.extend(det_reports)
        return reports, list(dict.fromkeys(warnings))

    # ---- operations ----
    def scan_file(
        self,
        request: ScanFileRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> ScanFileResponse:
        def run(progress: ProgressCallback, token: CancellationToken | None) -> ScanFileResponse:
            if token:
                token.raise_if_cancelled()
            root = ensure_allowed_root(request.workspace_root, self.settings)
            snapshot = self._snapshot(root, request)
            self._validate_requested_selection(snapshot, request)
            progress(
                "file_snapshot",
                "ok",
                f"Inspected {snapshot.path}",
                10.0,
                {"size": snapshot.size, "sha256": snapshot.sha256},
            )
            analysis = self._analyze_one_file(
                str(snapshot.path),
                snapshot.uri,
                snapshot.text,
                request.language_id or snapshot.language_id,
                progress,
            )
            if token:
                token.raise_if_cancelled()
            static_result, static_reports, static_warnings = self._run_static_analysis(
                root, [snapshot.path], progress
            )
            if token:
                token.raise_if_cancelled()
            findings, evidence_sources, det_reports, det_warnings, coverage = self._run_detection(
                [analysis], static_result, progress
            )
            reports, warnings = self._build_scan_reports(
                [analysis], static_reports, det_reports, static_warnings + det_warnings
            )
            # prepend snapshot report
            reports = [
                StageReport(
                    stage="file_snapshot",
                    status=StageStatus.OK,
                    data={
                        "size": snapshot.size,
                        "sha256": snapshot.sha256,
                        "languageId": snapshot.language_id,
                    },
                )
            ] + reports
            combined = combine_stage_results(
                [
                    StageResult(
                        stage=r.stage,
                        status=r.status,
                        reason_code=r.reason_code,
                        detail=r.detail,
                        warnings=r.warnings,
                        data=r.data,
                    )
                    for r in reports
                ]
            )
            resp = ScanFileResponse(
                **self._base_fields_from_reports("scan_file", request_id, reports, warnings),
                findings=findings,
                scope=ScanScope(uris=[snapshot.uri]),
                files_scanned=1,
                analysis_available=self._analysis_available_from_reports(reports),
                file=FileInfo(
                    path=str(snapshot.path),
                    uri=snapshot.uri,
                    size=snapshot.size,
                    sha256=snapshot.sha256,
                    language_id=request.language_id or snapshot.language_id,
                ),
            )
            self._persist_result(job_store, "scan_file", request_id, resp)
            return resp

        return self._run_with_job("scan_file", request_id, job_store, job_id, run)

    def scan_workspace(
        self,
        request: ScanWorkspaceRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> ScanWorkspaceResponse:
        def run(
            progress: ProgressCallback, token: CancellationToken | None
        ) -> ScanWorkspaceResponse:
            if token:
                token.raise_if_cancelled()
            files: dict[str, SourceFile] = {}
            roots = []
            for folder in request.workspace_folders:
                root = ensure_allowed_root(folder.path, self.settings)
                roots.append(root)

            if request.file_paths is not None:
                # Explicit paths come from the editor's bounded repository
                # inventory. They still pass through the same containment,
                # media, and resource validation as ordinary workspace files.
                explicit_sources = inspect_explicit_workspace_sources(
                    roots, request.file_paths, self.settings, token
                )
                for source in explicit_sources:
                    files[source.uri] = source
            else:
                for root in roots:
                    for source in enumerate_workspace_sources(root, self.settings):
                        files[source.uri] = source
                        if len(files) > self.settings.max_workspace_files:
                            raise ResourceLimitAppError(
                                "The workspace exceeds the configured file scan limit.",
                                code="E_WORKSPACE_TOO_LARGE",
                            )
            progress(
                "workspace_snapshot",
                "ok",
                f"Discovered {len(files)} source files",
                5.0,
                {"fileCount": len(files)},
            )
            analyses: list[_FileAnalysis] = []
            static_results: list[Any] = []
            static_reports: list[StageReport] = []
            static_warnings: list[str] = []
            # analyze files and run static per root (best-effort)
            total = max(1, len(files))
            for i, (uri, src) in enumerate(files.items()):
                if token:
                    token.raise_if_cancelled()
                try:
                    text = src.path.read_text(encoding="utf-8")
                except Exception as exc:
                    analyses.append(
                        _FileAnalysis(
                            path=str(src.path),
                            uri=uri,
                            language_id=src.language_id,
                            source_text="",
                            parse_error=f"read failed: {type(exc).__name__}",
                        )
                    )
                else:
                    analyses.append(
                        self._analyze_one_file(str(src.path), uri, text, src.language_id, progress)
                    )
                if (i + 1) % 10 == 0 or i + 1 == total:
                    progress(
                        "program_analysis",
                        "running",
                        f"Analyzed {i + 1}/{total} files",
                        5.0 + 50.0 * (i + 1) / total,
                    )
            # static analysis per root once on discovered source files (bounded by discovered set)
            for root in roots:
                if token:
                    token.raise_if_cancelled()
                targets = [
                    Path(a.path)
                    for a in analyses
                    if a.path and (Path(a.path).exists() if a.path else False)
                ]
                # Bound static target fanout for very large repos to keep responsiveness; detection still runs on analyzed files.
                max_static_targets = 500
                if len(targets) > max_static_targets:
                    static_warnings.append(
                        f"Static analyzers limited to first {max_static_targets} discovered targets for responsiveness (of {len(targets)})."
                    )
                    targets = targets[:max_static_targets]
                sres, reps, warns = self._run_static_analysis(root, targets, progress)
                if sres is not None:
                    static_results.append(sres)
                static_reports.extend(reps)
                static_warnings.extend(warns)
            # combine static results if multiple roots
            combined_static = None
            if static_results:
                try:
                    from bugdhor.static.models import StaticAnalysisResult, ScanStatus

                    scans = tuple(s for r in static_results for s in getattr(r, "scans", ()))
                    findings_static = tuple(
                        f for r in static_results for f in getattr(r, "findings", ())
                    )
                    warnings_s = tuple(
                        w for r in static_results for w in getattr(r, "warnings", ())
                    )
                    statuses = [
                        getattr(r, "status", ScanStatus.UNAVAILABLE) for r in static_results
                    ]
                    status = (
                        ScanStatus.PARTIAL
                        if any(
                            getattr(s, "value", s)
                            in {"partial", "failed", "timeout", "unavailable"}
                            for s in statuses
                        )
                        else (statuses[0] if statuses else ScanStatus.UNAVAILABLE)
                    )
                    combined_static = StaticAnalysisResult(
                        status=status, findings=findings_static, scans=scans, warnings=warnings_s
                    )
                except Exception:
                    combined_static = static_results[0]
            if token:
                token.raise_if_cancelled()
            findings, evidence_sources, det_reports, det_warnings, coverage = self._run_detection(
                analyses, combined_static, progress
            )
            reports, warnings = self._build_scan_reports(
                analyses,
                static_reports
                or [
                    StageReport(
                        stage="static_evidence",
                        status=StageStatus.UNAVAILABLE,
                        reason_code="E_ANALYZER_UNAVAILABLE",
                        detail="No static analysis runs executed.",
                    )
                ],
                det_reports,
                static_warnings + det_warnings,
            )
            reports = [
                StageReport(
                    stage="workspace_snapshot",
                    status=StageStatus.OK,
                    data={"fileCount": len(files), "rootCount": len(roots)},
                )
            ] + reports
            resp = ScanWorkspaceResponse(
                **self._base_fields_from_reports("scan_workspace", request_id, reports, warnings),
                findings=findings,
                scope=ScanScope(uris=list(files.keys())),
                files_scanned=len(files),
                analysis_available=self._analysis_available_from_reports(reports),
            )
            self._persist_result(job_store, "scan_workspace", request_id, resp)
            return resp

        return self._run_with_job("scan_workspace", request_id, job_store, job_id, run)

    def detection_analyze(
        self,
        request: DetectionRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> DetectionResponse:
        def run(progress: ProgressCallback, token: CancellationToken | None) -> DetectionResponse:
            if token:
                token.raise_if_cancelled()
            snapshot = self._inspect(request)
            analysis = self._analyze_one_file(
                str(snapshot.path),
                snapshot.uri,
                snapshot.text,
                request.language_id or snapshot.language_id,
                progress,
            )
            root = ensure_allowed_root(request.workspace_root, self.settings)
            static_result, static_reports, static_warnings = self._run_static_analysis(
                root, [snapshot.path], progress
            )
            findings, evidence_sources, det_reports, det_warnings, coverage = self._run_detection(
                [analysis], static_result, progress
            )
            reports, warnings = self._build_scan_reports(
                [analysis], static_reports, det_reports, static_warnings + det_warnings
            )
            reports = [self._snapshot_report(snapshot)] + reports
            resp = DetectionResponse(
                **self._base_fields_from_reports(
                    "detection_analyze", request_id, reports, warnings
                ),
                result=DetectionResult(
                    analysis_available=self._analysis_available_from_reports(reports),
                    findings=findings,
                    evidence_sources=evidence_sources,
                    score_kind="heuristic" if findings else None,
                ),
            )
            self._persist_result(job_store, "detection_analyze", request_id, resp)
            return resp

        return self._run_with_job("detection_analyze", request_id, job_store, job_id, run)

    def explanation_analyze(
        self,
        request: ExplanationRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> ExplanationResponse:
        def run(progress: ProgressCallback, token: CancellationToken | None) -> ExplanationResponse:
            if token:
                token.raise_if_cancelled()
            snapshot = self._inspect(request)
            if request.finding is not None and request.finding.location.uri != snapshot.uri:
                raise ValidationAppError("The finding location does not match the inspected file.")
            analysis = self._analyze_one_file(
                str(snapshot.path),
                snapshot.uri,
                snapshot.text,
                request.language_id or snapshot.language_id,
                progress,
            )
            root = ensure_allowed_root(request.workspace_root, self.settings)
            static_result, static_reports, static_warnings = self._run_static_analysis(
                root, [snapshot.path], progress
            )
            findings, evidence_sources, det_reports, det_warnings, coverage = self._run_detection(
                [analysis], static_result, progress
            )
            finding_id = request.finding.id if request.finding else request.finding_id
            # Only a finding actually produced by this detection run can be
            # explained from evidence. A client-supplied id without a matching
            # backend finding is reported unavailable instead of being invented.
            detector_findings = (
                getattr(analysis.detection, "findings", ()) if analysis.detection else ()
            )
            target = next(
                (
                    item
                    for item in detector_findings
                    if getattr(item, "finding_id", None) == finding_id
                ),
                None,
            )
            graph = None
            claim_kinds: list[str] = []
            limitations: list[str] = []
            exp_status = StageStatus.UNAVAILABLE
            exp_reason = "E_EXPLANATION_NO_MATCHING_FINDING"
            exp_detail = "No backend finding matched the requested finding id."
            if target is None:
                limitations.append(
                    "Explanation is unavailable because no backend finding matched the "
                    "requested id; no evidence was synthesized."
                )
            else:
                finding_id = target.finding_id
                try:
                    progress(
                        "explanation", "running", "Building evidence-grounded explanation", None
                    )
                    from bugdhor.explain.engine import ExplainableVulnerabilityEngine

                    record = ExplainableVulnerabilityEngine().explain(target, taint=analysis.taint)
                    graph = record.to_dict()
                    claim_kinds = sorted(
                        {
                            str(entry.get("claimKind") or entry.get("status"))
                            for entry in record.why_detected
                            if entry.get("claimKind") or entry.get("status")
                        }
                    )
                    limitations = list(record.limitations)
                    if request.include_feature_evidence:
                        limitations.append(
                            "No model-internal feature or counterfactual evidence was "
                            "supplied; this graph contains only program and static evidence."
                        )
                    exp_status = StageStatus.OK
                    exp_reason = None
                    exp_detail = None
                except Exception as exc:
                    exp_status = StageStatus.PARTIAL
                    exp_reason = "E_EXPLANATION_ERROR"
                    exp_detail = f"{type(exc).__name__}: {redact_text(exc)}"
                    limitations.append(exp_detail)
                    graph = None
                    claim_kinds = []
            reports, warnings = self._build_scan_reports(
                [analysis], static_reports, det_reports, static_warnings + det_warnings
            )
            reports.append(
                StageReport(
                    stage="explanation",
                    status=exp_status,
                    reason_code=exp_reason,
                    detail=exp_detail,
                    data={"findingId": finding_id, "claimKinds": claim_kinds},
                    warnings=limitations[:10],
                )
            )
            reports = [self._snapshot_report(snapshot)] + reports
            resp = ExplanationResponse(
                **self._base_fields_from_reports(
                    "explanation_analyze", request_id, reports, warnings
                ),
                result=ExplanationResult(
                    analysis_available=exp_status == StageStatus.OK,
                    finding_id=finding_id,
                    graph=graph,
                    claim_kinds=claim_kinds,
                    limitations=limitations,
                ),
            )
            self._persist_result(job_store, "explanation_analyze", request_id, resp)
            return resp

        return self._run_with_job("explanation_analyze", request_id, job_store, job_id, run)

    # ---- stubs / existing operations preserved ----
    def features_extract(
        self,
        request: FeatureExtractionRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> FeatureExtractionResponse:
        def run(
            progress: ProgressCallback, token: CancellationToken | None
        ) -> FeatureExtractionResponse:
            snapshot = self._inspect(request)
            execution = self._execute_declared(
                "features_extract",
                request_id,
                self._payload(
                    snapshot,
                    request.language_id,
                    saeArtifactId=request.sae_artifact_id,
                    layer=request.layer,
                    hookPoint=request.hook_point,
                    aggregation=request.aggregation,
                ),
                progress,
                token,
            )
            combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
            resp = FeatureExtractionResponse(
                **self._base_fields("features_extract", request_id, combined),
                result=FeatureExtractionResult(
                    analysis_available=self._analysis_available(execution),
                    sae_artifact_id=request.sae_artifact_id,
                    features=[],
                    coverage=None,
                    aggregation=request.aggregation,
                ),
            )
            self._persist_result(job_store, "features_extract", request_id, resp)
            return resp

        return self._run_with_job("features_extract", request_id, job_store, job_id, run)

    def counterfactual_analyze(
        self,
        request: CounterfactualRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> CounterfactualResponse:
        def run(
            progress: ProgressCallback, token: CancellationToken | None
        ) -> CounterfactualResponse:
            snapshot = self._inspect(request)
            execution = self._execute_declared(
                "counterfactual_analyze",
                request_id,
                self._payload(
                    snapshot,
                    request.language_id,
                    findingId=request.finding_id,
                    interventions=[item.model_dump(mode="json") for item in request.interventions],
                    budget=request.budget,
                    seed=request.seed,
                ),
                progress,
                token,
            )
            combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
            resp = CounterfactualResponse(
                **self._base_fields("counterfactual_analyze", request_id, combined),
                result=CounterfactualResult(
                    analysis_available=self._analysis_available(execution),
                    effects=[],
                    validity=None,
                    budget=request.budget,
                ),
            )
            self._persist_result(job_store, "counterfactual_analyze", request_id, resp)
            return resp

        return self._run_with_job("counterfactual_analyze", request_id, job_store, job_id, run)

    def prevention_steer(
        self,
        request: PreventionRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> PreventionResponse:
        def run(progress: ProgressCallback, token: CancellationToken | None) -> PreventionResponse:
            snapshot = self._inspect(request)
            execution = self._execute_declared(
                "prevention_steer",
                request_id,
                self._payload(
                    snapshot,
                    request.language_id,
                    featureIndices=list(request.feature_indices),
                    strength=request.strength,
                    targetMetric=request.target_metric,
                ),
                progress,
                token,
            )
            combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
            resp = PreventionResponse(
                **self._base_fields("prevention_steer", request_id, combined),
                result=PreventionResult(
                    analysis_available=self._analysis_available(execution),
                    plan=None,
                    guardrails=[],
                    evaluation=None,
                    limitations=[],
                ),
            )
            self._persist_result(job_store, "prevention_steer", request_id, resp)
            return resp

        return self._run_with_job("prevention_steer", request_id, job_store, job_id, run)

    def repair_generate(
        self,
        request: RepairRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> RepairResponse:
        def run(progress: ProgressCallback, token: CancellationToken | None) -> RepairResponse:
            snapshot = self._inspect(request)
            if token:
                token.raise_if_cancelled()
            if request.finding.document_uri and request.finding.document_uri != snapshot.uri:
                raise ValidationAppError("The finding location does not match the inspected file.")
            repository_context = RepositoryContextBuilder(self.settings).build(
                request.workspace_root, request.file_path
            )
            consent_model = getattr(request, "execution_consent", None)
            consent = ExecutionConsent(
                granted=bool(getattr(consent_model, "granted", False)),
                allow_network=bool(getattr(consent_model, "allow_network", False)),
                allow_privileged=bool(getattr(consent_model, "allow_privileged", False)),
                allow_destructive=bool(getattr(consent_model, "allow_destructive", False)),
                source=str(getattr(consent_model, "source", "user")),
            )
            progress("repair", "running", "Running integrated repair/verification workflow", None)
            workflow = RepairWorkflow(sandbox_backend=self.settings.sandbox_backend)
            record = workflow.run(
                workspace_root=request.workspace_root,
                file_path=request.file_path,
                original_source=snapshot.text,
                language_id=request.language_id or snapshot.language_id,
                cwe=request.finding.cwe,
                finding_id=request.finding.finding_id,
                patch=getattr(request, "patch", None),
                generate=bool(getattr(request, "generate", False)),
                repository_context=repository_context,
                finding=request.finding.model_dump(mode="json"),
                execution_consent=consent,
                functional_enabled=bool(getattr(request, "run_functional_tests", True)),
                test_timeout_seconds=float(getattr(request, "test_timeout_seconds", 120.0)),
                project_test_command=getattr(request, "project_test_command", None),
            )
            repair_id = uuid.uuid4().hex
            record.metadata["repairId"] = repair_id
            workflow_dict = record.to_dict()
            analysis_available = bool(
                (record.security or {}).get("analysisAvailable")
                or (record.functional or {}).get("executed")
                or record.state
                in {"SECURITY_PASSED", "FUNCTIONAL_PASSED", "FULLY_VERIFIED", "FAILED"}
            )
            reports = [
                self._snapshot_report(snapshot),
                StageReport(
                    stage="repair",
                    status=StageStatus.OK if analysis_available else StageStatus.PARTIAL,
                    reason_code=None if analysis_available else "E_REPAIR_WORKFLOW_INCONCLUSIVE",
                    detail=record.state,
                    data={"workflowState": record.state},
                ),
            ]
            candidate = record.candidate or {}
            if candidate.get("patch"):
                self._store_repair(
                    repair_id,
                    {
                        "repairId": repair_id,
                        "patch": candidate["patch"],
                        "originalSource": snapshot.text,
                        "originalSourceSha256": snapshot.sha256,
                        "patchedSourceSha256": candidate.get("patchedSourceSha256"),
                        "filePath": request.file_path,
                        "cwe": request.finding.cwe,
                        "findingId": request.finding.finding_id,
                        "workflow": workflow_dict,
                        "state": record.state,
                    },
                )
            resp = RepairResponse(
                **self._base_fields_from_reports("repair_generate", request_id, reports, []),
                result=RepairResult(
                    analysis_available=analysis_available,
                    state=record.state,
                    patch=candidate.get("patch"),
                    touched_files=candidate.get("touchedFiles", []),
                    rationale=[
                        f"Integrated workflow state: {record.state}.",
                        "Patch is a proposal only; explicit user approval is required before application.",
                    ],
                    risk_notes=list((record.security or {}).get("limitations", []))[:10],
                    requires_approval=True,
                    metadata=record.metadata,
                    workflow=workflow_dict,
                ),
            )
            self._persist_result(job_store, "repair_generate", request_id, resp)
            return resp

        return self._run_with_job("repair_generate", request_id, job_store, job_id, run)

    def recommendation_generate(
        self,
        request: RecommendationRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> RecommendationResponse:
        """Generate, verify, rank, and explain a proposal-only secure recommendation.

        The backend never applies code. Generation provenance is recorded from
        non-secret provider metadata; steering is never claimed for a provider
        that has not supplied real D/E/F access and a real steering pipeline.
        """

        def run(
            progress: ProgressCallback, token: CancellationToken | None
        ) -> RecommendationResponse:
            snapshot = self._inspect(request)
            if token:
                token.raise_if_cancelled()
            if request.finding.document_uri and request.finding.document_uri != snapshot.uri:
                raise ValidationAppError("The finding location does not match the inspected file.")
            repository_context = RepositoryContextBuilder(self.settings).build(
                request.workspace_root, request.file_path
            )
            consent_model = getattr(request, "execution_consent", None)
            consent = ExecutionConsent(
                granted=bool(getattr(consent_model, "granted", False)),
                allow_network=bool(getattr(consent_model, "allow_network", False)),
                allow_privileged=bool(getattr(consent_model, "allow_privileged", False)),
                allow_destructive=bool(getattr(consent_model, "allow_destructive", False)),
                source=str(getattr(consent_model, "source", "user")),
            )
            provider_model: RecommendationProviderModel = request.provider
            provider = {
                "providerId": provider_model.provider_id or "",
                "modelId": provider_model.model_id or "",
                "capabilities": list(provider_model.capabilities),
                "hosted": provider_model.hosted,
            }
            steering = {
                "requested": provider_model.steering_requested,
                "validated": provider_model.steering_validated,
                # The HTTP contract carries no activation pipeline; only genuine
                # local callers can supply one, so API-driven steering stays off.
                "pipeline": None,
                "capabilities": list(provider_model.capabilities),
            }
            progress("recommendation", "running", "Running secure recommendation workflow", None)
            engine = SecureRecommendationEngine(sandbox_backend=self.settings.sandbox_backend)
            result = engine.recommend(
                workspace_root=request.workspace_root,
                file_path=request.file_path,
                finding=request.finding.model_dump(mode="json"),
                source_text=snapshot.text,
                candidates=list(request.candidates),
                repository_context=repository_context,
                security_evidence=list(request.security_evidence),
                provider=provider,
                steering=steering,
                execution_consent=consent,
                language_id=request.language_id or snapshot.language_id,
                test_timeout_seconds=float(request.test_timeout_seconds),
                project_test_command=request.project_test_command,
                functional_tests_enabled=bool(request.run_functional_tests),
            )
            result_dict = result.to_dict()
            # The prompt text is returned to the caller that supplied the source
            # snapshot so a configured generation provider can be driven from
            # the backend-built prompt. Stage data intentionally keeps only
            # prompt metadata; no credentials or hidden reasoning are exposed.
            prompt_payload = dict(result_dict["prompt"])
            prompt_payload["text"] = result.prompt.text
            reports = [self._snapshot_report(snapshot)]
            for record in result.stages:
                status_map = {
                    "completed": StageStatus.OK,
                    "skipped": StageStatus.SKIPPED,
                    "unavailable": StageStatus.UNAVAILABLE,
                    "failed": StageStatus.PARTIAL,
                }
                reason = "E_RECOMMENDATION_STAGE_FAILED" if record.status == "failed" else None
                reports.append(
                    StageReport(
                        stage=f"recommendation_{record.stage}",
                        status=status_map.get(record.status, StageStatus.UNAVAILABLE),
                        reason_code=reason,
                        detail=record.detail or None,
                        data={"stageStatus": record.status, **dict(record.data)},
                    )
                )
            warnings: list[str] = []
            if not result.verified:
                warnings.append(
                    "No candidate passed all mandatory verification gates; no patch is recommended."
                )
            resp = RecommendationResponse(
                **self._base_fields_from_reports(
                    "recommendation_generate", request_id, reports, warnings
                ),
                result=RecommendationResult(
                    analysis_available=result.state in {"recommended", "rejected"},
                    finding_id=result.finding_id,
                    cwe=result.cwe,
                    state=result.state,
                    original_code=result.original_source,
                    repaired_code=result_dict["repairedCode"],
                    selected=result_dict["selected"],
                    candidates=result_dict["candidates"],
                    prompt=prompt_payload,
                    stages=result_dict["stages"],
                    explanation=result_dict["explanation"],
                    requires_approval=True,
                    verified=result.verified,
                    metadata=result_dict["metadata"],
                ),
            )
            self._persist_result(job_store, "recommendation_generate", request_id, resp)
            return resp

        return self._run_with_job("recommendation_generate", request_id, job_store, job_id, run)

    def verification_run(
        self,
        request: VerificationRequest,
        request_id: str,
        job_store: JobStore | None = None,
        job_id: str | None = None,
    ) -> VerificationResponse:
        def run(
            progress: ProgressCallback, token: CancellationToken | None
        ) -> VerificationResponse:
            stored = self._resolve_repair(request.repair_id)
            snapshot = self._inspect(request)
            source_text = snapshot.text
            patch = request.patch
            patched_source = request.patched_source
            cwe = request.cwe
            finding_id = request.finding_id
            if stored is not None:
                # A repairId is resolved only against this process's stored
                # proposal. The current file must still be the original or the
                # exact approved patched snapshot before the stored patch is used.
                allowed_hashes = {
                    stored.get("originalSourceSha256"),
                    stored.get("patchedSourceSha256"),
                }
                if snapshot.sha256 not in allowed_hashes:
                    raise ConflictAppError(
                        "The source no longer matches the stored repair snapshot.",
                        code="E_REPAIR_SNAPSHOT_MISMATCH",
                    )
                source_text = str(stored.get("originalSource") or snapshot.text)
                if patch is None and patched_source is None:
                    patch = str(stored.get("patch") or "")
                cwe = cwe or stored.get("cwe")
                finding_id = finding_id or stored.get("findingId")
            progress("verification", "running", "Running independent verification", None)
            execution = self._execute_declared(
                "verification_run",
                request_id,
                self._payload(
                    snapshot,
                    request.language_id,
                    sourceText=source_text,
                    repairId=request.repair_id,
                    patch=patch,
                    patchedSource=patched_source,
                    cwe=cwe,
                    findingId=finding_id,
                    profile=request.profile,
                    runExecution=request.run_execution,
                    sandboxBackend=self.settings.sandbox_backend,
                ),
                progress,
                token,
            )
            combined = self._with_snapshot(self._snapshot_result(snapshot), execution)
            stage_result = next((s for s in execution.stages if s.stage == "verification"), None)
            data = stage_result.data.get("verificationResult") if stage_result else None
            if not isinstance(data, dict):
                data = {
                    "analysisAvailable": False,
                    "repairId": request.repair_id,
                    "verdict": "inconclusive",
                    "classification": "inconclusive_verification",
                    "profile": request.profile,
                    "checks": [],
                    "sandboxBackend": self.settings.sandbox_backend,
                    "limitations": ["Independent verification did not produce a result payload."],
                    "report": {},
                }
            if stored is not None:
                workflow = stored.get("workflow") or {}
                report = data.setdefault("report", {})
                # This is prior evidence from the proposal workflow, not a new
                # execution claim. Static checks above are run fresh in this call.
                report["priorWorkflowEvidence"] = {
                    "repairId": stored.get("repairId"),
                    "state": stored.get("state"),
                    "securityVerification": workflow.get("security"),
                    "functionalVerification": workflow.get("functional"),
                    "beforeAfterComparison": workflow.get("comparison"),
                }
            resp = VerificationResponse(
                **self._base_fields("verification_run", request_id, combined),
                result=VerificationResult(**data),
            )
            self._persist_result(job_store, "verification_run", request_id, resp)
            return resp

        return self._run_with_job("verification_run", request_id, job_store, job_id, run)

    # ---- internal helpers ----
    def _store_repair(self, repair_id: str, entry: dict[str, Any]) -> None:
        """Keep a bounded proposal record for later repairId verification."""
        self._repair_store[repair_id] = entry
        while len(self._repair_store) > 256:
            self._repair_store.pop(next(iter(self._repair_store)))

    def _resolve_repair(self, repair_id: str | None) -> dict[str, Any] | None:
        if not repair_id:
            return None
        return self._repair_store.get(repair_id)

    def _snapshot(self, root: Path, request: Any) -> FileSnapshot:
        if request.source_text is not None:
            return inspect_source_text(root, request.file_path, request.source_text, self.settings)
        return inspect_source_file(root, request.file_path, self.settings)

    def _inspect(self, request: Any) -> FileSnapshot:
        root = ensure_allowed_root(request.workspace_root, self.settings)
        # Normalize once at the orchestrator boundary. Every downstream stage
        # receives a canonical relative path, never a caller-supplied path.
        canonical = canonical_relative_path(root, request.file_path, must_exist=True)
        request.file_path = str(canonical)
        snapshot = self._snapshot(root, request)
        if request.selection is not None:
            validate_selection(
                snapshot.text,
                request.selection.start.line,
                request.selection.start.character,
                request.selection.end.line,
                request.selection.end.character,
            )
        return snapshot

    def _validate_requested_selection(
        self, snapshot: FileSnapshot, request: ScanFileRequest
    ) -> None:
        if request.selection is None:
            return
        validate_selection(
            snapshot.text,
            request.selection.start.line,
            request.selection.start.character,
            request.selection.end.line,
            request.selection.end.character,
        )

    def _execute_declared(
        self,
        operation: str,
        request_id: str,
        payload: Mapping[str, Any],
        progress: ProgressCallback,
        token: CancellationToken | None,
    ) -> PipelineExecution:
        if token:
            token.raise_if_cancelled()
        stage_names = OPERATION_STAGES[operation]
        if not stage_names:
            return combine_stage_results([])
        pipeline = Pipeline(self.stages[name] for name in stage_names)
        context = StageContext(
            operation=operation, request_id=request_id, settings=self.settings, payload=payload
        )
        try:
            for name in stage_names:
                progress(name, "running", f"Running stage {name}", None)
            execution = pipeline.run(context)
            for st in execution.stages:
                progress(
                    st.stage,
                    st.status.value,
                    st.detail or f"Stage {st.stage} {st.status.value}",
                    None,
                )
        except AppError:
            raise
        except Exception:
            self.logger.exception(
                "Pipeline execution failed.",
                extra={"request_id": request_id, "operation": operation},
            )
            raise InternalAppError() from None
        if execution.status is PipelineStatus.FAILED:
            self.logger.error(
                "Pipeline reported a failed stage.",
                extra={"request_id": request_id, "operation": operation},
            )
            raise InternalAppError()
        return execution

    def _with_snapshot(
        self, snapshot: StageResult, execution: PipelineExecution
    ) -> PipelineExecution:
        return combine_stage_results([snapshot, *execution.stages])

    def _snapshot_result(self, snapshot: FileSnapshot) -> StageResult:
        return StageResult(
            stage="file_snapshot",
            status=StageStatus.OK,
            data={
                "size": snapshot.size,
                "sha256": snapshot.sha256,
                "languageId": snapshot.language_id,
            },
        )

    def _snapshot_report(self, snapshot: FileSnapshot) -> StageReport:
        return StageReport(
            stage="file_snapshot",
            status=StageStatus.OK,
            data={
                "size": snapshot.size,
                "sha256": snapshot.sha256,
                "languageId": snapshot.language_id,
            },
        )

    def _analysis_available(self, execution: PipelineExecution) -> bool:
        return execution.status in {PipelineStatus.COMPLETED, PipelineStatus.PARTIAL}

    def _payload(
        self, snapshot: FileSnapshot, language_id: str | None, **extra: Any
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "filePath": str(snapshot.path),
            "documentUri": snapshot.uri,
            "languageId": language_id or snapshot.language_id,
            "sha256": snapshot.sha256,
        }
        payload.update({key: value for key, value in extra.items() if value is not None})
        return payload

    def _base_fields(
        self, operation: str, request_id: str, combined: PipelineExecution
    ) -> dict[str, Any]:
        return {
            "operation": operation,
            "status": combined.status,
            "api_version": API_VERSION,
            "request_id": request_id,
            "stages": [
                StageReport(
                    stage=result.stage,
                    status=result.status,
                    reason_code=result.reason_code,
                    detail=result.detail,
                    warnings=result.warnings,
                    data=result.data,
                )
                for result in combined.stages
            ],
            "warnings": combined.warnings,
        }

    def _base_fields_from_reports(
        self, operation: str, request_id: str, reports: list[StageReport], warnings: list[str]
    ) -> dict[str, Any]:
        results = [
            StageResult(
                stage=r.stage,
                status=r.status,
                reason_code=r.reason_code,
                detail=r.detail,
                warnings=list(r.warnings),
                data=dict(r.data),
            )
            for r in reports
        ]
        combined = (
            combine_stage_results(results)
            if results
            else PipelineExecution(status=PipelineStatus.UNAVAILABLE, stages=[], warnings=[])
        )
        all_warnings = list(dict.fromkeys([*combined.warnings, *warnings]))
        return {
            "operation": operation,
            "status": combined.status,
            "api_version": API_VERSION,
            "request_id": request_id,
            "stages": [
                StageReport(
                    stage=result.stage,
                    status=result.status,
                    reason_code=result.reason_code,
                    detail=result.detail,
                    warnings=result.warnings,
                    data=result.data,
                )
                for result in combined.stages
            ],
            "warnings": all_warnings,
        }


__all__ = ["DEFAULT_STAGE_DEFINITIONS", "OPERATION_STAGES", "Orchestrator"]
