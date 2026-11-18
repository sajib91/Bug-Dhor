"""Risk semantics, grouping, and calibration boundaries for fusion.

The engine must never turn a heuristic score into a probability, must not add
dependent evidence as if it were independent, and must merge duplicates at one
location instead of reporting the same issue twice.
"""

from __future__ import annotations

import pytest

from bugdhor.detection.config import DetectionConfig, FusionWeights
from bugdhor.detection.context import ContextAssessor
from bugdhor.detection.fusion import (
    CalibrationProvider,
    fuse_evidence,
    with_calibration,
)
from bugdhor.detection.models import (
    CalibratedProbability,
    ClaimKind,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidencePolarity,
    EvidenceType,
    HeuristicRisk,
    RiskAssessment,
    VulnerabilityCategory,
    stable_finding_id,
)
from bugdhor.parsing import parse_source
from bugdhor.program_analysis import analyze_parsed

_SPLIT_HASH = "a" * 64


def _location(line: int = 0, column: int = 0, end_column: int = 10) -> EvidenceLocation:
    return EvidenceLocation(
        path="app.py",
        start_line=line,
        start_column=column,
        end_line=line,
        end_column=end_column,
    )


def _item(
    *,
    evidence_id: str = "ev-1",
    evidence_type: EvidenceType = EvidenceType.AST,
    family: EvidenceFamily = EvidenceFamily.PROGRAM_ANALYSIS,
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
    cwe: str | None = "CWE-89",
    strength: float = 0.8,
    reliability: float = 1.0,
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS,
    location: EvidenceLocation | None = None,
    rule_id: str = "ast.dynamic-sql-query",
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        family=family,
        claim_kind=(
            ClaimKind.OBSERVATION
            if polarity is EvidencePolarity.SUPPORTS
            else ClaimKind.OBSERVATION
        ),
        source="bugdhor.ast" if family is EvidenceFamily.PROGRAM_ANALYSIS else "semgrep",
        location=location or _location(),
        category=category,
        cwe=cwe,
        strength=strength,
        reliability=reliability,
        polarity=polarity,
        severity_hint="high",
        rule_id=rule_id,
        title="test evidence",
        detail="Synthetic evidence used by a fusion test.",
    )


def _fuse(
    items: list[EvidenceItem],
    *,
    config: DetectionConfig | None = None,
    calibration: CalibrationProvider | None = None,
    assessor: ContextAssessor | None = None,
):
    parsed = parse_source("value = 1\n", path="app.py")
    return fuse_evidence(
        items,
        assessor=assessor or ContextAssessor(parsed=parsed, path="app.py"),
        config=config or DetectionConfig(enrich_cfg=False, enrich_dfg=False),
        calibration=calibration,
        generated_at="2026-01-01T00:00:00Z",
    )


class _FixedCalibrator:
    provider_id = "test-calibrator"

    def __init__(self, probability: float = 0.91) -> None:
        self.probability = probability
        self.calls = 0

    def calibrate(self, **_kwargs: object) -> CalibratedProbability:
        self.calls += 1
        return CalibratedProbability(
            value=self.probability,
            calibrator_artifact_id="calibrator-2026-01",
            method="isotonic",
            dataset_id="bugdhor-bench-v3",
            split_hash=_SPLIT_HASH,
            brier_score=0.08,
            expected_calibration_error=0.04,
        )


def test_evidence_support_multiplies_strength_and_reliability() -> None:
    item = _item(strength=0.8, reliability=0.5)
    assert item.effective_support == pytest.approx(0.4)


def test_single_evidence_item_is_a_heuristic_not_a_probability() -> None:
    result = _fuse([_item(strength=0.8)])
    (finding,) = result.findings
    assert finding.risk.heuristic.value == pytest.approx(0.8)
    assert finding.risk.probability is None
    assert finding.risk.to_contract_dict()["kind"] == "heuristic"
    assert "not a probability" in finding.explanation


def test_repeated_dependent_evidence_is_damped_not_summed() -> None:
    single = _fuse([_item(evidence_id="ev-1", strength=0.8)]).findings[0]
    doubled = _fuse(
        [
            _item(evidence_id="ev-1", strength=0.8),
            _item(evidence_id="ev-2", strength=0.8),
        ]
    ).findings[0]
    naive_noisy_or = 1.0 - (1.0 - 0.8) * (1.0 - 0.8)
    assert doubled.risk.heuristic.value > single.risk.heuristic.value
    assert doubled.risk.heuristic.value < naive_noisy_or
    assert len(doubled.risk.heuristic.contributions) == 1


def test_distinct_program_analysis_types_get_a_bounded_cross_type_bonus() -> None:
    ast_only = _fuse([_item(evidence_id="ev-ast")]).findings[0]
    ast_and_taint = _fuse(
        [
            _item(evidence_id="ev-ast", evidence_type=EvidenceType.AST),
            _item(
                evidence_id="ev-taint",
                evidence_type=EvidenceType.TAINT,
                strength=0.7,
            ),
        ]
    ).findings[0]
    assert ast_and_taint.risk.heuristic.value > ast_only.risk.heuristic.value
    assert ast_and_taint.risk.heuristic.value <= FusionWeights().program_family_cap


def test_llm_family_is_capped_below_high_risk() -> None:
    result = _fuse(
        [
            _item(
                evidence_id="ev-llm",
                evidence_type=EvidenceType.LLM,
                family=EvidenceFamily.LLM,
                strength=0.4,
                reliability=0.45,
                rule_id="llm.sql_injection",
            )
        ]
    )
    (finding,) = result.findings
    assert finding.risk.heuristic.value <= FusionWeights().llm_family_cap
    assert finding.risk.heuristic.band in {"info", "low", "medium"}


def test_refutation_penalty_lowers_risk_and_is_explained() -> None:
    source = "def f():\n    return 1\n    cursor.execute(value)\n"
    parsed = parse_source(source, path="app.py")
    location = EvidenceLocation(
        path="app.py",
        start_line=2,
        start_column=4,
        end_line=2,
        end_column=24,
    )
    assessor = ContextAssessor(
        parsed=parsed,
        path="app.py",
        analysis=analyze_parsed(parsed),
    )
    refuted = _fuse(
        [_item(evidence_id="ev-ast", strength=0.8, location=location)],
        config=DetectionConfig(enrich_dfg=False),
        assessor=assessor,
    ).findings[0]
    assert refuted.risk.heuristic.value < 0.8 / 2
    assert refuted.risk.heuristic.refutation_penalty > 0.0
    assert any(
        item.rule_id == "cfg.unreachable-sink"
        for item in refuted.evidence
        if item.polarity is EvidencePolarity.REFUTES
    )
    assert "Refutation penalty" in refuted.explanation


def test_caller_supplied_refutation_is_attached_not_dropped() -> None:
    result = _fuse(
        [
            _item(evidence_id="ev-ast", strength=0.8),
            _item(
                evidence_id="ev-suppressed",
                evidence_type=EvidenceType.SEMGREP,
                strength=0.9,
                reliability=0.95,
                polarity=EvidencePolarity.REFUTES,
                rule_id="semgrep.suppressed",
                cwe=None,
                category=VulnerabilityCategory.UNKNOWN,
            ),
        ]
    )
    (finding,) = result.findings
    assert finding.risk.heuristic.refutation_penalty > 0.0
    assert any(
        item.evidence_id == "ev-suppressed" and item.polarity is EvidencePolarity.REFUTES
        for item in finding.evidence
    )


def test_distant_refutation_does_not_lower_an_unrelated_finding() -> None:
    result = _fuse(
        [
            _item(evidence_id="ev-ast", strength=0.8, location=_location(line=0)),
            _item(
                evidence_id="ev-distant",
                evidence_type=EvidenceType.SEMGREP,
                strength=0.9,
                reliability=0.95,
                polarity=EvidencePolarity.REFUTES,
                rule_id="semgrep.suppressed",
                cwe=None,
                category=VulnerabilityCategory.UNKNOWN,
                location=_location(line=40),
            ),
        ]
    )
    (finding,) = result.findings
    assert finding.risk.heuristic.refutation_penalty == 0.0


def test_overlapping_evidence_at_one_location_merges_to_one_finding() -> None:
    result = _fuse(
        [
            _item(evidence_id="ev-ast", strength=0.6),
            _item(
                evidence_id="ev-semgrep",
                evidence_type=EvidenceType.SEMGREP,
                family=EvidenceFamily.STATIC_TOOL,
                strength=0.7,
                rule_id="semgrep.sql-injection",
            ),
        ]
    )
    (finding,) = result.findings
    assert len(finding.evidence) == 2
    assert set(finding.families) == {"program_analysis", "static_tool"}


def test_adjacent_lines_are_separate_findings_by_default() -> None:
    result = _fuse(
        [
            _item(evidence_id="ev-a", location=_location(line=0)),
            _item(
                evidence_id="ev-b",
                location=_location(line=1),
                rule_id="ast.dynamic-sql-query-b",
            ),
        ]
    )
    assert len(result.findings) == 2


def test_line_tolerance_can_group_adjacent_lines_explicitly() -> None:
    result = _fuse(
        [
            _item(evidence_id="ev-a", location=_location(line=0)),
            _item(
                evidence_id="ev-b",
                location=_location(line=1),
                rule_id="ast.dynamic-sql-query-b",
            ),
        ],
        config=DetectionConfig(
            group_line_tolerance=1,
            enrich_cfg=False,
            enrich_dfg=False,
        ),
    )
    assert len(result.findings) == 1


def test_unsupported_evidence_is_retained_as_an_unclassified_candidate() -> None:
    result = _fuse(
        [
            _item(
                category=VulnerabilityCategory.UNKNOWN,
                cwe=None,
                rule_id="vendor.unknown-check",
                evidence_type=EvidenceType.SEMGREP,
                family=EvidenceFamily.STATIC_TOOL,
            )
        ]
    )
    assert result.findings == ()
    (candidate,) = result.unclassified
    assert candidate.location.path == "app.py"
    assert candidate.heuristic_risk is not None
    assert "CWE" in candidate.reason or "categor" in candidate.reason.lower()


def test_min_severity_filters_low_priority_findings() -> None:
    weak = [_item(strength=0.25)]
    assert len(_fuse(weak).findings) == 1
    filtered = _fuse(
        weak,
        config=DetectionConfig(
            min_severity="high",
            enrich_cfg=False,
            enrich_dfg=False,
        ),
    )
    assert filtered.findings == ()


def test_max_findings_truncation_is_reported() -> None:
    items = [
        _item(
            evidence_id=f"ev-{index}",
            location=_location(line=index),
            rule_id=f"ast.dynamic-sql-query-{index}",
        )
        for index in range(3)
    ]
    result = _fuse(
        items,
        config=DetectionConfig(
            max_findings=2,
            enrich_cfg=False,
            enrich_dfg=False,
        ),
    )
    assert len(result.findings) == 2
    assert any("max_findings" in warning for warning in result.warnings)


def test_calibrated_probability_is_kept_separate_from_heuristic_risk() -> None:
    calibrator = _FixedCalibrator(0.91)
    result = _fuse([_item(strength=0.8)], calibration=calibrator)
    (finding,) = result.findings
    assert calibrator.calls == 1
    assert finding.risk.calibrated is not None
    assert finding.risk.calibrated.value == pytest.approx(0.91)
    assert finding.risk.probability == pytest.approx(0.91)
    assert finding.risk.heuristic.value == pytest.approx(0.8)
    contract = finding.risk.to_contract_dict()
    assert contract["kind"] == "calibrated"
    assert contract["calibrator"]["datasetId"] == "bugdhor-bench-v3"
    assert contract["calibrator"]["splitHash"] == _SPLIT_HASH


def test_with_calibration_never_overwrites_heuristic_risk() -> None:
    finding = _fuse([_item(strength=0.8)]).findings[0]
    calibrated = _FixedCalibrator().calibrate()
    updated = with_calibration(finding, calibrated)
    assert updated.risk.heuristic == finding.risk.heuristic
    assert updated.risk.calibrated is not None
    assert with_calibration(finding, None) == finding


def test_score_records_reject_invalid_values() -> None:
    with pytest.raises(ValueError):
        HeuristicRisk(value=1.5, band="critical")
    with pytest.raises(ValueError):
        HeuristicRisk(value=0.5, band="nope")
    with pytest.raises(ValueError):
        CalibratedProbability(
            value=0.5,
            calibrator_artifact_id="",
            method="isotonic",
            dataset_id="data",
            split_hash=_SPLIT_HASH,
            brier_score=0.1,
            expected_calibration_error=0.1,
        )
    with pytest.raises(ValueError):
        CalibratedProbability(
            value=0.5,
            calibrator_artifact_id="artifact",
            method="isotonic",
            dataset_id="data",
            split_hash="not-a-hash",
            brier_score=0.1,
            expected_calibration_error=0.1,
        )


def test_risk_assessment_without_calibration_never_exposes_a_probability() -> None:
    assessment = RiskAssessment(heuristic=HeuristicRisk(value=0.9, band="critical"))
    assert assessment.probability is None
    assert assessment.to_contract_dict()["kind"] == "heuristic"


def test_finding_id_is_deterministic_and_location_sensitive() -> None:
    location = _location()
    first = stable_finding_id(
        path="app.py",
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe="CWE-89",
        location=location,
        rule_ids=("ast.dynamic-sql-query",),
    )
    second = stable_finding_id(
        path="app.py",
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe="CWE-89",
        location=location,
        rule_ids=("ast.dynamic-sql-query",),
    )
    moved = stable_finding_id(
        path="app.py",
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe="CWE-89",
        location=_location(line=4),
        rule_ids=("ast.dynamic-sql-query",),
    )
    assert first == second
    assert first != moved
