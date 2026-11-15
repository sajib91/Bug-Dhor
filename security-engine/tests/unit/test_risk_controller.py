from __future__ import annotations

from pathlib import Path

import pytest

from craftsec.steering import (
    CalibrationRequest,
    CalibrationResult,
    CweRiskController,
    CweRiskPolicy,
    RiskAssessmentInput,
    StaticEvidence,
)


class FixedCalibrator:
    def calibrate(self, request: CalibrationRequest) -> CalibrationResult:
        assert request.heuristic_priority > 0
        return CalibrationResult(0.82, "calibrator-1", "isotonic", "cwe-benchmark")


def _policy(cwe: str, *, multiplier: float = 1.0) -> CweRiskPolicy:
    return CweRiskPolicy(
        cwe=cwe,
        feature_weight=2.0,
        interaction_weight=1.5,
        static_weight=1.0,
        heuristic_weight=0.5,
        feature_activation_threshold=0.5,
        interaction_threshold=0.1,
        static_evidence_threshold=0.2,
        steering_threshold=0.5,
        steering_base_strength=0.25,
        steering_scale=0.1,
        max_steering_strength=2.0,
        context_multipliers={"internet_facing=true": multiplier},
    )


def test_cwe_specific_prioritization_and_calibration_are_separate() -> None:
    controller = CweRiskController(
        {"CWE-89": _policy("CWE-89", multiplier=2.0), "CWE-79": _policy("CWE-79")},
        calibrators={("local/qwen", "rev-1"): FixedCalibrator()},
    )

    decision = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-89",
            model_id="local/qwen",
            model_version="rev-1",
            source_context={"internet_facing": "true"},
            feature_activations={3: 1.0},
            feature_importance={3: 0.5},
            feature_interactions=[{"contrast": 0.4}],
            static_evidence=[StaticEvidence("sql-taint", 0.8, cwe="CWE-89")],
            heuristic_risk=0.6,
        )
    )

    assert decision.cwe == "CWE-89"
    assert decision.context_multiplier == 2.0
    assert decision.heuristic_priority > 0
    assert decision.calibrated_probability == pytest.approx(0.82)
    assert decision.risk_interpretation == "calibrated_probability"
    assert decision.steering_enabled is True
    assert decision.component_scores["features"] == pytest.approx(0.5)
    assert decision.component_scores["interactions"] == pytest.approx(0.4)
    assert len(controller.history) == 1


def test_multiple_cwe_policies_produce_distinct_threshold_and_strength_decisions() -> None:
    controller = CweRiskController(
        {
            "CWE-79": _policy("CWE-79"),
            "CWE-22": CweRiskPolicy(
                cwe="CWE-22",
                feature_activation_threshold=2.0,
                steering_threshold=5.0,
                steering_base_strength=1.0,
                steering_scale=0.0,
                max_steering_strength=1.0,
            ),
        }
    )

    xss = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-79",
            model_id="local/model",
            model_version="1",
            feature_activations={1: 1.0},
            heuristic_risk=1.0,
        )
    )
    traversal = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-22",
            model_id="local/model",
            model_version="1",
            feature_activations={1: 1.0},
            heuristic_risk=10.0,
        )
    )

    assert xss.steering_enabled is True
    assert traversal.feature_evidence_available is False
    assert traversal.steering_enabled is False
    assert traversal.calibrated_probability is None
    assert traversal.risk_interpretation == "heuristic_risk; not a probability"
    assert "model-specific calibration unavailable" in traversal.fallback_reasons


def test_missing_policy_or_feature_evidence_fails_closed_and_logs(tmp_path: Path) -> None:
    controller = CweRiskController({})
    decision = controller.assess(
        RiskAssessmentInput(
            cwe="CWE-502",
            model_id="local/model",
            model_version="1",
        )
    )

    assert decision.risk_band == "unavailable"
    assert decision.steering_enabled is False
    assert decision.steering_strength == 0.0
    assert "no CWE policy" in decision.fallback_reasons[0]

    output = controller.save_history(tmp_path / "risk-history.json")
    assert output.exists()
