from __future__ import annotations

from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from craftsec.sae import (  # noqa: E402
    FeatureAnnotationBook,
    FeatureAssociation,
    FeatureDictionary,
    FeatureDictionaryEntry,
    FeatureExperimentMetadata,
    FeatureInterpretationEngine,
    FeatureStability,
    InterventionObservation,
    export_reports_csv,
    export_reports_json,
)
from craftsec.sae.interpretation import FeatureExample  # noqa: E402


def _dictionary() -> FeatureDictionary:
    association = FeatureAssociation(
        feature_index=0,
        sample_count=4,
        vulnerable_count=2,
        secure_count=2,
        activation_frequency=0.5,
        vulnerable_activation_frequency=1.0,
        secure_activation_frequency=0.0,
        vulnerable_mean_activation=2.0,
        secure_mean_activation=0.0,
        mean_activation_difference=2.0,
        active_precision=1.0,
        active_recall=1.0,
        association_direction="vulnerable_higher",
    )
    entry = FeatureDictionaryEntry(
        feature_index=0,
        association=association,
        cwe_associations={"CWE-89": association},
        selectivity=1.0,
        stability=FeatureStability({"dataset-a": 2.0}, 1.0, 1),
    )
    return FeatureDictionary(
        metadata=FeatureExperimentMetadata(
            model_id="local/tiny",
            model_version="test",
            layer="layer.0",
            sae_checkpoint="sae.pt",
            dataset_ids=("dataset-a",),
            experiment_id="exp",
            activation_threshold=0.5,
        ),
        entries=(entry,),
    )


def test_interpretation_report_contains_examples_annotations_and_limitations(
    tmp_path: Path,
) -> None:
    examples = {
        0: (
            FeatureExample("v1", "cursor.execute(user)", 2.0, True, "dataset-a", "CWE-89"),
            FeatureExample("v2", "cursor.execute(user)", 1.5, True, "dataset-a", "CWE-89"),
            FeatureExample("s1", "cursor.execute(?)", 0.0, False, "dataset-a"),
            FeatureExample("s2", "parameterized()", 0.0, False, "dataset-a"),
        )
    }
    annotations = FeatureAnnotationBook()
    annotations.annotate(
        "feature-0",
        "Researcher description pending validation",
        annotator="researcher",
        confidence=0.6,
    )
    annotations.annotate("feature-0", "Revised description", annotator="researcher", confidence=0.7)
    interventions = (
        InterventionObservation(
            "int-1", 0, "v1", "activation_ablation", 2.0, 0.0, 1.0, 0.8
        ),
    )
    engine = FeatureInterpretationEngine(
        _dictionary(), examples, annotations=annotations, interventions=interventions
    )
    report = engine.report(0)

    assert report.feature_id == "feature-0"
    assert report.model_version == "test"
    assert report.representative_code_examples[0].source == "cursor.execute(user)"
    assert report.associated_cwe_categories == ("CWE-89",)
    assert report.annotation is not None
    assert report.annotation.description == "Revised description"
    assert report.annotation.revision == 2
    assert report.interventions[0].outcome_delta == pytest.approx(-0.2)
    assert "causal" in " ".join(report.limitations)
    assert "proven semantic meaning" in report.interpretation_status

    reports = (report,)
    json_path = export_reports_json(reports, tmp_path / "reports.json")
    csv_path = export_reports_csv(reports, tmp_path / "reports.csv")
    assert json_path.exists() and csv_path.exists()
    assert "feature-0" in json_path.read_text(encoding="utf-8")
    assert "interpretation_status" in csv_path.read_text(encoding="utf-8")

