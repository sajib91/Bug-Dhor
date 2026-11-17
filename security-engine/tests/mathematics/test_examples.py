from __future__ import annotations

import math

from mathematics.examples import run_examples


def test_reproducible_examples_run_end_to_end():
    first = run_examples()
    second = run_examples()
    assert first == second
    assert set(first) == {
        "sae",
        "measurement",
        "association",
        "single_feature",
        "pairwise",
        "higher_order",
        "counterfactual",
        "steering",
        "risk",
        "fusion",
        "preservation",
    }
    assert math.isfinite(first["sae"]["loss"])
    assert math.isfinite(first["association"]["cohens_d"][0])
    assert math.isfinite(first["pairwise"]["contrast"])
    assert math.isfinite(first["higher_order"]["contrast"])
    assert math.isfinite(first["counterfactual"]["delta"])
    assert first["risk"]["is_probability"] is False
    assert first["risk"]["band"] in {"Low", "Medium", "High", "Critical"}
    assert 0.0 <= first["fusion"]["noisy_or_score"] <= 1.0
    assert 0.0 <= first["fusion"]["logistic_probability"] <= 1.0
    assert first["preservation"]["accepted"] is True
    assert first["preservation"]["hoare_absent_is_not_pass"] == "inconclusive"
