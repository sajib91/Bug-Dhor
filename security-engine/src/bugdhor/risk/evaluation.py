"""Reproducible calibration evaluation runner.

Example::

    PYTHONPATH=src python -m bugdhor.risk.evaluation \
        --config research/configs/risk/calibration.json \
        --data /path/to/independently-labelled.jsonl \
        --output /tmp/risk-calibration-report.json

The runner performs a fit on the configured fit groups and an evaluation on
disjoint validation groups. It never mutates the dataset or configuration.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from bugdhor.risk.calibration import (
    calibration_config_from_mapping,
    evaluate_calibration,
    load_calibration_rows,
)


def run_evaluation(config_path: str | Path, data_path: str | Path) -> dict[str, object]:
    """Run one calibration evaluation and return its JSON-serializable report."""
    payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("calibration config root must be an object")
    config = calibration_config_from_mapping(payload)
    rows = load_calibration_rows(data_path, config)
    evaluation = evaluate_calibration(rows, config)
    return evaluation.report()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Path to the calibration config JSON")
    parser.add_argument("--data", required=True, help="Path to the labelled JSONL dataset")
    parser.add_argument("--output", required=True, help="Path for the JSON evaluation report")
    args = parser.parse_args(argv)
    report = run_evaluation(args.config, args.data)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "report": str(output)}))
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_evaluation"]
