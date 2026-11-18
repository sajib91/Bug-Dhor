# Risk calibration dataset contract

The unified risk engine does not ship a labelled security dataset and does not
fabricate calibration results. A calibration run requires a caller-supplied
JSONL file whose rows are described below. The schema is intentionally small so
that an independently collected dataset can be substituted without code
changes.

## Row schema

Each non-empty line is one JSON object:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `rowId` | string | yes | Stable identifier for the observation. |
| `group` | string | yes | Repository/project/repository-snapshot identifier used for group-disjoint splitting. |
| `score` | number in `[0, 1]` | yes | The heuristic risk index produced by a **frozen** risk configuration. |
| `label` | integer `0` or `1` | yes | Independent ground truth for whether the finding is a real vulnerability. |

Field names are configurable in `research/configs/risk/calibration.json`
(`rowIdField`, `groupField`, `scoreField`, `labelField`).

## Requirements for a valid calibration claim

- Labels must come from an independent source such as curated vulnerability
  reports or expert adjudication with documented inter-rater agreement. They
  must not be the output of the same detector being calibrated.
- `fitGroups` and `validationGroups` in the config must be disjoint. The loader
  rejects overlap and rows outside the declared split are ignored with a
  warning in the evaluation report.
- The risk configuration used to produce `score` must be frozen and its
  `configHash` recorded alongside the experiment. Changing weights, thresholds,
  or group mappings invalidates the calibration artifact.
- Metrics (Brier score, log loss, expected calibration error, AUROC) are
  computed on the validation split only. Bootstrap intervals are computed with
  the configured seed and resample count.
- An artifact is usable for a calibrated probability only if it passes every
  acceptance threshold. A rejected artifact is retained in the report with its
  failures but `CalibrationArtifact.probability()` returns `None`.

## Reproducible invocation

```bash
cd security-engine
PYTHONPATH=src ./.venv/bin/python -m bugdhor.risk.evaluation \
  --config ../research/configs/risk/calibration.json \
  --data /path/to/independently-labelled.jsonl \
  --output /path/to/calibration-report.json
```

The report embeds the full calibration config, the split hash, the data hash,
the fitted parameters, validation metrics, bootstrap intervals, and acceptance
decision. It contains no source code and no secrets.

## Synthetic fixtures

Synthetic rows used by the unit tests live under `security-engine/tests/` and
are labelled as synthetic in the test code. They exercise the runner and the
acceptance/rejection logic only; they are not evidence of calibration quality.
