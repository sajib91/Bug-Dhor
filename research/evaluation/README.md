# Evaluation

This directory contains evaluation design and metric implementations used by research runs.

## Implemented framework (no results)

The `security-engine` now includes a reproducible experimental evaluation framework under `bugdhor.experiments` and `bugdhor.evaluation`:

- **Datasets** (`bugdhor.experiments.datasets`): registry/loaders for Big-Vul, Devign, Juliet, PrimeVul, DiverseVul, CodeXGLUE, and CyberSecEval, subject to **actual local availability and explicit license acknowledgment** (no bundled/fabricated data). Includes sample normalization, dataset validation, duplicate detection/deduplication, and split-leakage checks.
- **Splits** (`bugdhor.experiments.splits`): repository-level, temporal (when parseable metadata permits), CWE-based, and cross-language splitting with explicit unsupported/unavailable/partial handling and split hashing.
- **Experiment groups** (`bugdhor.experiments.groups`): E0–E8 definitions and prerequisite checks (Original LLM, Security prompting, Static-analysis baseline, Single-feature SAE steering, Multi-feature analysis, Interaction-aware steering, Automated repair, Steering plus repair, Full Bug Dhor).
- **Configuration & tracking** (`bugdhor.experiments.config`): deterministic config hashing, run manifests, environment/tool metadata capture, and raw output recording (JSON/JSONL) without fabricating metrics.
- **Evaluation pipeline** (`bugdhor.experiments.evaluation`): model-level `ModelEvaluator` interface and `ExperimentRunner` that executes only when required data/models/tools/capabilities are available; unavailable prerequisites are recorded with reasons and unmeasured metrics remain null.
- **Metrics** (`bugdhor.evaluation.metrics`): detection (Precision, Recall, F1, MCC, PR-AUC), localization (line-level precision/recall, localization accuracy), repair (repair success rate, verified repair success, functional pass rate, security regression rate), explainability (feature faithfulness, explanation consistency, counterfactual validity), and performance (inference overhead, analysis latency, memory usage) computed from provided observations only.
- **Statistical analysis** (`bugdhor.evaluation.statistics`): assumption checks (normality/independence/sample-size reporting), bootstrap confidence intervals (including cluster bootstrap when cluster IDs provided), paired tests (paired t-test where computable, Wilcoxon signed-rank, paired permutation test), nonparametric alternatives, effect sizes (e.g. Cohen's d, Cliff's delta), and multiple-comparison correction (Holm-Bonferroni, Benjamini-Hochberg). Analyses require provided observations, report sample sizes/missing data, and do not fabricate p-values/CIs/effect sizes.
- **Ablations & comparisons** (`bugdhor.evaluation.ablation`, `bugdhor.evaluation.comparisons`): ablation analyses A1–A8 (without SAE features/counterfactual/pairwise/higher-order/steering/static-analysis fusion/repository context/independent verification) and cross-model/cross-dataset comparisons with paired or independent designs, dependence-aware notes/clustering support, and corrected summaries.
- **Statistical reporting/export** (`bugdhor.evaluation.reporting`, `bugdhor.experiments.export`): publication-ready CSV outputs and Excel-compatible export (XLSX when an engine is available, otherwise CSVs) generated from actual experimental data, including sample sizes, missing data, confidence intervals, tests, effect sizes, corrections, and significance notes distinguishing statistical from practical significance.
- **Export** (`bugdhor.experiments.export`): JSON/CSV/JSONL and result-bundle export of manifests, raw outputs, metrics, and per-sample records.

Calibration metrics (e.g. Brier/ECE) remain out of scope until genuine calibrators/data are available. No benchmark numbers exist yet. Any future number must link to an exported experiment bundle and state its claim kind, sample size, seed, model/SAE hashes, and limitations.
