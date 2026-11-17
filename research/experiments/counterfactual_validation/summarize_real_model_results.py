"""Render markdown summaries from the real-model validation artifact.

The summary is descriptive.  It reports point contrasts, percentile-bootstrap
intervals over prompts, sign agreement across groups, and SAE quality metrics.
Intervals are not significance tests; "interval excludes zero" is reported only
as a descriptive count.

Usage::

    .venv/bin/python research/experiments/counterfactual_validation/summarize_real_model_results.py
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

RESULTS = Path(__file__).resolve().parent / "results"


def _fmt(value: float | None, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    return f"{value:+.{digits}f}"


def _interval(record: dict[str, Any], digits: int = 4) -> str:
    low = record.get("confidence_low")
    high = record.get("confidence_high")
    if low is None or high is None:
        return "n/a"
    return f"[{low:+.{digits}f}, {high:+.{digits}f}]"


def _config_table(configs: list[dict[str, Any]]) -> list[str]:
    lines = [
        (
            "| Checkpoint | Layer | SAE rel. recon. err. | SAE mean L0 | Dead | "
            "Step | Mean abs single effect | Pairwise range | Triple |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for config in configs:
        if config.get("status") == "error":
            lines.append(
                f"| {config['checkpoint']} | {config['layer_index']} | "
                f"error | | | | | | |"
            )
            continue
        sae = config["sae"]
        singles = config["single_feature_effects"]["primary_direction"]
        pair_values = [item["contrast"] for item in config["pairwise"]]
        single_values = list(singles.values())
        lines.append(
            "| {checkpoint} | {layer} | {err:.2e} | {l0:.1f} | {dead} | "
            "{step:.3f} | {single:.4f} | {low:+.4f} to {high:+.4f} | "
            "{triple:+.4f} |".format(
                checkpoint=config["checkpoint"],
                layer=config["layer_index"],
                err=float(sae["relative_reconstruction_error"]),
                l0=float(sae["mean_l0"]),
                dead=sae["dead_features"],
                step=float(config["intervention"]["direction_step"]),
                single=sum(single_values) / len(single_values),
                low=min(pair_values),
                high=max(pair_values),
                triple=float(config["triple"]["contrast"]),
            )
        )
    return lines


def _pooled_table(configs: list[dict[str, Any]]) -> list[str]:
    lines = [
        (
            "| Checkpoint | Layer | Pooled pairwise | 95% interval | "
            "CWE sign consistency | Pairs with interval > 0 | "
            "Pairs with interval < 0 |"
        ),
        "|---|---:|---:|---|---:|---:|---:|",
    ]
    for config in configs:
        if config.get("status") == "error":
            continue
        pooled = config["layer_pooled"]["pooled_pairwise"]
        above = sum(item["confidence_low"] > 0.0 for item in config["pairwise"])
        below = sum(item["confidence_high"] < 0.0 for item in config["pairwise"])
        lines.append(
            "| {checkpoint} | {layer} | {contrast} | {interval} | {sign:.2f} | "
            "{above} | {below} |".format(
                checkpoint=config["checkpoint"],
                layer=config["layer_index"],
                contrast=_fmt(float(pooled["contrast"])),
                interval=_interval(pooled),
                sign=float(config["layer_pooled"]["cwe_sign_consistency"]),
                above=above,
                below=below,
            )
        )
    return lines


def _cwe_table(configs: list[dict[str, Any]]) -> list[str]:
    cwes = sorted(
        {
            cwe
            for config in configs
            if config.get("status") != "error"
            for cwe in config["layer_pooled"]["cwe_pooled"]
        }
    )
    header = (
        "| Checkpoint | Layer | "
        + " | ".join(cwes)
        + " | Sign consistent | Intervals overlap |"
    )
    lines = [
        header,
        "|---|---:|" + "---:|" * len(cwes) + "---:|---:|",
    ]
    for config in configs:
        if config.get("status") == "error":
            continue
        pooled = config["layer_pooled"]
        cells = [_fmt(float(pooled["cwe_pooled"][cwe]["contrast"])) for cwe in cwes]
        lines.append(
            "| {checkpoint} | {layer} | {cells} | {sign} | {overlap} |".format(
                checkpoint=config["checkpoint"],
                layer=config["layer_index"],
                cells=" | ".join(cells),
                sign="yes" if pooled["cwe_same_sign"] else "no",
                overlap="yes" if pooled["cwe_all_intervals_overlap"] else "no",
            )
        )
    return lines


def _pair_table(config: dict[str, Any]) -> list[str]:
    lines = [
        (
            "| Features | Contrast | 95% interval | Unit sign consistency | "
            "CWE sign consistency |"
        ),
        "|---|---:|---|---:|---:|",
    ]
    for item in config["pairwise"]:
        lines.append(
            "| {features} | {contrast} | {interval} | {unit:.2f} | {cwe:.2f} |".format(
                features=", ".join(str(value) for value in item["features"]),
                contrast=_fmt(float(item["contrast"])),
                interval=_interval(item),
                unit=float(item["unit_sign_consistency"]),
                cwe=float(item["cwe_sign_consistency"]),
            )
        )
    return lines


def _layer_stability(payload: dict[str, Any]) -> list[str]:
    stability = payload.get("stability", {}).get("across_layers", {})
    lines = [
        (
            "| Checkpoint | Same sign across layers | Sign consistency | "
            "All intervals overlap |"
        ),
        "|---|---:|---:|---:|",
    ]
    for checkpoint, entry in stability.items():
        lines.append(
            "| {checkpoint} | {same} | {consistency:.2f} | {overlap} |".format(
                checkpoint=checkpoint,
                same="yes" if entry["same_sign"] else "no",
                consistency=float(entry["sign_consistency"]),
                overlap="yes" if entry["all_intervals_overlap"] else "no",
            )
        )
    return lines


def _checkpoint_stability(payload: dict[str, Any]) -> list[str]:
    stability = payload.get("stability", {}).get("across_checkpoints", {})
    if not stability.get("available"):
        return ["Cross-checkpoint comparison unavailable."]
    lines = [
        (
            "| Layer | Base pooled | Instruct pooled | Same sign | "
            "Intervals overlap | Base triple | Instruct triple |"
        ),
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for layer in stability["layers"]:
        lines.append(
            "| {layer} | {base} | {instruct} | {same} | {overlap} | "
            "{base_triple} | {instruct_triple} |".format(
                layer=layer["layer_index"],
                base=_fmt(float(layer["base_pooled_contrast"])),
                instruct=_fmt(float(layer["instruct_pooled_contrast"])),
                same="yes" if layer["same_sign"] else "no",
                overlap="yes" if layer["all_intervals_overlap"] else "no",
                base_triple=_fmt(float(layer["base_triple_contrast"])),
                instruct_triple=_fmt(float(layer["instruct_triple_contrast"])),
            )
        )
    lines.append("")
    lines.append(
        "Layers with same sign: {same}/{total}; interval overlap: "
        "{overlap}/{total}; triple sign agreement: {triple}/{total}; "
        "mean best decoder cosine: {cosine:.3f}.".format(
            same=stability["same_sign_layers"],
            overlap=stability["interval_overlap_layers"],
            triple=stability["triple_sign_agreement_layers"],
            total=stability["layer_count"],
            cosine=float(stability["mean_selected_feature_best_decoder_cosine"]),
        )
    )
    return lines


def _ablation_table(configs: list[dict[str, Any]]) -> list[str]:
    lines = [
        (
            "| Checkpoint | Layer | Mean abs ablation effect | "
            "Ablation pairwise contrast | 95% interval |"
        ),
        "|---|---:|---:|---:|---|",
    ]
    for config in configs:
        if config.get("status") == "error":
            continue
        effects = config["single_feature_effects"]["natural_ablation"]
        values = [item["mean_abs_outcome_change"] for item in effects.values()]
        ablation = config["ablation_pairwise"]
        lines.append(
            "| {checkpoint} | {layer} | {effect:.4f} | {contrast} | "
            "{interval} |".format(
                checkpoint=config["checkpoint"],
                layer=config["layer_index"],
                effect=sum(values) / len(values),
                contrast=_fmt(float(ablation["contrast"])),
                interval=_interval(ablation),
            )
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=str(RESULTS / "real_model_validation.json"))
    parser.add_argument("--config", default=None, help="print one config's pairs")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text())
    configs = payload["configs"]
    completed = [config for config in configs if config.get("status") != "error"]

    print("## SAE and intervention summary\n")
    print("\n".join(_config_table(configs)))
    print("\n## Pooled pairwise contrasts\n")
    print("\n".join(_pooled_table(completed)))
    print("\n## CWE-pattern pooled contrasts\n")
    print("\n".join(_cwe_table(completed)))
    print("\n## Layer stability (pooled pairwise contrast)\n")
    print("\n".join(_layer_stability(payload)))
    print("\n## Cross-checkpoint stability\n")
    print("\n".join(_checkpoint_stability(payload)))
    print("\n## Natural-ablation sensitivity check\n")
    print("\n".join(_ablation_table(completed)))

    if args.config:
        checkpoint, layer = args.config.split(":", maxsplit=1)
        selected = [
            config
            for config in completed
            if config["checkpoint"] == checkpoint
            and str(config["layer_index"]) == layer
        ]
        for config in selected:
            print(f"\n## Pairwise detail: {checkpoint} layer {layer}\n")
            print("\n".join(_pair_table(config)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
