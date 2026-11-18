"""Run evidence-backed compatibility probes for Bug Dhor model targets.

The runner records declared capabilities separately from observed ones. A target
is reported as ``supported`` only when a probe produced concrete evidence.
Missing checkpoints, hosts, credentials, artifacts, or steering contracts stay
``unavailable`` or ``not_run``.

Run from the repository root::

    .venv/bin/python research/experiments/model_compatibility/run_compatibility_matrix.py
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = ROOT / "research" / "configs" / "models" / "compatibility-matrix.json"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "results"
SRC = ROOT / "security-engine" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from bugdhor.models.compatibility import (
    AssistantIntegrationCard,
    Capability,
    CapabilityProbe,
    CompatibilityReport,
    ModelCapabilityCard,
    ProbeStatus,
    as_plain,
)

ALL_CAPABILITIES = tuple(Capability)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _strip_private(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_private(item)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, list):
        return [_strip_private(item) for item in value]
    return value


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        _strip_private(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:  # noqa: BLE001 - provenance must not abort a probe run
        return None


def environment_snapshot(config: dict[str, Any]) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "pythonVersion": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpuCount": os.cpu_count(),
        "declaredDevice": config.get("environment", {}).get("device"),
        "declaredDtype": config.get("environment", {}).get("dtype"),
    }
    try:
        import torch  # type: ignore[import-not-found]

        snapshot["torchVersion"] = torch.__version__
        snapshot["cudaAvailable"] = bool(torch.cuda.is_available())
        snapshot["mpsAvailable"] = bool(torch.backends.mps.is_available())
    except Exception:  # noqa: BLE001 - absent ML deps are observable metadata
        snapshot["torchVersion"] = None
        snapshot["cudaAvailable"] = None
        snapshot["mpsAvailable"] = None
    try:
        import transformers  # type: ignore[import-not-found]

        snapshot["transformersVersion"] = transformers.__version__
    except Exception:  # noqa: BLE001 - absent ML deps are observable metadata
        snapshot["transformersVersion"] = None
    return snapshot


def checkpoint_path(repo_id: str, revision: str | None) -> Path | None:
    """Find an already-downloaded snapshot without initiating a download."""
    cache_root = Path(os.environ.get("HF_HUB_CACHE", Path.home() / ".cache" / "huggingface" / "hub"))
    snapshots = cache_root / f"models--{repo_id.replace('/', '--')}" / "snapshots"
    if not snapshots.is_dir():
        return None
    if revision:
        candidate = snapshots / revision
        return candidate if candidate.is_dir() else None
    candidates = sorted(path for path in snapshots.iterdir() if path.is_dir())
    return candidates[-1] if candidates else None


def unavailable_probes(reason: str) -> tuple[CapabilityProbe, ...]:
    return tuple(
        CapabilityProbe(capability=capability, status=ProbeStatus.UNAVAILABLE, reason=reason)
        for capability in ALL_CAPABILITIES
    )


def status_from_probes(
    probes: tuple[CapabilityProbe, ...], capability: Capability
) -> ProbeStatus:
    for probe in probes:
        if probe.capability is capability:
            return probe.status
    return ProbeStatus.NOT_RUN


def parse_target(
    target: dict[str, Any],
    probes: tuple[CapabilityProbe, ...],
    hardware: dict[str, Any],
    inference_limitations: tuple[str, ...],
) -> ModelCapabilityCard:
    architectures = hardware.get("architecture") or ()
    architecture = target.get("architecture") or (architectures[0] if architectures else None)
    tokenizer = target.get("tokenizer") or hardware.get("tokenizerClass")
    layers = target.get("availableLayers")
    if layers is None and hardware.get("discoveredLayers"):
        layers = tuple(hardware["discoveredLayers"])
    elif layers is None and hardware.get("discoveredLayerCount"):
        layers = tuple(range(int(hardware["discoveredLayerCount"])))
    return ModelCapabilityCard(
        target_id=target["targetId"],
        name=target["name"],
        checkpoint_identifier=target["checkpointIdentifier"],
        provider_identifier=target.get("providerIdentifier"),
        version=target.get("version"),
        revision=target.get("revision"),
        architecture=architecture,
        tokenizer=tokenizer,
        available_layers=tuple(layers) if layers is not None else None,
        activation_access=status_from_probes(probes, Capability.ACTIVATION_EXTRACTION),
        sae_compatibility=status_from_probes(probes, Capability.SAE_COMPATIBILITY),
        steering_compatibility=status_from_probes(probes, Capability.ACTIVATION_STEERING),
        hardware_requirements=hardware,
        inference_limitations=inference_limitations,
        runtime=target["runtime"],
        probes=probes,
        declared_capabilities=tuple(target.get("declaredCapabilities", ())),
    )


def probe_model_target(
    target: dict[str, Any], config: dict[str, Any], config_dir: Path
) -> ModelCapabilityCard:
    runtime = target["runtime"]
    hardware: dict[str, Any] = {}
    limitations: tuple[str, ...] = ()

    if runtime == "transformers_direct":
        revision = target.get("revision")
        snapshot = checkpoint_path(target["checkpointIdentifier"], revision)
        if snapshot is None:
            reason = "checkpoint_not_present in local Hugging Face cache"
            return parse_target(target, unavailable_probes(reason), hardware, (reason,))
        probe_module = importlib.import_module("bugdhor.models.compatibility_probes")
        probes, hardware, limitations = probe_module.probe_transformers_target(
            target=target,
            config=config,
            config_dir=config_dir,
            snapshot=snapshot,
        )
        return parse_target(target, probes, hardware, limitations)

    if runtime == "bugdhor_adapter":
        snapshot = checkpoint_path(target["checkpointIdentifier"], target.get("revision"))
        if snapshot is None:
            reason = "registered checkpoint_not_present in local Hugging Face cache"
            return parse_target(target, unavailable_probes(reason), hardware, (reason,))
        probe_module = importlib.import_module("bugdhor.models.compatibility_probes")
        probes, hardware, limitations = probe_module.probe_registered_adapter(
            target=target,
            config=config,
            config_dir=config_dir,
            snapshot=snapshot,
        )
        return parse_target(target, probes, hardware, limitations)

    reason = f"unsupported compatibility runtime {runtime!r}"
    return parse_target(target, unavailable_probes(reason), hardware, (reason,))


def probe_assistant_target(target: dict[str, Any]) -> AssistantIntegrationCard:
    requires_host = bool(target.get("requiresHost", False))
    missing = [name for name in target.get("requiresEnv", []) if not os.environ.get(name)]
    reasons: list[str] = []
    if requires_host:
        reasons.append("no VS Code host is available to the CLI runner")
    if missing:
        reasons.append("missing " + ", ".join(missing))
    status = ProbeStatus.UNAVAILABLE if reasons else ProbeStatus.NOT_RUN
    return AssistantIntegrationCard(
        target_id=target["targetId"],
        provider_kind=target["providerKind"],
        label=target["label"],
        status=status,
        discovered_capabilities=(),
        declared_capabilities=dict(target.get("declaredCapabilities", {})),
        reason="; ".join(reasons) if reasons else "no provider discovery probe registered",
        evidence={"requiresHost": requires_host, "missingEnvVarNames": missing},
    )


def build_report(config: dict[str, Any], config_dir: Path) -> CompatibilityReport:
    config_hash = canonical_hash(config)
    environment = environment_snapshot(config)
    models = tuple(
        probe_model_target(target, config, config_dir)
        for target in config.get("modelTargets", [])
    )
    assistants = tuple(
        probe_assistant_target(target) for target in config.get("assistantTargets", [])
    )
    return CompatibilityReport(
        schema_version=config.get("schemaVersion", "1.0.0"),
        generated_at=utc_now(),
        config_hash=config_hash,
        git_commit=git_commit(),
        environment=environment,
        models=models,
        assistant_integrations=assistants,
        limitations=tuple(config.get("limitations", ())),
        claim_boundary=(
            "Only capabilities with concrete probe evidence are reported as supported. "
            "Generation fluency is not security accuracy; model-internal effects are not "
            "real-world causal effects; hosted providers expose no internals."
        ),
    )


def _short_status(probe: CapabilityProbe | None) -> str:
    if probe is None:
        return "not_run"
    return probe.status.value


def render_markdown(report: CompatibilityReport) -> str:
    headers = [
        "Target",
        "Runtime",
        "Generation",
        "Analysis",
        "Secure gen",
        "Activations",
        "SAE",
        "Counterfactual",
        "Steering",
        "Token-level",
        "Reproducibility",
        "Hardware",
    ]
    lines = [
        "# Model compatibility report",
        "",
        f"- Generated at: `{report.generated_at}`",
        f"- Config hash: `{report.config_hash}`",
        f"- Git commit: `{report.git_commit or 'unknown'}`",
        f"- Python: `{report.environment.get('pythonVersion')}`",
        f"- Platform: `{report.environment.get('platform')}`",
        f"- Torch: `{report.environment.get('torchVersion')}`",
        f"- Transformers: `{report.environment.get('transformersVersion')}`",
        "",
        "Declared capabilities are configuration, not evidence. Only observed probe outcomes are reported below.",
        "",
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for model in report.models:
        by_capability = {probe.capability: probe for probe in model.probes}
        row = [
            model.target_id,
            model.runtime,
            _short_status(by_capability.get(Capability.CODE_GENERATION)),
            _short_status(by_capability.get(Capability.CODE_ANALYSIS)),
            _short_status(by_capability.get(Capability.SECURE_CODE_GENERATION)),
            _short_status(by_capability.get(Capability.ACTIVATION_EXTRACTION)),
            _short_status(by_capability.get(Capability.SAE_COMPATIBILITY)),
            _short_status(by_capability.get(Capability.COUNTERFACTUAL_INTERVENTION)),
            _short_status(by_capability.get(Capability.ACTIVATION_STEERING)),
            _short_status(by_capability.get(Capability.TOKEN_LEVEL_INTERVENTION)),
            _short_status(by_capability.get(Capability.OUTPUT_REPRODUCIBILITY)),
            _short_status(by_capability.get(Capability.HARDWARE_INFERENCE_LIMITS)),
        ]
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(
        [
            "",
            "## Per-target details",
            "",
        ]
    )
    for model in report.models:
        lines.extend(
            [
                f"### {model.target_id}",
                "",
                f"- Name: {model.name}",
                f"- Checkpoint: `{model.checkpoint_identifier}`",
                f"- Revision: `{model.revision or 'unresolved'}`",
                f"- Architecture: `{model.architecture or 'unobserved'}`",
                f"- Tokenizer: `{model.tokenizer or 'unobserved'}`",
                f"- Layers: {model.available_layers if model.available_layers is not None else 'unobserved'}",
                "",
                "| Capability | Status | Evidence / reason |",
                "|---|---|---|",
            ]
        )
        for probe in model.probes:
            summary = probe.reason or json.dumps(
                as_plain(probe.evidence), sort_keys=True, ensure_ascii=False
            )
            summary = summary.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {probe.capability.value} | {probe.status.value} | {summary} |")
        lines.append("")

    lines.extend(
        [
            "## Assistant integrations",
            "",
            "| Provider | Observed status | Discovered capabilities | Declared A-F | Reason |",
            "|---|---|---|---|---|",
        ]
    )
    for integration in report.assistant_integrations:
        declared = "/".join(
            f"{key}:{value}" for key, value in sorted(integration.declared_capabilities.items())
        )
        reason = (integration.reason or "").replace("|", "\\|")
        lines.append(
            f"| {integration.label} | {integration.status.value} | "
            f"{', '.join(integration.discovered_capabilities) or 'none'} | {declared} | {reason} |"
        )

    lines.extend(
        [
            "",
            "## Claim boundary",
            "",
            report.claim_boundary,
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)

    config = load_json(args.config)
    report = build_report(config, args.config.parent)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "model_compatibility_report.json"
    md_path = args.output_dir / "model_compatibility_report.md"
    json_path.write_text(
        json.dumps(as_plain(report.to_dict()), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(report), encoding="utf-8")
    supported = [
        f"{model.target_id}:{probe.capability.value}"
        for model in report.models
        for probe in model.probes
        if probe.status is ProbeStatus.SUPPORTED
    ]
    print(
        json.dumps(
            {
                "report": str(json_path),
                "summary": str(md_path),
                "supportedProbes": supported,
                "configHash": report.config_hash,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
