"""Real capability probes for locally available Transformers checkpoints.

These probes exercise importable Bug Dhor libraries with real checkpoints and
real SAE artifacts. They never use the HTTP feature/counterfactual/steering
stubs, never download weights, and report missing prerequisites instead of
inferring capabilities from configuration.
"""

from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import resource
import sys
import time
import types
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from bugdhor.models.activations import ActivationCollector, LayerDiscovery
from bugdhor.models.adapter import InferenceResult
from bugdhor.models.compatibility import Capability, CapabilityProbe, ProbeStatus
from bugdhor.models.config import GenerationConfig, ModelConfig
from bugdhor.models.inference import InferenceEngine
from bugdhor.models.manager import ModelManager
from bugdhor.sae.checkpoint import load_checkpoint
from bugdhor.sae.model import SparseAutoencoder

_LIMITATIONS = (
    "Generation probes measure output production, not code correctness or security.",
    "SAE features are tied to one model revision, layer, and hook point.",
    "Counterfactual and steering effects are model-internal, not real-world causal effects.",
    "Hosted providers expose no model internals and are not probed by this module.",
)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, torch.Tensor):
        return {
            "shape": list(value.shape),
            "dtype": str(value.dtype).replace("torch.", ""),
            "device": str(value.device),
            "requiresGrad": bool(value.requires_grad),
        }
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    return value


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _generation_config(config: Mapping[str, Any]) -> GenerationConfig:
    values = config.get("generation", {})
    return GenerationConfig(
        max_new_tokens=int(values.get("maxNewTokens", 64)),
        do_sample=bool(values.get("doSample", False)),
        temperature=float(values.get("temperature", 0.2)),
        top_p=float(values.get("topP", 0.95)),
    )


class _SnapshotAdapter:
    """Minimal local adapter used to drive the production InferenceEngine."""

    def __init__(
        self,
        *,
        model: Any,
        tokenizer: Any,
        model_id: str,
        model_version: str,
        device: str,
        torch_module: Any,
    ) -> None:
        self.model = model
        self.tokenizer = tokenizer
        self.model_id = model_id
        self.model_version = model_version
        self.device = device
        self._torch = torch_module
        self.supports_activations = True

    def generate(
        self,
        prompt: str,
        *,
        generation_kwargs: Mapping[str, Any],
        capture_activations: bool = False,
    ) -> InferenceResult:
        inputs = self.tokenizer(prompt, return_tensors="pt")
        inputs = {
            key: value.to(self.device)
            for key, value in inputs.items()
            if hasattr(value, "to")
        }
        kwargs = dict(generation_kwargs)
        kwargs["return_dict_in_generate"] = True
        kwargs["output_hidden_states"] = capture_activations
        with self._torch.inference_mode():
            output = self.model.generate(**inputs, **kwargs)
        sequences = output.sequences
        prompt_tokens = int(inputs["input_ids"].shape[-1])
        generated = sequences[:, prompt_tokens:]
        text = self.tokenizer.decode(generated[0], skip_special_tokens=True)
        return InferenceResult(
            text=text,
            prompt_tokens=prompt_tokens,
            generated_tokens=int(generated.shape[-1]),
        )

    def collect_activations(self, prompts: Sequence[str], **kwargs: Any) -> Any:
        collector = ActivationCollector(
            self.model,
            self.tokenizer,
            model_id=self.model_id,
            model_version=self.model_version,
            tokenizer_id=str(getattr(self.tokenizer, "name_or_path", self.model_id)),
            tokenizer_version=self._tokenizer_version(),
            device=self.device,
            layer_names=kwargs.get("layer_names"),
            layer_indices=kwargs.get("layer_indices"),
        )
        return collector.collect(
            prompts,
            batch_size=int(kwargs.get("batch_size", 1)),
            functions=kwargs.get("functions"),
        )

    def unload(self) -> None:
        del self.model
        del self.tokenizer
        gc.collect()

    def _tokenizer_version(self) -> str:
        version = getattr(self.tokenizer, "version", None)
        return str(version) if version is not None else "unknown"


def _probe(
    capability: Capability,
    function: Any,
    *,
    claim_kind: str | None = None,
    limitations: Sequence[str] = (),
) -> CapabilityProbe:
    try:
        return function()
    except Exception as error:  # noqa: BLE001 - each probe reports its own failure
        return CapabilityProbe(
            capability=capability,
            status=ProbeStatus.ERROR,
            reason=f"{type(error).__name__}: {error}",
            claim_kind=claim_kind,
            limitations=tuple(limitations),
        )


def _generation_probe(
    engine: InferenceEngine,
    capability: Capability,
    prompt: str,
    generation: GenerationConfig,
    *,
    require_json: bool = False,
) -> CapabilityProbe:
    started = time.perf_counter()
    result = engine.generate(prompt, generation=generation)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    parsed_json = False
    if require_json:
        try:
            json.loads(result.text)
            parsed_json = True
        except Exception:  # noqa: BLE001 - malformed output is an observation
            parsed_json = False
    supported = bool(result.text.strip()) and result.generated_tokens > 0
    if require_json and not parsed_json:
        status = ProbeStatus.PARTIAL
        reason = "generated text was not valid JSON; format compliance is not established"
    else:
        status = ProbeStatus.SUPPORTED if supported else ProbeStatus.UNSUPPORTED
        reason = None if supported else "empty generated output"
    return CapabilityProbe(
        capability=capability,
        status=status,
        evidence={
            "textSha256": _sha256_text(result.text),
            "preview": result.text[:240],
            "promptTokens": result.prompt_tokens,
            "generatedTokens": result.generated_tokens,
            "elapsedMs": elapsed_ms,
            "parsedJson": parsed_json if require_json else None,
        },
        reason=reason,
        claim_kind="observation",
        limitations=(
            "Text production does not establish code correctness, security, or semantic quality.",
        ),
    )


def _install_legacy_pickle_aliases() -> None:
    """Map old ``craftsec`` pickle globals onto the current Bug Dhor classes.

    The research SAE artifacts were generated before the repository rename.
    Their training metadata references ``craftsec.sae.*``; without these aliases
    ``torch.load`` cannot reconstruct the metadata even though the tensors and
    SAE configuration are local and trusted.
    """
    from bugdhor.sae import config as sae_config
    from bugdhor.sae import metrics as sae_metrics
    from bugdhor.sae import training as sae_training

    if "craftsec" not in sys.modules:
        package = types.ModuleType("craftsec")
        package.__path__ = []
        sys.modules["craftsec"] = package
    if "craftsec.sae" not in sys.modules:
        subpackage = types.ModuleType("craftsec.sae")
        subpackage.__path__ = []
        sys.modules["craftsec.sae"] = subpackage
    for name, module in (
        ("craftsec.sae.config", sae_config),
        ("craftsec.sae.metrics", sae_metrics),
        ("craftsec.sae.training", sae_training),
    ):
        sys.modules.setdefault(name, module)
        setattr(sys.modules["craftsec.sae"], name.rsplit(".", 1)[-1], module)


def _load_sae(
    target: Mapping[str, Any], config_dir: Path, hidden_size: int
) -> tuple[SparseAutoencoder | None, CapabilityProbe]:
    artifacts = target.get("saeArtifacts") or []
    if not artifacts:
        return None, CapabilityProbe(
            capability=Capability.SAE_COMPATIBILITY,
            status=ProbeStatus.UNAVAILABLE,
            reason="no SAE artifact declared for this model target",
            limitations=("LIM-SAE-01",),
        )
    artifact = artifacts[0]
    path = (config_dir / artifact["path"]).resolve()
    if not path.is_file():
        return None, CapabilityProbe(
            capability=Capability.SAE_COMPATIBILITY,
            status=ProbeStatus.UNAVAILABLE,
            reason=f"SAE artifact not found: {path}",
            limitations=("LIM-SAE-01",),
        )
    _install_legacy_pickle_aliases()
    sae, _training = load_checkpoint(path)
    config = sae.config
    dimensions_match = int(config.input_dim) == int(hidden_size)
    decoder = sae.decoder.weight.detach().cpu()
    finite = bool(torch.isfinite(decoder).all())
    hook_declared = str(artifact.get("hookPoint", "")).strip() != ""
    status = (
        ProbeStatus.SUPPORTED
        if dimensions_match and finite and hook_declared
        else ProbeStatus.PARTIAL
    )
    probe = CapabilityProbe(
        capability=Capability.SAE_COMPATIBILITY,
        status=status,
        evidence={
            "artifactId": artifact.get("artifactId"),
            "path": path,
            "sha256": _sha256_file(path),
            "configHash": config.config_hash,
            "inputDim": config.input_dim,
            "hiddenSize": hidden_size,
            "latentDim": config.latent_dim,
            "decoderShape": list(decoder.shape),
            "finiteDecoder": finite,
            "declaredHookPoint": artifact.get("hookPoint"),
        },
        reason=None
        if status is ProbeStatus.SUPPORTED
        else "SAE checkpoint dimensions, weights, or hook declaration did not fully validate",
        claim_kind="computed",
        limitations=(
            "Checkpoint validation covers config hash, input dimension, and finite weights.",
            "Hook point is declared by the config; the checkpoint format does not embed it.",
            "LIM-SAE-01: features are tied to one model revision, layer, and hook.",
        ),
    )
    return sae, probe


def _intervention_probes(
    *,
    target: Mapping[str, Any],
    adapter: _SnapshotAdapter,
    sae: SparseAutoencoder | None,
    layer: str | None,
    generation: GenerationConfig,
    prompt: str,
) -> list[CapabilityProbe]:
    unavailable_reason = None
    if sae is None:
        unavailable_reason = "SAE artifact unavailable"
    elif layer is None:
        unavailable_reason = "compatible intervention layer unavailable"
    if unavailable_reason:
        return [
            CapabilityProbe(
                capability=capability,
                status=ProbeStatus.UNAVAILABLE,
                reason=unavailable_reason,
            )
            for capability in (
                Capability.COUNTERFACTUAL_INTERVENTION,
                Capability.TOKEN_LEVEL_INTERVENTION,
                Capability.ACTIVATION_STEERING,
            )
        ]

    from bugdhor.counterfactual.engine import CounterfactualEngine, CounterfactualSpec
    from bugdhor.steering.engine import ActivationSteeringEngine, SteeringSpec

    cf_settings = target.get("counterfactual", {})
    feature_index = int(cf_settings.get("featureIndex", 0))
    seed = int(os.environ.get("BUGDHOR_COMPATIBILITY_SEED", "17"))
    experiment_id = f"compat-{target['targetId']}"

    def run_counterfactual() -> CapabilityProbe:
        engine = CounterfactualEngine(
            adapter,
            sae,
            layer=layer,
            sae_checkpoint=str(target.get("saeArtifacts", [{}])[0].get("artifactId", "unknown")),
            experiment_id=experiment_id,
            seed=seed,
        )
        result = engine.run(
            prompt,
            CounterfactualSpec(
                feature_index=feature_index,
                mode="ablate",
                target_positions=(0,),
            ),
            generation=generation,
        )
        delta = result.activation.feature_delta
        return CapabilityProbe(
            capability=Capability.COUNTERFACTUAL_INTERVENTION,
            status=ProbeStatus.SUPPORTED
            if math.isfinite(delta) and result.metadata.target_positions == (0,)
            else ProbeStatus.PARTIAL,
            evidence={
                "experimentId": result.metadata.experiment_id,
                "layer": result.metadata.layer,
                "featureIndex": result.metadata.feature_index,
                "mode": result.metadata.intervention_mode,
                "targetPositions": result.metadata.target_positions,
                "baselineValues": list(result.activation.baseline_values),
                "interventionValues": list(result.activation.intervention_values),
                "featureDelta": delta,
                "outputChanged": result.comparison.output_changed,
            },
            reason="Controlled activation comparison only; no causal claim.",
            claim_kind="hypothesis",
            limitations=("LIM-CF-01", "LIM-CF-03"),
        )

    def run_token_level() -> CapabilityProbe:
        # Reuse the position-indexed counterfactual result: the engine records
        # measured values for exactly the requested token position.
        engine = CounterfactualEngine(
            adapter,
            sae,
            layer=layer,
            sae_checkpoint=str(target.get("saeArtifacts", [{}])[0].get("artifactId", "unknown")),
            experiment_id=f"{experiment_id}-token",
            seed=seed,
        )
        result = engine.run(
            prompt,
            CounterfactualSpec(
                feature_index=feature_index,
                mode="ablate",
                target_positions=(0,),
            ),
            generation=generation,
        )
        positions = result.metadata.target_positions or ()
        measured = len(result.activation.intervention_values)
        return CapabilityProbe(
            capability=Capability.TOKEN_LEVEL_INTERVENTION,
            status=ProbeStatus.SUPPORTED
            if positions == (0,) and measured == 1
            else ProbeStatus.PARTIAL,
            evidence={
                "requestedPositions": [0],
                "recordedPositions": list(positions),
                "measuredValues": measured,
                "baselineValues": list(result.activation.baseline_values),
                "interventionValues": list(result.activation.intervention_values),
            },
            reason="Position-indexed intervention with measured post-intervention values.",
            claim_kind="computed",
            limitations=("HTTP schemas do not expose arbitrary token positions.",),
        )

    def run_steering() -> CapabilityProbe:
        engine = ActivationSteeringEngine(
            adapter,
            sae,
            layer=layer,
            sae_checkpoint=str(target.get("saeArtifacts", [{}])[0].get("artifactId", "unknown")),
            experiment_id=f"{experiment_id}-steer",
            seed=seed,
        )
        result = engine.run(
            prompt,
            SteeringSpec(
                feature_indices=(feature_index,),
                strengths=(0.5,),
                target_positions=(0,),
                enabled=True,
                max_delta_norm=1.5,
            ),
            generation=generation,
        )
        validation = result.validation
        return CapabilityProbe(
            capability=Capability.ACTIVATION_STEERING,
            status=ProbeStatus.SUPPORTED
            if validation.enabled
            and validation.compatible
            and validation.finite
            and validation.shape_valid
            else ProbeStatus.PARTIAL,
            evidence={
                "enabled": validation.enabled,
                "layer": validation.layer,
                "compatible": validation.compatible,
                "finite": validation.finite,
                "shapeValid": validation.shape_valid,
                "maxDeltaNorm": validation.max_delta_norm,
                "outputChanged": result.comparison.output_changed,
                "activationDeltas": list(result.activation_deltas),
            },
            reason="Steering changes output behavior; it does not establish a security gain.",
            claim_kind="hypothesis",
            limitations=("LIM-STEER-01", "LIM-STEER-02"),
        )

    return [
        _probe(Capability.COUNTERFACTUAL_INTERVENTION, run_counterfactual, claim_kind="hypothesis"),
        _probe(Capability.TOKEN_LEVEL_INTERVENTION, run_token_level, claim_kind="computed"),
        _probe(Capability.ACTIVATION_STEERING, run_steering, claim_kind="hypothesis"),
    ]


def run_probes_for_adapter(
    *,
    target: Mapping[str, Any],
    adapter: _SnapshotAdapter,
    config: Mapping[str, Any],
    config_dir: Path,
    snapshot: Path,
    hardware: dict[str, Any],
) -> tuple[tuple[CapabilityProbe, ...], tuple[str, ...]]:
    """Run all ten probes against a loaded local Transformers adapter."""
    generation = _generation_config(config)
    prompts = config.get("prompts", {})
    code_prompt = str(prompts.get("codeGeneration", "Write a Python function."))
    analysis_prompt = str(prompts.get("codeAnalysis", "Analyze this code."))
    secure_prompt = str(prompts.get("secureCodeGeneration", "Write defensive Python code."))

    manager = ModelManager(adapter_factory=lambda _: adapter)
    manager.load(ModelConfig(model="compatibility-probe"))
    engine = InferenceEngine(manager)

    discovered = LayerDiscovery.discover(adapter.model)
    hidden_size = int(getattr(adapter.model.config, "hidden_size", 0) or 0)
    requested_layer = int(
        (target.get("counterfactual") or {}).get("layer")
        or (target.get("saeArtifacts") or [{}])[0].get("layer")
        or 0
    )
    layer = None
    if 0 <= requested_layer < len(discovered):
        layer = discovered[requested_layer]

    hardware.update(
        {
            "observedDevice": adapter.device,
            "observedDtype": str(next(adapter.model.parameters()).dtype).replace("torch.", ""),
            "architecture": list(getattr(adapter.model.config, "architectures", []) or []),
            "tokenizerClass": type(adapter.tokenizer).__name__,
            "hiddenSize": hidden_size,
            "discoveredLayerCount": len(discovered),
            "discoveredLayers": list(discovered),
            "selectedLayer": layer,
            "modelBytes": sum(
                path.stat().st_size for path in snapshot.rglob("*") if path.is_file()
            ),
            "peakRssMb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024, 2),
        }
    )

    def activation_probe() -> CapabilityProbe:
        if layer is None:
            return CapabilityProbe(
                capability=Capability.ACTIVATION_EXTRACTION,
                status=ProbeStatus.UNAVAILABLE,
                reason="requested layer index was not discovered",
            )
        batches = adapter.collect_activations([code_prompt], layer_names=(layer,), batch_size=1)
        values = batches[0].activations[layer]
        valid = (
            tuple(values.shape)[0] == 1
            and tuple(values.shape)[-1] == hidden_size
            and not values.requires_grad
            and values.device.type == "cpu"
        )
        return CapabilityProbe(
            capability=Capability.ACTIVATION_EXTRACTION,
            status=ProbeStatus.SUPPORTED if valid else ProbeStatus.PARTIAL,
            evidence={
                "layer": layer,
                "shape": list(values.shape),
                "dtype": str(values.dtype).replace("torch.", ""),
                "device": str(values.device),
                "requiresGrad": bool(values.requires_grad),
                "provenance": asdict(batches[0].metadata),
            },
            reason=None if valid else "activation tensor did not satisfy the collector contract",
            claim_kind="observation",
            limitations=("Activation presence does not imply semantic feature validity.",),
        )

    def reproducibility_probe() -> CapabilityProbe:
        seed = int(os.environ.get("BUGDHOR_COMPATIBILITY_SEED", "17"))
        hashes: list[str] = []
        for _ in range(int(config.get("generation", {}).get("repetitions", 2))):
            torch.manual_seed(seed)
            result = engine.generate(code_prompt, generation=generation)
            hashes.append(_sha256_text(result.text))
        identical = len(set(hashes)) == 1
        return CapabilityProbe(
            capability=Capability.OUTPUT_REPRODUCIBILITY,
            status=ProbeStatus.SUPPORTED if identical else ProbeStatus.PARTIAL,
            evidence={
                "outputHashes": hashes,
                "identical": identical,
                "determinismTier": "seeded" if identical else "nondeterministic",
                "doSample": generation.do_sample,
                "device": adapter.device,
            },
            reason=None
            if identical
            else "repeated greedy generations differed on this host",
            claim_kind="observation",
            limitations=(
                "This result does not establish determinism on other hardware or library versions.",
            ),
        )

    sae, sae_probe = _load_sae(target, config_dir, hidden_size)
    probes = [
        _probe(
            Capability.CODE_GENERATION,
            lambda: _generation_probe(
                engine, Capability.CODE_GENERATION, code_prompt, generation
            ),
        ),
        _probe(
            Capability.CODE_ANALYSIS,
            lambda: _generation_probe(
                engine,
                Capability.CODE_ANALYSIS,
                analysis_prompt,
                generation,
                require_json=True,
            ),
        ),
        _probe(
            Capability.SECURE_CODE_GENERATION,
            lambda: _generation_probe(
                engine, Capability.SECURE_CODE_GENERATION, secure_prompt, generation
            ),
        ),
        _probe(Capability.ACTIVATION_EXTRACTION, activation_probe, claim_kind="observation"),
        sae_probe,
        *_intervention_probes(
            target=target,
            adapter=adapter,
            sae=sae,
            layer=layer,
            generation=generation,
            prompt=code_prompt,
        ),
        _probe(
            Capability.OUTPUT_REPRODUCIBILITY, reproducibility_probe, claim_kind="observation"
        ),
        CapabilityProbe(
            capability=Capability.HARDWARE_INFERENCE_LIMITS,
            status=ProbeStatus.SUPPORTED,
            evidence=hardware,
            reason="Measured from the loaded checkpoint and host runtime.",
            claim_kind="observation",
            limitations=(
                "Production DevicePreference has no MPS option; these direct probes use CPU.",
                "gpu_concurrency is configured but not enforced by the production runtime.",
            ),
        ),
    ]
    return tuple(probes), _LIMITATIONS


def probe_transformers_target(
    *,
    target: Mapping[str, Any],
    config: Mapping[str, Any],
    config_dir: Path,
    snapshot: Path,
) -> tuple[tuple[CapabilityProbe, ...], dict[str, Any], tuple[str, ...]]:
    """Load an already-downloaded checkpoint and run independent probes."""
    started = time.perf_counter()
    torch.manual_seed(int(os.environ.get("BUGDHOR_COMPATIBILITY_SEED", "17")))
    model = AutoModelForCausalLM.from_pretrained(
        str(snapshot),
        local_files_only=True,
        torch_dtype=torch.float32,
        trust_remote_code=False,
    )
    tokenizer = AutoTokenizer.from_pretrained(
        str(snapshot),
        local_files_only=True,
        trust_remote_code=False,
    )
    model.eval()
    adapter = _SnapshotAdapter(
        model=model,
        tokenizer=tokenizer,
        model_id=str(target["checkpointIdentifier"]),
        model_version=str(target.get("revision") or "unresolved"),
        device="cpu",
        torch_module=torch,
    )
    hardware: dict[str, Any] = {
        "loadMs": round((time.perf_counter() - started) * 1000, 2),
        "torchVersion": torch.__version__,
        "cudaAvailable": bool(torch.cuda.is_available()),
        "mpsAvailable": bool(torch.backends.mps.is_available()),
        "declaredDevice": config.get("environment", {}).get("device"),
    }
    try:
        probes, limitations = run_probes_for_adapter(
            target=target,
            adapter=adapter,
            config=config,
            config_dir=config_dir,
            snapshot=snapshot,
            hardware=hardware,
        )
        return probes, hardware, limitations
    finally:
        adapter.unload()
        gc.collect()


def probe_registered_adapter(
    *,
    target: Mapping[str, Any],
    config: Mapping[str, Any],
    config_dir: Path,
    snapshot: Path,
) -> tuple[tuple[CapabilityProbe, ...], dict[str, Any], tuple[str, ...]]:
    """Load a production registry adapter from an already-present checkpoint."""
    from bugdhor.models.config import DevicePreference
    from bugdhor.models.huggingface import HuggingFaceAdapter

    model_config = ModelConfig(
        model=str(target.get("registryKey") or target["checkpointIdentifier"]),
        device=DevicePreference.CPU,
        model_path=str(snapshot),
        revision=target.get("revision"),
        local_files_only=True,
        torch_dtype="float32",
    )
    adapter_instance = HuggingFaceAdapter(model_config)
    adapter = _SnapshotAdapter(
        model=adapter_instance.model,
        tokenizer=adapter_instance.tokenizer,
        model_id=adapter_instance.model_id,
        model_version=adapter_instance.model_version,
        device=adapter_instance.device,
        torch_module=torch,
    )
    hardware: dict[str, Any] = {
        "runtime": "bugdhor_adapter",
        "torchVersion": torch.__version__,
        "cudaAvailable": bool(torch.cuda.is_available()),
        "mpsAvailable": bool(torch.backends.mps.is_available()),
    }
    try:
        probes, limitations = run_probes_for_adapter(
            target=target,
            adapter=adapter,
            config=config,
            config_dir=config_dir,
            snapshot=snapshot,
            hardware=hardware,
        )
        return probes, hardware, limitations
    finally:
        adapter_instance.unload()
        gc.collect()


__all__ = ["probe_registered_adapter", "probe_transformers_target", "run_probes_for_adapter"]
