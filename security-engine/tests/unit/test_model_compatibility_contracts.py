"""Contract tests for evidence-backed model compatibility reports."""

from __future__ import annotations

from bugdhor.models.compatibility import (
    Capability,
    CapabilityProbe,
    CompatibilityReport,
    ModelCapabilityCard,
    ProbeStatus,
    model_capability_card_from_dict,
)


def test_capability_probe_serialization_preserves_observations() -> None:
    probe = CapabilityProbe(
        capability=Capability.ACTIVATION_EXTRACTION,
        status=ProbeStatus.SUPPORTED,
        evidence={"layer": 4, "shape": [12, 896]},
        claim_kind="observation",
        limitations=("LIM-SAE-01",),
    )
    payload = probe.to_dict()
    assert payload["capability"] == "activation_extraction"
    assert payload["status"] == "supported"
    assert payload["evidence"]["shape"] == [12, 896]
    assert payload["claimKind"] == "observation"
    assert payload["limitations"] == ["LIM-SAE-01"]


def test_model_card_round_trip_distinguishes_declared_and_observed() -> None:
    card = ModelCapabilityCard(
        target_id="probe-1",
        name="Example",
        checkpoint_identifier="org/example",
        provider_identifier=None,
        version=None,
        revision="abc123",
        architecture="ExampleForCausalLM",
        tokenizer="ExampleTokenizerFast",
        available_layers=(0, 1, 2),
        activation_access=ProbeStatus.SUPPORTED,
        sae_compatibility=ProbeStatus.UNAVAILABLE,
        steering_compatibility=ProbeStatus.NOT_RUN,
        hardware_requirements={"device": "cpu"},
        inference_limitations=("no MPS support in adapter",),
        runtime="transformers_direct",
        probes=(
            CapabilityProbe(Capability.CODE_GENERATION, ProbeStatus.SUPPORTED),
            CapabilityProbe(Capability.SAE_COMPATIBILITY, ProbeStatus.UNAVAILABLE),
        ),
        declared_capabilities=("code_generation", "sae_compatibility"),
    )
    restored = model_capability_card_from_dict(card.to_dict())
    assert restored == card
    observed = {probe.capability: probe.status for probe in restored.probes}
    assert observed[Capability.SAE_COMPATIBILITY] is ProbeStatus.UNAVAILABLE
    assert "sae_compatibility" in restored.declared_capabilities


def test_report_serializes_camel_case_contract() -> None:
    report = CompatibilityReport(
        schema_version="1.0.0",
        generated_at="2026-11-18T00:00:00Z",
        config_hash="abc",
        git_commit=None,
        environment={"platform": "test"},
        models=(),
        assistant_integrations=(),
        limitations=("LIM-ENV-01",),
        claim_boundary="Only observed probes are reported as supported.",
    )
    payload = report.to_dict()
    assert payload["schemaVersion"] == "1.0.0"
    assert payload["generatedAt"].endswith("Z")
    assert payload["configHash"] == "abc"
    assert payload["gitCommit"] is None
    assert payload["claimBoundary"] == "Only observed probes are reported as supported."
