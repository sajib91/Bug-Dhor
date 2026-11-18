"""Experiment group definitions for Bug Dhor evaluation."""

from __future__ import annotations

EXPERIMENT_GROUPS: dict[str, str] = {
    "E0": "Original LLM (no security-specific intervention)",
    "E1": "Security prompting baseline",
    "E2": "Static-analysis baseline",
    "E3": "Single-feature SAE steering",
    "E4": "Multi-feature analysis",
    "E5": "Interaction-aware steering",
    "E6": "Automated repair",
    "E7": "Steering plus repair",
    "E8": "Full Bug Dhor framework",
}


GROUP_REQUIREMENTS: dict[str, dict[str, object]] = {
    "E0": {"requires_sae": False, "requires_repair": False, "requires_static": False},
    "E1": {"requires_sae": False, "requires_repair": False, "requires_static": False},
    "E2": {"requires_sae": False, "requires_repair": False, "requires_static": True},
    "E3": {"requires_sae": True, "requires_repair": False, "requires_static": False},
    "E4": {"requires_sae": True, "requires_repair": False, "requires_static": False},
    "E5": {"requires_sae": True, "requires_repair": False, "requires_static": False},
    "E6": {"requires_sae": False, "requires_repair": True, "requires_static": False},
    "E7": {"requires_sae": True, "requires_repair": True, "requires_static": False},
    "E8": {"requires_sae": True, "requires_repair": True, "requires_static": True},
}


def list_groups() -> list[dict[str, object]]:
    return [
        {"id": gid, "description": desc, "requirements": GROUP_REQUIREMENTS.get(gid, {})}
        for gid, desc in EXPERIMENT_GROUPS.items()
    ]


__all__ = ["EXPERIMENT_GROUPS", "GROUP_REQUIREMENTS", "list_groups"]
