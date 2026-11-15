"""CFG and DFG context used to corroborate or refute candidate findings.

Context evidence is deliberately asymmetric. An unreachable sink is a strong
refutation; merely reaching a sink is *not* support, because reachability is a
precondition for almost every statement. Data-flow corroboration is kept weak
so it cannot turn a syntactic pattern into a high-risk finding by itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import networkx as nx

from craftsec.detection.config import FusionWeights
from craftsec.detection.models import (
    ClaimKind,
    EvidenceFamily,
    EvidenceItem,
    EvidenceLocation,
    EvidencePolarity,
    EvidenceType,
    VulnerabilityCategory,
)
from craftsec.parsing.models import SourceSpan
from craftsec.parsing.parser import ParsedSource
from craftsec.program_analysis.analysis import ProgramAnalysis
from craftsec.program_analysis.cfg import ControlFlowGraph
from craftsec.program_analysis.models import DFGNodeKind
from craftsec.program_analysis.taint import TaintAnalysis

_CATEGORY_TAINT_KINDS = {
    VulnerabilityCategory.SQL_INJECTION: {"sql_injection"},
    VulnerabilityCategory.COMMAND_INJECTION: {"command_injection"},
    VulnerabilityCategory.CODE_INJECTION: {"command_injection"},
    VulnerabilityCategory.XSS: {"xss"},
    VulnerabilityCategory.PATH_TRAVERSAL: {"path_traversal"},
    VulnerabilityCategory.UNSAFE_DESERIALIZATION: {"unsafe_deserialization"},
}


@dataclass(frozen=True, slots=True)
class ContextAssessor:
    """Assess one candidate location against CFG and DFG products."""

    parsed: ParsedSource
    path: str
    analysis: ProgramAnalysis | None = None
    taint: TaintAnalysis | None = None
    config_hash: str | None = None

    @property
    def cfg(self) -> tuple[ControlFlowGraph, ...]:
        if self.analysis is not None:
            return self.analysis.cfg.functions
        if self.taint is not None:
            return self.taint.cfg.functions
        return ()

    def assess(
        self,
        location: EvidenceLocation,
        category: VulnerabilityCategory,
        *,
        weights: FusionWeights,
        has_taint_flow: bool,
        enrich_cfg: bool = True,
        enrich_dfg: bool = True,
    ) -> tuple[EvidenceItem, ...]:
        evidence: list[EvidenceItem] = []
        if enrich_cfg:
            evidence.extend(self._cfg_evidence(location))
        if enrich_dfg:
            evidence.extend(self._dfg_evidence(location, weights))
        evidence.extend(
            self._sanitizer_evidence(
                location,
                category,
                has_taint_flow=has_taint_flow,
            )
        )
        return tuple(evidence)

    # ------------------------------------------------------------------ #
    # CFG
    # ------------------------------------------------------------------ #
    def _cfg_evidence(
        self,
        location: EvidenceLocation,
    ) -> tuple[EvidenceItem, ...]:
        for graph in self.cfg:
            for block in graph.blocks:
                if block.kind.value != "basic" or not block.statements:
                    continue
                if not _span_contains(block.span, location):
                    continue
                reachable = nx.has_path(graph.graph, graph.entry_id, block.block_id)
                if reachable:
                    return ()
                return (
                    EvidenceItem(
                        evidence_id=_context_id("cfg", location, block.block_id),
                        evidence_type=EvidenceType.CFG,
                        family=EvidenceFamily.PROGRAM_ANALYSIS,
                        claim_kind=ClaimKind.OBSERVATION,
                        source="craftsec.cfg",
                        location=location,
                        category=VulnerabilityCategory.UNKNOWN,
                        strength=0.90,
                        reliability=0.95,
                        polarity=EvidencePolarity.REFUTES,
                        severity_hint="info",
                        rule_id="cfg.unreachable-sink",
                        title="Candidate location is unreachable",
                        detail=(
                            f"The basic block {block.block_id!r} in scope "
                            f"{graph.scope_name!r} has no path from the CFG entry. "
                            "Unreachable code cannot be triggered as written."
                        ),
                        config_hash=self.config_hash,
                        limitations=(
                            "CFG reachability is intraprocedural and ignores external "
                            "callers, reflection, and dynamic dispatch.",
                        ),
                    ),
                )
        return ()

    # ------------------------------------------------------------------ #
    # DFG
    # ------------------------------------------------------------------ #
    def _dfg_evidence(
        self,
        location: EvidenceLocation,
        weights: FusionWeights,
    ) -> tuple[EvidenceItem, ...]:
        analysis = self.analysis
        if analysis is None and self.taint is not None:
            dfg = self.taint.dfg
            graphs = (dfg.module, *dfg.functions)
        elif analysis is not None:
            graphs = (analysis.dfg.module, *analysis.dfg.functions)
        else:
            return ()
        for graph in graphs:
            for node in graph.nodes:
                if node.kind not in {
                    DFGNodeKind.DEFINITION,
                    DFGNodeKind.USE,
                    DFGNodeKind.CALL,
                }:
                    continue
                if not _span_contains(node.span, location):
                    continue
                incoming = tuple(graph.graph.in_edges(node.node_id))
                outgoing = tuple(graph.graph.out_edges(node.node_id))
                if not incoming and not outgoing:
                    continue
                return (
                    EvidenceItem(
                        evidence_id=_context_id("dfg", location, node.node_id),
                        evidence_type=EvidenceType.DFG,
                        family=EvidenceFamily.PROGRAM_ANALYSIS,
                        claim_kind=ClaimKind.OBSERVATION,
                        source="craftsec.dfg",
                        location=location,
                        category=VulnerabilityCategory.UNKNOWN,
                        strength=min(0.30, weights.taint * 0.25),
                        reliability=0.75,
                        polarity=EvidencePolarity.SUPPORTS,
                        severity_hint="info",
                        rule_id="dfg.observed-dependency",
                        title="Data-flow dependency observed at the candidate",
                        detail=(
                            f"DFG node {node.node_id!r} ({node.kind.value}) has "
                            f"{len(incoming)} incoming and {len(outgoing)} outgoing "
                            "data-flow edges. This corroborates a dependency but "
                            "does not prove attacker control."
                        ),
                        config_hash=self.config_hash,
                        limitations=("DFG corroboration is intraprocedural and syntactic.",),
                    ),
                )
        return ()

    # ------------------------------------------------------------------ #
    # Sanitizers
    # ------------------------------------------------------------------ #
    def _sanitizer_evidence(
        self,
        location: EvidenceLocation,
        category: VulnerabilityCategory,
        *,
        has_taint_flow: bool,
    ) -> tuple[EvidenceItem, ...]:
        if self.taint is None or has_taint_flow:
            return ()
        allowed_kinds = _CATEGORY_TAINT_KINDS.get(category)
        for site in (*self.taint.sanitizers, *self.taint.validators):
            if allowed_kinds is not None and site.kinds:
                if not any(kind.value in allowed_kinds for kind in site.kinds):
                    continue
            site_location = EvidenceLocation.from_source(site.span, self.path)
            if not _locations_touch(site_location, location):
                if site_location.path != location.path or site_location.line_distance(location) > 3:
                    continue
            return (
                EvidenceItem(
                    evidence_id=_context_id("sanitizer", location, site.site_id),
                    evidence_type=EvidenceType.TAINT,
                    family=EvidenceFamily.PROGRAM_ANALYSIS,
                    claim_kind=ClaimKind.OBSERVATION,
                    source="craftsec.taint.sanitizers",
                    location=site_location,
                    related_locations=(location,),
                    category=category,
                    strength=0.65,
                    reliability=0.85,
                    polarity=EvidencePolarity.REFUTES,
                    severity_hint="info",
                    rule_id=f"taint.observed-{site.role.value}",
                    title=f"Observed {site.role.value} near the candidate",
                    detail=(
                        f"Configuration rule {site.rule!r} identifies a "
                        f"{site.role.value} near this location, while no unsanitized "
                        "source-to-sink flow was found. This lowers, but does not "
                        "eliminate, the finding's risk."
                    ),
                    config_hash=self.config_hash,
                    limitations=(
                        "A sanitizer is only effective for the specific context and "
                        "encoding it implements.",
                    ),
                ),
            )
        return ()


def _span_contains(span: SourceSpan, location: EvidenceLocation) -> bool:
    start = (span.start.line, span.start.character)
    end = (span.end.line, span.end.character)
    return start <= location.start and location.end <= end


def _locations_touch(left: EvidenceLocation, right: EvidenceLocation) -> bool:
    if left.path != right.path:
        return False
    return left.start <= right.end and right.start <= left.end


def _context_id(prefix: str, location: EvidenceLocation, node_id: str) -> str:
    material = "|".join(
        (
            prefix,
            location.path,
            str(location.start_line),
            str(location.start_column),
            str(location.end_line),
            str(location.end_column),
            node_id,
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"ev-ctx-{digest[:20]}"


__all__ = ["ContextAssessor"]
