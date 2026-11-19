from dataclasses import dataclass, field

from .ir import IRProgram
from .models import (
    CallEdge,
    ControlFlowGraph,
    DataFlowResult,
    Definition,
    FunctionSummary,
    ScopeDataFlow,
    Use,
)
from .profiles import LanguageProfile
from .scopes import ScopeAnalysis


LIMITATIONS = (
    "Flow facts are computed per syntax scope; heap objects, aliases, "
    "and attribute mutations are not modelled by the core data-flow pass.",
    "Interprocedural data flow adds bounded call-site mapping in the taint "
    "pass; core reaching definitions remain intra-procedural.",
    "Exception edges are conservative and do not model abrupt control "
    "flow through finally blocks precisely.",
    "Comprehension and lambda scopes have symbol data but no separate "
    "control-flow graph.",
)


@dataclass
class _FlowFacts:
    definitions: dict[str, Definition] = field(default_factory=dict)
    uses: dict[str, Use] = field(default_factory=dict)
    defs_by_statement: dict[str, list[str]] = field(
        default_factory=dict
    )
    uses_by_statement: dict[str, list[str]] = field(
        default_factory=dict
    )
    keys_by_def: dict[str, str] = field(default_factory=dict)
    keys_by_use: dict[str, str] = field(default_factory=dict)
    names_by_def: dict[str, str] = field(default_factory=dict)
    names_by_use: dict[str, str] = field(default_factory=dict)
    names_by_key: dict[str, str] = field(default_factory=dict)
    literals_by_def: dict[str, str | None] = field(
        default_factory=dict
    )
    scope_data: dict[str, ScopeDataFlow] = field(
        default_factory=dict
    )


class DataFlowAnalyzer:
    """Compute reaching definitions, liveness, and dependency chains."""

    def __init__(
        self,
        scope_analysis: ScopeAnalysis,
        ir_program: IRProgram,
        cfgs: list[ControlFlowGraph],
        profile: LanguageProfile,
    ) -> None:
        self.scope_analysis = scope_analysis
        self.ir_program = ir_program
        self.cfgs = cfgs
        self.profile = profile
        self.facts = _FlowFacts()
        self.result = DataFlowResult(limitations=LIMITATIONS)

    def analyze(self) -> DataFlowResult:
        self._build_facts()
        self._analyze_graphs()
        self._build_call_edges()
        self._build_summaries()
        self.result.scopes = [
            self.facts.scope_data[scope.id]
            for scope in self.scope_analysis.scopes
        ]
        return self.result

    def _build_facts(self) -> None:
        for scope in self.scope_analysis.scopes:
            self.facts.scope_data[scope.id] = ScopeDataFlow(
                scope_id=scope.id
            )

        for statement_id, declarations in (
            self.scope_analysis.declarations_by_statement.items()
        ):
            for index, declaration in enumerate(declarations):
                definition_id = (
                    f"def:{declaration.symbol_id or declaration.name}:"
                    f"{statement_id}:{index}"
                )
                symbol = self.scope_analysis.symbol(
                    declaration.symbol_id
                )
                definition = Definition(
                    id=definition_id,
                    name=declaration.name,
                    symbol_id=declaration.symbol_id,
                    scope_id=(
                        symbol.scope_id
                        if symbol
                        else self.scope_analysis.scope_for(
                            declaration.node
                        )
                    ),
                    statement_id=statement_id,
                    location=declaration.location,
                    kind=declaration.kind,
                )
                self.facts.definitions[definition_id] = definition
                self.facts.keys_by_def[definition_id] = (
                    declaration.symbol_id
                    or f"name:{declaration.name}"
                )
                self.facts.names_by_def[definition_id] = (
                    declaration.name
                )
                self.facts.names_by_key[
                    self.facts.keys_by_def[definition_id]
                ] = declaration.name
                self.facts.defs_by_statement.setdefault(
                    statement_id, []
                ).append(definition_id)
                statement = self.ir_program.by_id.get(statement_id)
                self.facts.literals_by_def[definition_id] = (
                    statement.literal if statement else None
                )
                self.facts.scope_data[
                    definition.scope_id
                ].definitions.append(definition)

        for statement_id, uses in (
            self.scope_analysis.uses_by_statement.items()
        ):
            for index, use in enumerate(uses):
                use_id = (
                    f"use:{use.symbol_id or use.name}:"
                    f"{statement_id}:{index}"
                )
                symbol = self.scope_analysis.symbol(use.symbol_id)
                record = Use(
                    id=use_id,
                    name=use.name,
                    symbol_id=use.symbol_id,
                    scope_id=(
                        symbol.scope_id
                        if symbol
                        else self.scope_analysis.scope_for(
                            use.node
                        )
                    ),
                    statement_id=statement_id,
                    location=use.location,
                    kind=use.kind,
                )
                self.facts.uses[use_id] = record
                self.facts.keys_by_use[use_id] = (
                    use.symbol_id or f"name:{use.name}"
                )
                self.facts.names_by_use[use_id] = use.name
                self.facts.names_by_key[
                    self.facts.keys_by_use[use_id]
                ] = use.name
                self.facts.uses_by_statement.setdefault(
                    statement_id, []
                ).append(use_id)
                self.facts.scope_data[
                    record.scope_id
                ].uses.append(record)

    def _statement_for_node(self, node_id: str):
        cfg_node = next(
            (
                item
                for graph in self.cfgs
                for item in graph.nodes.values()
                if item.id == node_id
            ),
            None,
        )
        if cfg_node is None or not cfg_node.statement_id:
            return None
        return self.ir_program.by_id.get(cfg_node.statement_id)

    def _analyze_graphs(self) -> None:
        for graph in self.cfgs:
            node_ids = sorted(graph.nodes)
            graph_defs = {
                definition_id
                for node_id in node_ids
                for statement_id in [
                    (
                        graph.nodes[node_id].statement_id
                        if node_id in graph.nodes
                        else ""
                    )
                ]
                for definition_id in self.facts.defs_by_statement.get(
                    statement_id, []
                )
            }
            gen_defs: dict[str, set[str]] = {}
            kill_defs: dict[str, set[str]] = {}
            gen_uses: dict[str, set[str]] = {}
            use_keys: dict[str, set[str]] = {}
            def_keys: dict[str, set[str]] = {}

            for node_id in node_ids:
                statement = self._statement_for_node(node_id)
                statement_id = (
                    statement.id if statement is not None else ""
                )
                definitions = set(
                    self.facts.defs_by_statement.get(
                        statement_id, []
                    )
                )
                uses = set(
                    self.facts.uses_by_statement.get(
                        statement_id, []
                    )
                )
                gen_defs[node_id] = definitions
                gen_uses[node_id] = uses
                keys = {
                    self.facts.keys_by_def[item]
                    for item in definitions
                }
                kill_defs[node_id] = {
                    item
                    for item in graph_defs
                    if self.facts.keys_by_def[item] in keys
                } - definitions
                def_keys[node_id] = keys
                use_keys[node_id] = {
                    self.facts.keys_by_use[item] for item in uses
                }

            in_state: dict[str, set[str]] = {
                node_id: set() for node_id in node_ids
            }
            out_state: dict[str, set[str]] = {
                node_id: set() for node_id in node_ids
            }
            changed = True
            while changed:
                changed = False
                for node_id in node_ids:
                    incoming: set[str] = set()
                    for predecessor in graph.nodes[
                        node_id
                    ].predecessors:
                        incoming |= out_state[predecessor]
                    new_out = (
                        incoming - kill_defs[node_id]
                    ) | gen_defs[node_id]
                    if (
                        incoming != in_state[node_id]
                        or new_out != out_state[node_id]
                    ):
                        in_state[node_id] = incoming
                        out_state[node_id] = new_out
                        changed = True

            live_in: dict[str, set[str]] = {
                node_id: set() for node_id in node_ids
            }
            live_out: dict[str, set[str]] = {
                node_id: set() for node_id in node_ids
            }
            changed = True
            while changed:
                changed = False
                for node_id in reversed(node_ids):
                    outgoing: set[str] = set()
                    for successor in graph.nodes[node_id].successors:
                        outgoing |= live_in[successor]
                    new_in = use_keys[node_id] | (
                        outgoing - def_keys[node_id]
                    )
                    if (
                        new_in != live_in[node_id]
                        or outgoing != live_out[node_id]
                    ):
                        live_in[node_id] = new_in
                        live_out[node_id] = outgoing
                        changed = True

            scope_data = self.facts.scope_data.get(graph.scope_id)
            if scope_data is None:
                continue
            for node_id in node_ids:
                statement = self._statement_for_node(node_id)
                if statement is None:
                    continue
                scope_data.reaching_definitions[statement.id] = sorted(
                    in_state[node_id]
                )
                scope_data.live_variables[statement.id] = {
                    "in": sorted(
                        {
                            self.facts.names_by_key[item]
                            for item in live_in[node_id]
                            if item in self.facts.names_by_key
                        }
                    ),
                    "out": sorted(
                        {
                            self.facts.names_by_key[item]
                            for item in live_out[node_id]
                            if item in self.facts.names_by_key
                        }
                    ),
                }

                for use_id in self.facts.uses_by_statement.get(
                    statement.id, []
                ):
                    key = self.facts.keys_by_use[use_id]
                    matching = [
                        definition_id
                        for definition_id in in_state[node_id]
                        if self.facts.keys_by_def[definition_id]
                        == key
                    ]
                    scope_data.def_use_chains[use_id] = sorted(
                        matching
                    )
                    for definition_id in matching:
                        scope_data.use_def_chains.setdefault(
                            definition_id, []
                        ).append(use_id)

                used_names = {
                    self.facts.names_by_use[item]
                    for item in self.facts.uses_by_statement.get(
                        statement.id, []
                    )
                }
                for definition_id in self.facts.defs_by_statement.get(
                    statement.id, []
                ):
                    name = self.facts.names_by_def[definition_id]
                    scope_data.dependencies[definition_id] = sorted(
                        used_names - {name}
                    )
                    scope_data.assignment_propagation[
                        definition_id
                    ] = self.facts.literals_by_def.get(definition_id)

            for definition_id, use_ids in scope_data.use_def_chains.items():
                scope_data.use_def_chains[definition_id] = sorted(
                    set(use_ids)
                )

    def _build_summaries(self) -> None:
        module_scope_id = self.scope_analysis.scopes[0].id
        call_sites_by_callee: dict[str, set[str]] = {}
        for edge in self.result.call_edges:
            if edge.callee_symbol_id:
                call_sites_by_callee.setdefault(
                    edge.callee_symbol_id, set()
                ).add(edge.statement_id)
            call_sites_by_callee.setdefault(
                f"name:{edge.callee_name}", set()
            ).add(edge.statement_id)
        for scope in self.scope_analysis.scopes:
            if scope.kind not in {"function", "lambda"}:
                continue
            parameters = [
                symbol.name
                for symbol in self.scope_analysis.symbols
                if symbol.scope_id == scope.id
                and symbol.symbol_type == "parameter"
            ]
            returns: list[str] = []
            calls: set[str] = set()
            globals_used: set[str] = set()
            for statement in self.ir_program.statements:
                if statement.scope_id != scope.id:
                    continue
                calls.update(statement.calls)
                for use_id in self.facts.uses_by_statement.get(
                    statement.id, []
                ):
                    record = self.facts.uses[use_id]
                    if record.symbol_id:
                        symbol = self.scope_analysis.symbol(
                            record.symbol_id
                        )
                        if (
                            symbol
                            and symbol.scope_id == module_scope_id
                        ):
                            globals_used.add(symbol.name)
                    if statement.kind == "return":
                        returns.append(record.name)
            callee = next(
                (
                    symbol.id
                    for symbol in self.scope_analysis.symbols
                    if symbol.symbol_type
                    in {"function", "method"}
                    and symbol.name == scope.name
                    and symbol.scope_id == scope.parent_id
                ),
                "",
            )
            call_sites = set(call_sites_by_callee.get(callee, set()))
            call_sites |= call_sites_by_callee.get(
                f"name:{scope.name}", set()
            )
            self.result.function_summaries.append(
                FunctionSummary(
                    symbol_id=callee,
                    name=scope.name,
                    parameters=tuple(sorted(parameters)),
                    returns=", ".join(sorted(set(returns))) or None,
                    calls=tuple(sorted(calls)),
                    globals_used=tuple(sorted(globals_used)),
                    call_sites=tuple(sorted(call_sites)),
                )
            )

    def _build_call_edges(self) -> None:
        for call in self.scope_analysis.calls:
            self.result.call_edges.append(
                CallEdge(
                    caller_scope_id=self.scope_analysis.scope_for(
                        call.node
                    ),
                    callee_symbol_id=call.symbol_id or "",
                    callee_name=call.name,
                    statement_id=call.statement_id,
                )
            )
