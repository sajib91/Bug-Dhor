from dataclasses import dataclass, field

from tree_sitter import Node

from .models import (
    AssignmentRecord,
    Reference,
    Scope,
    SourceLocation,
    Symbol,
)
from .profiles import (
    IDENTIFIER_TYPES,
    LanguageProfile,
    is_function_scope_node,
)
from .tree import FlowContext, node_key, statement_id


CALL_NODE_TYPES = {
    "call",
    "call_expression",
    "new_expression",
    "method_invocation",
    "object_creation_expression",
}

PARAMETER_CONTAINER_TYPES = {
    "parameters",
    "lambda_parameters",
    "formal_parameters",
}

BUILTINS = {
    "python": {
        "abs", "all", "any", "bool", "dict", "enumerate", "eval",
        "Exception", "exec", "float", "getattr", "hasattr", "int", "input",
        "isinstance", "len", "list", "max", "min",
        "object", "open", "print", "range", "set", "str", "sum", "super",
        "tuple", "type", "ValueError", "zip", "True", "False", "None",
        "self", "cls",
    },
    "javascript": {
        "Array", "Boolean", "console", "Date", "document", "Error", "JSON",
        "Math", "Number", "Object", "parseFloat", "parseInt", "Promise",
        "require", "setTimeout", "String", "window",
    },
    "java": {
        "ArrayList", "Boolean", "Double", "Exception", "Integer", "List",
        "Math", "Object", "Scanner", "String", "System",
    },
}


@dataclass(frozen=True)
class DeclarationUse:
    symbol_id: str
    name: str
    node: Node
    location: SourceLocation
    kind: str
    statement_id: str
    value_node: Node | None = None


@dataclass(frozen=True)
class UseRecord:
    symbol_id: str | None
    name: str
    node: Node
    location: SourceLocation
    kind: str
    statement_id: str


@dataclass(frozen=True)
class CallRecord:
    name: str
    symbol_id: str | None
    node: Node
    location: SourceLocation
    statement_id: str
    arguments: tuple[str, ...]


@dataclass
class ScopeAnalysis:
    file: str
    language: str
    scopes: list[Scope] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    node_scope: dict[tuple[int, int, str], str] = field(
        default_factory=dict
    )
    scope_root: dict[str, Node] = field(default_factory=dict)
    declarations_by_statement: dict[str, list[DeclarationUse]] = field(
        default_factory=dict
    )
    uses_by_statement: dict[str, list[UseRecord]] = field(
        default_factory=dict
    )
    calls: list[CallRecord] = field(default_factory=list)
    unresolved_references: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def scope_for(self, node: Node) -> str:
        return self.node_scope.get(node_key(node), self.scopes[0].id)

    def symbol(self, symbol_id: str | None) -> Symbol | None:
        if not symbol_id:
            return None
        for symbol in self.symbols:
            if symbol.id == symbol_id:
                return symbol
        return None


class ScopeAnalyzer:
    """Build the scope tree, symbol table, and resolved references."""

    def __init__(
        self,
        context: FlowContext,
        profile: LanguageProfile,
    ) -> None:
        self.context = context
        self.profile = profile
        self.result = ScopeAnalysis(
            file=context.file,
            language=context.language,
        )
        self._scopes_by_id: dict[str, Scope] = {}
        self._symbols_by_key: dict[tuple[str, str], Symbol] = {}
        self._declaration_keys: set[tuple[int, int, str]] = set()
        self._directive_keys: set[tuple[int, int, str]] = set()
        self._directives: dict[str, dict[str, str | None]] = {}
        self._directive_kinds: dict[str, dict[str, str]] = {}
        self._directive_names: dict[str, dict[str, list[Node]]] = {}

    def analyze(self) -> ScopeAnalysis:
        self._create_scopes(self.context.root, None)
        self._collect_directive_names(self.context.root)
        pending: list[tuple] = []
        self._register_all_declarations(
            self.context.root, "", pending
        )
        self._resolve_directive_targets()
        for item in pending:
            self._register_declaration(*item)
        self._register_all_references(self.context.root, "")
        return self.result

    def _add_scope(
        self,
        node: Node,
        kind: str,
        name: str,
        parent_id: str | None,
    ) -> Scope:
        scope_id = f"scope:{kind}:{node.start_byte}:{node.end_byte}"
        location = self.context.location(node)
        scope = Scope(
            id=scope_id,
            kind=kind,
            name=name or "<anonymous>",
            parent_id=parent_id,
            language=self.context.language,
            location=location,
        )
        self._scopes_by_id[scope_id] = scope
        self.result.scopes.append(scope)
        self.result.scope_root[scope_id] = node
        if parent_id is not None:
            parent = self._scopes_by_id[parent_id]
            if scope_id not in parent.children:
                parent.children.append(scope_id)
        return scope

    def _is_function_scope_node(self, node: Node) -> bool:
        return is_function_scope_node(
            node, self.profile, self.context
        )

    def _create_scopes(
        self,
        node: Node,
        current_scope_id: str | None,
    ) -> None:
        key = node_key(node)
        if current_scope_id is None:
            scope = self._add_scope(
                node, "module", "<module>", None
            )
            self.result.node_scope[key] = scope.id
            for child in node.children:
                self._create_scopes(child, scope.id)
            return

        self.result.node_scope[key] = current_scope_id

        if self._is_function_scope_node(node):
            name_node, name, _, _ = self.profile.function_info(
                node, self.context
            )
            kind = (
                "lambda"
                if node.type in {"lambda", "lambda_expression"}
                else "function"
            )
            child = self._add_scope(
                node, kind, self.context.text(name_node) or name,
                current_scope_id,
            )
            if name_node is not None:
                self.result.node_scope[
                    node_key(name_node)
                ] = current_scope_id
            for sub_node in node.children:
                if (
                    name_node is not None
                    and node_key(sub_node) == node_key(name_node)
                ):
                    continue
                self._create_scopes(sub_node, child.id)
            return

        if self.profile.is_class(node):
            name_node, name, _ = self.profile.class_info(
                node, self.context
            )
            child = self._add_scope(
                node,
                "class",
                self.context.text(name_node) or name,
                current_scope_id,
            )
            if name_node is not None:
                self.result.node_scope[
                    node_key(name_node)
                ] = current_scope_id
            for sub_node in node.children:
                if (
                    name_node is not None
                    and node_key(sub_node) == node_key(name_node)
                ):
                    continue
                self._create_scopes(sub_node, child.id)
            return

        if (
            self.profile.is_comprehension(node)
            or (
                self.profile.is_block(node)
                and self.profile.block_creates_scope(
                    node, self.context
                )
            )
        ):
            kind = (
                "comprehension"
                if self.profile.is_comprehension(node)
                else "block"
            )
            child = self._add_scope(
                node,
                kind,
                f"{kind}@{node.start_point.row + 1}",
                current_scope_id,
            )
            for sub_node in node.children:
                self._create_scopes(sub_node, child.id)
            return

        for sub_node in node.children:
            self._create_scopes(sub_node, current_scope_id)

    def _collect_directive_names(self, node: Node) -> None:
        if node.type in {"global_statement", "nonlocal_statement"}:
            scope_id = self.result.scope_for(node)
            name_nodes = [
                child
                for child in node.named_children
                if child.type == "identifier"
            ]
            kind = (
                "global"
                if node.type == "global_statement"
                else "nonlocal"
            )
            names = (
                self.profile.global_names(node, self.context)
                if kind == "global"
                else self.profile.nonlocal_names(
                    node, self.context
                )
            )
            for name, name_node in zip(names, name_nodes):
                self._directive_keys.add(node_key(name_node))
                self._directives.setdefault(scope_id, {})[name] = (
                    self.result.scopes[0].id
                    if kind == "global"
                    else None
                )
                self._directive_kinds.setdefault(scope_id, {})[
                    name
                ] = kind
                self._directive_names.setdefault(scope_id, {}).setdefault(
                    name, []
                ).append(name_node)
        for child in node.children:
            self._collect_directive_names(child)

    def _resolve_directive_targets(self) -> None:
        for scope_id, names in self._directives.items():
            for name, target in list(names.items()):
                if self._directive_kinds[scope_id][name] != "nonlocal":
                    continue
                if target is None:
                    resolved = self._resolve_nonlocal_scope(
                        scope_id, name
                    )
                    if resolved is None:
                        self.result.limitations.append(
                            f"nonlocal '{name}' has no enclosing "
                            "binding; the name is treated as local."
                        )
                    names[name] = resolved

    def _resolve_nonlocal_scope(
        self, scope_id: str, name: str
    ) -> str | None:
        scope = self._scopes_by_id.get(scope_id)
        current_id = scope.parent_id if scope else None
        while current_id is not None:
            current = self._scopes_by_id[current_id]
            if (
                current.kind in {"function", "lambda"}
                and name in current.symbol_ids
            ):
                return current_id
            current_id = current.parent_id
        return None

    def _statement_for(
        self,
        node: Node,
        inherited_statement_id: str,
    ) -> str:
        if (
            inherited_statement_id == ""
            or node.type in PARAMETER_CONTAINER_TYPES
            or self.profile.statement_kind(node, self.context)
            != "expr"
        ):
            return statement_id(node)
        return inherited_statement_id

    def _register_all_declarations(
        self,
        node: Node,
        inherited_statement_id: str,
        pending: list[tuple],
    ) -> None:
        parent_statement_id = self._statement_for(
            node, inherited_statement_id
        )
        scope_id = self.result.scope_for(node)
        for declaration in list(
            self.profile.declaration_names(node, self.context)
        ):
            name = declaration.name.strip()
            if (
                name
                and name in self._directives.get(scope_id, {})
            ):
                pending.append(
                    (
                        declaration,
                        scope_id,
                        parent_statement_id,
                        node,
                    )
                )
            else:
                self._register_declaration(
                    declaration,
                    scope_id,
                    parent_statement_id,
                    node,
                )
        for child in node.children:
            self._register_all_declarations(
                child, parent_statement_id, pending
            )

    def _register_all_references(
        self,
        node: Node,
        inherited_statement_id: str,
    ) -> None:
        key = node_key(node)
        parent_statement_id = self._statement_for(
            node, inherited_statement_id
        )
        scope_id = self.result.scope_for(node)
        if (
            node.type in IDENTIFIER_TYPES
            and key not in self._declaration_keys
            and key not in self._directive_keys
            and not self.profile.is_non_use_node(node, self.context)
        ):
            self._register_reference(
                node, scope_id, parent_statement_id
            )
        if node.type in CALL_NODE_TYPES:
            self._register_call(
                node, scope_id, parent_statement_id
            )
        for child in node.children:
            self._register_all_references(
                child, parent_statement_id
            )

    def _target_scope_id(
        self,
        declaration_target: str,
        current_scope_id: str,
    ) -> str:
        if declaration_target == "module":
            return self.result.scopes[0].id
        if declaration_target == "function":
            scope_id: str | None = current_scope_id
            while scope_id is not None:
                scope = self._scopes_by_id[scope_id]
                if scope.kind in {"function", "lambda", "module"}:
                    return scope_id
                scope_id = scope.parent_id
            return self.result.scopes[0].id
        if declaration_target == "class":
            scope_id = current_scope_id
            while scope_id is not None:
                scope = self._scopes_by_id[scope_id]
                if scope.kind == "class":
                    return scope_id
                scope_id = scope.parent_id
        return current_scope_id

    def _register_declaration(
        self,
        declaration,
        scope_id: str,
        parent_statement_id: str,
        node: Node,
    ) -> None:
        name = declaration.name.strip()
        if not name:
            return

        if declaration.target == "assign":
            existing = self._resolve_symbol(scope_id, name)
            target_scope_id = (
                existing.scope_id
                if existing is not None
                else self.result.scopes[0].id
            )
        else:
            target_scope_id = self._target_scope_id(
                declaration.target, scope_id
            )
        directive = self._directives.get(scope_id, {}).get(name)
        if name in self._directives.get(scope_id, {}):
            target_scope_id = directive or current_scope_id

        symbol = self._symbols_by_key.get(
            (target_scope_id, name)
        )
        location = self.context.location(declaration.name_node)
        if symbol is None:
            symbol = Symbol(
                id=f"sym:{target_scope_id}:{name}",
                name=name,
                symbol_type=declaration.kind,
                scope_id=target_scope_id,
                language=self.context.language,
                declaration=location,
            )
            symbol.declarations.append(location)
            self._symbols_by_key[(target_scope_id, name)] = symbol
            self.result.symbols.append(symbol)
            self._scopes_by_id[target_scope_id].symbol_ids[
                name
            ] = symbol.id
        else:
            symbol.add_declaration(location)
            precedence = {
                "variable": 0,
                "field": 0,
                "import": 0,
                "parameter": 1,
                "function": 2,
                "class": 2,
            }
            if precedence.get(
                declaration.kind, 0
            ) > precedence.get(symbol.symbol_type, 0):
                symbol.symbol_type = declaration.kind

        if not declaration.name_is_use and node.type != "augmented_assignment":
            self._declaration_keys.add(
                node_key(declaration.name_node)
            )
        record = DeclarationUse(
            symbol_id=symbol.id,
            name=name,
            node=declaration.name_node,
            location=location,
            kind=declaration.kind,
            statement_id=parent_statement_id,
            value_node=declaration.value_node,
        )
        self.result.declarations_by_statement.setdefault(
            parent_statement_id, []
        ).append(record)

        if declaration.kind in {
            "variable",
            "parameter",
            "import",
            "field",
        }:
            value_text = self.context.text(declaration.value_node)
            assignment = AssignmentRecord(
                file=location.file,
                line=location.line,
                column=location.column,
                statement_id=parent_statement_id,
                value_text=value_text,
                kind=(
                    "augmented"
                    if declaration.name_is_use
                    else declaration.kind
                ),
            )
            if not any(
                item.statement_id == assignment.statement_id
                and item.line == assignment.line
                and item.column == assignment.column
                for item in symbol.assignments
            ):
                symbol.add_assignment(assignment)

    def _resolve_symbol(
        self, scope_id: str, name: str
    ) -> Symbol | None:
        directive = self._directives.get(scope_id, {}).get(name)
        if directive is not None:
            scope_id = directive
        current_id: str | None = scope_id
        first = True
        while current_id is not None:
            scope = self._scopes_by_id[current_id]
            skip_class = (
                self.context.language == "python"
                and not first
                and scope.kind == "class"
            )
            if not skip_class and name in scope.symbol_ids:
                return self._symbols_by_key.get(
                    (current_id, name)
                )
            current_id = scope.parent_id
            first = False
        return None

    def _register_reference(
        self,
        node: Node,
        scope_id: str,
        parent_statement_id: str,
    ) -> None:
        name = self.context.text(node)
        symbol = self._resolve_symbol(scope_id, name)
        parent = self.context.parent(node)
        kind = "use"
        if parent is not None:
            for field_name in ("function", "constructor"):
                field_node = self.context.field(parent, field_name)
                if (
                    field_node is not None
                    and node_key(field_node) == node_key(node)
                ):
                    kind = "call"
        location = self.context.location(node)
        reference = Reference(
            file=location.file,
            line=location.line,
            column=location.column,
            kind=kind,
            statement_id=parent_statement_id,
        )
        self.result.uses_by_statement.setdefault(
            parent_statement_id, []
        ).append(
            UseRecord(
                symbol_id=symbol.id if symbol else None,
                name=name,
                node=node,
                location=location,
                kind=kind,
                statement_id=parent_statement_id,
            )
        )
        if symbol is not None:
            symbol.add_reference(reference)
        elif name not in BUILTINS.get(
            self.context.language, set()
        ):
            self.result.unresolved_references.append(
                {
                    "name": name,
                    "scope_id": scope_id,
                    "kind": kind,
                    "location": location.to_dict(),
                    "statement_id": parent_statement_id,
                }
            )

    def _register_call(
        self,
        node: Node,
        scope_id: str,
        parent_statement_id: str,
    ) -> None:
        name = self.profile.call_name(node, self.context)
        if not name:
            return
        base_name = name.split(".")[0]
        symbol = self._resolve_symbol(scope_id, base_name)
        if symbol is None:
            symbol = self._resolve_symbol(scope_id, name)
        self.result.calls.append(
            CallRecord(
                name=name,
                symbol_id=symbol.id if symbol else None,
                node=node,
                location=self.context.location(node),
                statement_id=parent_statement_id,
                arguments=self.profile.call_arguments(
                    node, self.context
                ),
            )
        )
