from bugdhor_ast.flow import FlowEngine


def symbols_by_name(result):
    return {
        (symbol.name, symbol.scope_id): symbol
        for symbol in result.symbols
    }


def scope_kinds(result):
    return {scope.kind for scope in result.scopes}


def test_python_symbol_table_and_scope_kinds():
    source = (
        "import os\n"
        "GLOBAL = 1\n"
        "class Outer:\n"
        "    field = 2\n"
        "    def method(self, arg):\n"
        "        local = arg + GLOBAL\n"
        "        def nested():\n"
        "            nonlocal local\n"
        "            local += 1\n"
        "            return local\n"
        "        return nested\n"
        "\n"
        "def top(a, b=3):\n"
        "    global GLOBAL\n"
        "    GLOBAL = a\n"
        "    vals = [v for v in range(b)]\n"
        "    lam = lambda q: q + a\n"
        "    return vals\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    symbols = symbols_by_name(result)

    assert {
        "module",
        "class",
        "function",
        "comprehension",
        "lambda",
    } <= scope_kinds(result)

    module_scope = result.scopes[0].id
    method_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "method"
    )
    nested_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "nested"
    )
    top_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "top"
    )
    comprehension_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "comprehension"
    )
    lambda_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "lambda"
    )

    assert ("os", module_scope) in symbols
    assert symbols[("GLOBAL", module_scope)].declaration_line == 2
    assert len(
        symbols[("GLOBAL", module_scope)].assignments
    ) == 2
    assert ("field", next(
        scope.id
        for scope in result.scopes
        if scope.kind == "class"
    )) in symbols
    assert symbols[("self", method_scope)].symbol_type == "parameter"
    assert symbols[("arg", method_scope)].symbol_type == "parameter"

    local = symbols[("local", method_scope)]
    assert len(local.assignments) == 2
    assert len(local.references) == 2

    assert ("v", comprehension_scope) in symbols
    assert ("q", lambda_scope) in symbols
    assert ("vals", top_scope) in symbols
    assert ("lam", top_scope) in symbols
    assert result.unresolved_references == []

    ids = [symbol.id for symbol in result.symbols]
    assert len(ids) == len(set(ids))
    declarations = [
        (
            symbol.name,
            symbol.scope_id,
            symbol.declaration_line,
            symbol.declaration_column,
        )
        for symbol in result.symbols
    ]
    assert len(declarations) == len(set(declarations))


def test_python_closure_shadowing_creates_three_symbols():
    source = (
        "x = 1\n"
        "def outer():\n"
        "    x = 2\n"
        "    def inner():\n"
        "        x = 3\n"
        "        return x\n"
        "    return inner\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    x_symbols = [
        symbol for symbol in result.symbols if symbol.name == "x"
    ]

    assert len(x_symbols) == 3
    assert {symbol.scope_id for symbol in x_symbols} == {
        result.scopes[0].id,
        *[
            scope.id
            for scope in result.scopes
            if scope.kind == "function"
        ],
    }
    assert any(symbol.declaration_line == 5 for symbol in x_symbols)
    assert result.unresolved_references == []


def test_python_nonlocal_binds_to_enclosing_function():
    source = (
        "def outer():\n"
        "    n = 1\n"
        "    def inner():\n"
        "        nonlocal n\n"
        "        n = 2\n"
        "        return n\n"
        "    return inner\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    outer_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "outer"
    )
    n_symbol = next(
        symbol
        for symbol in result.symbols
        if symbol.name == "n" and symbol.scope_id == outer_scope
    )

    assert len(n_symbol.assignments) == 2
    assert any(
        reference.line == 6 for reference in n_symbol.references
    )
    assert not any(
        symbol.name == "n" and symbol.scope_id != outer_scope
        for symbol in result.symbols
    )


def test_javascript_var_let_block_and_arrow_scopes():
    source = (
        "var g = 1;\n"
        "let m = 2;\n"
        "function outer(a) {\n"
        "  let x = a;\n"
        "  if (x) { let y = 1; var z = y; }\n"
        "  return x + z + g;\n"
        "}\n"
        "const arrow = (p) => p + g;\n"
        "class C {\n"
        "  field = 1;\n"
        "  method(q) { let t = q; return t + this.field; }\n"
        "}\n"
    )
    result = FlowEngine().analyze_source(source, "javascript")
    symbols = symbols_by_name(result)

    module_scope = result.scopes[0].id
    function_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "outer"
    )
    arrow_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "function" and scope.name == "<anonymous>"
    )
    block_scopes = {
        scope.id for scope in result.scopes if scope.kind == "block"
    }
    class_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "class"
    )

    assert ("g", module_scope) in symbols
    assert ("z", function_scope) in symbols
    assert ("x", function_scope) in symbols
    assert any(
        ("y", scope_id) in symbols for scope_id in block_scopes
    )
    assert ("p", arrow_scope) in symbols
    assert ("field", class_scope) in symbols
    assert ("arrow", module_scope) in symbols


def test_java_class_method_constructor_and_block_scopes():
    source = (
        "import java.util.List;\n"
        "class C {\n"
        "  int field = 1;\n"
        "  void f(int a) {\n"
        "    int x = a;\n"
        "    if (x > 0) { int y = 1; x = y; }\n"
        "  }\n"
        "  C(int p) { this.field = p; }\n"
        "}\n"
    )
    result = FlowEngine().analyze_source(source, "java")
    symbols = symbols_by_name(result)

    module_scope = result.scopes[0].id
    class_scope = next(
        scope.id
        for scope in result.scopes
        if scope.kind == "class"
    )
    function_scopes = {
        scope.id: scope.name
        for scope in result.scopes
        if scope.kind == "function"
    }
    f_scope = next(
        scope_id
        for scope_id, name in function_scopes.items()
        if name == "f"
    )
    constructor_scope = next(
        scope_id
        for scope_id, name in function_scopes.items()
        if name == "C"
    )
    block_scopes = {
        scope.id for scope in result.scopes if scope.kind == "block"
    }

    assert ("List", module_scope) in symbols
    assert ("field", class_scope) in symbols
    assert symbols[("field", class_scope)].symbol_type == "field"
    assert ("a", f_scope) in symbols
    assert ("x", f_scope) in symbols
    assert any(
        ("y", scope_id) in symbols for scope_id in block_scopes
    )
    assert ("p", constructor_scope) in symbols
