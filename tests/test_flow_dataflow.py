from bugdhor_ast.flow import FlowEngine


def scope_id(result, name, kind="function"):
    return next(
        scope.id
        for scope in result.scopes
        if scope.name == name and scope.kind == kind
    )


def scope_data(result, scope):
    return next(
        item
        for item in result.data_flow.scopes
        if item.scope_id == scope
    )


def definition_map(data):
    return {
        definition.id: definition
        for definition in data.definitions
    }


def test_reaching_definitions_and_def_use_chains():
    source = (
        "x = 1\n"
        "def f(flag):\n"
        "    y = 0\n"
        "    if flag:\n"
        "        y = 1\n"
        "    else:\n"
        "        y = 2\n"
        "    z = y + x\n"
        "    return z\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    function_scope = scope_id(result, "f")
    data = scope_data(result, function_scope)

    y_definitions = [
        definition
        for definition in data.definitions
        if definition.name == "y"
    ]
    assert {definition.location.line for definition in y_definitions} == {
        3, 5, 7
    }

    y_use = next(
        use
        for use in data.uses
        if use.name == "y" and use.location.line == 8
    )
    definitions_by_id = definition_map(data)
    chained_definitions = data.def_use_chains[y_use.id]
    assert len(chained_definitions) == 2
    assert {
        definitions_by_id[definition_id].location.line
        for definition_id in chained_definitions
    } == {5, 7}
    assert chained_definitions != [
        definition.id
        for definition in y_definitions
        if definition.location.line == 3
    ]

    for definition_id in chained_definitions:
        assert y_use.id in data.use_def_chains[definition_id]

    z_definition = next(
        definition
        for definition in data.definitions
        if definition.name == "z"
    )
    assert set(data.dependencies[z_definition.id]) == {"x", "y"}


def test_live_variables_and_assignment_propagation():
    source = (
        "x = 1\n"
        "def f(flag):\n"
        "    y = 0\n"
        "    if flag:\n"
        "        y = 1\n"
        "    else:\n"
        "        y = 2\n"
        "    z = y + x\n"
        "    return z\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    data = scope_data(result, scope_id(result, "f"))

    z_statement = next(
        definition.statement_id
        for definition in data.definitions
        if definition.name == "z"
    )
    assert data.live_variables[z_statement]["in"] == ["x", "y"]
    assert data.live_variables[z_statement]["out"] == ["z"]

    module_data = scope_data(result, result.scopes[0].id)
    x_definition = next(
        definition
        for definition in module_data.definitions
        if definition.name == "x"
    )
    assert module_data.assignment_propagation[x_definition.id] == "1"


def test_function_summaries_and_call_edges():
    source = (
        "x = 1\n"
        "def f(flag):\n"
        "    y = flag + x\n"
        "    return y\n"
        "def caller():\n"
        "    return f(1)\n"
    )
    result = FlowEngine().analyze_source(source, "python")
    flow = result.data_flow

    summary = next(
        item for item in flow.function_summaries if item.name == "f"
    )
    assert summary.parameters == ("flag",)
    assert summary.returns == "y"
    assert summary.globals_used == ("x",)

    edge = next(
        item
        for item in flow.call_edges
        if item.callee_name == "f"
    )
    assert edge.caller_scope_id == scope_id(result, "caller")
    assert edge.callee_symbol_id.startswith("sym:")


def test_javascript_scope_aware_def_use():
    source = (
        "var g = 0;\n"
        "function f(a) {\n"
        "  let x = a;\n"
        "  if (a) { x = 2; }\n"
        "  return x + g;\n"
        "}\n"
    )
    result = FlowEngine().analyze_source(source, "javascript")
    data = scope_data(result, scope_id(result, "f"))

    use = next(
        use
        for use in data.uses
        if use.name == "x" and use.location.line == 5
    )
    definitions_by_id = definition_map(data)
    definitions = [
        definitions_by_id[definition_id]
        for definition_id in data.def_use_chains[use.id]
    ]
    assert {definition.location.line for definition in definitions} == {
        3, 4
    }


def test_java_field_and_parameter_flow():
    source = (
        "class C {\n"
        "  int field;\n"
        "  void f(int a) {\n"
        "    int x = a;\n"
        "    x = x + 1;\n"
        "    field = x;\n"
        "  }\n"
        "}\n"
    )
    result = FlowEngine().analyze_source(source, "java")
    data = scope_data(result, scope_id(result, "f"))

    use = next(
        use
        for use in data.uses
        if use.name == "x" and use.location.line == 5
    )
    definitions_by_id = definition_map(data)
    definitions = [
        definitions_by_id[definition_id]
        for definition_id in data.def_use_chains[use.id]
    ]
    assert any(definition.location.line == 4 for definition in definitions)

    class_data = scope_data(
        result, scope_id(result, "C", "class")
    )
    assert any(
        definition.name == "field"
        for definition in class_data.definitions
    )
