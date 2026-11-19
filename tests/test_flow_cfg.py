from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine


PYTHON_SOURCE = """def f(flag):
    x = 0
    if flag:
        x = 1
    else:
        x = 2
    for i in range(3):
        if i == 1:
            continue
        break
    try:
        x = 3
    except ValueError as e:
        x = 4
    finally:
        x = 5
    return x
"""


def reachable_nodes(graph):
    seen = {graph.entry}
    pending = [graph.entry]
    while pending:
        current = pending.pop()
        for target in graph.nodes[current].successors:
            if target not in seen:
                seen.add(target)
                pending.append(target)
    return seen


def test_python_cfg_structure_and_consistency():
    result = FlowEngine().analyze_source(PYTHON_SOURCE, "python")
    graphs = result.control_flow_graphs

    assert len(graphs) == 2
    assert {graph.scope_kind for graph in graphs} == {
        "module",
        "function",
    }
    for graph in graphs:
        assert graph.validate() == []
        assert graph.entry in graph.nodes
        assert graph.exit in graph.nodes
        assert all(
            node.location.line >= 1 and node.location.column >= 1
            for node in graph.nodes.values()
        )
        assert reachable_nodes(graph) == set(graph.nodes)

    function_graph = next(
        graph for graph in graphs if graph.scope_kind == "function"
    )
    kinds = {node.kind for node in function_graph.nodes.values()}
    assert {
        "entry",
        "exit",
        "params",
        "assign",
        "if",
        "else",
        "loop",
        "continue",
        "break",
        "try",
        "handler",
        "finally",
        "return",
    } <= kinds
    assert {"try_join"} <= kinds

    edge_kinds = {edge.kind for edge in function_graph.edges}
    assert {
        "entry",
        "params",
        "assign",
        "true",
        "false",
        "body",
        "exit",
        "continue",
        "break",
        "handler",
        "normal",
        "return",
    } <= edge_kinds

    by_kind = {
        node.kind: node.id for node in function_graph.nodes.values()
    }
    continue_edge = next(
        edge
        for edge in function_graph.edges
        if edge.kind == "continue"
    )
    assert continue_edge.target == by_kind["loop"]

    break_edge = next(
        edge for edge in function_graph.edges if edge.kind == "break"
    )
    assert break_edge.target != by_kind["loop"]

    return_edge = next(
        edge for edge in function_graph.edges if edge.kind == "return"
    )
    assert return_edge.target == function_graph.exit
    assert function_graph.nodes[function_graph.exit].successors == []


def test_cfg_json_is_serializable_and_self_consistent():
    result = FlowEngine().analyze_source(PYTHON_SOURCE, "python")
    payload = result.to_dict(FLOW_SECTIONS)

    graphs = payload["control_flow_graph"]
    assert graphs
    for graph in graphs:
        assert graph["consistent"] is True
        node_ids = {node["id"] for node in graph["nodes"]}
        assert len(node_ids) == len(graph["nodes"])
        assert graph["entry"] in node_ids
        assert graph["exit"] in node_ids
        for edge in graph["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids
        for node in graph["nodes"]:
            assert set(node["successors"]) == {
                edge["target"]
                for edge in graph["edges"]
                if edge["source"] == node["id"]
            }
            assert set(node["predecessors"]) == {
                edge["source"]
                for edge in graph["edges"]
                if edge["target"] == node["id"]
            }


def test_javascript_and_java_cfg_consistency():
    cases = {
        "javascript": (
            "var g = 1;\n"
            "function f(a) {\n"
            "  let x = a;\n"
            "  if (x) { x = 2; } else { x = 3; }\n"
            "  for (let i = 0; i < 3; i++) {\n"
            "    if (i) continue;\n"
            "    break;\n"
            "  }\n"
            "  return x;\n"
            "}\n"
        ),
        "java": (
            "class C {\n"
            "  int field = 1;\n"
            "  void f(int a) {\n"
            "    int x = a;\n"
            "    if (x > 0) { x = 2; } else { x = 3; }\n"
            "    for (int i = 0; i < 3; i++) {\n"
            "      if (i == 1) continue;\n"
            "      break;\n"
            "    }\n"
            "    return;\n"
            "  }\n"
            "}\n"
        ),
    }

    for language, source in cases.items():
        result = FlowEngine().analyze_source(source, language)
        assert result.control_flow_graphs
        for graph in result.control_flow_graphs:
            assert graph.validate() == []
            assert reachable_nodes(graph) == set(graph.nodes)
        assert any(
            graph.scope_kind == "function"
            for graph in result.control_flow_graphs
        )
        function_graph = next(
            graph
            for graph in result.control_flow_graphs
            if graph.scope_kind == "function"
        )
        kinds = {
            node.kind for node in function_graph.nodes.values()
        }
        assert {"if", "loop", "continue", "break"} <= kinds
        if language == "java":
            assert any(
                graph.scope_kind == "class"
                for graph in result.control_flow_graphs
            )


def test_to_dict_filters_optional_flow_sections():
    result = FlowEngine().analyze_source("x = 1\n", "python")

    payload = result.to_dict(("symbols",))

    assert "symbols" in payload
    assert all(
        section not in payload
        for section in FLOW_SECTIONS
        if section != "symbols"
    )
    assert payload["has_syntax_errors"] is False
