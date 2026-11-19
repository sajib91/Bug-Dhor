import pytest

from tree_sitter import Node

from bugdhor_ast.engine import BugDhorASTEngine
from bugdhor_ast.flow.profiles import (
    JavaScriptProfile,
    JavaProfile,
    LanguageProfile,
    PythonProfile,
    get_profile,
)
from bugdhor_ast.flow.tree import (
    FlowContext,
    node_key,
    statement_id,
)


def context_for(source, language):
    root = (
        BugDhorASTEngine()
        .get_parser(language)
        .parse(source.encode("utf-8"))
        .root_node
    )
    return FlowContext(source, language, "<test>", root)


def first(context, *types):
    return next(context.nodes_of_type(*types))


def names(profile, node, context):
    return [item.name for item in profile.declaration_names(node, context)]


def test_tree_helpers_for_empty_and_missing_nodes():
    assert node_key(None) == (-1, -1, "")
    assert statement_id(None) == ""

    context = context_for(
        "def outer():\n"
        "    def inner():\n"
        "        value = 1\n"
        "    return value\n",
        "python",
    )
    function_nodes = list(context.nodes_of_type("function_definition"))
    assert len(function_nodes) == 2
    assert node_key(function_nodes[0]) == (
        function_nodes[0].start_byte,
        function_nodes[0].end_byte,
        function_nodes[0].type,
    )
    assert statement_id(function_nodes[0]).startswith("stmt:")

    identifiers = [
        node
        for node in context.nodes_of_type("identifier")
        if context.text(node) == "value"
    ]
    value = identifiers[-1]
    assert context.field_text(value, "missing") is None
    assert context.field_text(function_nodes[0], "name") == "outer"
    assert context.text(None) == ""
    assert context.location(None).line == 0
    assert context.nodes_of_type("function_definition", "return_statement")
    assert context.parent(value) is not None
    assert list(context.ancestors(value))
    assert context.has_ancestor(value, "function_definition")
    assert not context.has_ancestor(value, "class_definition")
    assert context.enclosing_function(value) is not None


def test_base_profile_defaults_and_generic_tree_hooks():
    profile = LanguageProfile()
    context = context_for(
        "import os\n"
        "def f(a):\n"
        "    obj.attr = a\n"
        "    obj.method(k=a)\n"
        "    x = 1\n"
        "    y = True\n"
        "    z = 'text'\n"
        "    return x\n",
        "python",
    )
    module = context.root
    call = first(context, "call")
    keyword = first(context, "keyword_argument")
    function = first(context, "function_definition")

    assert profile.is_module(module) is False
    assert profile.is_function(function) is False
    assert profile.is_class(module) is False
    assert profile.is_block(module) is False
    assert profile.is_comprehension(module) is False
    assert profile.block_creates_scope(function, context) is False
    assert profile.declaration_names(call, context) == []
    assert profile.global_names(call, context) == []
    assert profile.nonlocal_names(call, context) == []
    assert profile.handler_declarations(call, context) == []
    assert profile.statement_kind(call, context) == "expr"
    assert context.text(profile.condition_node(keyword, context)) == "a"
    assert profile.condition_node(module, context) is None
    assert profile.body_node(function, context) is not None
    assert profile.alternative_node(function, context) is None
    assert profile.handler_nodes(module, context) == []
    assert profile.finally_node(module, context) is None
    assert profile.call_name(call, context) == "obj.method"
    assert profile.call_name(function, context) == ""
    assert profile.call_arguments(call, context) == ("k=a",)
    assert profile.literal_value(None, context) is None
    assert profile.literal_value(first(context, "integer"), context) == "1"
    assert profile.literal_value(first(context, "true"), context) == "True"
    assert profile.literal_value(first(context, "string"), context) == "text"
    assert profile.literal_value(first(context, "identifier"), context).startswith("@alias:")
    assert profile.is_non_use_node(module, context) is True
    assert profile.import_types() == (
        "import_statement",
        "import_from_statement",
        "import_declaration",
    )
    assert [context.text(node) for node in profile.identifier_nodes(function, context)]


def test_python_profile_imports_declarations_and_literals():
    source = (
        "import os, sys as system\n"
        "from pkg import thing\n"
        "global counter\n"
        "nonlocal outer_value\n"
        "try:\n"
        "    pass\n"
        "except ValueError:\n"
        "    pass\n"
        "x = True\n"
        "y = False\n"
    )
    profile = PythonProfile()
    context = context_for(source, "python")

    import_node = first(context, "import_statement")
    assert names(profile, import_node, context) == ["os", "system"]
    from_node = first(context, "import_from_statement")
    assert names(profile, from_node, context) == ["thing"]
    assert profile.global_names(first(context, "global_statement"), context) == [
        "counter"
    ]
    assert profile.nonlocal_names(
        first(context, "nonlocal_statement"), context
    ) == ["outer_value"]
    assert profile.declaration_names(
        first(context, "except_clause"), context
    ) == []
    assert profile.literal_value(first(context, "true"), context) == "True"
    assert profile.literal_value(first(context, "false"), context) == "False"
    assert profile.condition_node(context.root, context) is None


def test_python_profile_ir_statement_kinds_cover_grammar_statements():
    source = (
        "import os\n"
        "x = 1\n"
        "x += 2\n"
        "if x:\n"
        "    pass\n"
        "else:\n"
        "    pass\n"
        "for i in [1]:\n"
        "    continue\n"
        "while x:\n"
        "    break\n"
        "try:\n"
        "    raise ValueError()\n"
        "finally:\n"
        "    pass\n"
    )
    context = context_for(source, "python")
    profile = PythonProfile()
    kinds = {
        node.type: profile.statement_kind(node, context)
        for node in context.walk()
        if node.type in {
            "import_statement",
            "assignment",
            "augmented_assignment",
            "if_statement",
            "else_clause",
            "for_statement",
            "while_statement",
            "try_statement",
            "finally_clause",
            "break_statement",
            "continue_statement",
            "raise_statement",
        }
    }
    assert kinds["import_statement"] == "import"
    assert kinds["assignment"] == "assign"
    assert kinds["augmented_assignment"] == "assign"
    assert kinds["if_statement"] == "if"
    assert kinds["else_clause"] == "else"
    assert kinds["for_statement"] == "loop"
    assert kinds["while_statement"] == "loop"
    assert kinds["try_statement"] == "try"
    assert kinds["finally_clause"] == "finally"
    assert kinds["break_statement"] == "break"
    assert kinds["continue_statement"] == "continue"
    assert kinds["raise_statement"] == "throw"


def test_javascript_profile_binding_patterns_and_imports():
    source = (
        'import def, * as ns from "m";\n'
        'import { name as alias } from "m";\n'
        "class C { field = 1; }\n"
        "const {p, q: renamed} = obj;\n"
        "const arrow = (b) => b;\n"
        "try { risky(); } catch (err) { let y = err; }\n"
        "const t = `hello`;\n"
        "const o = new Thing();\n"
    )
    profile = JavaScriptProfile()
    context = context_for(source, "javascript")

    clause = first(context, "import_clause")
    assert names(profile, clause, context) == ["def", "ns"]
    specifier = first(context, "import_specifier")
    assert names(profile, specifier, context) == ["alias"]
    assert names(profile, first(context, "field_definition"), context) == [
        "field"
    ]
    assert names(
        profile, first(context, "variable_declarator"), context
    ) == ["p", "renamed"]
    assert names(profile, first(context, "catch_clause"), context) == [
        "err"
    ]
    assert [
        item.name
        for item in profile.handler_declarations(
            first(context, "catch_clause"), context
        )
    ] == ["err"]
    assert names(profile, first(context, "class_declaration"), context) == [
        "C"
    ]
    assert names(profile, first(context, "arrow_function"), context) == []
    assert profile.literal_value(first(context, "template_string"), context) == "hello"
    assert profile.call_name(first(context, "new_expression"), context) == "Thing"
    assert profile.call_arguments(first(context, "new_expression"), context) == ()
    assert profile.condition_node(context.root, context) is None


def test_javascript_profile_binding_name_helpers():
    context = context_for(
        "const {p, q: renamed, r: 1} = obj;\n", "javascript"
    )
    pattern = first(context, "object_pattern")
    bindings = list(JavaScriptProfile._binding_names(pattern))
    assert [context.text(node) for node in bindings] == ["p", "renamed"]
    assert list(JavaScriptProfile._binding_names(None)) == []


def test_java_profile_fields_parameters_and_calls():
    source = (
        "import java.util.*;\n"
        "import java.util.List;\n"
        "interface I { void run(); }\n"
        "enum E { A }\n"
        "class C {\n"
        "  int field = 1;\n"
        "  C() {}\n"
        "  void f(int a) {\n"
        "    int x = 1;\n"
        "    x += 2;\n"
        "    for (String item : items) { use(item); }\n"
        "    try { risky(); } catch (Exception e) { use(e); }\n"
        "    Object o = new Object();\n"
        "    if (x > 0) { use(x); } else { use(0); }\n"
        "  }\n"
        "}\n"
    )
    profile = JavaProfile()
    context = context_for(source, "java")

    assert names(profile, first(context, "import_declaration"), context) == []
    imports = [
        names(profile, node, context)
        for node in context.nodes_of_type("import_declaration")
    ]
    assert imports == [[], ["List"]]
    assert names(profile, first(context, "field_declaration"), context) == [
        "field"
    ]
    assert names(profile, first(context, "formal_parameter"), context) == [
        "a"
    ]
    assert names(profile, first(context, "enhanced_for_statement"), context) == [
        "item"
    ]
    assert names(profile, first(context, "catch_formal_parameter"), context) == [
        "e"
    ]
    assert names(profile, first(context, "method_declaration"), context) == [
        "run"
    ]
    assert names(profile, first(context, "class_declaration"), context) == [
        "C"
    ]
    assert names(profile, first(context, "interface_declaration"), context) == [
        "I"
    ]
    assert names(profile, first(context, "enum_declaration"), context) == ["E"]
    assert [
        item.name
        for item in profile.handler_declarations(
            first(context, "try_statement"), context
        )
    ] == ["e"]

    invocation = first(context, "method_invocation")
    assert profile.call_name(invocation, context) == "use"
    assert profile.call_name(
        first(context, "object_creation_expression"), context
    ) == "Object"
    assert profile.call_name(context.root, context) == ""
    assert profile.call_arguments(context.root, context) == ()
    assert profile.body_node(first(context, "if_statement"), context) is not None
    assert profile.alternative_node(first(context, "if_statement"), context) is not None
    assert profile.alternative_node(context.root, context) is None
    assert profile.statement_kind(first(context, "field_declaration"), context) == "decl"


def test_get_profile_rejects_unsupported_language():
    with pytest.raises(ValueError, match="Flow analysis is not supported"):
        get_profile("ruby")
    assert get_profile("python").language == "python"
    assert isinstance(get_profile("javascript"), JavaScriptProfile)
    assert isinstance(get_profile("java"), JavaProfile)
