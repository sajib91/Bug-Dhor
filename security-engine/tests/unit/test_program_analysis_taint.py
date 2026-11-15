from __future__ import annotations

import json
from dataclasses import replace

import networkx as nx
import pytest

from craftsec.parsing import parse_source
from craftsec.parsing.models import SupportedLanguage
from craftsec.program_analysis import (
    NameMatch,
    PropagatorMode,
    PropagatorRule,
    SinkRule,
    SourceRule,
    TaintAnalysis,
    TaintConfidence,
    TaintConfig,
    TaintKind,
    analyze_taint,
    analyze_taint_file,
    default_taint_config,
)


def only_finding(analysis: TaintAnalysis, kind: TaintKind):
    matches = analysis.findings_for(kind)
    assert len(matches) == 1, f"expected one {kind.value} finding, got {matches!r}"
    return matches[0]


def test_python_sql_injection_flow() -> None:
    source = """def handler(request):
    query = "SELECT * FROM users WHERE name = '" + request.args["name"] + "'"
    cursor.execute(query)
"""
    analysis = analyze_taint(source, path="sql.py")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.source_rule == "python.http_request"
    assert finding.sink_rule == "sql.execute"
    assert finding.source_text == 'request.args["name"]'
    assert "cursor.execute" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH
    assert finding.path[0].role == "source"
    assert finding.path[-1].role == "sink"
    assert analysis.sources and analysis.sinks


def test_python_command_injection_flow() -> None:
    source = """def handler(request):
    os.system("ping -c 1 " + request.args["host"])
"""
    analysis = analyze_taint(source, path="command.py")

    finding = only_finding(analysis, TaintKind.COMMAND_INJECTION)
    assert finding.sink_rule == "command.system"
    assert finding.source_text == 'request.args["host"]'
    assert "os.system" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_python_cross_site_scripting_flow() -> None:
    source = """def handler(request):
    return render_template_string("<p>" + request.args["name"] + "</p>")
"""
    analysis = analyze_taint(source, path="xss.py")

    finding = only_finding(analysis, TaintKind.XSS)
    assert finding.sink_rule == "xss.python_response"
    assert finding.source_text == 'request.args["name"]'
    assert "render_template_string" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_python_path_traversal_flow() -> None:
    source = """def handler(request):
    with open(request.args["path"]) as handle:
        return handle.read()
"""
    analysis = analyze_taint(source, path="path.py")

    finding = only_finding(analysis, TaintKind.PATH_TRAVERSAL)
    assert finding.sink_rule == "path.open"
    assert finding.source_text == 'request.args["path"]'
    assert finding.argument_text == 'request.args["path"]'
    assert finding.confidence is TaintConfidence.HIGH


def test_python_unsafe_deserialization_flow() -> None:
    source = """def handler(request):
    return pickle.loads(request.data)
"""
    analysis = analyze_taint(source, path="deserialize.py")

    finding = only_finding(analysis, TaintKind.UNSAFE_DESERIALIZATION)
    assert finding.sink_rule == "deserialization.pickle"
    assert finding.source_text == "request.data"
    assert "pickle.loads" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_javascript_sql_injection_flow() -> None:
    source = """function handler(req) {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
"""
    analysis = analyze_taint(source, path="sql.js")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.source_rule == "javascript.http_request"
    assert finding.sink_rule == "sql.query"
    assert finding.source_text == "req.query.name"
    assert "db.query" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_javascript_command_injection_flow() -> None:
    source = """function handler(req) {
  child_process.exec("ping -c 1 " + req.query.host);
}
"""
    analysis = analyze_taint(source, path="command.js")

    finding = only_finding(analysis, TaintKind.COMMAND_INJECTION)
    assert finding.sink_rule == "command.node_child_process"
    assert finding.source_text == "req.query.host"
    assert "child_process.exec" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_javascript_dom_assignment_xss_flow() -> None:
    source = """function handler(req, element) {
  element.innerHTML = req.query.html;
}
"""
    analysis = analyze_taint(source, path="xss.js")

    finding = only_finding(analysis, TaintKind.XSS)
    assert finding.sink_rule == "xss.dom_assignment"
    assert finding.source_text == "req.query.html"
    assert finding.sink_text == "element.innerHTML"
    assert finding.argument_text == "req.query.html"
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any("DOM" in note for note in finding.confidence_notes)


def test_javascript_path_traversal_flow() -> None:
    source = """function handler(req) {
  fs.readFileSync(req.query.file);
}
"""
    analysis = analyze_taint(source, path="path.js")

    finding = only_finding(analysis, TaintKind.PATH_TRAVERSAL)
    assert finding.sink_rule == "path.file_operations"
    assert finding.source_text == "req.query.file"
    assert "fs.readFileSync" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_javascript_unsafe_deserialization_flow() -> None:
    source = """function handler(req) {
  return unserialize(req.body.payload);
}
"""
    analysis = analyze_taint(source, path="deserialize.js")

    finding = only_finding(analysis, TaintKind.UNSAFE_DESERIALIZATION)
    assert finding.sink_rule == "deserialization.generic"
    assert finding.source_text == "req.body.payload"
    assert "unserialize" in finding.sink_text
    assert finding.confidence is TaintConfidence.HIGH


def test_parameterized_query_is_not_a_flow() -> None:
    source = """def handler(request):
    cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        (request.args["id"],),
    )
"""
    analysis = analyze_taint(source, path="parameterized.py")

    assert analysis.findings == ()
    assert analysis.findings_for(TaintKind.SQL_INJECTION) == ()
    assert [site.rule for site in analysis.sinks] == ["sql.execute"]


def test_numeric_sanitizer_blocks_configured_kinds_only() -> None:
    source = """def handler(request):
    cursor.execute("SELECT * FROM t WHERE id = " + str(int(request.args["id"])))
    open(int(request.args["path"]))
"""
    analysis = analyze_taint(source, path="numeric.py")

    assert analysis.findings_for(TaintKind.SQL_INJECTION) == ()
    finding = only_finding(analysis, TaintKind.PATH_TRAVERSAL)
    assert finding.source_text == 'request.args["path"]'
    assert finding.sink_text.startswith("open(")
    assert {site.rule for site in analysis.sanitizers} == {"python.numeric_conversion"}


def test_html_sanitizer_blocks_xss_but_not_sql() -> None:
    source = """def handler(request):
    cursor.execute(html.escape(request.args["query"]))
    return render_template_string(html.escape(request.args["query"]))
"""
    analysis = analyze_taint(source, path="escaping.py")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.source_text == 'request.args["query"]'
    assert analysis.findings_for(TaintKind.XSS) == ()
    assert {site.rule for site in analysis.sanitizers} == {"python.html_escape"}


def test_javascript_sanitizers_prevent_configured_flows() -> None:
    source = """function handler(req, element) {
  const id = parseInt(req.query.id, 10);
  db.query("SELECT * FROM t WHERE id = " + id);
  element.innerHTML = escapeHtml(req.query.html);
}
"""
    analysis = analyze_taint(source, path="sanitized.js")

    assert analysis.findings == ()
    assert {site.rule for site in analysis.sanitizers} == {
        "javascript.numeric_conversion",
        "javascript.html_escape",
    }


def test_interprocedural_argument_reaches_sink() -> None:
    source = """def run(command):
    os.system(command)

def handler(request):
    run(request.args["command"])
"""
    analysis = analyze_taint(source, path="argument.py")

    finding = only_finding(analysis, TaintKind.COMMAND_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any(step.role == "parameter" for step in finding.path)
    assert any("same-file" in note for note in finding.confidence_notes)
    assert any(step.via == "parameter" for step in finding.path)


def test_interprocedural_return_reaches_caller() -> None:
    source = """def get_name(request):
    return request.args["name"]

def handler(request):
    cursor.execute(get_name(request))
"""
    analysis = analyze_taint(source, path="return_value.py")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any(step.via == "interprocedural_call" for step in finding.path)
    assert any("return" in step.role for step in finding.path)


def test_expression_bodied_lambda_and_arrow_return_flow() -> None:
    lambda_source = """get_name = lambda request: request.args["name"]
def handler(request):
    cursor.execute(get_name(request))
"""
    analysis = analyze_taint(lambda_source, path="lambda.py")
    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any(step.via == "interprocedural_call" for step in finding.path)

    arrow_source = """const getName = (req) => req.query.name;
function handler(req) {
  db.query(getName(req));
}
"""
    analysis = analyze_taint(arrow_source, path="arrow.js")
    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any(step.via == "interprocedural_call" for step in finding.path)


def test_same_file_sanitizer_wrapper_blocks_flow() -> None:
    source = """def clean(value):
    return html.escape(value)

def handler(request, element):
    element.innerHTML = clean(request.args["html"])
"""
    analysis = analyze_taint(source, path="wrapper.py")

    assert analysis.findings_for(TaintKind.XSS) == ()
    assert [site.rule for site in analysis.sanitizers] == ["python.html_escape"]
    assert analysis.unresolved_calls == 0


def test_python_self_method_resolution() -> None:
    source = """class Repository:
    def sink(self, value):
        cursor.execute(value)

    def handle(self, request):
        self.sink(request.args["query"])
"""
    analysis = analyze_taint(source, path="method.py")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert "cursor.execute" in finding.sink_text
    assert analysis.unresolved_calls == 0


def test_javascript_this_method_resolution() -> None:
    source = """class Repository {
  sink(value) {
    db.query(value);
  }
  handle(req) {
    this.sink(req.query.query);
  }
}
"""
    analysis = analyze_taint(source, path="method.js")

    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert "db.query" in finding.sink_text
    assert analysis.unresolved_calls == 0


def test_interprocedural_analysis_can_be_disabled() -> None:
    source = """def get_name(request):
    return request.args["name"]

def handler(request):
    cursor.execute(get_name(request))
"""
    config = replace(default_taint_config(), interprocedural=False)
    analysis = analyze_taint(source, path="disabled.py", config=config)

    assert analysis.findings == ()
    assert analysis.graph.number_of_nodes() > 0


def test_ambiguous_and_unknown_calls_block_value_flow() -> None:
    ambiguous = """def run(request):
    return request.args["a"]

def run(request):
    return request.args["b"]

def handler(request):
    cursor.execute(run(request))
"""
    analysis = analyze_taint(ambiguous, path="ambiguous.py")
    assert analysis.findings == ()
    assert analysis.unresolved_calls == 1

    unknown = """def handler(request):
    value = transform(request.args["query"])
    cursor.execute(value)
"""
    analysis = analyze_taint(unknown, path="unknown.py")
    assert analysis.findings == ()
    assert analysis.unresolved_calls == 1
    assert len(analysis.sources) == 1
    assert len(analysis.sinks) == 1


def test_calls_configured_as_sources_or_sinks_are_not_unresolved() -> None:
    source = """def handler(request):
    cursor.execute(request.args["query"])
"""
    analysis = analyze_taint(source, path="configured.py")

    assert analysis.unresolved_calls == 0
    assert len(analysis.findings) == 1


def test_sink_argument_index_selects_only_the_configured_argument() -> None:
    tainted_first = """def handler(request):
    query = request.args["query"]
    params = request.args["params"]
    cursor.execute(query, (params,))
"""
    analysis = analyze_taint(tainted_first, path="first_argument.py")
    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.argument_text == "query"

    tainted_second = """def handler(request):
    cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        (request.args["id"],),
    )
"""
    analysis = analyze_taint(tainted_second, path="second_argument.py")
    assert analysis.findings == ()


def test_insert_adjacent_html_uses_its_second_argument() -> None:
    tainted_second = """function handler(req, element) {
  element.insertAdjacentHTML("beforeend", req.query.html);
}
"""
    analysis = analyze_taint(tainted_second, path="insert.js")
    finding = only_finding(analysis, TaintKind.XSS)
    assert finding.argument_text == "req.query.html"

    tainted_first = """function handler(req, element) {
  element.insertAdjacentHTML(req.query.html, "beforeend");
}
"""
    analysis = analyze_taint(tainted_first, path="insert_first.js")
    assert analysis.findings == ()


def test_validator_is_recorded_but_does_not_clear_taint() -> None:
    source = """def handler(request):
    path = request.args["path"]
    if validate_path(path):
        open(path)
"""
    analysis = analyze_taint(source, path="validator.py")

    assert [site.rule for site in analysis.validators] == ["python.path_validator"]
    finding = only_finding(analysis, TaintKind.PATH_TRAVERSAL)
    assert any("Validator calls" in note for note in finding.confidence_notes)


def test_custom_configuration_replaces_instead_of_merging_defaults() -> None:
    config = TaintConfig(
        sources=(
            SourceRule(
                name="app.input",
                patterns=("tainted_value",),
                kinds=(TaintKind.XSS,),
                match=NameMatch.EXACT,
            ),
        ),
        sinks=(
            SinkRule(
                name="app.html",
                kind=TaintKind.XSS,
                patterns=("write_html",),
                argument=0,
                match=NameMatch.EXACT,
            ),
        ),
    )
    source = """def handler():
    value = tainted_value
    write_html(value)
    cursor.execute(value)
"""
    analysis = analyze_taint(source, path="custom.py", config=config)

    finding = only_finding(analysis, TaintKind.XSS)
    assert finding.source_rule == "app.input"
    assert finding.sink_rule == "app.html"
    assert [site.rule for site in analysis.sources] == ["app.input"]
    assert [site.rule for site in analysis.sinks] == ["app.html"]

    default_source = """def handler(request):
    cursor.execute(request.args["query"])
"""
    analysis = analyze_taint(default_source, path="defaults.py", config=config)
    assert analysis.sources == ()
    assert analysis.sinks == ()
    assert analysis.findings == ()


def test_custom_propagator_carries_taint_to_its_result() -> None:
    config = TaintConfig(
        sources=(
            SourceRule(
                name="app.input",
                patterns=("input_value",),
                kinds=(TaintKind.COMMAND_INJECTION,),
                match=NameMatch.EXACT,
            ),
        ),
        propagators=(
            PropagatorRule(
                name="app.wrapper",
                patterns=("wrap_value",),
                mode=PropagatorMode.BOTH,
                kinds=(TaintKind.COMMAND_INJECTION,),
                match=NameMatch.EXACT,
            ),
        ),
        sinks=(
            SinkRule(
                name="app.run",
                kind=TaintKind.COMMAND_INJECTION,
                patterns=("run_command",),
                argument=0,
                match=NameMatch.EXACT,
            ),
        ),
    )
    source = """def handler():
    value = wrap_value(input_value)
    run_command(value)
"""
    analysis = analyze_taint(source, path="propagator.py", config=config)

    finding = only_finding(analysis, TaintKind.COMMAND_INJECTION)
    assert finding.confidence is TaintConfidence.MEDIUM
    assert any(step.via == "propagator" for step in finding.path)
    assert analysis.unresolved_calls == 0


def test_rule_validation_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="at least one non-empty pattern"):
        SourceRule(name="empty.patterns", patterns=())
    with pytest.raises(ValueError, match="at least one taint kind"):
        SourceRule(name="empty.kinds", patterns=("value",), kinds=())
    with pytest.raises(ValueError, match="non-negative"):
        SinkRule(name="bad.index", kind=TaintKind.XSS, patterns=("sink",), argument=-1)
    with pytest.raises(ValueError, match="unique"):
        TaintConfig(
            sources=(
                SourceRule(name="duplicate", patterns=("one",)),
                SourceRule(name="duplicate", patterns=("two",)),
            )
        )
    with pytest.raises(ValueError, match="max_paths_per_sink"):
        TaintConfig(max_paths_per_sink=0)
    with pytest.raises(ValueError, match="max_findings"):
        TaintConfig(max_findings=0)


def test_source_sites_deduplicate_nested_expressions() -> None:
    source = """def handler(request):
    query = request.args.get("query")
    cursor.execute(query)
"""
    analysis = analyze_taint(source, path="dedupe.py")

    assert len(analysis.sources) == 1
    assert analysis.sources[0].text == "request.args.get"
    finding = only_finding(analysis, TaintKind.SQL_INJECTION)
    assert finding.source_text == 'request.args.get("query")'


def test_findings_are_potential_and_carry_limitations() -> None:
    source = """def handler(request):
    cursor.execute(request.args["query"])
"""
    analysis = analyze_taint(source, path="limitations.py")
    finding = only_finding(analysis, TaintKind.SQL_INJECTION)

    assert finding.to_dict()["potential"] is True
    assert all(limitation.startswith("LIM-PA-") for limitation in analysis.limitations)
    assert any("LIM-PA-09" in limitation for limitation in finding.limitations)
    assert any("LIM-PA-10" in limitation for limitation in finding.limitations)
    assert any("LIM-PA-11" in limitation for limitation in finding.limitations)
    assert any("exploitability" in note for note in finding.confidence_notes)


def test_path_limits_are_applied() -> None:
    source = """def handler(request):
    first = request.args["first"]
    second = request.args["second"]
    cursor.execute(first + second)
"""
    config = replace(default_taint_config(), max_paths_per_sink=1)
    analysis = analyze_taint(source, path="paths.py", config=config)
    assert len(analysis.findings) == 1

    two_sinks = """def handler(request):
    query = request.args["query"]
    cursor.execute(query)
    os.system(query)
"""
    config = replace(default_taint_config(), max_findings=1)
    analysis = analyze_taint(two_sinks, path="findings.py", config=config)
    assert len(analysis.findings) == 1


def test_analysis_to_dict_is_json_serializable_and_describes_graph() -> None:
    source = """def handler(request):
    query = request.args["query"]
    cursor.execute(query)
"""
    analysis = analyze_taint(source, path="serialize.py")
    payload = analysis.to_dict()
    encoded = json.dumps(payload)

    assert isinstance(analysis.graph, nx.DiGraph)
    assert "LIM-PA-10" in encoded
    assert payload["path"] == "serialize.py"
    assert payload["language"] == "python"
    assert payload["summary"]["findings"] == 1
    assert payload["findings"][0]["potential"] is True
    assert payload["findings"][0]["path"][0]["role"] == "source"
    assert payload["findings"][0]["path"][-1]["role"] == "sink"
    assert payload["graph"]["nodes"]
    assert payload["graph"]["edges"]
    for node in payload["graph"]["nodes"]:
        assert "span" in node
    for edge in payload["graph"]["edges"]:
        assert "span" in edge


def test_analyze_taint_file_and_parsed_input(tmp_path) -> None:
    source = """function handler(req) {
  db.query(req.query.query);
}
"""
    path = tmp_path / "flow.js"
    path.write_text(source, encoding="utf-8")
    analysis = analyze_taint_file(path)
    assert analysis.parsed.language is SupportedLanguage.JAVASCRIPT
    only_finding(analysis, TaintKind.SQL_INJECTION)

    parsed = parse_source(source, path="flow.js")
    analysis = analyze_taint(parsed)
    assert analysis.parsed is parsed
    only_finding(analysis, TaintKind.SQL_INJECTION)


def test_no_source_or_no_sink_produces_no_findings() -> None:
    no_source = """def handler():
    cursor.execute("SELECT * FROM users")
"""
    analysis = analyze_taint(no_source, path="no_source.py")
    assert analysis.sources == ()
    assert analysis.sinks
    assert analysis.findings == ()

    no_sink = """def handler(request):
    return request.args["query"]
"""
    analysis = analyze_taint(no_sink, path="no_sink.py")
    assert analysis.sources
    assert analysis.sinks == ()
    assert analysis.findings == ()
