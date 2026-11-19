from bugdhor_ast.flow import FlowEngine


def sink_lines(result):
    return [item.sink_location.line for item in result.taint_analysis.findings]


def test_caller_argument_maps_to_parameter_and_return_value():
    source = (
        "def passthrough(x):\n"
        "    return x\n"
        "\n"
        "def run():\n"
        "    data = input()\n"
        "    out = passthrough(data)\n"
        "    eval(out)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    assert sink_lines(result) == [7]
    finding = result.taint_analysis.findings[0]
    assert finding.source_name == "input"
    assert finding.source_location.line == 5
    assert {step["kind"] for step in finding.path} >= {
        "source",
        "assignment",
        "sink",
    }


def test_call_site_specific_taint_does_not_cross_call_sites():
    source = (
        "def echo(x):\n"
        "    return x\n"
        "\n"
        "a = echo(input())\n"
        "b = echo(\"safe\")\n"
        "eval(a)\n"
        "eval(b)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    assert sink_lines(result) == [6]
    assert result.taint_analysis.findings[0].source_location.line == 4


def test_bounded_recursive_analysis_terminates_and_keeps_taint():
    source = (
        "def rec(n):\n"
        "    if n > 0:\n"
        "        return rec(n - 1)\n"
        "    return input()\n"
        "\n"
        "value = rec(2)\n"
        "eval(value)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    assert sink_lines(result) == [7]
    assert result.taint_analysis.findings[0].source_rule == "PY-SRC-001"


def test_unresolved_calls_are_conservative():
    source = (
        "def run():\n"
        "    data = input()\n"
        "    unknown_transform(data)\n"
        "    eval(data)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    assert sink_lines(result) == [4]
    assert all(
        "unresolved" not in step["kind"]
        for finding in result.taint_analysis.findings
        for step in finding.path
    )


def test_repeated_calls_converge_with_bounded_paths():
    function_count = 12
    source = (
        "".join(
            f"def passthrough_{index}(value):\n    return value\n"
            for index in range(function_count)
        )
        + "data = input()\n"
        + "".join(
            f"result_{index} = passthrough_{index}(data)\n"
            for index in range(function_count)
        )
        + "".join(
            f"eval(result_{index})\n"
            for index in range(function_count)
        )
    )

    result = FlowEngine().analyze_source(source, "python")

    assert len(result.taint_analysis.findings) == function_count
    assert all(
        len(finding.path) <= 4
        for finding in result.taint_analysis.findings
    )


def test_function_summary_records_call_sites():
    source = (
        "def helper(a):\n"
        "    return a\n"
        "\n"
        "x = helper(1)\n"
        "y = helper(2)\n"
    )
    result = FlowEngine().analyze_source(source, "python")

    summary = next(
        item
        for item in result.data_flow.function_summaries
        if item.name == "helper"
    )
    assert len(summary.call_sites) == 2
    assert all(
        statement.startswith("stmt:")
        for statement in summary.call_sites
    )
