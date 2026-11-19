from bugdhor_ast.flow import FlowEngine


def findings(result):
    return [
        (
            item.source_name,
            item.source_location.line,
            item.sink_location.line,
            [step["kind"] for step in item.path],
        )
        for item in result.taint_analysis.findings
    ]


def test_object_field_write_and_read():
    source = (
        "obj = {}\n"
        "obj.field = input()\n"
        "eval(obj.field)\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            2,
            3,
            ["source", "slot_write", "slot_read", "sink"],
        )
    ]


def test_dictionary_value_write_and_read():
    source = (
        "data = {}\n"
        "data['k'] = input()\n"
        "eval(data['k'])\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            2,
            3,
            ["source", "slot_write", "slot_read", "sink"],
        )
    ]


def test_list_append_and_index_read():
    source = (
        "items = []\n"
        "items.append(input())\n"
        "eval(items[0])\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            2,
            3,
            ["source", "slot_write", "slot_read", "sink"],
        )
    ]


def test_list_index_write_and_read():
    source = (
        "items = [0]\n"
        "items[0] = input()\n"
        "eval(items[0])\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            2,
            3,
            ["source", "slot_write", "slot_read", "sink"],
        )
    ]


def test_simple_alias_normalizes_writes_and_reads():
    source = (
        "obj = {}\n"
        "alias = obj\n"
        "alias.field = input()\n"
        "eval(obj.field)\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            3,
            4,
            ["source", "slot_write", "slot_read", "sink"],
        )
    ]


def test_attribute_read_copies_taint_to_local():
    source = (
        "obj = {}\n"
        "obj.field = input()\n"
        "value = obj.field\n"
        "eval(value)\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        (
            "input",
            2,
            4,
            ["source", "slot_write", "slot_read", "assignment", "sink"],
        )
    ]


def test_string_concatenation_preserves_taint():
    source = (
        "data = input()\n"
        "value = 'prefix-' + data\n"
        "eval(value)\n"
    )

    assert findings(FlowEngine().analyze_source(source, "python")) == [
        ("input", 1, 3, ["source", "assignment", "assignment", "sink"])
    ]


def test_safe_literals_and_sanitized_slots_are_not_reported():
    source = (
        "obj = {}\n"
        "obj.field = 'trusted'\n"
        "eval(obj.field)\n"
        "obj.safe = html.escape(input())\n"
        "eval(obj.safe)\n"
        "items = []\n"
        "items.append('trusted')\n"
        "eval(items[0])\n"
    )

    assert FlowEngine().analyze_source(source, "python").taint_analysis.findings == []
