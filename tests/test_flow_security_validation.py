import pytest

from bugdhor_ast.flow import FLOW_SECTIONS, FlowEngine


CASES = [
    {
        "id": "python-input-eval",
        "language": "python",
        "prefix": "PY",
        "source": (
            "data = input()\n"
            "eval(data)\n"
            "safe = int(data)\n"
            "eval(safe)\n"
            'eval("literal")\n'
        ),
        "expected": [(2, "PY-SNK-001", "input")],
        "path_kinds": ["source", "assignment", "sink"],
    },
    {
        "id": "python-helper-sink",
        "language": "python",
        "prefix": "PY",
        "source": (
            "def passthrough(x):\n"
            "    return x\n"
            "\n"
            "data = input()\n"
            "out = passthrough(data)\n"
            "eval(out)\n"
            'eval("literal")\n'
        ),
        "expected": [(6, "PY-SNK-001", "input")],
        "path_kinds": ["source", "assignment", "assignment", "sink"],
    },
    {
        "id": "javascript-query-innerhtml",
        "language": "javascript",
        "prefix": "JS",
        "source": (
            "const q = new URLSearchParams(location.search).get('q');\n"
            "document.body.innerHTML = q;\n"
            "const safe = DOMPurify.sanitize(q);\n"
            "document.body.innerHTML = safe;\n"
            'document.body.innerHTML = "<b>ok</b>";\n'
        ),
        "expected": [(2, "JS-SNK-003", "new URLSearchParams(location.search).get")],
        "path_kinds": ["source", "assignment", "sink"],
    },
    {
        "id": "javascript-prompt-eval",
        "language": "javascript",
        "prefix": "JS",
        "source": (
            'const user = prompt("value");\n'
            "eval(user);\n"
            "const n = parseInt(user);\n"
            "eval(n);\n"
            'eval("1+1");\n'
        ),
        "expected": [(2, "JS-SNK-001", "prompt")],
        "path_kinds": ["source", "assignment", "sink"],
    },
    {
        "id": "javascript-function-argument",
        "language": "javascript",
        "prefix": "JS",
        "source": (
            "function dangerous(value) { eval(value); }\n"
            "const q = req.query.user;\n"
            "dangerous(q);\n"
            "const safe = encodeURIComponent(q);\n"
            "dangerous(safe);\n"
        ),
        "expected": [(1, "JS-SNK-001", "req.query.user")],
        "path_kinds": [
            "source", "assignment", "argument", "parameter", "sink",
        ],
    },
    {
        "id": "java-request-sql",
        "language": "java",
        "prefix": "JAVA",
        "source": (
            "class C {\n"
            "  void f(HttpServletRequest request, Statement stmt) {\n"
            '    String q = request.getParameter("q");\n'
            "    stmt.executeQuery(q);\n"
            "    String n = Integer.parseInt(q);\n"
            "    stmt.executeQuery(n);\n"
            '    stmt.executeQuery("SELECT 1");\n'
            "  }\n"
            "}\n"
        ),
        "expected": [(4, "JAVA-SNK-003", "request.getParameter")],
        "path_kinds": ["source", "assignment", "sink"],
    },
    {
        "id": "java-request-runtime-exec",
        "language": "java",
        "prefix": "JAVA",
        "source": (
            "class C {\n"
            "  void f(HttpServletRequest request) {\n"
            '    String cmd = request.getParameter("cmd");\n'
            "    Runtime.getRuntime().exec(cmd);\n"
            "    String safe = sanitize(cmd);\n"
            "    Runtime.getRuntime().exec(safe);\n"
            "  }\n"
            "}\n"
        ),
        "expected": [(4, "JAVA-SNK-001", "request.getParameter")],
        "path_kinds": ["source", "assignment", "sink"],
    },
    {
        "id": "java-method-argument",
        "language": "java",
        "prefix": "JAVA",
        "source": (
            "class C {\n"
            "  void dangerous(String value) { eval(value); }\n"
            "  void f(HttpServletRequest request) {\n"
            '    String q = request.getParameter("q");\n'
            "    dangerous(q);\n"
            "    String safe = Integer.parseInt(q);\n"
            "    dangerous(safe);\n"
            "  }\n"
            "}\n"
        ),
        "expected": [(2, "JAVA-SNK-008", "request.getParameter")],
        "path_kinds": [
            "source", "assignment", "argument", "parameter", "sink",
        ],
    },
]


@pytest.mark.parametrize("case", CASES, ids=[item["id"] for item in CASES])
def test_source_sink_security_matrix(case):
    result = FlowEngine().analyze_source(case["source"], case["language"])
    findings = result.taint_analysis.findings

    actual = [
        (item.sink_location.line, item.sink_rule, item.source_name)
        for item in findings
    ]
    assert actual == case["expected"]

    prefix = case["prefix"]
    for finding in findings:
        assert finding.source_rule.startswith(f"{prefix}-SRC-")
        assert finding.sink_rule.startswith(f"{prefix}-SNK-")
        assert finding.id.startswith("taint:")
        assert [step["kind"] for step in finding.path] == case["path_kinds"]
        assert finding.path[0]["rule"] == finding.source_rule
        assert finding.path[0]["location"]["line"] == finding.source_location.line
        assert finding.path[-1]["rule"] == finding.sink_rule
        assert finding.path[-1]["location"]["line"] == finding.sink_location.line
        assert finding.confidence in {"low", "medium", "high"}


def test_taint_json_schema_keeps_phase3_keys():
    result = FlowEngine().analyze_source(
        "data = input()\neval(data)\n", "python"
    )
    payload = result.to_dict()

    assert set(FLOW_SECTIONS) <= set(payload)
    taint = payload["taint_analysis"]
    assert {"language", "summary", "rules", "findings", "limitations"} <= set(taint)
    assert taint["summary"] == {
        "findings": 1,
        "sources": 7,
        "sanitizers": 4,
        "sinks": 7,
    }
    finding = taint["findings"][0]
    assert {
        "id",
        "source_rule",
        "source_name",
        "source_location",
        "sink_rule",
        "sink_name",
        "sink_location",
        "path",
        "confidence",
        "sanitizers",
        "limitations",
    } <= set(finding)
    assert {
        "id", "kind", "name", "pattern", "language", "argument_index",
        "description",
    } <= set(taint["rules"][0])
